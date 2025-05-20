import asyncio
import collections.abc
import dataclasses
import datetime
import functools
import http
import json
import logging

import aiohttp.web
import dacite
import jsonpath_ng
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync

import consts
import features
import deliverydb.model as dm
import deliverydb.util as du
import k8s.backlog
import k8s.util
import middleware.auth
import ocm_util
import odg.cvss
import odg.extensions_cfg
import odg.findings
import odg.model
import rescore.utility
import util
import yp


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class LicenseFinding(odg.model.Finding):
    package_name: str
    package_versions: tuple[str, ...] # "..." for dacite.from_dict
    license: odg.model.License
    filesystem_paths: list[odg.model.FilesystemPath]


@dataclasses.dataclass
class VulnerabilityFinding(odg.model.Finding):
    package_name: str
    package_versions: tuple[str, ...] # "..." for dacite.from_dict
    cve: str
    cvss_v3_score: float
    cvss: str
    summary: str | None
    urls: list[str]
    filesystem_paths: list[odg.model.FilesystemPath]


@dataclasses.dataclass
class MalwareFinding(odg.model.Finding):
    finding: odg.model.MalwareFindingDetails


@dataclasses.dataclass
class RescoringProposal:
    finding: (
        LicenseFinding
        | VulnerabilityFinding
        | MalwareFinding
        | odg.model.SastFinding
        | odg.model.CryptoFinding
        | odg.model.OsIdFinding
    )
    finding_type: odg.model.Datatype
    severity: str
    matching_rules: list[str]
    applicable_rescorings: tuple[dict, ...] # "..." for dacite.from_dict
    discovery_date: str
    due_date: str | None
    sprint: yp.Sprint | None


async def _find_artefact_metadata(
    db_session: sqlasync.session.AsyncSession,
    artefact: odg.model.ComponentArtefactId,
    type_filter: list[str]=[],
) -> list[odg.model.ArtefactMetadata]:
    db_statement = sa.select(dm.ArtefactMetaData).where(
        sa.and_(
            dm.ArtefactMetaData.component_name == artefact.component_name,
            sa.or_(
                dm.ArtefactMetaData.component_version == sa.null(),
                dm.ArtefactMetaData.component_version == artefact.component_version,
            ),
            dm.ArtefactMetaData.artefact_kind == artefact.artefact_kind,
            dm.ArtefactMetaData.artefact_name == artefact.artefact.artefact_name,
            dm.ArtefactMetaData.artefact_version == artefact.artefact.artefact_version,
            dm.ArtefactMetaData.artefact_type == artefact.artefact.artefact_type,
            dm.ArtefactMetaData.artefact_extra_id_normalised
                == artefact.artefact.normalised_artefact_extra_id,
            dm.ArtefactMetaData.type != odg.model.Datatype.RESCORING,
            sa.or_(
                not type_filter,
                dm.ArtefactMetaData.type.in_(type_filter),
            ),
        ),
    )

    db_stream = await db_session.stream(db_statement)

    return [
        du.db_artefact_metadata_row_to_dso(row)
        async for partition in db_stream.partitions(size=50)
        for row in partition
    ]


async def _find_rescorings(
    db_session: sqlasync.session.AsyncSession,
    artefact: odg.model.ComponentArtefactId,
    type_filter: list[str]=[],
) -> list[odg.model.ArtefactMetadata]:
    db_statement = sa.select(dm.ArtefactMetaData).where(
        sa.and_(
            dm.ArtefactMetaData.type == odg.model.Datatype.RESCORING,
            sa.or_(
                # regular `not` or `is None` not working with sqlalchemy
                dm.ArtefactMetaData.component_name == sa.null(),
                dm.ArtefactMetaData.component_name == artefact.component_name,
            ),
            sa.or_(
                dm.ArtefactMetaData.component_version == sa.null(),
                dm.ArtefactMetaData.component_version == artefact.component_version
            ),
            sa.or_(
                dm.ArtefactMetaData.artefact_name == sa.null(),
                dm.ArtefactMetaData.artefact_name == artefact.artefact.artefact_name,
            ),
            sa.or_(
                dm.ArtefactMetaData.artefact_version == sa.null(),
                dm.ArtefactMetaData.artefact_version == artefact.artefact.artefact_version,
            ),
            sa.or_(
                dm.ArtefactMetaData.artefact_extra_id_normalised == '',
                dm.ArtefactMetaData.artefact_extra_id_normalised
                    == artefact.artefact.normalised_artefact_extra_id,
            ),
            dm.ArtefactMetaData.artefact_kind == artefact.artefact_kind,
            dm.ArtefactMetaData.artefact_type == artefact.artefact.artefact_type,
        )
    )

    if type_filter:
        db_statement = db_statement.where(
            du.ArtefactMetadataFilters.filter_for_rescoring_type(type_filter),
        )

    db_stream = await db_session.stream(db_statement)

    return [
        du.db_artefact_metadata_row_to_dso(row)
        async for partition in db_stream.partitions(size=50)
        for row in partition
    ]


def filesystem_paths_for_finding(
    artefact_metadata: tuple[odg.model.ArtefactMetadata],
    finding: odg.model.ArtefactMetadata,
    package_versions: tuple[str]=(),
) -> list[odg.model.FilesystemPath]:
    if not package_versions:
        # only show filesystem paths for package versions which actually have findings;
        # in case no package versions are supplied, BDBA was not able to detect a version
        # so include only filesystem paths for packages without version
        package_versions = (None,)

    matching_structure_info = tuple(
        matching_info for matching_info in artefact_metadata
        if (
            matching_info.meta.type == odg.model.Datatype.STRUCTURE_INFO
            and matching_info.data.package_name == finding.data.package_name
            and matching_info.data.package_version in package_versions
            and matching_info.artefact.component_name == finding.artefact.component_name
            and matching_info.artefact.component_version == finding.artefact.component_version
            and matching_info.artefact.artefact_kind == finding.artefact.artefact_kind
            and matching_info.artefact.artefact.artefact_name
                == finding.artefact.artefact.artefact_name
            and matching_info.artefact.artefact.artefact_version
                == finding.artefact.artefact.artefact_version
            and matching_info.artefact.artefact.artefact_type
                == finding.artefact.artefact.artefact_type
            and matching_info.artefact.artefact.normalised_artefact_extra_id
                == finding.artefact.artefact.normalised_artefact_extra_id
        )
    )

    return [
        path
        for structure_info in matching_structure_info
        for path in structure_info.data.filesystem_paths
    ]


def sprint_for_finding(
    due_date: datetime.date | None,
    sprints: list[yp.Sprint],
) -> yp.Sprint | None:
    '''
    Returns the sprint with the closest future end date compared to the provided
    `due_date`. In case the `due_date` is `None` (this might be the case if a finding already
    belongs to a category which is to be interpreted as "assessed") or no such sprint can be found,
    `None` is returned instead.
    '''
    if not due_date or not sprints:
        return None

    for sprint in sorted(sprints, key=lambda sprint: sprint.end_date):
        if sprint.end_date.date() > due_date:
            return sprint

    logger.warning(f'could not determine target sprint for {due_date=}')
    return None


def _package_versions_and_filesystem_paths(
    artefact_metadata_across_package_version: tuple[odg.model.ArtefactMetadata],
    artefact_metadata: collections.abc.Iterable[odg.model.ArtefactMetadata],
    finding: odg.model.ArtefactMetadata,
) -> tuple[tuple[str], list[odg.model.FilesystemPath]]:
    package_versions = tuple(
        matching_am.data.package_version
        for matching_am in artefact_metadata_across_package_version
        if matching_am.data.package_version
    )

    filesystem_paths = filesystem_paths_for_finding(
        artefact_metadata=artefact_metadata,
        finding=finding,
        package_versions=package_versions,
    )

    return package_versions, filesystem_paths


async def _iter_rescoring_proposals(
    artefact_metadata: collections.abc.Iterable[odg.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[odg.model.ArtefactMetadata],
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    cve_categorisation: odg.cvss.CveCategorisation | None,
    sprints: list[yp.Sprint]=[],
) -> collections.abc.AsyncGenerator[RescoringProposal, None, None]:
    '''
    yield rescorings for supported finding types
    implements special handling for BDBA findings (grouping across different package-versions)
    '''

    seen_ids = set()
    loop = asyncio.get_running_loop()

    for am in artefact_metadata:
        if (
            am.meta.type == odg.model.Datatype.STRUCTURE_INFO
            or am.id in seen_ids
        ):
            continue

        for finding_cfg in finding_cfgs:
            if odg.model.Datatype(am.meta.type) is finding_cfg.type:
                break
        else:
            # we checked this already earlier, all types must have a correspondig configuration
            raise RuntimeError('this is a bug, this line should never be reached')

        current_rescorings = await loop.run_in_executor(None, functools.partial(
            rescore.utility.rescorings_for_finding_by_specificity,
            finding=am,
            rescorings=rescorings,
        ))
        severity = am.data.severity

        if current_rescorings:
            rescoring = current_rescorings[0]
            current_severity = rescoring.data.severity
            matching_rule_names = rescoring.data.matching_rules
        else:
            rescoring = None
            current_severity = severity
            matching_rule_names = [odg.model.MetaRescoringRules.ORIGINAL_SEVERITY]

        categorisation = finding_cfg.categorisation_by_id(current_severity)
        due_date = categorisation.effective_due_date(
            finding=am,
            rescoring=rescoring,
        )

        sprint = sprint_for_finding(
            due_date=due_date,
            sprints=sprints,
        )

        if due_date:
            due_date = due_date.isoformat()

        # patch in `id` because it is required in order to be able to delete rescorings
        serialised_current_rescorings = tuple(
            {
                **dataclasses.asdict(rescoring),
                'id': rescoring.id,
            } for rescoring in current_rescorings
        )

        if finding_cfg.type is odg.model.Datatype.MALWARE_FINDING:
            yield dacite.from_dict(
                data_class=RescoringProposal,
                data={
                    'finding': {
                        'finding': {
                            'filename': am.data.finding.filename,
                            'content_digest': am.data.finding.content_digest,
                            'malware': am.data.finding.malware,
                        },
                        'severity': severity,
                    },
                    'finding_type': finding_cfg.type,
                    'severity': current_severity,
                    'matching_rules': matching_rule_names,
                    'applicable_rescorings': serialised_current_rescorings,
                    'discovery_date': am.discovery_date.isoformat(),
                    'due_date': due_date,
                    'sprint': sprint,
                },
            )

        elif finding_cfg.type is odg.model.Datatype.SAST_FINDING:
            yield dacite.from_dict(
                data_class=RescoringProposal,
                data={
                    'finding': {
                        'sast_status': am.data.sast_status,
                        'sub_type': am.data.sub_type,
                        'severity': severity,
                    },
                    'finding_type': finding_cfg.type,
                    'severity': current_severity,
                    'matching_rules': matching_rule_names,
                    'applicable_rescorings': serialised_current_rescorings,
                    'discovery_date': am.discovery_date.isoformat(),
                    'due_date': due_date,
                    'sprint': sprint,
                },
            )

        elif finding_cfg.type in (
            odg.model.Datatype.VULNERABILITY_FINDING,
            odg.model.Datatype.LICENSE_FINDING,
        ):
            artefact_metadata_with_same_ocm = tuple(
                matching_am for matching_am in artefact_metadata
                if (
                    matching_am.id not in seen_ids
                    and matching_am.meta.type == am.meta.type
                    and matching_am.artefact.component_name == am.artefact.component_name
                    and matching_am.artefact.component_version == am.artefact.component_version
                    and matching_am.artefact.artefact_kind is am.artefact.artefact_kind
                    and matching_am.artefact.artefact.artefact_name
                        == am.artefact.artefact.artefact_name
                    and matching_am.artefact.artefact.artefact_version
                        == am.artefact.artefact.artefact_version
                    and matching_am.artefact.artefact.artefact_type
                        == am.artefact.artefact.artefact_type
                    and matching_am.artefact.artefact.normalised_artefact_extra_id
                        == am.artefact.artefact.normalised_artefact_extra_id
                )
            )
            package_name = am.data.package_name

            if finding_cfg.type is odg.model.Datatype.VULNERABILITY_FINDING:
                cve = am.data.cve
                cvss = odg.cvss.CVSSV3.from_dict(cvss=am.data.cvss)
                cvss_v3_score = am.data.cvss_v3_score

                am_across_package_versions = tuple(
                    artefact_metadatum for artefact_metadatum in artefact_metadata_with_same_ocm
                    if (
                        artefact_metadatum.data.cve == cve and
                        artefact_metadatum.data.package_name == package_name
                    )
                )
                seen_ids.update(
                    tuple(
                        local_am.id for local_am
                        in am_across_package_versions
                    )
                )

                package_versions, filesystem_paths = _package_versions_and_filesystem_paths(
                    artefact_metadata_across_package_version=am_across_package_versions,
                    artefact_metadata=artefact_metadata,
                    finding=am,
                )

                # only propose rescoring if finding is not rescored yet
                if not current_rescorings and finding_cfg.rescoring_ruleset and cve_categorisation:
                    rescoring_rules = list(rescore.utility.matching_rescore_rules(
                        rescoring_rules=finding_cfg.rescoring_ruleset.rules,
                        categorisation=cve_categorisation,
                        cvss=cvss,
                    ))

                    current_severity = rescore.utility.rescore_finding(
                        finding_cfg=finding_cfg,
                        current_categorisation=categorisation,
                        rescoring_rules=rescoring_rules,
                        operations=finding_cfg.rescoring_ruleset.operations,
                    ).id

                    matching_rule_names = [rule.name for rule in rescoring_rules]

                yield dacite.from_dict(
                    data_class=RescoringProposal,
                    data={
                        'finding': {
                            'package_name': package_name,
                            'package_versions': package_versions,
                            'severity': severity,
                            'cve': cve,
                            'cvss_v3_score': cvss_v3_score,
                            'cvss': f'{cvss}',
                            'summary': am.data.summary,
                            'urls': [f'https://nvd.nist.gov/vuln/detail/{cve}'],
                            'filesystem_paths': filesystem_paths,
                        },
                        'finding_type': finding_cfg.type,
                        'severity': current_severity,
                        'matching_rules': matching_rule_names,
                        'applicable_rescorings': serialised_current_rescorings,
                        'discovery_date': am.discovery_date.isoformat(),
                        'due_date': due_date,
                        'sprint': sprint,
                    },
                )

            elif finding_cfg.type is odg.model.Datatype.LICENSE_FINDING:
                license = am.data.license

                am_across_package_versions = tuple(
                    matching_am for matching_am in artefact_metadata_with_same_ocm
                    if (
                        matching_am.data.license.name == license.name and
                        matching_am.data.package_name == package_name
                    )
                )
                seen_ids.update(
                    tuple(
                        local_am.id for local_am
                        in am_across_package_versions
                    )
                )

                package_versions, filesystem_paths = _package_versions_and_filesystem_paths(
                    artefact_metadata_across_package_version=am_across_package_versions,
                    artefact_metadata=artefact_metadata,
                    finding=am,
                )

                yield dacite.from_dict(
                    data_class=RescoringProposal,
                    data={
                        'finding': {
                            'package_name': package_name,
                            'package_versions': package_versions,
                            'severity': severity,
                            'license': license,
                            'filesystem_paths': filesystem_paths,
                        },
                        'finding_type': finding_cfg.type,
                        'severity': current_severity,
                        'matching_rules': matching_rule_names,
                        'applicable_rescorings': serialised_current_rescorings,
                        'discovery_date': am.discovery_date.isoformat(),
                        'due_date': due_date,
                        'sprint': sprint,
                    },
                )

        elif finding_cfg.type is odg.model.Datatype.CRYPTO_FINDING:
            yield dacite.from_dict(
                data_class=RescoringProposal,
                data={
                    'finding': dataclasses.asdict(am.data),
                    'finding_type': finding_cfg.type,
                    'severity': current_severity,
                    'matching_rules': matching_rule_names,
                    'applicable_rescorings': serialised_current_rescorings,
                    'discovery_date': am.discovery_date.isoformat(),
                    'due_date': due_date,
                    'sprint': sprint,
                },
                config=dacite.Config(
                    strict=True,
                ),
            )
        elif finding_cfg.type is odg.model.Datatype.OSID_FINDING:
            yield dacite.from_dict(
                data_class=RescoringProposal,
                data={
                    'finding': dataclasses.asdict(am.data),
                    'finding_type': finding_cfg.type,
                    'severity': current_severity,
                    'matching_rules': matching_rule_names,
                    'applicable_rescorings': serialised_current_rescorings,
                    'discovery_date': am.discovery_date.isoformat(),
                    'due_date': due_date,
                    'sprint': sprint,
                },
            )

        seen_ids.add(am.id)


async def create_backlog_items_for_rescored_artefacts(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    rescorings: collections.abc.Iterable[odg.model.ArtefactMetadata],
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
):
    '''
    Determines those artefacts from `rescorings`, which still contain all attributes which are
    relevant for grouping in the GitHub issues, and creates respective issue replicator backlog
    items for those. If some of these properties are not set (e.g. because the rescoring scope is
    too generous), those artefact will be skipped and their GitHub issues will have to be updated
    with the next usual issue update (based on the configured issue replicator interval).
    '''
    artefact_groups = set()

    for rescoring in rescorings:
        finding_type = odg.model.Datatype(rescoring.data.referenced_type)

        for finding_cfg in finding_cfgs:
            if finding_type is finding_cfg.type:
                break
        else:
            raise ValueError(f'did not find finding-cfg for {finding_type=}')

        if not finding_cfg.issues.enable_issues:
            # no need to create a BLI if issues are disabled anyways for this finding type
            continue

        artefact_raw = dataclasses.asdict(rescoring.artefact)

        required_attr_not_set = False
        for attr_ref in finding_cfg.issues.attrs_to_group_by:
            attr_path = jsonpath_ng.parse(attr_ref)

            if (
                not (prop := attr_path.find(artefact_raw))
                or prop[0].value is None
            ):
                required_attr_not_set = True
                break

        if required_attr_not_set:
            # if any grouping relevant attribute is not set, we are unable to create a corresponding
            # BLI which contains the minimum required attributes
            continue

        artefact_groups.add(finding_cfg.issues.strip_artefact(
            artefact=rescoring.artefact,
            keep_group_attributes=True,
        ))

    for artefact in artefact_groups:
        k8s.backlog.create_backlog_item(
            service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            artefact=artefact,
            priority=k8s.backlog.BacklogPriorities.CRITICAL,
        )


class Rescore(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    async def options(self):
        return aiohttp.web.Response()

    async def post(self):
        '''
        ---
        description: Applies rescoring to delivery-db.
        tags:
        - Rescoring
        parameters:
        - in: body
          name: body
          required: false
          schema:
            type: object
            properties:
              entries:
                type: array
                items:
                  $ref: '#/definitions/ArtefactMetadata'
        responses:
          "201":
            description: Successful operation.
        '''
        body = await self.request.json()
        rescorings_raw: list[dict] = body.get('entries')

        extensions_cfg = self.request.app[consts.APP_EXTENSIONS_CFG]
        user: middleware.auth.GithubUser = self.request[consts.REQUEST_GITHUB_USER]
        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        def iter_rescorings(
            rescorings_raw: list[dict],
        ) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
            for rescoring_raw in rescorings_raw:
                rescoring_raw['data']['user'] = dataclasses.asdict(user)

                rescoring = odg.model.ArtefactMetadata.from_dict(rescoring_raw)

                if not rescoring.meta.type == odg.model.Datatype.RESCORING:
                    raise aiohttp.web.HTTPBadRequest(
                        reason=f'Rescoring must be of type {odg.model.Datatype.RESCORING}',
                        text=f'{rescoring.meta.type=}',
                    )

                yield rescoring

        rescorings = tuple(iter_rescorings(rescorings_raw=rescorings_raw))

        try:
            for rescoring in rescorings:
                rescoring_db = du.to_db_artefact_metadata(
                    artefact_metadata=rescoring,
                )

                # avoid adding rescoring duplicates -> purge old entries
                await db_session.execute(sa.delete(dm.ArtefactMetaData).where(
                    dm.ArtefactMetaData.id == rescoring_db.id,
                ))

                db_session.add(rescoring_db)

            await db_session.commit()
        except:
            await db_session.rollback()
            raise

        if (
            extensions_cfg
            and extensions_cfg.issue_replicator
            and extensions_cfg.issue_replicator.enabled
        ):
            asyncio.create_task(create_backlog_items_for_rescored_artefacts(
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
                rescorings=rescorings,
                finding_cfgs=self.request.app[consts.APP_FINDING_CFGS],
            ))

        return aiohttp.web.Response(
            status=http.HTTPStatus.CREATED,
        )

    async def get(self):
        '''
        ---
        description:
          Calculates vulnerability rescorings based on cve-categorisation and cve-rescoring-ruleset.
          cve-categorisation is read from respective component-descriptor label,
          cve-rescoring-rule-set is specified by name. Rescorings are not applied yet, just
          "previewed".
        tags:
        - Rescoring
        produces:
        - application/json
        parameters:
        - in: query
          name: componentName
          type: string
          required: true
        - in: query
          name: componentVersion
          type: string
          required: true
        - in: query
          name: artefactKind
          type: string
          required: true
        - in: query
          name: artefactName
          type: string
          required: true
        - in: query
          name: artefactVersion
          type: string
          required: true
        - in: query
          name: artefactType
          type: string
          required: true
        - in: query
          name: artefactExtraId
          type: string
          required: false
        - in: query
          name: type
          schema:
            $ref: '#/definitions/Datatype'
          required: false
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                $ref: '#/definitions/RescoringProposal'
        '''
        params = self.request.rel_url.query

        component_name = util.param(params, 'componentName', required=True)
        component_version = util.param(params, 'componentVersion', required=True)
        artefact_kind = odg.model.ArtefactKind(util.param(params, 'artefactKind', required=True))
        artefact_name = util.param(params, 'artefactName', required=True)
        artefact_version = util.param(params, 'artefactVersion', required=True)
        artefact_type = util.param(params, 'artefactType', required=True)
        artefact_extra_id = json.loads(util.param(params, 'artefactExtraId', default='{}'))
        type_filter = params.getall('type', default=[])

        finding_cfgs = self.request.app[consts.APP_FINDING_CFGS]
        for finding_type in type_filter:
            for finding_cfg in finding_cfgs:
                if odg.model.Datatype(finding_type) is finding_cfg.type:
                    break
            else:
                raise aiohttp.web.HTTPNotFound(
                    text=f'No configuration for finding type "{finding_type}" found',
                )

        # also filter for structure info to enrich findings
        if (
            odg.model.Datatype.LICENSE_FINDING in type_filter
            or odg.model.Datatype.VULNERABILITY_FINDING in type_filter
        ):
            type_filter.append(odg.model.Datatype.STRUCTURE_INFO)

        artefact = odg.model.ComponentArtefactId(
            component_name=component_name,
            component_version=component_version,
            artefact_kind=artefact_kind,
            artefact=odg.model.LocalArtefactId(
                artefact_name=artefact_name,
                artefact_version=artefact_version,
                artefact_type=artefact_type,
                artefact_extra_id=artefact_extra_id,
            ),
        )

        if odg.model.Datatype.VULNERABILITY_FINDING in type_filter:
            artefact_node = await ocm_util.find_artefact_node(
                component_descriptor_lookup=self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP],
                artefact=artefact,
                absent_ok=True,
            )

            if not artefact_node:
                raise aiohttp.web.HTTPNotFound(
                    reason='Artefact not found in component descriptor',
                    text=f'{artefact=}',
                )

            cve_categorisation = rescore.utility.find_cve_categorisation(artefact_node)
        else:
            cve_categorisation = None

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        artefact_metadata = await _find_artefact_metadata(
            db_session=db_session,
            artefact=artefact,
            type_filter=type_filter,
        )

        rescorings = await _find_rescorings(
            db_session=db_session,
            artefact=artefact,
            type_filter=type_filter,
        )

        rescoring_proposals = [
            rescoring_proposal async for rescoring_proposal in _iter_rescoring_proposals(
                artefact_metadata=artefact_metadata,
                rescorings=rescorings,
                finding_cfgs=finding_cfgs,
                cve_categorisation=cve_categorisation,
                sprints=self.request.app[consts.APP_SPRINTS],
            )
        ]

        return aiohttp.web.json_response(
            data=rescoring_proposals,
            dumps=util.dict_to_json_factory,
        )
