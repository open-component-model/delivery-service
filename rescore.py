import collections.abc
import dataclasses
import datetime
import http
import logging

import aiohttp.web
import dacite
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync

import cnudie.iter
import cnudie.retrieve
import dso.cvss
import dso.labels
import dso.model
import github.compliance.model as gcm
import ocm

import config
import consts
import features
import deliverydb.model as dm
import deliverydb.util as du
import k8s.backlog
import k8s.model
import k8s.util
import middleware.auth
import rescoring_util
import util
import yp


logger = logging.getLogger(__name__)
CveRescoringRuleSetLookup = collections.abc.Callable[
    [str],
    features.CveRescoringRuleSet | None,
]
Severity = str # sap-specific categorisation (see cc-utils github/compliance/model/Severity)


@dataclasses.dataclass(frozen=True)
class LicenseFinding(dso.model.Finding):
    package_name: str
    package_versions: tuple[str, ...] # "..." for dacite.from_dict
    license: dso.model.License
    filesystem_paths: list[dso.model.FilesystemPath]


@dataclasses.dataclass(frozen=True)
class VulnerabilityFinding(dso.model.Finding):
    package_name: str
    package_versions: tuple[str, ...] # "..." for dacite.from_dict
    cve: str
    cvss_v3_score: float
    cvss: str
    summary: str | None
    urls: list[str]
    filesystem_paths: list[dso.model.FilesystemPath]


@dataclasses.dataclass(frozen=True)
class MalwareFinding(dso.model.Finding, dso.model.MalwareFindingDetails):
    pass


@dataclasses.dataclass(frozen=True)
class RescoringProposal:
    finding: (
        LicenseFinding
        | VulnerabilityFinding
        | MalwareFinding
    )
    finding_type: str
    severity: Severity
    matching_rules: list[str]
    applicable_rescorings: tuple[dso.model.ArtefactMetadata, ...] # "..." for dacite.from_dict
    discovery_date: str
    sprint: yp.Sprint | None


def _find_cve_rescoring_rule_set(
    default_cve_rescoring_rule_set: features.CveRescoringRuleSet,
    cve_rescoring_rule_set_lookup: CveRescoringRuleSetLookup,
    cve_rescoring_rule_set_name: str | None,
) -> features.CveRescoringRuleSet | None:
    if not cve_rescoring_rule_set_name:
        return default_cve_rescoring_rule_set

    return cve_rescoring_rule_set_lookup(cve_rescoring_rule_set_name)


async def _find_artefact_node(
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    component: ocm.Component,
    artefact: dso.model.ComponentArtefactId,
) -> cnudie.iter.Node | cnudie.iter.ArtefactNode | None:
    if artefact.artefact_kind is dso.model.ArtefactKind.SOURCE:
        node_filter = cnudie.iter.Filter.sources
    elif artefact.artefact_kind is dso.model.ArtefactKind.RESOURCE:
        node_filter = cnudie.iter.Filter.resources
    else:
        raise ValueError(artefact.artefact_kind)

    artefact_ref = artefact.artefact

    async for node in cnudie.iter.iter(
        component=component,
        lookup=component_descriptor_lookup,
        node_filter=node_filter,
    ):
        if node.artefact.name != artefact_ref.artefact_name:
            continue
        if node.artefact.version != artefact_ref.artefact_version:
            continue
        if node.artefact.type != artefact_ref.artefact_type:
            continue

        return node


async def _find_artefact_node_or_raise(
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    artefact: dso.model.ComponentArtefactId,
) -> cnudie.iter.Node | cnudie.iter.ArtefactNode:
    component = (await util.retrieve_component_descriptor(
        ocm.ComponentIdentity(
            name=artefact.component_name,
            version=artefact.component_version,
        ),
        component_descriptor_lookup=component_descriptor_lookup,
    )).component

    try:
        artefact_node = await _find_artefact_node(
            component_descriptor_lookup=component_descriptor_lookup,
            component=component,
            artefact=artefact,
        )
    except ValueError:
        logger.info(f'artefact not found in component descriptor, {artefact=}')
        artefact_node = None

    if not artefact_node:
        raise aiohttp.web.HTTPNotFound(
            reason='Artefact not found in component descriptor',
            text=f'{artefact=}',
        )

    return artefact_node


def _find_cve_label(
    artefact_node: cnudie.iter.Node | cnudie.iter.ArtefactNode,
) -> dso.cvss.CveCategorisation | None:
    label_name = dso.labels.CveCategorisationLabel.name
    artefact = artefact_node.artefact
    component = artefact_node.component

    if not (categorisation_label := artefact.find_label(label_name)):
        if not (categorisation_label := component.find_label(label_name)):
            return None

    categorisation_label = dso.labels.deserialise_label(categorisation_label)
    return categorisation_label.value


async def _find_artefact_metadata(
    db_session: sqlasync.session.AsyncSession,
    artefact: dso.model.ComponentArtefactId,
    type_filter: list[str]=[],
) -> list[dso.model.ArtefactMetadata]:
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
            dm.ArtefactMetaData.type != dso.model.Datatype.RESCORING,
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
    artefact: dso.model.ComponentArtefactId,
    type_filter: list[str]=[],
) -> list[dso.model.ArtefactMetadata]:
    db_statement = sa.select(dm.ArtefactMetaData).where(
        sa.and_(
            dm.ArtefactMetaData.type == dso.model.Datatype.RESCORING,
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


def _rescore_vulnerabilitiy(
    rescoring_rules: collections.abc.Iterable[dso.cvss.RescoringRule] | None,
    categorisation: dso.cvss.CveCategorisation | None,
    cvss: dso.cvss.CVSSV3 | dict,
    severity: dso.cvss.CVESeverity,
) -> dso.cvss.CVESeverity:
    if not rescoring_rules or not categorisation:
        return severity

    rules = dso.cvss.matching_rescore_rules(
        rescoring_rules=rescoring_rules,
        categorisation=categorisation,
        cvss=cvss,
    )

    return dso.cvss.rescore(
        rescoring_rules=rules,
        severity=severity,
    )


def filesystem_paths_for_finding(
    artefact_metadata: tuple[dso.model.ArtefactMetadata],
    finding: dso.model.ArtefactMetadata,
    package_versions: tuple[str]=(),
) -> list[dso.model.FilesystemPath]:
    if not package_versions:
        # only show filesystem paths for package versions which actually have findings;
        # in case no package versions are supplied, BDBA was not able to detect a version
        # so include only filesystem paths for packages without version
        package_versions = (None,)

    matching_structure_info = tuple(
        matching_info for matching_info in artefact_metadata
        if (
            matching_info.meta.type == dso.model.Datatype.STRUCTURE_INFO
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
            and matching_info.artefact.artefact.normalised_artefact_extra_id()
                == finding.artefact.artefact.normalised_artefact_extra_id()
        )
    )

    return [
        path
        for structure_info in matching_structure_info
        for path in structure_info.data.filesystem_paths
    ]


def sprint_for_finding(
    finding: dso.model.ArtefactMetadata,
    severity: gcm.Severity | None,
    max_processing_days: gcm.MaxProcessingTimesDays | None,
    sprints: list[yp.Sprint],
) -> yp.Sprint | None:
    if not severity or not max_processing_days or not sprints:
        return None

    max_days = max_processing_days.for_severity(severity=severity)
    date = finding.discovery_date + datetime.timedelta(days=max_days)

    for sprint in sorted(sprints, key=lambda sprint: sprint.end_date):
        if sprint.end_date.date() > date:
            break
    else:
        logger.warning(f'could not determine target sprint for {finding=} with {severity=}')
        return None

    return sprint


def _rescorings_and_sprint(
    artefact_metadatum: dso.model.ArtefactMetadata,
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    max_processing_days: gcm.MaxProcessingTimesDays | None=None,
    sprints: list[yp.Sprint]=[],
) -> tuple[tuple[dso.model.ArtefactMetadata], yp.Sprint]:
    current_rescorings = rescoring_util.rescorings_for_finding_by_specificity(
        finding=artefact_metadatum,
        rescorings=rescorings,
    )

    if current_rescorings:
        current_severity = gcm.Severity[current_rescorings[0].data.severity]
    else:
        current_severity = gcm.Severity[artefact_metadatum.data.severity]

    sprint = sprint_for_finding(
        finding=artefact_metadatum,
        severity=current_severity,
        max_processing_days=max_processing_days,
        sprints=sprints,
    )

    return current_rescorings, sprint


def _package_versions_and_filesystem_paths(
    artefact_metadata_across_package_version: tuple[dso.model.ArtefactMetadata],
    artefact_metadata: collections.abc.Iterable[dso.model.ArtefactMetadata],
    finding: dso.model.ArtefactMetadata,
) -> tuple[tuple[str], list[dso.model.FilesystemPath]]:
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


def _iter_rescoring_proposals(
    artefact_metadata: collections.abc.Iterable[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    rescoring_rules: collections.abc.Iterable[dso.cvss.RescoringRule] | None,
    categorisation: dso.cvss.CveCategorisation | None,
    max_processing_days: gcm.MaxProcessingTimesDays | None=None,
    sprints: list[yp.Sprint]=[],
) -> collections.abc.Generator[RescoringProposal, None, None]:
    '''
    yield rescorings for supported finding types
    implements special handling for BDBA findings (grouping across different package-versions)
    '''

    seen_ids = set()

    for am in artefact_metadata:
        if (
            am.meta.type == dso.model.Datatype.STRUCTURE_INFO
            or am.id in seen_ids
        ):
            continue

        current_rescorings, sprint = _rescorings_and_sprint(
            artefact_metadatum=am,
            rescorings=rescorings,
            max_processing_days=max_processing_days,
            sprints=sprints,
        )
        severity = dso.cvss.CVESeverity[am.data.severity]

        if am.meta.type == dso.model.Datatype.MALWARE_FINDING:
            yield dacite.from_dict(
                data_class=RescoringProposal,
                data={
                    'finding': {
                        'filename': am.data.finding.filename,
                        'content_digest': am.data.finding.content_digest,
                        'malware': am.data.finding.malware,
                        'severity': severity.name,
                    },
                    'finding_type': dso.model.Datatype.MALWARE_FINDING,
                    'severity': severity.name,
                    'matching_rules': [dso.model.MetaRescoringRules.ORIGINAL_SEVERITY],
                    'applicable_rescorings': current_rescorings,
                    'discovery_date': am.discovery_date.isoformat(),
                    'sprint': sprint,
                },
            )

        elif am.meta.type in (
            dso.model.Datatype.VULNERABILITY,
            dso.model.Datatype.LICENSE,
        ):
            artefact_metadata_with_same_ocm = tuple(
                matching_am for matching_am in artefact_metadata
                if (
                    matching_am.id not in seen_ids
                    and matching_am.meta.type == am.meta.type
                    and matching_am.artefact.component_name == am.artefact.component_name
                    and matching_am.artefact.component_version == am.artefact.component_version
                    and matching_am.artefact.artefact_kind == am.artefact.artefact_kind
                    and matching_am.artefact.artefact.artefact_name
                        == am.artefact.artefact.artefact_name
                    and matching_am.artefact.artefact.artefact_version
                        == am.artefact.artefact.artefact_version
                    and matching_am.artefact.artefact.artefact_type
                        == am.artefact.artefact.artefact_type
                    and matching_am.artefact.artefact.normalised_artefact_extra_id()
                        == am.artefact.artefact.normalised_artefact_extra_id()
                )
            )
            package_name = am.data.package_name

            if am.meta.type == dso.model.Datatype.VULNERABILITY:
                cve = am.data.cve
                cvss = dso.cvss.CVSSV3.from_dict(cvss=am.data.cvss)
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

                yield dacite.from_dict(
                    data_class=RescoringProposal,
                    data={
                        'finding': {
                            'package_name': package_name,
                            'package_versions': package_versions,
                            'severity': severity.name,
                            'cve': cve,
                            'cvss_v3_score': cvss_v3_score,
                            'cvss': f'{cvss}',
                            'summary': am.data.summary,
                            'urls': [f'https://nvd.nist.gov/vuln/detail/{cve}'],
                            'filesystem_paths': filesystem_paths,
                        },
                        'finding_type': dso.model.Datatype.VULNERABILITY,
                        'severity': _rescore_vulnerabilitiy(
                            rescoring_rules=rescoring_rules,
                            categorisation=categorisation,
                            cvss=cvss,
                            severity=severity,
                        ).name,
                        'matching_rules': [
                            rule.name if rule.name else rule.category_value
                            for rule in dso.cvss.matching_rescore_rules(
                                rescoring_rules=rescoring_rules,
                                categorisation=categorisation,
                                cvss=cvss,
                            )
                        ] if rescoring_rules and categorisation else [
                            dso.model.MetaRescoringRules.ORIGINAL_SEVERITY,
                        ],
                        'applicable_rescorings': current_rescorings,
                        'discovery_date': am.discovery_date.isoformat(),
                        'sprint': sprint,
                    },
                )

            elif am.meta.type == dso.model.Datatype.LICENSE:
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
                            'severity': severity.name,
                            'license': license,
                            'filesystem_paths': filesystem_paths,
                        },
                        'finding_type': dso.model.Datatype.LICENSE,
                        'severity': severity.name,
                        'matching_rules': [dso.model.MetaRescoringRules.ORIGINAL_SEVERITY],
                        'applicable_rescorings': current_rescorings,
                        'discovery_date': am.discovery_date.isoformat(),
                        'sprint': sprint,
                    },
                )

        seen_ids.add(am.id)


def iter_matching_artefacts(
    compliance_snapshots: tuple[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
) -> collections.abc.Generator[dso.model.ComponentArtefactId, None, None]:
    '''
    Some rescorings don't have any component name or artefact name set because their scope may be
    across different names. However, backlog items for the issue replicator need to have both of
    them set. Therefore, this functions uses given compliance snapshots to find all artefacts which
    match the scope of the rescorings. These artefacts can then be used further to create appropiate
    backlog items.
    '''
    seen_rescored_artefacts = set()
    seen_artefacts = set()

    for rescoring in rescorings:
        artefact = rescoring.artefact
        artefact_key = (
            f'{artefact.component_name}:{artefact.artefact_kind}'
            f'{artefact.artefact.artefact_name}:{artefact.artefact.artefact_type}'
        )
        if artefact_key in seen_rescored_artefacts:
            continue
        seen_rescored_artefacts.add(artefact_key)

        if artefact.component_name and artefact.artefact.artefact_name:
            # all required props for backlog item present
            # no need to search for matching artefacts in compliance snapshots
            yield artefact
            continue

        for compliance_snapshot in compliance_snapshots:
            a = compliance_snapshot.artefact

            if (
                artefact.component_name
                and artefact.component_name != a.component_name
            ):
                continue

            if artefact.artefact_kind != a.artefact_kind:
                continue

            if (
                artefact.artefact.artefact_name
                and artefact.artefact.artefact_name != a.artefact.artefact_name
            ):
                continue

            if artefact.artefact.artefact_type != a.artefact.artefact_type:
                continue

            a_key = (
                f'{a.component_name}:{a.artefact_kind}:'
                f'{a.artefact.artefact_name}:{a.artefact.artefact_type}'
            )
            if a_key in seen_artefacts:
                continue
            seen_artefacts.add(a_key)

            yield a


async def create_backlog_items_for_rescored_artefacts(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    db_session: sqlasync.session.AsyncSession,
    rescorings: collections.abc.Iterable[dso.model.ComponentArtefactId],
    scan_config_name: str=None,
):
    if not scan_config_name:
        scan_configs = k8s.util.iter_scan_configurations(
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )

        # only if there is one scan config we can assume for sure that this config should be used
        if len(scan_configs) != 1:
            return

        scan_config_name = scan_configs[0].name

    db_statement = sa.select(dm.ArtefactMetaData).where(
        dm.ArtefactMetaData.type == dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
        dm.ArtefactMetaData.cfg_name == scan_config_name,
    )
    db_stream = await db_session.stream(db_statement)

    compliance_snapshots = [
        du.db_artefact_metadata_row_to_dso(row)
        async for partition in db_stream.partitions(size=50)
        for row in partition
    ]

    active_compliance_snapshots = tuple(
        cs for cs in compliance_snapshots
        if cs.data.current_state().status == dso.model.ComplianceSnapshotStatuses.ACTIVE
    )

    artefacts = iter_matching_artefacts(
        compliance_snapshots=active_compliance_snapshots,
        rescorings=rescorings,
    )

    for artefact in artefacts:
        k8s.backlog.create_backlog_item(
            service=config.Services.ISSUE_REPLICATOR,
            cfg_name=scan_config_name,
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
        applies rescoring to delivery-db, only for authenticated users

        **expected query parameters:**

            - scanConfigName (optional) <string> \n

        **expected request body:**
            entries: <array> of <object> \n
            - artefact: <object> \n
                component_name: <string> \n
                component_version: <string> \n
                artefact_kind: <string> \n
                artefact: <object> \n
                  artefact_name: <string> \n
                  artefact_version: <string> \n
                  artefact_type: <string> \n
                  artefact_extra_id: <object> \n
              meta: <object> \n
                datasource: <string> # e.g. delivery-dashboard or cli \n
                type: rescorings \n
              data: <object> \n
                finding: <object> # schema depends on data.referenced_type \n
                referenced_type: <string> # type of finding, e.g. finding/vulnerability \n
                severity: <string> # one of github.compliance.model.Severity \n
                matching_rules: <array> of <string> \n
                comment: <string> \n
        '''
        params = self.request.rel_url.query

        body = await self.request.json()
        rescorings_raw: list[dict] = body.get('entries')

        user: middleware.auth.GithubUser = self.request[consts.REQUEST_GITHUB_USER]
        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        scan_config_name = util.param(params, 'scanConfigName')

        def iter_rescorings(
            rescorings_raw: list[dict],
        ) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
            for rescoring_raw in rescorings_raw:
                rescoring_raw['data']['user'] = dataclasses.asdict(user)

                rescoring = dso.model.ArtefactMetadata.from_dict(rescoring_raw)

                if not rescoring.meta.type == dso.model.Datatype.RESCORING:
                    raise aiohttp.web.HTTPBadRequest(
                        reason=f'Rescoring must be of type {dso.model.Datatype.RESCORING}',
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
                    du.ArtefactMetadataFilters.by_single_scan_result(rescoring_db),
                ))

                db_session.add(rescoring_db)

            await db_session.commit()
        except:
            await db_session.rollback()
            raise

        await create_backlog_items_for_rescored_artefacts(
            namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
            kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            db_session=db_session,
            rescorings=rescorings,
            scan_config_name=scan_config_name,
        )

        return aiohttp.web.Response(
            status=http.HTTPStatus.CREATED,
        )

    async def get(self):
        '''
        calculates vulnerabilities rescorings based on cve-categorisation and cve-rescoring-ruleset.

        cve-categorisation is read from respective component-descriptor label, cve-rescoring-rule-set
        is specified by name.
        rescorings are not applied yet, just "previewed".

        **expected query parameters:**

            - componentName (required) \n
            - componentVersion (required) \n
            - artefactKind (required) \n
            - artefactName (required) \n
            - artefactVersion (required) \n
            - artefactType (required) \n
            - artefactExtraId (optional) \n
            - type (optional) \n
            - scanConfigName (optional) \n
            - cveRescoringRuleSetName (optional): defaults to global default cveRescoringRuleSet \n

        **response:**

            <array> of <object> \n
            - finding: <object> # schema depends on  type of finding, e.g. finding/vulnerability \n
                id: <object> \n
                severity: <string> # one of github.compliance.model.Severity \n
              severity: <string> # one of github.compliance.model.Severity \n
              matching_rules: <array> of <string> # applicable cve-categorisation rules \n
              applicable_rescorings: <array> of <object> \n
              - artefact: <object> \n
                  component_name: <string> \n
                  component_version: <string> \n
                  artefact_kind: <string> \n
                  artefact: <object> \n
                    artefact_name: <string> \n
                    artefact_version: <string> \n
                    artefact_type: <string> \n
                    artefact_extra_id: <object> \n
                meta: <object> \n
                  datasource: <string> # e.g. delivery-dashboard or cli \n
                  type: rescoring \n
                data: <object> \n
                  finding: <object> # schema depends on data.referenced_type \n
                  referenced_type: <string> # type of finding, e.g. finding/vulnerability \n
                  severity: <string> # one of github.compliance.model.Severity \n
                  matching_rules: <array> of <string> \n
                  user: <object> \n
                  comment: <string> \n
        '''
        params = self.request.rel_url.query

        component_name = util.param(params, 'componentName', required=True)
        component_version = util.param(params, 'componentVersion', required=True)
        artefact_kind = util.param(params, 'artefactKind', required=True)
        artefact_name = util.param(params, 'artefactName', required=True)
        artefact_version = util.param(params, 'artefactVersion', required=True)
        artefact_type = util.param(params, 'artefactType', required=True)
        artefact_extra_id = util.param(params, 'artefactExtraId', default=dict())
        type_filter = params.getall('type', default=[])
        scan_config_name = util.param(params, 'scanConfigName')

        # also filter for structure info to enrich findings
        type_filter.append(dso.model.Datatype.STRUCTURE_INFO)

        cve_rescoring_rule_set_name = util.param(params, 'cveRescoringRuleSetName')

        cve_rescoring_rule_set = _find_cve_rescoring_rule_set(
            default_cve_rescoring_rule_set=self.request.app[consts.APP_DEFAULT_RULE_SET_CALLBACK](),
            cve_rescoring_rule_set_lookup=self.request.app[consts.APP_CVE_RESCORING_RULE_SET_LOOKUP],
            cve_rescoring_rule_set_name=cve_rescoring_rule_set_name,
        )

        artefact_kind = dso.model.ArtefactKind(artefact_kind)

        artefact = dso.model.ComponentArtefactId(
            component_name=component_name,
            component_version=component_version,
            artefact_kind=artefact_kind,
            artefact=dso.model.LocalArtefactId(
                artefact_name=artefact_name,
                artefact_version=artefact_version,
                artefact_type=artefact_type,
                artefact_extra_id=artefact_extra_id,
            ),
        )

        if dso.model.Datatype.VULNERABILITY in type_filter:
            artefact_node = await _find_artefact_node_or_raise(
                component_descriptor_lookup=self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP],
                artefact=artefact,
            )

            categorisation = _find_cve_label(artefact_node=artefact_node)
        else:
            categorisation = None

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

        scan_configs = k8s.util.iter_scan_configurations(
            namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
            kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
        )

        if scan_config_name:
            for scan_config in scan_configs:
                if scan_config.name == scan_config_name:
                    break
            else:
                raise aiohttp.web.HTTPBadRequest(
                    text=f'did not find scan config with {scan_config_name=}',
                )
        elif scan_configs:
            if len(scan_configs) == 1:
                scan_config = scan_configs[0]
            else:
                # workaround: at this point, we actually don't know which scan configuration to use
                # to lookup the configuration for allowed processing times. Currently, however, all
                # scan configurations contain the same configuration for allowed processing times,
                # hence we can just use the first scan configuration
                # TODO: do a more elaborated approach once configuration management is re-worked
                scan_config = scan_configs[0]
        else:
            max_processing_days = None

        if scan_config:
            issue_replicator_config = config.deserialise_issue_replicator_config(
                spec_config=scan_config.config,
            )
            if issue_replicator_config:
                max_processing_days = issue_replicator_config.max_processing_days
            else:
                max_processing_days = gcm.MaxProcessingTimesDays()

        rescoring_proposals = _iter_rescoring_proposals(
            artefact_metadata=artefact_metadata,
            rescorings=rescorings,
            rescoring_rules=cve_rescoring_rule_set.rules if cve_rescoring_rule_set else None,
            categorisation=categorisation,
            max_processing_days=max_processing_days,
            sprints=self.request.app[consts.APP_SPRINTS],
        )

        return aiohttp.web.json_response(
            data=rescoring_proposals,
            dumps=util.dict_to_json_factory,
        )

    async def delete(self):
        '''
        deletes rescoring from delivery-db, only for authenticated users

        **expected query parameters:**

            - id (required) <array> of <int> \n
            - scanConfigName (optional) <string> \n
        '''
        params = self.request.rel_url.query

        ids = params.getall('id')
        scan_config_name = util.param(params, 'scanConfigName')

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        try:
            db_statement = sa.select(dm.ArtefactMetaData).where(
                dm.ArtefactMetaData.id.cast(sa.String).in_(ids),
            )
            db_stream = await db_session.stream(db_statement)

            rescorings = [
                du.db_artefact_metadata_row_to_dso(row)
                async for partition in db_stream.partitions(size=50)
                for row in partition
            ]

            await db_session.execute(sa.delete(dm.ArtefactMetaData).where(
                dm.ArtefactMetaData.id.cast(sa.String).in_(ids),
            ))
            await db_session.commit()
        except:
            await db_session.rollback()
            raise

        await create_backlog_items_for_rescored_artefacts(
            namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
            kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            db_session=db_session,
            rescorings=rescorings,
            scan_config_name=scan_config_name,
        )

        return aiohttp.web.Response(
            status=http.HTTPStatus.NO_CONTENT,
        )
