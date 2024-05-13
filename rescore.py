import collections.abc
import dataclasses
import datetime
import enum
import logging
import typing

import dacite
import falcon
import sqlalchemy as sa
import sqlalchemy.orm.session as ss

import cnudie.iter
import cnudie.retrieve
import dso.cvss
import dso.labels
import dso.model
import gci.componentmodel as cm
import github.compliance.model as gcm

import config
import features
import deliverydb.model as dm
import deliverydb.util as du
import k8s.backlog
import k8s.model
import k8s.util
import middleware.auth
import util
import yp


logger = logging.getLogger(__name__)
CveRescoringRuleSetLookup = collections.abc.Callable[
    [str],
    features.CveRescoringRuleSet | None,
]
Severity = str # sap-specific categorisation (see cc-utils github/compliance/model/Severity)


class RescoringSpecificity(enum.IntEnum):
    GLOBAL = 0
    COMPONENT = 1
    ARTEFACT = 2
    SINGLE = 3


@dataclasses.dataclass(frozen=True)
class BDBAPackageId:
    package_name: str
    package_versions: tuple[str, ...] # "..." for dacite.from_dict
    source: str = dso.model.Datasource.BDBA


@dataclasses.dataclass(frozen=True)
class Finding:
    id: BDBAPackageId
    severity: Severity


@dataclasses.dataclass(frozen=True)
class LicenseFinding(Finding):
    license: dso.model.License
    filesystem_paths: list[dso.model.FilesystemPath]


@dataclasses.dataclass(frozen=True)
class VulnerabilityFinding(Finding):
    cve: str
    cvss_v3_score: float
    cvss: str
    summary: str | None
    urls: list[str]
    filesystem_paths: list[dso.model.FilesystemPath]


@dataclasses.dataclass(frozen=True)
class RescoringProposal:
    finding: (
        LicenseFinding
        | VulnerabilityFinding
    )
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


def _find_artefact_node(
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    component: cm.Component,
    artefact: dso.model.ComponentArtefactId,
) -> typing.Union[cnudie.iter.Node, cnudie.iter.ArtefactNode] | None:
    if artefact.artefact_kind == 'source':
        node_filter = cnudie.iter.Filter.sources
    else:
        node_filter = cnudie.iter.Filter.resources

    artefact_ref = artefact.artefact

    for node in cnudie.iter.iter(
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


def _find_artefact_node_or_raise(
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    artefact: dso.model.ComponentArtefactId,
) -> typing.Union[cnudie.iter.Node, cnudie.iter.ArtefactNode]:
    component = util.retrieve_component_descriptor(
        cm.ComponentIdentity(
            name=artefact.component_name,
            version=artefact.component_version,
        ),
        component_descriptor_lookup=component_descriptor_lookup,
    ).component

    try:
        artefact_node = _find_artefact_node(
            component_descriptor_lookup=component_descriptor_lookup,
            component=component,
            artefact=artefact,
        )
    except ValueError:
        logger.info(f'artefact not found in component descriptor, {artefact=}')
        artefact_node = None

    if not artefact_node:
        raise falcon.HTTPNotFound(
            title='artefact not found in component descriptor',
            description=f'{artefact=}',
        )

    return artefact_node


def _find_cve_label(
    artefact_node: typing.Union[cnudie.iter.Node, cnudie.iter.ArtefactNode],
) -> dso.cvss.CveCategorisation | None:
    label_name = dso.labels.CveCategorisationLabel.name
    artefact = artefact_node.artefact
    component = artefact_node.component

    if not (categorisation_label := artefact.find_label(label_name)):
        if not (categorisation_label := component.find_label(label_name)):
            return None

    categorisation_label = dso.labels.deserialise_label(categorisation_label)
    return categorisation_label.value


def _find_artefact_metadata(
    session: ss.Session,
    artefact_node: typing.Union[cnudie.iter.Node, cnudie.iter.ArtefactNode],
    type_filter: list[str]=[],
) -> list[dm.ArtefactMetaData]:
    if isinstance(artefact_node, cnudie.iter.ResourceNode):
        artefact_kind = 'resource'
    elif isinstance(artefact_node, cnudie.iter.SourceNode):
        artefact_kind = 'source'

    query = session.query(dm.ArtefactMetaData).filter(
        sa.and_(
            dm.ArtefactMetaData.component_name == artefact_node.component.name,
            dm.ArtefactMetaData.component_version == artefact_node.component.version,
            dm.ArtefactMetaData.artefact_kind == artefact_kind,
            dm.ArtefactMetaData.artefact_name == artefact_node.artefact.name,
            dm.ArtefactMetaData.artefact_version == artefact_node.artefact.version,
            dm.ArtefactMetaData.artefact_type == artefact_node.artefact.type,
            dm.ArtefactMetaData.type != dso.model.Datatype.RESCORING,
            sa.or_(
                not type_filter,
                dm.ArtefactMetaData.type.in_(type_filter),
            ),
        ),
    )

    return query.all()


def _find_rescorings(
    session: ss.Session,
    artefact_node: typing.Union[cnudie.iter.Node, cnudie.iter.ArtefactNode],
    type_filter: list[str]=[],
) -> tuple[dso.model.ArtefactMetadata]:
    if isinstance(artefact_node, cnudie.iter.ResourceNode):
        artefact_kind = 'resource'
    elif isinstance(artefact_node, cnudie.iter.SourceNode):
        artefact_kind = 'source'

    rescorings_query = session.query(dm.ArtefactMetaData).filter(
        sa.and_(
            dm.ArtefactMetaData.type == dso.model.Datatype.RESCORING,
            sa.or_(
                # regular `not` or `is None` not working with sqlalchemy
                dm.ArtefactMetaData.component_name == sa.null(),
                dm.ArtefactMetaData.component_name == artefact_node.component.name,
            ),
            sa.or_(
                dm.ArtefactMetaData.component_version == sa.null(),
                dm.ArtefactMetaData.component_version == artefact_node.component.version
            ),
            sa.or_(
                dm.ArtefactMetaData.artefact_name == sa.null(),
                dm.ArtefactMetaData.artefact_name == artefact_node.artefact.name,
            ),
            sa.or_(
                dm.ArtefactMetaData.artefact_version == sa.null(),
                dm.ArtefactMetaData.artefact_version == artefact_node.artefact.version,
            ),
            dm.ArtefactMetaData.artefact_kind == artefact_kind,
            dm.ArtefactMetaData.artefact_type == artefact_node.artefact.type,
        )
    )

    if type_filter:
        rescorings_query = rescorings_query.filter(
            du.ArtefactMetadataFilters.filter_for_rescoring_type(type_filter),
        )

    rescorings_raw = rescorings_query.all()
    return tuple(
        du.db_artefact_metadata_to_dso(
            artefact_metadata=raw,
        )
        for raw in rescorings_raw
    )


def _iter_rescorings_for_finding(
    finding: dm.ArtefactMetaData,
    rescorings: tuple[dso.model.ArtefactMetadata],
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    for rescoring in rescorings:
        artefact_ref = rescoring.artefact
        data = rescoring.data

        if rescoring.meta.relation.refers_to != finding.type:
            continue

        if artefact_ref.artefact_kind != finding.artefact_kind:
            continue

        if artefact_ref.artefact.artefact_type != finding.artefact_type:
            continue

        if (
            artefact_ref.component_name
            and artefact_ref.component_name != finding.component_name
        ):
            continue

        if (
            artefact_ref.component_version
            and artefact_ref.component_version != finding.component_version
        ):
            continue

        if (
            artefact_ref.artefact.artefact_name
            and artefact_ref.artefact.artefact_name != finding.artefact_name
        ):
            continue

        if (
            artefact_ref.artefact.artefact_version
            and artefact_ref.artefact.artefact_version != finding.artefact_version
        ):
            continue

        if (
            artefact_ref.artefact.artefact_extra_id
            and artefact_ref.artefact.normalised_artefact_extra_id()
                != finding.artefact_extra_id_normalised
        ):
            continue

        if data.finding.id.source != finding.data.get('id').get('source'):
            continue

        if (
            finding.type == dso.model.Datatype.VULNERABILITY
            and (
                data.finding.cve != finding.data.get('cve')
                or (
                    data.finding.id.source == dso.model.Datasource.BDBA
                    and data.finding.id.package_name != finding.data.get('id').get('package_name')
                )
            )
        ):
            continue

        if (
            finding.type == dso.model.Datatype.LICENSE
            and (
                data.finding.license.name != finding.data.get('license').get('name')
                or (
                    data.finding.id.source == dso.model.Datasource.BDBA
                    and data.finding.id.package_name != finding.data.get('id').get('package_name')
                )
            )
        ):
            continue

        yield rescoring


def _specificity_of_rescoring(rescoring: dso.model.ArtefactMetadata) -> RescoringSpecificity:
    '''
    There are four possible scopes for a rescoring. If multiple rescorings match
    one finding, the rescoring with the greatest specificity based on its scope
    should be used.

    Thereby, the "Global" scope has neither component name or version nor artefact
    name or version set. The "Component" scope only refers to the component name,
    the "Artefact" scope only to the component name as well as the artefact name.
    Last, the "Single" scope requires all four parameters to be set.
    '''
    if not rescoring.artefact.component_name:
        return RescoringSpecificity.GLOBAL

    if not rescoring.artefact.artefact.artefact_name:
       return RescoringSpecificity.COMPONENT

    if not rescoring.artefact.component_version:
       return RescoringSpecificity.ARTEFACT

    return RescoringSpecificity.SINGLE


def rescorings_for_finding_by_specificity(
    finding: dm.ArtefactMetaData,
    rescorings: tuple[dso.model.ArtefactMetadata],
) -> tuple[dso.model.ArtefactMetadata]:
    '''
    Returns all rescorings of `rescorings` which match the given `finding`. If multiple
    rescorings match the finding, they are ordered based on their specificity (greatest
    specificity first and if the specificity is the same, the latest rescorings wins).
    '''
    rescorings_for_finding = _iter_rescorings_for_finding(
        finding=finding,
        rescorings=rescorings,
    )

    return tuple(sorted(
        rescorings_for_finding,
        key=lambda rescoring: (
            _specificity_of_rescoring(rescoring=rescoring),
            rescoring.meta.creation_date,
        ),
        reverse=True,
    ))


def _rescore_vulnerabilitiy(
    rescoring_rules: tuple[dso.cvss.RescoringRule] | None,
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
    artefact_metadata: list[dm.ArtefactMetaData],
    finding: dm.ArtefactMetaData,
    package_versions: tuple[str]=(),
) -> list[dso.model.FilesystemPath]:
    id = finding.data.get('id')

    if not package_versions:
        # only show filesystem paths for package versions which actually have findings;
        # in case no package versions are supplied, BDBA was not able to detect a version
        # so include only filesystem paths for packages without version
        package_versions = (None,)

    matching_structure_info = tuple(
        matching_info for matching_info in artefact_metadata
        if (
            matching_info.type == dso.model.Datatype.STRUCTURE_INFO
            and matching_info.data.get('id').get('source') == id.get('source')
            and matching_info.data.get('id').get('package_name') == id.get('package_name')
            and matching_info.data.get('id').get('package_version') in package_versions
            and matching_info.component_name == finding.component_name
            and matching_info.component_version == finding.component_version
            and matching_info.artefact_kind == finding.artefact_kind
            and matching_info.artefact_name == finding.artefact_name
            and matching_info.artefact_version == finding.artefact_version
            and matching_info.artefact_type == finding.artefact_type
            and matching_info.artefact_extra_id_normalised == finding.artefact_extra_id_normalised
        )
    )

    return [
        dacite.from_dict(
            data_class=dso.model.FilesystemPath,
            data=path,
        )
        for structure_info in matching_structure_info
        for path in structure_info.data.get('filesystem_paths')
    ]


def sprint_for_finding(
    finding: dm.ArtefactMetaData,
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


def _iter_rescoring_proposals(
    artefact_metadata: list[dm.ArtefactMetaData],
    rescorings: tuple[dso.model.ArtefactMetadata],
    rescoring_rules: tuple[dso.cvss.RescoringRule] | None,
    categorisation: dso.cvss.CveCategorisation | None,
    max_processing_days: gcm.MaxProcessingTimesDays | None=None,
    sprints: list[yp.Sprint]=[],
) -> collections.abc.Generator[RescoringProposal, None, None]:
    seen_ids = set()

    for am in artefact_metadata:
        if am.id in seen_ids:
            continue

        matching_artefact_metadata = tuple(
            matching_am for matching_am in artefact_metadata
            if (
                matching_am.id not in seen_ids
                and matching_am.type == am.type
                and matching_am.component_name == am.component_name
                and matching_am.component_version == am.component_version
                and matching_am.artefact_kind == am.artefact_kind
                and matching_am.artefact_name == am.artefact_name
                and matching_am.artefact_version == am.artefact_version
                and matching_am.artefact_type == am.artefact_type
                and matching_am.artefact_extra_id_normalised == am.artefact_extra_id_normalised
            )
        )

        seen_ids.add(am.id)

        current_rescorings = rescorings_for_finding_by_specificity(
            finding=am,
            rescorings=rescorings,
        )

        if current_rescorings:
            current_severity = gcm.Severity[current_rescorings[0].data.severity]
        elif am.type != dso.model.Datatype.STRUCTURE_INFO:
            # structure info does not have any severity but is just retrieved to evaluate
            # whether a scan exists for the given artefacts (if no finding is found)
            current_severity = gcm.Severity[am.data.get('severity')]
        else:
            current_severity = None

        sprint = sprint_for_finding(
            finding=am,
            severity=current_severity,
            max_processing_days=max_processing_days,
            sprints=sprints,
        )

        if (
            am.type == dso.model.Datatype.VULNERABILITY
            and am.data.get('id').get('source') == dso.model.Datasource.BDBA
        ):
            cve = am.data.get('cve')
            cvss = dso.cvss.CVSSV3.from_dict(cvss=am.data.get('cvss'))
            cvss_v3_score = am.data.get('cvss_v3_score')
            severity = dso.cvss.CVESeverity[am.data.get('severity')]
            package_name = am.data.get('id').get('package_name')

            finding_matching_am = tuple(
                matching_am for matching_am in matching_artefact_metadata
                if (
                    matching_am.data.get('cve') == cve and
                    matching_am.data.get('id').get('package_name') == package_name
                )
            )
            seen_ids.update(tuple(matching_am.id for matching_am in finding_matching_am))

            package_versions = tuple(
                matching_am.data.get('id').get('package_version')
                for matching_am in finding_matching_am
                if matching_am.data.get('id').get('package_version')
            )

            filesystem_paths = filesystem_paths_for_finding(
                artefact_metadata=artefact_metadata,
                finding=am,
                package_versions=package_versions,
            )

            yield dacite.from_dict(
                data_class=RescoringProposal,
                data={
                    'finding': {
                        'id': {
                            'package_name': package_name,
                            'package_versions': package_versions,
                            'source': dso.model.Datasource.BDBA,
                        },
                        'severity': severity.name,
                        'cve': cve,
                        'cvss_v3_score': cvss_v3_score,
                        'cvss': f'{cvss}',
                        'summary': am.data.get('summary'),
                        'urls': [f'https://nvd.nist.gov/vuln/detail/{cve}'],
                        'filesystem_paths': filesystem_paths,
                    },
                    'severity': _rescore_vulnerabilitiy(
                        rescoring_rules=rescoring_rules,
                        categorisation=categorisation,
                        cvss=cvss,
                        severity=severity,
                    ).name,
                    'matching_rules': [
                        rule.name for rule in dso.cvss.matching_rescore_rules(
                            rescoring_rules=rescoring_rules,
                            categorisation=categorisation,
                            cvss=cvss,
                        )
                    ] if rescoring_rules and categorisation else ['original-severity'],
                    'applicable_rescorings': current_rescorings,
                    'discovery_date': am.discovery_date.isoformat(),
                    'sprint': sprint,
                },
            )

        elif (
            am.type == dso.model.Datatype.LICENSE
            and am.data.get('id').get('source') == dso.model.Datasource.BDBA
        ):
            license = am.data.get('license')
            severity = am.data.get('severity')
            package_name = am.data.get('id').get('package_name')

            finding_matching_am = tuple(
                matching_am for matching_am in matching_artefact_metadata
                if (
                    matching_am.data.get('license').get('name') == license.get('name') and
                    matching_am.data.get('id').get('package_name') == package_name
                )
            )
            seen_ids.update(tuple(matching_am.id for matching_am in finding_matching_am))

            package_versions = tuple(
                matching_am.data.get('id').get('package_version')
                for matching_am in finding_matching_am
                if matching_am.data.get('id').get('package_version')
            )

            filesystem_paths = filesystem_paths_for_finding(
                artefact_metadata=artefact_metadata,
                finding=am,
                package_versions=package_versions,
            )

            yield dacite.from_dict(
                data_class=RescoringProposal,
                data={
                    'finding': {
                        'id': {
                            'package_name': package_name,
                            'package_versions': package_versions,
                            'source': dso.model.Datasource.BDBA,
                        },
                        'severity': severity,
                        'license': license,
                        'filesystem_paths': filesystem_paths,
                    },
                    'severity': severity,
                    'matching_rules': ['original-severity'],
                    'applicable_rescorings': current_rescorings,
                    'discovery_date': am.discovery_date.isoformat(),
                    'sprint': sprint,
                },
            )


def iter_matching_artefacts(
    compliance_snapshots: tuple[dso.model.ArtefactMetadata],
    rescorings: tuple[dso.model.ArtefactMetadata],
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


def create_backlog_items_for_rescored_artefacts(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    session: ss.Session,
    rescorings: tuple[dso.model.ComponentArtefactId],
):
    scan_configs = tuple(k8s.util.iter_scan_configurations(
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    ))

    # only if there is one scan config we can assume for sure that this config should be used
    if len(scan_configs) != 1:
        return

    scan_config_name = scan_configs[0].name

    compliance_snapshots_raw = session.query(dm.ArtefactMetaData).filter(
        dm.ArtefactMetaData.type == dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
        dm.ArtefactMetaData.data.op('->>')('cfg_name').cast(sa.String) == scan_config_name,
    ).all()

    compliance_snapshots = tuple(
        du.db_artefact_metadata_to_dso(
            artefact_metadata=raw,
        )
        for raw in compliance_snapshots_raw
    )

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


class Rescore:
    required_features = (features.FeatureDeliveryDB,)

    def __init__(
        self,
        cve_rescoring_rule_set_lookup: CveRescoringRuleSetLookup,
        default_rule_set_callback: collections.abc.Callable[[], features.CveRescoringRuleSet],
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        namespace_callback,
        kubernetes_api_callback,
        sprints_repo_callback,
        sprints_relpath_callback,
    ):
        self.cve_rescoring_rule_set_lookup = cve_rescoring_rule_set_lookup
        self.default_rule_set_callback = default_rule_set_callback
        self.component_descriptor_lookup = component_descriptor_lookup
        self.namespace_callback = namespace_callback
        self.kubernetes_api_callback = kubernetes_api_callback
        self.sprints_repo_callback = sprints_repo_callback
        self.sprints_relpath_callback = sprints_relpath_callback

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        '''
        applies rescoring to delivery-db, only for authenticated users

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
                relation: <object> \n
                  refers_to: <string> # type of finding, e.g. finding/vulnerability \n
                  relation_kind: rescore \n
              data: <object> \n
                finding: <object> # schema depends on meta.relation.refers_to \n
                severity: <string> # one of github.compliance.model.Severity \n
                matching_rules: <array> of <string> \n
                comment: <string> \n
        '''
        body = req.media
        rescorings_raw: list[dict] = body.get('entries')

        user: middleware.auth.GithubUser = req.context['github_user']
        session: ss.Session = req.context.db_session

        def iter_rescorings(
            rescorings_raw: list[dict],
        ) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
            for rescoring_raw in rescorings_raw:
                rescoring_raw['data']['user'] = dataclasses.asdict(user)

                rescoring = dso.model.ArtefactMetadata.from_dict(rescoring_raw)

                if not rescoring.meta.type == dso.model.Datatype.RESCORING:
                    raise falcon.HTTPBadRequest(
                        title=f'rescoring must be of type {dso.model.Datatype.RESCORING}',
                        description=f'{rescoring.meta.type=}',
                    )

                yield rescoring

        rescorings = tuple(iter_rescorings(rescorings_raw=rescorings_raw))

        try:
            for rescoring in rescorings:
                rescoring_db = du.to_db_artefact_metadata(
                    artefact_metadata=rescoring,
                )

                # avoid adding rescoring duplicates -> purge old entries
                session.query(dm.ArtefactMetaData).filter(
                    du.ArtefactMetadataFilters.filter_for_rescoring(rescoring_db),
                ).delete()

                session.add(rescoring_db)
                session.commit()
        except:
            session.rollback()
            raise

        create_backlog_items_for_rescored_artefacts(
            namespace=self.namespace_callback(),
            kubernetes_api=self.kubernetes_api_callback(),
            session=session,
            rescorings=rescorings,
        )

        resp.status = falcon.HTTP_CREATED

    @middleware.auth.noauth
    def on_get(self, req: falcon.Request, resp: falcon.Response):
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
                  relation: <object> \n
                    refers_to: <string> # type of finding, e.g. finding/vulnerability \n
                    relation_kind: rescore \n
                data: <object> \n
                  finding: <object> # schema depends on meta.relation.refers_to \n
                  severity: <string> # one of github.compliance.model.Severity \n
                  matching_rules: <array> of <string> \n
                  user: <object> \n
                  comment: <string> \n
        '''
        session: ss.Session = req.context.db_session

        component_name = req.get_param('componentName', required=True)
        component_version = req.get_param('componentVersion', required=True)
        artefact_kind = req.get_param('artefactKind', required=True)
        artefact_name = req.get_param('artefactName', required=True)
        artefact_version = req.get_param('artefactVersion', required=True)
        artefact_type = req.get_param('artefactType', required=True)
        artefact_extra_id = req.get_param('artefactExtraId', required=False, default=dict())
        type_filter = req.get_param_as_list('type', required=False)

        # also filter for structure info to enrich findings
        type_filter.append(dso.model.Datatype.STRUCTURE_INFO)

        cve_rescoring_rule_set_name = req.get_param(
            'cveRescoringRuleSetName',
            required=False,
            default=None,
        )

        cve_rescoring_rule_set = _find_cve_rescoring_rule_set(
            default_cve_rescoring_rule_set=self.default_rule_set_callback(),
            cve_rescoring_rule_set_lookup=self.cve_rescoring_rule_set_lookup,
            cve_rescoring_rule_set_name=cve_rescoring_rule_set_name,
        )

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

        artefact_node = _find_artefact_node_or_raise(
            component_descriptor_lookup=self.component_descriptor_lookup,
            artefact=artefact,
        )

        categorisation = _find_cve_label(artefact_node=artefact_node)

        artefact_metadata = _find_artefact_metadata(
            session=session,
            artefact_node=artefact_node,
            type_filter=type_filter,
        )

        rescorings = _find_rescorings(
            session=session,
            artefact_node=artefact_node,
            type_filter=type_filter,
        )

        scan_configs = tuple(k8s.util.iter_scan_configurations(
            namespace=self.namespace_callback(),
            kubernetes_api=self.kubernetes_api_callback(),
        ))

        # only if there is one scan config we can assume for sure that this config should be used
        if len(scan_configs) != 1:
            max_processing_days = None
            sprints = []
        else:
            scan_config = scan_configs[0]
            issue_replicator_config = config.deserialise_issue_replicator_config(
                spec_config=scan_config.config,
            )
            if issue_replicator_config:
                max_processing_days = issue_replicator_config.max_processing_days
            else:
                max_processing_days = gcm.MaxProcessingTimesDays()

            if (
                (repo := self.sprints_repo_callback())
                and (relpath := self.sprints_relpath_callback())
            ):
                sprints = yp._sprints(
                    repo=repo,
                    sprints_file_relpath=relpath,
                )
            else:
                sprints = []

        rescoring_proposals = _iter_rescoring_proposals(
            artefact_metadata=artefact_metadata,
            rescorings=rescorings,
            rescoring_rules=cve_rescoring_rule_set.rules if cve_rescoring_rule_set else None,
            categorisation=categorisation,
            max_processing_days=max_processing_days,
            sprints=sprints,
        )

        resp.media = tuple(rescoring_proposals)

    def on_delete(self, req: falcon.Request, resp: falcon.Response):
        '''
        deletes rescoring from delivery-db, only for authenticated users

        **expected query parameters:**

            - id (required) <array> of <int> \n
        '''
        session: ss.Session = req.context.db_session

        ids = req.get_param_as_list('id', required=True)

        try:
            query = session.query(dm.ArtefactMetaData).filter(
                dm.ArtefactMetaData.id.cast(sa.String).in_(ids),
            )

            rescorings_raw = query.all()
            rescorings = tuple(
                du.db_artefact_metadata_to_dso(
                    artefact_metadata=raw,
                )
                for raw in rescorings_raw
            )

            query.delete()
            session.commit()

            create_backlog_items_for_rescored_artefacts(
                namespace=self.namespace_callback(),
                kubernetes_api=self.kubernetes_api_callback(),
                session=session,
                rescorings=rescorings,
            )
        except:
            session.rollback()
            raise

        resp.status = falcon.HTTP_NO_CONTENT
