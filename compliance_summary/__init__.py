import asyncio
import collections
import collections.abc
import dataclasses
import enum
import functools
import logging

import sqlalchemy.ext.asyncio as sqlasync

import cnudie.retrieve
import cnudie.retrieve_async
import dso.model
import ocm

import deliverydb.cache
import deliverydb.util
import odg.findings
import rescore.utility


logger = logging.getLogger(__name__)


class ComplianceEntryCategorisation(enum.StrEnum):
    UNKNOWN = 'UNKNOWN'
    CLEAN = 'CLEAN'


def categorisation_to_summary_categorisation(
    categorisation: odg.findings.FindingCategorisation,
) -> ComplianceEntryCategorisation | str:
    if categorisation.value == 0:
        # Rather use "CLEAN" instead of the custom none-categorisation for the summary as it either
        # means there are no findings or all findings have been assessed, whereas the
        # none-categorisation should only be used for the latter (e.g. "false-positive").
        return ComplianceEntryCategorisation.CLEAN

    return categorisation.id


def rescored_severity_if_any(
    finding: dso.model.ArtefactMetadata,
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
) -> str | None:
    rescorings_for_finding = rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        rescorings=rescorings,
    )

    if not rescorings_for_finding:
        return None

    # rescorings are already sorted by specificity and creation date
    most_specific_rescoring = rescorings_for_finding[0]

    return most_specific_rescoring.data.severity


class ComplianceScanStatus:
    NO_DATA = 'no_data'
    OK = 'ok'


@dataclasses.dataclass
class ComplianceSummaryEntry:
    '''
    :param FindingType type
    :param Datasource source
    :param ComplianceEntryCategorisation | str categorisation:
        The id of the most severe categorisation which was found for the given `source` and `type`.
        Note, if the semantic value of this categorisation is "0", the meta-category `CLEAN` is used,
        and if no scan is found, the meta-category `UNKNOWN` is used.
    :param int value:
        The semantic value of the respective categorisation.
    :param ComplianceScanStatus scanStatus
    '''
    type: odg.findings.FindingType
    source: dso.model.Datasource
    categorisation: ComplianceEntryCategorisation | str
    value: int
    scanStatus: ComplianceScanStatus


@dataclasses.dataclass
class ArtefactComplianceSummary:
    artefact: dso.model.ComponentArtefactId
    entries: list[ComplianceSummaryEntry]


@dataclasses.dataclass
class ComponentComplianceSummary:
    componentId: ocm.ComponentIdentity
    entries: list[ComplianceSummaryEntry]
    artefacts: list[ArtefactComplianceSummary]


async def severity_for_finding(
    finding: dso.model.ArtefactMetadata,
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata]=tuple(),
) -> ComplianceEntryCategorisation | str | None:
    '''
    Severity for known `ArtefactMetadata`.
    '''
    if rescorings:
        loop = asyncio.get_running_loop()
        rescored_severity = await loop.run_in_executor(None, functools.partial(
            rescored_severity_if_any,
            finding=finding,
            rescorings=rescorings,
        ))
        if rescored_severity:
            return rescored_severity

    return finding.data.severity


async def calculate_summary_entry(
    finding_cfg: odg.findings.Finding,
    findings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
) -> ComplianceSummaryEntry:
    '''
    returns most severe (highest semantic value) `ComplianceSummaryEntry`
    `findings` must be of same datatype and not empty!
    '''
    most_severe_categorisation = None

    for finding in findings:
        severity_name = await severity_for_finding(
            finding=finding,
            rescorings=rescorings,
        )

        categorisation = finding_cfg.categorisation_by_id(severity_name)

        if (
            not most_severe_categorisation
            or categorisation.value > most_severe_categorisation.value
        ):
            most_severe_categorisation = categorisation

    return ComplianceSummaryEntry(
        type=finding_cfg.type,
        source=finding.meta.datasource,
        categorisation=categorisation_to_summary_categorisation(most_severe_categorisation),
        value=most_severe_categorisation.value,
        scanStatus=ComplianceScanStatus.OK,
    )


async def compliance_summary_entry(
    finding_cfg: odg.findings.Finding,
    datasource: str,
    scan_exists: bool,
    findings: collections.abc.Sequence[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Sequence[dso.model.ArtefactMetadata],
) -> ComplianceSummaryEntry:
    if not scan_exists:
        return ComplianceSummaryEntry(
            type=finding_cfg.type,
            source=datasource,
            categorisation=ComplianceEntryCategorisation.UNKNOWN,
            value=-1,
            scanStatus=ComplianceScanStatus.NO_DATA,
        )

    if not findings:
        return ComplianceSummaryEntry(
            type=finding_cfg.type,
            source=datasource,
            categorisation=ComplianceEntryCategorisation.CLEAN,
            value=0,
            scanStatus=ComplianceScanStatus.OK,
        )

    return await calculate_summary_entry(
        finding_cfg=finding_cfg,
        findings=findings,
        rescorings=rescorings,
    )


async def artefact_datatype_summary(
    artefact: dso.model.ComponentArtefactId,
    finding_cfg: odg.findings.Finding,
    datasource: str,
    artefact_scan_infos: collections.abc.Sequence[dso.model.ArtefactMetadata],
    findings: collections.abc.Sequence[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Sequence[dso.model.ArtefactMetadata],
) -> ComplianceSummaryEntry:
    findings_for_artefact = [
        finding for finding in findings
        if (
            finding.artefact.artefact_kind is artefact.artefact_kind
            and finding.artefact.artefact == artefact.artefact
        )
    ]

    rescorings_for_artefact = [
        rescoring for rescoring in rescorings
        if (
            rescoring.artefact.artefact_kind is artefact.artefact_kind
            and rescoring.artefact.artefact.artefact_type == artefact.artefact.artefact_type
            and (
                not rescoring.artefact.artefact.artefact_name
                or rescoring.artefact.artefact.artefact_name == artefact.artefact.artefact_name
            ) and (
                not rescoring.artefact.artefact.artefact_version
                or rescoring.artefact.artefact.artefact_version == artefact.artefact.artefact_version
            ) and (
                not rescoring.artefact.artefact.normalised_artefact_extra_id
                or rescoring.artefact.artefact.normalised_artefact_extra_id
                    == artefact.artefact.normalised_artefact_extra_id
            )
        )
    ]

    for artefact_scan_info in artefact_scan_infos:
        if (
            artefact_scan_info.artefact.artefact_kind is artefact.artefact_kind
            and artefact_scan_info.artefact.artefact == artefact.artefact
        ):
            scan_exists = True
            break
    else:
        scan_exists = False

    return await compliance_summary_entry(
        finding_cfg=finding_cfg,
        datasource=datasource,
        scan_exists=scan_exists,
        findings=findings_for_artefact,
        rescorings=rescorings_for_artefact,
    )


# Note: The cache manager expects this function to use the persistent db-cache annotator. If this
# would be removed in a future change, the cache manager also had to be adjusted to prevent
# unnecessary load.
@deliverydb.cache.dbcached_function(
    ttl_seconds=60 * 60 * 24, # 1 day
    exclude_kwargs=(
        'finding_cfg',
        'component_descriptor_lookup',
        'ocm_repo',
    ),
)
async def component_datatype_summaries(
    component: ocm.ComponentIdentity,
    finding_cfg: odg.findings.Finding,
    finding_type: odg.findings.FindingType,
    datasource: str,
    db_session: sqlasync.session.AsyncSession,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    ocm_repo: ocm.OciOcmRepository | None=None,
    shortcut_cache: bool=False,
) -> list[tuple[dso.model.ComponentArtefactId, ComplianceSummaryEntry]]:
    if ocm_repo:
        component = (await component_descriptor_lookup(
            component,
            ocm_repository_lookup=cnudie.retrieve.ocm_repository_lookup(ocm_repo),
        )).component
    else:
        component = (await component_descriptor_lookup(component)).component

    artefact_scan_infos = await deliverydb.util.findings_for_component(
        component=component,
        finding_type=dso.model.Datatype.ARTEFACT_SCAN_INFO,
        datasource=datasource,
        db_session=db_session,
    )

    if artefact_scan_infos:
        findings = await deliverydb.util.findings_for_component(
            component=component,
            finding_type=finding_type,
            datasource=datasource,
            db_session=db_session,
        )
    else:
        # if no scan exists, we don't have to query for findings
        findings = []

    if findings:
        rescorings = await deliverydb.util.rescorings_for_component(
            component=component,
            finding_type=finding_type,
            db_session=db_session,
        )
    else:
        # if no findings exist, we don't have to query for rescorings
        rescorings = []

    summaries = []
    for artefact in component.resources + component.sources:
        artefact = dso.model.component_artefact_id_from_ocm(
            component=component,
            artefact=artefact,
        )

        if not finding_cfg.matches(artefact):
            continue

        artefact_summary = await artefact_datatype_summary(
            artefact=artefact,
            finding_cfg=finding_cfg,
            datasource=datasource,
            artefact_scan_infos=artefact_scan_infos,
            findings=findings,
            rescorings=rescorings,
        )

        summaries.append((
            artefact,
            artefact_summary,
        ))

    if not summaries:
        return summaries

    component_summary = None
    for _, artefact_summary in summaries:
        if (
            not component_summary
            or artefact_summary.value > component_summary.value
        ):
            component_summary = artefact_summary

    summaries.insert(0, (
        dso.model.ComponentArtefactId(
            component_name=component.name,
            component_version=component.version,
            artefact=None,
        ),
        component_summary,
    ))

    return summaries


async def component_compliance_summary(
    component: ocm.ComponentIdentity,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    db_session: sqlasync.session.AsyncSession,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    ocm_repo: ocm.OciOcmRepository | None=None,
    shortcut_cache: bool=False,
) -> ComponentComplianceSummary:
    component_entries = []
    artefacts_entries_by_artefact = collections.defaultdict(list)

    for finding_cfg in finding_cfgs:
        summary_entries_by_artefact = await component_datatype_summaries(
            component=component,
            finding_cfg=finding_cfg,
            finding_type=finding_cfg.type,
            datasource=dso.model.Datatype.datatype_to_datasource(finding_cfg.type),
            db_session=db_session,
            component_descriptor_lookup=component_descriptor_lookup,
            ocm_repo=ocm_repo,
            shortcut_cache=shortcut_cache,
        )

        if not summary_entries_by_artefact:
            continue

        # first entry is always the component summary
        component_entries.append(summary_entries_by_artefact[0][1])

        for component_artefact_id, summary_entry in summary_entries_by_artefact[1:]:
            artefacts_entries_by_artefact[component_artefact_id].append(summary_entry)

    return ComponentComplianceSummary(
        componentId=component,
        entries=component_entries,
        artefacts=[
            ArtefactComplianceSummary(
                artefact=artefact,
                entries=entries,
            ) for artefact, entries in artefacts_entries_by_artefact.items()
        ],
    )
