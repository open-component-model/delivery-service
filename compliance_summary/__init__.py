import asyncio
import collections
import collections.abc
import dataclasses
import enum
import functools
import logging

import awesomeversion
import dacite
import sqlalchemy.ext.asyncio as sqlasync

import cnudie.retrieve
import cnudie.retrieve_async
import dso.model
import ocm
import unixutil.model as um

import delivery.model
import delivery.util as du
import deliverydb.cache
import deliverydb.util
import eol
import odg.findings
import osinfo
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


@dataclasses.dataclass(frozen=True)
class SeverityMappingBase:
    severityName: str


@dataclasses.dataclass(frozen=True)
class CodecheckSeverityNamesMapping(SeverityMappingBase):
    codecheckSeverityNames: list[str]

    async def match(
        self,
        finding: dso.model.ArtefactMetadata,
        **kwargs,
    ) -> ComplianceEntryCategorisation | str | None:
        findings = dataclasses.asdict(finding.data.findings)

        if not any(findings.values()):
            return ComplianceEntryCategorisation.CLEAN

        for risk_severity_name in self.codecheckSeverityNames:
            if findings[risk_severity_name]:
                return self.severityName

        return None


@dataclasses.dataclass(frozen=True)
class OsStatusMapping(SeverityMappingBase):
    status: list[str]

    async def match(
        self,
        finding: dso.model.ArtefactMetadata,
        **kwargs,
    ) -> str | None:

        eol_client = kwargs['eol_client']

        class OsStatus(enum.Enum):
            '''
            values used to map severity, see `compliance_summary/artefact_metadata_cfg.yaml`
            '''
            NO_BRANCH_INFO = 'noBranchInfo'
            NO_RELEASE_INFO = 'noReleaseInfo'
            UNABLE_TO_COMPARE_VERSION = 'unableToCompareVersion'
            IS_EOL = 'isEol'
            UPDATE_AVAILABLE_FOR_BRANCH = 'updateAvailableForBranch'
            GREATEST_BRANCH_VERSION = 'greatestBranchVersion'
            EMPTY_OS_ID = 'emptyOsId'

        def empty_os_id(
            os_id: um.OperatingSystemId,
        ) -> bool:
            if not any([
                field
                for field in os_id.__dict__.values()
            ]):
                return True
            return False

        def determine_status(release_infos: list[delivery.model.OsReleaseInfo]) -> OsStatus:
            branch_info = du.find_branch_info(
                os_id=os_id,
                os_infos=release_infos,
            )

            if not branch_info:
                return OsStatus.NO_BRANCH_INFO

            is_eol = du.branch_reached_eol(
                os_id=os_id,
                os_infos=release_infos,
            )

            try:
                update_avilable = du.update_available(
                    os_id=os_id,
                    os_infos=release_infos,
                )
            except awesomeversion.exceptions.AwesomeVersionCompareException:
                return OsStatus.UNABLE_TO_COMPARE_VERSION

            if is_eol:
                return OsStatus.IS_EOL

            if update_avilable:
                return OsStatus.UPDATE_AVAILABLE_FOR_BRANCH

            return OsStatus.GREATEST_BRANCH_VERSION

        def severity_for_os_status(os_status: OsStatus) -> str | None:
            severity_name = self.severityName
            for mapping_status in self.status:
                if mapping_status == os_status.value:
                    return severity_name
            return None

        os_id = finding.data.os_info

        if empty_os_id(os_id):
            return severity_for_os_status(OsStatus.EMPTY_OS_ID)

        release_infos = await osinfo.os_release_infos(
            os_id=eol.normalise_os_id(os_id.ID),
            eol_client=eol_client,
        )

        if not release_infos:
            logger.debug(f'did not find release-info for {os_id=}')
            return severity_for_os_status(OsStatus.NO_RELEASE_INFO)

        return severity_for_os_status(determine_status(release_infos))


@dataclasses.dataclass(frozen=True)
class ArtefactMetadataCfg:
    '''
    Represents configuration for a single ArtefactMetadataType.
    `categories` classifies an ArtefactMetadataType, e.g. compliance or structureInfo.
    `severityMappings` holds mapping configuration to a single severity string.
    Each evaluated ArtefactMetadataType has its own Mapping dataclass.
    '''
    type: str
    severityMappings: list[OsStatusMapping | CodecheckSeverityNamesMapping] | None
    categories: list[str] = dataclasses.field(default_factory=list)

    async def match(
        self,
        finding: dso.model.ArtefactMetadata,
        **kwargs,
    ) -> ComplianceEntryCategorisation | str | None:
        '''
        matches finding against severityMappings
        '''
        for severity_mapping in self.severityMappings:
            if (severity := await severity_mapping.match(finding, **kwargs)):
                return severity

        raise RuntimeError(f'no severity mapping for {finding.meta.type=}')


def artefact_metadata_cfg_by_type(artefact_metadata_cfg: dict) -> dict[str, ArtefactMetadataCfg]:
    '''
    parse raw cfg, raise on duplicate artefact metadata type names
    '''

    cfg_by_type = {}

    for artefact_metadata_cfg_raw in artefact_metadata_cfg['artefactMetadataCfg']:
        cfg = dacite.from_dict(
            data_class=ArtefactMetadataCfg,
            data=artefact_metadata_cfg_raw,
        )

        if cfg_by_type.get(cfg.type):
            raise RuntimeError(f'duplicate artefact metadata cfg for {cfg.type=}')

        cfg_by_type[cfg.type] = cfg

    return cfg_by_type


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
    artefact_metadata_cfg: ArtefactMetadataCfg | None=None,
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata]=tuple(),
    eol_client: eol.EolClient | None=None,
) -> ComplianceEntryCategorisation | str | None:
    '''
    Severity for known `ArtefactMetadata`.

    Raises `RuntimeError` if no severity mapping could be applied.
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

    if hasattr(finding.data, 'severity'):
        # these types have the severity already stored in their data field
        # no need to do separate severity mapping
        return finding.data.severity

    return await artefact_metadata_cfg.match(
        finding=finding,
        eol_client=eol_client,
    )


async def calculate_summary_entry(
    finding_cfg: odg.findings.Finding,
    findings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    eol_client: eol.EolClient,
    artefact_metadata_cfg: ArtefactMetadataCfg | None=None,
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
            eol_client=eol_client,
            artefact_metadata_cfg=artefact_metadata_cfg,
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
    eol_client: eol.EolClient,
    artefact_metadata_cfg: ArtefactMetadataCfg,
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
        eol_client=eol_client,
        artefact_metadata_cfg=artefact_metadata_cfg,
    )


async def artefact_datatype_summary(
    artefact: dso.model.ComponentArtefactId,
    finding_cfg: odg.findings.Finding,
    datasource: str,
    artefact_scan_infos: collections.abc.Sequence[dso.model.ArtefactMetadata],
    findings: collections.abc.Sequence[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Sequence[dso.model.ArtefactMetadata],
    eol_client: eol.EolClient,
    artefact_metadata_cfg: ArtefactMetadataCfg,
) -> ComplianceSummaryEntry:
    findings_for_artefact = [
        finding for finding in findings
        if (
            finding.artefact.artefact_kind is artefact.artefact_kind
            and finding.artefact.artefact == artefact.artefact
        )
    ]

    if not dso.model.Datasource.has_scan_info(datasource):
        # TODO remove this conditional branch once all datasources emit scan info objects
        scan_exists = bool(findings_for_artefact)

    else:
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
        rescorings=rescorings,
        eol_client=eol_client,
        artefact_metadata_cfg=artefact_metadata_cfg,
    )


# Note: The cache manager expects this function to use the persistent db-cache annotator. If this
# would be removed in a future change, the cache manager also had to be adjusted to prevent
# unnecessary load.
@deliverydb.cache.dbcached_function(
    ttl_seconds=60 * 60 * 24, # 1 day
    exclude_kwargs=(
        'finding_cfg',
        'component_descriptor_lookup',
        'eol_client',
        'artefact_metadata_cfg',
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
    eol_client: eol.EolClient,
    artefact_metadata_cfg: ArtefactMetadataCfg,
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

    if not dso.model.Datasource.has_scan_info(datasource):
        # TODO remove this conditional branch once all datasources emit scan info objects
        artefact_scan_infos = None

        findings = await deliverydb.util.findings_for_component(
            component=component,
            finding_type=finding_type,
            datasource=datasource,
            db_session=db_session,
        )
        scan_exists = bool(findings)

        # the remaining datasources do not support rescorings so retrieval of the same
        # can be safely skipped in this case
        rescorings = []

    else:
        artefact_scan_infos = await deliverydb.util.findings_for_component(
            component=component,
            finding_type=dso.model.Datatype.ARTEFACT_SCAN_INFO,
            datasource=datasource,
            db_session=db_session,
        )

        if scan_exists := bool(artefact_scan_infos):
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
    matches_artefact = False
    for artefact in component.resources + component.sources:
        artefact = dso.model.component_artefact_id_from_ocm(
            component=component,
            artefact=artefact,
        )

        if not finding_cfg.matches(artefact):
            continue

        matches_artefact = True

        artefact_summary = await artefact_datatype_summary(
            artefact=artefact,
            finding_cfg=finding_cfg,
            datasource=datasource,
            artefact_scan_infos=artefact_scan_infos,
            findings=findings,
            rescorings=rescorings,
            eol_client=eol_client,
            artefact_metadata_cfg=artefact_metadata_cfg,
        )

        summaries.append((
            artefact,
            artefact_summary,
        ))

    if not matches_artefact:
        return summaries

    # only if findings are reported for at least one artefact, show also on component level
    component_summary = await compliance_summary_entry(
        finding_cfg=finding_cfg,
        datasource=datasource,
        scan_exists=scan_exists,
        findings=findings,
        rescorings=rescorings,
        eol_client=eol_client,
        artefact_metadata_cfg=artefact_metadata_cfg,
    )
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
    eol_client: eol.EolClient,
    artefact_metadata_cfg_by_type: dict[str, ArtefactMetadataCfg],
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
            eol_client=eol_client,
            artefact_metadata_cfg=artefact_metadata_cfg_by_type.get(finding_cfg.type),
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
