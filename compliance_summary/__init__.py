import collections.abc
import dataclasses
import enum
import logging

import awesomeversion
import dacite

import dso.model
import github.compliance.model as gcm
import ocm
import unixutil.model as um

import delivery.model
import delivery.util as du
import eol
import ocm_util
import osinfo
import rescore.util


logger = logging.getLogger(__name__)


class ComplianceEntrySeverity(enum.IntEnum):
    UNKNOWN = 0
    CLEAN = 1
    LOW = 2
    MEDIUM = 4
    HIGH = 8
    CRITICAL = 16
    BLOCKER = 32


def severity_to_summary_severity(severity: gcm.Severity) -> ComplianceEntrySeverity:
    if severity == gcm.Severity.NONE:
        return ComplianceEntrySeverity.CLEAN

    return ComplianceEntrySeverity[severity.name]


def rescored_severity_if_any(
    finding: dso.model.ArtefactMetadata,
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
) -> str | None:
    rescorings_for_finding = rescore.util.rescorings_for_finding_by_specificity(
        finding=finding,
        rescorings=rescorings,
    )

    if not rescorings_for_finding:
        return None

    # rescorings are already sorted by specificity and creation date
    most_specific_rescoring = rescorings_for_finding[0]

    return severity_to_summary_severity(
        severity=gcm.Severity[most_specific_rescoring.data.severity]
    ).name


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
    ) -> str | None:
        findings = dataclasses.asdict(finding.data.findings)

        if not any(findings.values()):
            return ComplianceEntrySeverity.CLEAN.name

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
    ) -> str | None:
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


@dataclasses.dataclass(frozen=True)
class ComplianceSummaryEntry:
    type: dso.model.Datatype
    source: dso.model.Datasource
    severity: ComplianceEntrySeverity
    scanStatus: ComplianceScanStatus


@dataclasses.dataclass(frozen=True)
class ArtefactComplianceSummary:
    artefact: dso.model.ComponentArtefactId
    entries: list[ComplianceSummaryEntry]


@dataclasses.dataclass(frozen=True)
class ComponentComplianceSummary:
    componentId: ocm.ComponentIdentity
    entries: list[ComplianceSummaryEntry]
    artefacts: list[ArtefactComplianceSummary]


@dataclasses.dataclass(frozen=True)
class SummaryConfig:
    default_entries: dict[str, ComplianceSummaryEntry]


async def component_summaries(
    findings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    components: tuple[ocm.Component],
    eol_client: eol.EolClient,
    artefact_metadata_cfg_by_type: dict,
    cfg: SummaryConfig = SummaryConfig(
        default_entries={
            dso.model.Datatype.LICENSE: ComplianceSummaryEntry(
                type=dso.model.Datatype.LICENSE,
                source=dso.model.Datasource.BDBA,
                severity=ComplianceEntrySeverity.UNKNOWN,
                scanStatus=ComplianceScanStatus.NO_DATA,
            ),
            dso.model.Datatype.VULNERABILITY: ComplianceSummaryEntry(
                type=dso.model.Datatype.VULNERABILITY,
                source=dso.model.Datasource.BDBA,
                severity=ComplianceEntrySeverity.UNKNOWN,
                scanStatus=ComplianceScanStatus.NO_DATA,
            ),
            dso.model.Datatype.OS_IDS: ComplianceSummaryEntry(
                type=dso.model.Datatype.OS_IDS,
                source=dso.model.Datasource.CC_UTILS,
                severity=ComplianceEntrySeverity.UNKNOWN,
                scanStatus=ComplianceScanStatus.NO_DATA,
            ),
            dso.model.Datatype.CODECHECKS_AGGREGATED: ComplianceSummaryEntry(
                type=dso.model.Datatype.CODECHECKS_AGGREGATED,
                source=dso.model.Datasource.CHECKMARX,
                severity=ComplianceEntrySeverity.UNKNOWN,
                scanStatus=ComplianceScanStatus.NO_DATA,
            ),
            dso.model.Datatype.MALWARE_FINDING: ComplianceSummaryEntry(
                type=dso.model.Datatype.MALWARE_FINDING,
                source=dso.model.Datasource.CLAMAV,
                severity=ComplianceEntrySeverity.UNKNOWN,
                scanStatus=ComplianceScanStatus.NO_DATA,
            )
        },
    ),
) -> collections.abc.AsyncGenerator[ComponentComplianceSummary, None, None]:
    '''
    yields compliance summaries per component and per artefact containing most
    critical flaw for each `data_type`.
    On absence of flaw per data_type, corresponding `default_entry` is taken.
    '''
    for component in components:
        if len(components) == 1:
            # findings were already pre-filtered by query
            filtered_findings = findings
            filtered_rescorings = rescorings
        else:
            filtered_findings = tuple(
                finding for finding in findings
                if ocm_util.find_artefact_of_component_or_none(
                    component=component,
                    artefact=finding.artefact,
                )
            )

            filtered_rescorings = tuple(
                rescoring for rescoring in rescorings
                if (
                    not rescoring.artefact.component_name or
                    rescoring.artefact.component_name == component.name
                ) and (
                    not rescoring.artefact.component_version or
                    rescoring.artefact.component_version == component.version
                )
            )

        yield ComponentComplianceSummary(
            componentId=ocm.ComponentIdentity(
                name=component.name,
                version=component.version,
            ),
            entries=[
                summary async for summary in calculate_summary(
                    artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
                    findings=filtered_findings,
                    rescorings=filtered_rescorings,
                    defaults=cfg.default_entries,
                    types=tuple(type for type in cfg.default_entries.keys()),
                    eol_client=eol_client,
                )
            ],
            artefacts=[await calculate_artefact_summary(
                component=component,
                artefact=artefact,
                findings=filtered_findings,
                rescorings=filtered_rescorings,
                defaults=cfg.default_entries,
                eol_client=eol_client,
                artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
            ) for artefact in component.resources + component.sources],
        )


async def calculate_artefact_summary(
    component: ocm.Component,
    artefact: ocm.Resource | ocm.Source,
    findings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    defaults: dict[ComplianceSummaryEntry],
    eol_client: eol.EolClient,
    artefact_metadata_cfg_by_type: dict[str, ArtefactMetadataCfg],
) -> ArtefactComplianceSummary:
    if isinstance(artefact, ocm.Resource):
        artefact_kind = dso.model.ArtefactKind.RESOURCE
    elif isinstance(artefact, ocm.Source):
        artefact_kind = dso.model.ArtefactKind.SOURCE
    else:
        raise ValueError(artefact)

    artefact_type = artefact.type.value if isinstance(artefact.type, enum.Enum) else artefact.type

    findings_for_artefact = tuple(
        finding for finding in findings
        if (
            finding.artefact.artefact_kind == artefact_kind
            and finding.artefact.artefact.artefact_name == artefact.name
            and finding.artefact.artefact.artefact_version == artefact.version
            and finding.artefact.artefact.artefact_type == artefact_type
            and finding.artefact.artefact.normalised_artefact_extra_id()
                == dso.model.normalise_artefact_extra_id(
                    artefact_extra_id=artefact.extraIdentity,
                )
        )
    )

    return ArtefactComplianceSummary(
        artefact=dso.model.ComponentArtefactId(
            component_name=component.name,
            component_version=component.version,
            artefact_kind=artefact_kind.value,
            artefact=dso.model.LocalArtefactId(
                artefact_name=artefact.name,
                artefact_version=artefact.version,
                artefact_type=artefact_type,
                artefact_extra_id=artefact.extraIdentity,
            ),
        ),
        entries=[
            summary async for summary in calculate_summary(
                artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
                findings=findings_for_artefact,
                rescorings=rescorings,
                defaults=defaults,
                types=tuple(type for type in defaults.keys()),
                eol_client=eol_client,
            )
        ],
    )


async def calculate_summary(
    findings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    defaults: dict[ComplianceSummaryEntry],
    types: tuple[dso.model.Datatype],
    eol_client: eol.EolClient,
    artefact_metadata_cfg_by_type: dict[str, ArtefactMetadataCfg],
) -> collections.abc.AsyncGenerator[ComplianceSummaryEntry, None, None]:
    '''
    yields exactly one `ComplianceSummaryEntry` per type in `types` from `findings`,
    on absence fallback to corresponding default.
    '''
    for finding_type in types:
        artefact_metadata_cfg = artefact_metadata_cfg_by_type.get(finding_type)

        findings_with_given_type = tuple(
            finding for finding in findings
            if finding.meta.type == finding_type
        )

        if not findings_with_given_type:
            # check if scan exists and has no findings instead of
            # component is not scanned and thus has no findinngs
            datasource = defaults[finding_type].source

            findings_with_matching_datasource = [
                finding for finding in findings
                if finding.meta.datasource == datasource
            ]

            if findings_with_matching_datasource:
                yield ComplianceSummaryEntry(
                    type=finding_type,
                    source=datasource,
                    severity=ComplianceEntrySeverity.CLEAN,
                    scanStatus=ComplianceScanStatus.OK,
                )
                continue

            yield defaults[finding_type]
            continue

        rescorings_for_type = tuple(
            rescoring for rescoring in rescorings
            if rescoring.data.referenced_type == finding_type
        )

        yield await calculate_summary_entry(
            findings=findings_with_given_type,
            rescorings=rescorings_for_type,
            eol_client=eol_client,
            artefact_metadata_cfg=artefact_metadata_cfg,
        )


async def severity_for_finding(
    finding: dso.model.ArtefactMetadata,
    artefact_metadata_cfg: ArtefactMetadataCfg | None = None,
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata] = tuple(),
    eol_client: eol.EolClient | None = None,
    known_artefact_metadata_types: tuple[str] = (
        dso.model.Datatype.VULNERABILITY,
        dso.model.Datatype.LICENSE,
        dso.model.Datatype.OS_IDS,
        dso.model.Datatype.CODECHECKS_AGGREGATED,
        dso.model.Datatype.MALWARE_FINDING,
    ),
) -> str | None:
    '''
    Severity for known `ArtefactMetadata`.

    `None` indicates unknown `ArtefactMetadata`.
    Raises `RuntimeError` if no severity mapping could be applied.
    '''

    if not finding.meta.type in known_artefact_metadata_types:
        return None

    if rescorings:
        rescored_severity = rescored_severity_if_any(
            finding=finding,
            rescorings=rescorings,
        )
        if rescored_severity:
            return rescored_severity

    if finding.meta.type in (
        dso.model.Datatype.LICENSE,
        dso.model.Datatype.VULNERABILITY,
        dso.model.Datatype.MALWARE_FINDING,
    ):
        # these types have the severity already stored in their data field
        # no need to do separate severity mapping
        return severity_to_summary_severity(
            severity=gcm.Severity[finding.data.severity],
        ).name

    return await artefact_metadata_cfg.match(
        finding=finding,
        eol_client=eol_client,
    )


async def calculate_summary_entry(
    findings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
    eol_client: eol.EolClient,
    artefact_metadata_cfg: ArtefactMetadataCfg | None = None,
) -> ComplianceSummaryEntry:
    '''
    returns most critical (highest severity) `ComplianceSummaryEntry`
    `findings` must be of same datatype and not empty!
    '''
    most_critical = ComplianceSummaryEntry(
        type=findings[0].meta.type,
        source=findings[0].meta.datasource,
        severity=ComplianceEntrySeverity.UNKNOWN,
        scanStatus=ComplianceScanStatus.OK,
    )

    for finding in findings:
        severity_name = await severity_for_finding(
            finding=finding,
            rescorings=rescorings,
            eol_client=eol_client,
            artefact_metadata_cfg=artefact_metadata_cfg,
        )
        severity = ComplianceEntrySeverity[severity_name]

        if severity > most_critical.severity:
            most_critical = ComplianceSummaryEntry(
                type=finding.meta.type,
                source=finding.meta.datasource,
                severity=severity,
                scanStatus=ComplianceScanStatus.OK,
            )

    return most_critical
