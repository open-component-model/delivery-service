import collections.abc
import dataclasses
import datetime
import enum
import logging

import dacite
import github3
import github3.repos

import concourse.model.traits.image_scan as image_scan
import cnudie.iter
import dso.cvss
import dso.model
import github.compliance.milestone as gcmi
import github.compliance.model
import ocm

import bdba.model
import config_filter
import ctx_util
import lookups
import rescore.model


logger = logging.getLogger(__name__)


class Services(enum.StrEnum):
    ARTEFACT_ENUMERATOR = 'artefactEnumerator'
    BACKLOG_CONTROLLER = 'backlogController'
    BDBA = 'bdba'
    CLAMAV = 'clamav'
    DELIVERY_DB_BACKUP = 'deliveryDbBackup'
    ISSUE_REPLICATOR = 'issueReplicator'


@dataclasses.dataclass(frozen=True)
class Component:
    component_name: str
    version: str
    version_filter: str
    max_versions_limit: int
    ocm_repo: ocm.OciOcmRepository


@dataclasses.dataclass(frozen=True)
class TimeRange:
    start_date: datetime.date
    end_date: datetime.date


@dataclasses.dataclass(frozen=True)
class ArtefactEnumeratorConfig:
    '''
    :param str delivery_service_url
    :param int compliance_snapshot_grace_period:
        time after which inactive compliance snapshots are deleted from the delivery-db
    :param tuple[str] artefact_types:
        list of artefact types for which compliance snapshots should be created
    :param Callable[Node, bool] node_filter:
        filter of artefact nodes to explicitly in- or exclude artefacts compliance snapshot creation
    :param tuple[Component] components:
        components which are classified as "active" and for which compliance snapshots are created
    :param TimeRange sprints_time_range:
        earliest start and latest end date for which compliance snapshots should be created
    '''
    delivery_service_url: str
    compliance_snapshot_grace_period: int
    artefact_types: tuple[str]
    node_filter: collections.abc.Callable[[cnudie.iter.Node], bool]
    components: tuple[Component]
    sprints_time_range: TimeRange


@dataclasses.dataclass(frozen=True)
class ClamAVConfig:
    '''
    :param str delivery_service_url
    :param int lookup_new_backlog_item_interval:
        time to wait in case no backlog item was found before searching for new backlog item again
    :param int rescan_interval:
        time after which an artefact must be re-scanned at latest
    :param str aws_cfg_name
        cfg-element used to create s3 client to retrieve artefacts
    :param tuple[str] artefact_types:
        list of artefact types which should be scanned, other artefact types are skipped
    '''
    delivery_service_url: str
    lookup_new_backlog_item_interval: int
    rescan_interval: int
    aws_cfg_name: str
    artefact_types: tuple[str]


@dataclasses.dataclass(frozen=True)
class BDBAConfig:
    '''
    :param str delivery_service_url
    :param int rescan_interval:
        time after which an artefact must be re-scanned at latest
    :param int lookup_new_backlog_item_interval:
        time to wait in case no backlog item was found before searching for new backlog item again
    :param str cfg_name:
        name of config element to use for bdba scanning
    :param int group_id:
        bdba group id to use for scanning
    :param tuple[int] reference_group_ids:
        bdba group ids to consider when copying existing assessments
    :param CVSSVersion cvss_version
    :param str aws_cfg_set_name:
        name of config element to use for creating a s3 client
    :param ProcessingMode processing_mode:
        defines the scanning behaviour in case there is already an existing scan
    :param tuple[str] artefact_types:
        list of artefact types which should be scanned, other artefact types are skipped
    :param Callable[Node, bool] node_filter:
        filter of artefact nodes to explicitly in- or exclude artefacts from the bdba scan
    :param CveRescoringRuleSet cve_rescoring_ruleset:
        these rules are applied to automatically rescore findings below `auto_assess_max_severity`
    :param CVESeverity auto_assess_max_severity:
        only findings below this severity will be auto-rescored
    :param LicenseCfg license_cfg:
        required to differentiate between allowed and prohibited licenses
    :param int delete_inactive_products_after_seconds:
        time after which a bdba product is deleted if the scanned artefact is not active anymore
    :param set[str] blacklist_finding_types:
        finding types which are provided by BDBA but should _not_ be populated into the delivery-db
    '''
    delivery_service_url: str
    rescan_interval: int
    lookup_new_backlog_item_interval: int
    cfg_name: str
    group_id: int
    reference_group_ids: tuple[int]
    cvss_version: bdba.model.CVSSVersion
    aws_cfg_set_name: str
    processing_mode: bdba.model.ProcessingMode
    artefact_types: tuple[str]
    node_filter: collections.abc.Callable[[cnudie.iter.Node], bool]
    cve_rescoring_ruleset: rescore.model.CveRescoringRuleSet | None
    auto_assess_max_severity: dso.cvss.CVESeverity
    license_cfg: image_scan.LicenseCfg
    delete_inactive_products_after_seconds: int
    blacklist_finding_types: set[str]


@dataclasses.dataclass(frozen=True)
class FindingTypeIssueReplicationCfgBase:
    '''
    :param str finding_type:
        finding type this configuration should be applied for
        (see cc-utils dso/model.py for available "Datatype"s)
    :param bool enable_issue_assignees
    :param bool enable_issue_per_finding:
        when set to true issues are created per finding for a
        specific artefact as oppsed to a single issue with
        all findings
    '''
    finding_type: str
    enable_issue_assignees: bool
    enable_issue_per_finding: bool


@dataclasses.dataclass(frozen=True)
class VulnerabilityIssueReplicationCfg(FindingTypeIssueReplicationCfgBase):
    '''
    :param int cve_threshold:
        vulnerability findings below this threshold won't be reported in the issue(s)
    '''
    cve_threshold: int


@dataclasses.dataclass(frozen=True)
class IssueReplicatorConfig:
    '''
    :param str delivery_service_url
    :param str delivery_dashboard_url
    :param int replication_interval:
        time after which an issue must be updated at latest
    :param int lookup_new_backlog_item_interval:
        time to wait in case no backlog item was found before searching for new backlog item again
    :param LicenseCfg license_cfg:
        required to differentiate between allowed and prohibited licenses
    :param MaxProcessingTimesDays max_processing_days:
        configuration of allowed maximum processing time based on the severity of the findings
    :param github_api_lookup
    :param Repository github_issues_repository
    :param tuple[GithubIssueTemplateCfg] github_issue_template_cfgs:
        templates to configure appearance and format of issues based on type of findings
    :param set[str] github_issue_labels_to_preserve:
        labels matching one of these regexes won't be removed upon an issue update
    :param int number_included_closed_issues:
        number of closed issues to consider when evaluating creating vs re-opening an issue
    :param tuple[str] artefact_types:
        list of artefact types for which issues should be created, other artefact types are skipped
    :param Callable[Node, bool] node_filter:
        filter of artefact nodes to explicitly in- or exclude artefacts from the issue replication
    :param tuple[RescoringRule] cve_rescoring_rules:
        these rules are applied to calculate proposed rescorings which are displayed in the issue
    :param tuple[FindingTypeIssueReplicationCfgBase] finding_type_issue_replication_cfgs:
        these cfgs are finding type specific and allow fine granular configuration
    '''
    delivery_service_url: str
    delivery_dashboard_url: str
    replication_interval: int
    lookup_new_backlog_item_interval: int
    license_cfg: image_scan.LicenseCfg
    max_processing_days: github.compliance.model.MaxProcessingTimesDays
    github_api_lookup: collections.abc.Callable[[str], github3.GitHub]
    github_issues_repository: github3.repos.Repository
    github_issue_template_cfgs: tuple[image_scan.GithubIssueTemplateCfg]
    github_issue_labels_to_preserve: set[str]
    number_included_closed_issues: int
    artefact_types: tuple[str]
    node_filter: collections.abc.Callable[[cnudie.iter.Node], bool]
    cve_rescoring_rules: tuple[rescore.model.RescoringRule]
    finding_type_issue_replication_cfgs: tuple[FindingTypeIssueReplicationCfgBase]
    milestone_cfg: gcmi.MilestoneConfiguration


@dataclasses.dataclass(frozen=True)
class ScanConfiguration:
    artefact_enumerator_config: ArtefactEnumeratorConfig
    bdba_config: BDBAConfig
    issue_replicator_config: IssueReplicatorConfig
    clamav_config: ClamAVConfig


def deserialise_component_config(
    component_config: dict,
) -> Component:
    component_name = deserialise_config_property(
        config=component_config,
        property_key='component_name',
    )

    version = deserialise_config_property(
        config=component_config,
        property_key='version',
        absent_ok=True,
        on_absent_message=(
            'missing version in components config, this will result '
            'in the greatest available release version being used'
        ),
    )
    if version == 'greatest':
        # version = None will be treated from subsequent
        # function "cnudie.retrieve.greatest_component_versions" like greatest
        version = None

    version_filter = deserialise_config_property(
        config=component_config,
        property_key='version_filter',
        absent_ok=True,
        on_absent_message=(
            'missing version filter in components config, this will result '
            'in the default version filter of the delivery service being used'
        ),
    )

    max_versions_limit = deserialise_config_property(
        config=component_config,
        property_key='max_versions_limit',
        default_value=1,
    )

    ocm_repo_raw = deserialise_config_property(
        config=component_config,
        property_key='ocm_repo',
        absent_ok=True,
        on_absent_message=(
            'missing ocm repo in components config, this will result '
            'in the ocm repo lookup of the delivery service being used'
        ),
    )
    if ocm_repo_raw:
        ocm_repo = ocm.OciOcmRepository(
            baseUrl=ocm_repo_raw,
        )
    else:
        ocm_repo = None

    return Component(
        component_name=component_name,
        version=version,
        version_filter=version_filter,
        max_versions_limit=max_versions_limit,
        ocm_repo=ocm_repo,
    )


def deserialise_artefact_enumerator_config(
    spec_config: dict,
) -> ArtefactEnumeratorConfig | None:
    default_config = spec_config.get('defaults', dict())
    artefact_enumerator_config = spec_config.get('artefactEnumerator')

    if not artefact_enumerator_config:
        return None

    delivery_service_url = deserialise_config_property(
        config=artefact_enumerator_config,
        property_key='delivery_service_url',
        default_config=default_config,
    )

    compliance_snapshot_grace_period = deserialise_config_property(
        config=artefact_enumerator_config,
        property_key='compliance_snapshot_grace_period',
        default_value=60 * 60 * 24, # 24h
    )

    artefact_types = tuple(deserialise_config_property(
        config=artefact_enumerator_config,
        property_key='artefact_types',
        default_config=default_config,
        default_value=(
            ocm.ArtefactType.OCI_IMAGE,
            'application/tar+vm-image-rootfs',
        ),
    ))

    matching_configs_raw = deserialise_config_property(
        config=artefact_enumerator_config,
        property_key='matching_configs',
        default_config=default_config,
        default_value=[],
    )
    matching_configs = config_filter.matching_configs_from_dicts(
        dicts=matching_configs_raw,
    )
    node_filter = config_filter.filter_for_matching_configs(
        configs=matching_configs,
    )

    components_raw = deserialise_config_property(
        config=artefact_enumerator_config,
        property_key='components',
        default_value=[],
    )
    components = tuple(
        deserialise_component_config(component_config=component_raw)
        for component_raw in components_raw
    )

    sprints_relative_time_range = deserialise_config_property(
        config=artefact_enumerator_config,
        property_key='sprints_relative_time_range',
        default_value=None,
        absent_ok=True,
        on_absent_message='no time range for sprints specified, all sprints will be considered',
    )
    if sprints_relative_time_range:
        today = datetime.date.today()
        days_from = sprints_relative_time_range.get('days_from')
        days_to = sprints_relative_time_range.get('days_to')
        sprints_time_range = TimeRange(
            start_date=today + datetime.timedelta(days=days_from),
            end_date=today + datetime.timedelta(days=days_to),
        )
    else:
        sprints_time_range = None

    return ArtefactEnumeratorConfig(
        delivery_service_url=delivery_service_url,
        compliance_snapshot_grace_period=compliance_snapshot_grace_period,
        artefact_types=artefact_types,
        node_filter=node_filter,
        components=components,
        sprints_time_range=sprints_time_range,
    )


def deserialise_clamav_config(
    spec_config: dict,
) -> ClamAVConfig:
    default_config = spec_config.get('defaults', dict())
    clamav_config = spec_config.get('clamav')

    if not clamav_config:
        return

    delivery_service_url = deserialise_config_property(
        config=clamav_config,
        property_key='delivery_service_url',
        default_config=default_config,
    )

    lookup_new_backlog_item_interval = deserialise_config_property(
        config=clamav_config,
        property_key='lookup_new_backlog_item_interval',
        default_config=default_config,
        default_value=60,
    )

    rescan_interval = deserialise_config_property(
        config=clamav_config,
        property_key='rescan_interval',
        default_value=86400, # daily
    )

    aws_cfg_name = deserialise_config_property(
        config=clamav_config,
        property_key='aws_cfg_name',
        absent_ok=True,
        on_absent_message='artefacts of access type s3 will not be scanned'
    )

    artefact_types = tuple(deserialise_config_property(
        config=clamav_config,
        property_key='artefact_types',
        default_config=default_config,
        default_value=(
            ocm.ArtefactType.OCI_IMAGE,
            'application/tar+vm-image-rootfs',
        ),
    ))

    return ClamAVConfig(
        delivery_service_url=delivery_service_url,
        lookup_new_backlog_item_interval=lookup_new_backlog_item_interval,
        rescan_interval=rescan_interval,
        aws_cfg_name=aws_cfg_name,
        artefact_types=artefact_types,
    )


def deserialise_bdba_config(
    spec_config: dict,
) -> BDBAConfig:
    default_config = spec_config.get('defaults', dict())
    bdba_config = spec_config.get('bdba')

    if not bdba_config:
        return

    delivery_service_url = deserialise_config_property(
        config=bdba_config,
        property_key='delivery_service_url',
        default_config=default_config,
    )

    rescan_interval = deserialise_config_property(
        config=bdba_config,
        property_key='rescan_interval',
    )

    lookup_new_backlog_item_interval = deserialise_config_property(
        config=bdba_config,
        property_key='lookup_new_backlog_item_interval',
        default_config=default_config,
        default_value=60,
    )

    cfg_name = deserialise_config_property(
        config=bdba_config,
        property_key='cfg_name',
    )

    group_id = deserialise_config_property(
        config=bdba_config,
        property_key='group_id',
    )

    reference_group_ids = tuple(deserialise_config_property(
        config=bdba_config,
        property_key='referenceGroupIds',
        default_value=[],
    ))

    cvss_version_raw = deserialise_config_property(
        config=bdba_config,
        property_key='cvss_version',
        default_value='CVSSv3',
    )
    cvss_version = bdba.model.CVSSVersion(cvss_version_raw)

    aws_cfg_set_name = deserialise_config_property(
        config=bdba_config,
        property_key='aws_cfg_set_name',
        absent_ok=True,
    )

    processing_mode_raw = deserialise_config_property(
        config=bdba_config,
        property_key='processing_mode',
        default_value=bdba.model.ProcessingMode.RESCAN.value,
    )
    processing_mode = bdba.model.ProcessingMode(processing_mode_raw)

    artefact_types = tuple(deserialise_config_property(
        config=bdba_config,
        property_key='artefact_types',
        default_config=default_config,
        default_value=(
            ocm.ArtefactType.OCI_IMAGE,
            'application/tar+vm-image-rootfs',
        ),
    ))

    matching_configs_raw = deserialise_config_property(
        config=bdba_config,
        property_key='matching_configs',
        default_config=default_config,
        default_value=[],
    )
    matching_configs = config_filter.matching_configs_from_dicts(
        dicts=matching_configs_raw,
    )
    node_filter = config_filter.filter_for_matching_configs(
        configs=matching_configs,
    )

    cve_rescoring_ruleset = deserialise_config_property(
        config=bdba_config,
        property_key='rescoring',
        default_config=default_config,
        absent_ok=True,
    )

    if cve_rescoring_ruleset:
        # only one ruleset for now, will be updated with cm06-related "typed" rulesets
        rescoring_rule_set_raw = cve_rescoring_ruleset['rescoringRuleSets'][0]

        cve_rescoring_ruleset = dacite.from_dict(
            data_class=rescore.model.CveRescoringRuleSet,
            data=dict(
                **rescoring_rule_set_raw,
                rules=list(
                    rescore.model.rescoring_rules_from_dicts(rescoring_rule_set_raw['rule_set'])
                ),
            ),
        )

    if cve_rescoring_ruleset:
        auto_assess_max_severity_raw = deserialise_config_property(
            config=bdba_config,
            property_key='auto_assess_max_severity',
        )
        auto_assess_max_severity = dso.cvss.CVESeverity[auto_assess_max_severity_raw]
    else:
        logger.info('no cve rescoring rules specified, rescoring will not be available')
        auto_assess_max_severity = None

    prohibited_licenses = deserialise_config_property(
        config=bdba_config,
        property_key='prohibited_licenses',
        default_config=default_config,
        default_value=[],
    )
    license_cfg = image_scan.LicenseCfg(prohibited_licenses=prohibited_licenses)

    delete_inactive_products_after_seconds = deserialise_config_property(
        config=bdba_config,
        property_key='delete_inactive_products_after_seconds',
        default_value=None,
        absent_ok=True,
        on_absent_message='inactive bdba products will not be deleted',
    )

    blacklist_finding_types = deserialise_config_property(
        config=bdba_config,
        property_key='blacklist_finding_types',
        default_value=[],
    )

    if isinstance(blacklist_finding_types, str):
        blacklist_finding_types = [blacklist_finding_types]

    blacklist_finding_types = set(blacklist_finding_types)

    if dso.model.Datatype.VULNERABILITY in blacklist_finding_types:
        # BDBA only supports rescorings (i.e. triages) for vulnerabilites, hence we do not have to
        # store them if vulnerabilities are blacklisted anyways
        blacklist_finding_types.add(dso.model.Datatype.RESCORING)

    return BDBAConfig(
        delivery_service_url=delivery_service_url,
        rescan_interval=rescan_interval,
        lookup_new_backlog_item_interval=lookup_new_backlog_item_interval,
        cfg_name=cfg_name,
        group_id=group_id,
        reference_group_ids=reference_group_ids,
        cvss_version=cvss_version,
        aws_cfg_set_name=aws_cfg_set_name,
        processing_mode=processing_mode,
        artefact_types=artefact_types,
        node_filter=node_filter,
        cve_rescoring_ruleset=cve_rescoring_ruleset,
        auto_assess_max_severity=auto_assess_max_severity,
        license_cfg=license_cfg,
        delete_inactive_products_after_seconds=delete_inactive_products_after_seconds,
        blacklist_finding_types=blacklist_finding_types,
    )


def deserialise_finding_type_issue_replication_cfg(
    finding_type_issue_replication_cfg: dict,
) -> FindingTypeIssueReplicationCfgBase | VulnerabilityIssueReplicationCfg:
    finding_type = deserialise_config_property(
        config=finding_type_issue_replication_cfg,
        property_key='finding_type',
    )

    enable_issue_assignees = deserialise_config_property(
        config=finding_type_issue_replication_cfg,
        property_key='enable_issue_assignees',
        default_value=False,
    )

    enable_issue_per_finding = deserialise_config_property(
        config=finding_type_issue_replication_cfg,
        property_key='enable_issue_per_finding',
        default_value=False,
    )

    match finding_type:
        case dso.model.Datatype.LICENSE, dso.model.Datatype.DIKI_FINDING:
            return FindingTypeIssueReplicationCfgBase(
                finding_type=finding_type,
                enable_issue_assignees=enable_issue_assignees,
                enable_issue_per_finding=enable_issue_per_finding,
            )
        case dso.model.Datatype.VULNERABILITY:
            cve_threshold = deserialise_config_property(
                config=finding_type_issue_replication_cfg,
                property_key='cve_threshold',
            )

            return VulnerabilityIssueReplicationCfg(
                finding_type=finding_type,
                enable_issue_assignees=enable_issue_assignees,
                enable_issue_per_finding=enable_issue_per_finding,
                cve_threshold=cve_threshold,
            )
        case _:
            return FindingTypeIssueReplicationCfgBase(
                finding_type=finding_type,
                enable_issue_assignees=enable_issue_assignees,
                enable_issue_per_finding=enable_issue_per_finding,
            )


def deserialise_milestone_cfg(
    milestone_cfg_raw: dict | None,
) -> gcmi.MilestoneConfiguration:
    if not milestone_cfg_raw:
        return gcmi.MilestoneConfiguration()

    milestone_title_cfg = milestone_cfg_raw.get('title')
    milestone_due_date_cfg = milestone_cfg_raw.get('due_date')

    if milestone_title_cfg:
        title_prefix = milestone_title_cfg.get('prefix')
        title_suffix = milestone_title_cfg.get('suffix')
        title_sprint_cfg = milestone_title_cfg.get('sprint')
    else:
        title_prefix = gcmi.MilestoneConfiguration.title_prefix
        title_suffix = gcmi.MilestoneConfiguration.title_suffix
        title_sprint_cfg = None

    if title_sprint_cfg:
        sprint_value_type = title_sprint_cfg.get('value_type')

        if sprint_value_type == 'name':
            title_callback = lambda sprint: sprint.name

        elif sprint_value_type == 'date':
            name = title_sprint_cfg.get('date_name', 'end_date')
            str_format = title_sprint_cfg.get('date_string_format', '%Y-%m-%d')

            title_callback = lambda sprint: sprint.find_sprint_date(name).value.strftime(str_format)

        else:
            raise ValueError(f'invalid milestone sprint value type {sprint_value_type}')

    else:
        title_callback = gcmi.MilestoneConfiguration.title_callback

    if milestone_due_date_cfg:
        name = milestone_due_date_cfg.get('date_name')
        due_date_callback = lambda sprint: sprint.find_sprint_date(name).value
    else:
        due_date_callback = gcmi.MilestoneConfiguration.due_date_callback

    return gcmi.MilestoneConfiguration(
        title_callback=title_callback,
        title_prefix=title_prefix,
        title_suffix=title_suffix,
        due_date_callback=due_date_callback,
    )


def deserialise_issue_replicator_config(
    spec_config: dict,
) -> IssueReplicatorConfig:
    default_config = spec_config.get('defaults', dict())
    issue_replicator_config = spec_config.get('issueReplicator')

    if not issue_replicator_config:
        return

    delivery_service_url = deserialise_config_property(
        config=issue_replicator_config,
        property_key='delivery_service_url',
        default_config=default_config,
    )
    delivery_dashboard_url = deserialise_config_property(
        config=issue_replicator_config,
        property_key='delivery_dashboard_url',
        default_config=default_config,
        absent_ok=True,
    )

    replication_interval = deserialise_config_property(
        config=issue_replicator_config,
        property_key='replication_interval',
    )

    lookup_new_backlog_item_interval = deserialise_config_property(
        config=issue_replicator_config,
        property_key='lookup_new_backlog_item_interval',
        default_config=default_config,
        default_value=60,
    )

    prohibited_licenses = deserialise_config_property(
        config=issue_replicator_config,
        property_key='prohibited_licenses',
        default_config=default_config,
        default_value=[],
    )
    license_cfg = image_scan.LicenseCfg(prohibited_licenses=prohibited_licenses)

    max_processing_days_raw = deserialise_config_property(
        config=issue_replicator_config,
        property_key='max_processing_days',
        default_value={},
    )
    max_processing_days = dacite.from_dict(
        data_class=github.compliance.model.MaxProcessingTimesDays,
        data=max_processing_days_raw,
    )

    github_issues_target_repository_url = deserialise_config_property(
        config=issue_replicator_config,
        property_key='github_issues_target_repository_url',
    )
    github_api_lookup = lookups.github_api_lookup(
        cfg_factory=ctx_util.cfg_factory(),
    )
    github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)
    try:
        github_issues_repository = github_repo_lookup(github_issues_target_repository_url)
    except Exception as e:
        # repo is only required for issue replicator -> ignore error here to allow other services
        # to run (issue replicator will fail soon enough)
        logger.warning(
            'failed to access GitHub issue repository (note: this error can be safely ignored by '
            f'all extensions except the issue replicator); {e}'
        )
        github_issues_repository = None

    github_issue_templates = deserialise_config_property(
        config=issue_replicator_config,
        property_key='github_issue_templates',
    )
    github_issue_template_cfgs = tuple(
        dacite.from_dict(
            data_class=image_scan.GithubIssueTemplateCfg,
            data=ghit,
        ) for ghit in github_issue_templates
    )

    github_issue_labels_to_preserve = set(deserialise_config_property(
        config=issue_replicator_config,
        property_key='github_issue_labels_to_preserve',
        default_value=set(),
    ))

    number_included_closed_issues = deserialise_config_property(
        config=issue_replicator_config,
        property_key='number_included_closed_issues',
        default_value=0,
    )

    artefact_types = tuple(deserialise_config_property(
        config=issue_replicator_config,
        property_key='artefact_types',
        default_config=default_config,
        default_value=(
            ocm.ArtefactType.OCI_IMAGE,
            'application/tar+vm-image-rootfs',
        ),
    ))

    matching_configs_raw = deserialise_config_property(
        config=issue_replicator_config,
        property_key='matching_configs',
        default_config=default_config,
        default_value=[],
    )
    matching_configs = config_filter.matching_configs_from_dicts(
        dicts=matching_configs_raw,
    )
    node_filter = config_filter.filter_for_matching_configs(
        configs=matching_configs,
    )

    cve_rescoring_rules_raw = deserialise_config_property(
        config=issue_replicator_config,
        property_key='cve_rescoring_rules',
        default_config=default_config,
        default_value=[],
    )
    cve_rescoring_rules = tuple(rescore.model.rescoring_rules_from_dicts(cve_rescoring_rules_raw))

    finding_type_issue_replication_cfgs_raw = deserialise_config_property(
        config=issue_replicator_config,
        property_key='finding_type_issue_replication_configs',
        default_config=default_config,
        default_value=[],
    )

    finding_type_issue_replication_cfgs = tuple(
        deserialise_finding_type_issue_replication_cfg(
            finding_type_issue_replication_cfg=finding_type_issue_replication_cfg_raw,
        )
        for finding_type_issue_replication_cfg_raw in finding_type_issue_replication_cfgs_raw
    )

    milestone_cfg_raw = deserialise_config_property(
        config=issue_replicator_config,
        property_key='milestones',
        absent_ok=True,
    )

    milestone_cfg = deserialise_milestone_cfg(
        milestone_cfg_raw=milestone_cfg_raw,
    )

    return IssueReplicatorConfig(
        delivery_service_url=delivery_service_url,
        delivery_dashboard_url=delivery_dashboard_url,
        replication_interval=replication_interval,
        lookup_new_backlog_item_interval=lookup_new_backlog_item_interval,
        license_cfg=license_cfg,
        max_processing_days=max_processing_days,
        github_api_lookup=github_api_lookup,
        github_issues_repository=github_issues_repository,
        github_issue_template_cfgs=github_issue_template_cfgs,
        github_issue_labels_to_preserve=github_issue_labels_to_preserve,
        number_included_closed_issues=number_included_closed_issues,
        artefact_types=artefact_types,
        node_filter=node_filter,
        cve_rescoring_rules=cve_rescoring_rules,
        finding_type_issue_replication_cfgs=finding_type_issue_replication_cfgs,
        milestone_cfg=milestone_cfg,
    )


def deserialise_scan_configuration(
    spec_config: dict,
    included_services: tuple[Services],
) -> ScanConfiguration:
    if Services.ARTEFACT_ENUMERATOR in included_services:
        artefact_enumerator_config = deserialise_artefact_enumerator_config(
            spec_config=spec_config,
        )
    else:
        artefact_enumerator_config = None

    if Services.BDBA in included_services:
        bdba_config = deserialise_bdba_config(
            spec_config=spec_config,
        )
    else:
        bdba_config = None

    if Services.ISSUE_REPLICATOR in included_services:
        issue_replicator_config = deserialise_issue_replicator_config(
            spec_config=spec_config,
        )
    else:
        issue_replicator_config = None

    if Services.CLAMAV in included_services:
        clamav_config = deserialise_clamav_config(
            spec_config=spec_config,
        )
    else:
        clamav_config = None

    return ScanConfiguration(
        artefact_enumerator_config=artefact_enumerator_config,
        bdba_config=bdba_config,
        issue_replicator_config=issue_replicator_config,
        clamav_config=clamav_config,
    )


def deserialise_config_property(
    config: dict,
    property_key: str,
    default_config: dict=dict(),
    default_property_key: str=None,
    default_value=None,
    absent_ok: bool=False,
    on_absent_message: str=None,
):
    if not default_property_key:
        default_property_key = property_key

    # explicitly check for "None" in case of consciously set empty list/object/etc.
    property = (
        prop
        if (prop := config.get(property_key)) is not None
        else (
            default_prop
            if (default_prop := default_config.get(default_property_key)) is not None
            else default_value
        )
    )

    if property is None:
        if absent_ok:
            logger.info(
                on_absent_message or
                f'no "{property_key}" in config specified and no default is set,' +
                'the corresponding feature may not be available'
            )
        else:
            raise ValueError(on_absent_message or f'missing "{property_key}" in config')

    return property
