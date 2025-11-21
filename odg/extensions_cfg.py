import collections.abc
import dataclasses
import enum
import logging
import re
import typing

import cachetools
import dacite
import github3.repos
import yaml

import github.compliance.milestone as gcmi
import ocm

import crypto_extension.config
import lookups
import odg.model
import odg.shared_cfg
import responsibles_extension.filters as ref
import responsibles_extension.strategies as res


logger = logging.getLogger(__name__)


class Services(enum.StrEnum):
    ACCESS_MANAGER = 'accessManager'
    ARTEFACT_ENUMERATOR = 'artefactEnumerator'
    BACKLOG_CONTROLLER = 'backlogController'
    BLACKDUCK = 'blackduck'
    BDBA = 'bdba'
    CACHE_MANAGER = 'cacheManager'
    CLAMAV = 'clamav'
    CRYPTO = 'crypto'
    DELIVERY_DB_BACKUP = 'deliveryDbBackup'
    GHAS = 'ghas'
    ISSUE_REPLICATOR = 'issueReplicator'
    OSID = 'osid'
    RESPONSIBLES = 'responsibles'
    SAST = 'sast'
    ODG_OPERATOR = 'odg-operator'


class VersionAliases(enum.StrEnum):
    GREATEST = 'greatest'


class WarningVerbosities(enum.StrEnum):
    FAIL = 'fail'
    IGNORE = 'ignore'
    WARNING = 'warning'


@dataclasses.dataclass(kw_only=True)
class ExtensionCfgMixins:
    enabled: bool = True
    service: Services


@dataclasses.dataclass
class BacklogItemMixins(ExtensionCfgMixins):
    '''
    Defines properties and functions which are shared among those extensions which determine their
    workload using the BacklogItem custom resource.
    '''
    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
    ) -> bool:
        raise NotImplementedError('function must be implemented by derived classes')


@dataclasses.dataclass
class Component:
    component_name: str
    version: str | None
    ocm_repo_url: str | None
    max_versions_limit: int = 1

    def __post_init__(self):
        # "version=None" will be treated from subsequent functions like "greatest"
        if self.version == VersionAliases.GREATEST:
            self.version = None

    @property
    def ocm_repo(self) -> ocm.OciOcmRepository | None:
        if not self.ocm_repo_url:
            return None

        return ocm.OciOcmRepository(
            baseUrl=self.ocm_repo_url,
        )


@dataclasses.dataclass(kw_only=True)
class AccessManagerConfig(ExtensionCfgMixins):
    service: Services = Services.ACCESS_MANAGER
    schedule: str = '*/10 * * * *' # every 10 minutes
    successful_jobs_history_limit: int = 1
    failed_jobs_history_limit: int = 1


@dataclasses.dataclass(kw_only=True)
class ArtefactEnumeratorConfig(ExtensionCfgMixins):
    '''
    :param str delivery_service_url
    :param list[Component] components:
        Components which are classified as "active" and for which compliance snapshots are created.
    :param int compliance_snapshot_grace_period:
        Time after which inactive compliance snapshots are deleted from the delivery-db. During this
        period, the inactive snapshots are used to possibly close outdated GitHub issues (i.e. the
        ones which have a due date which is by now out-of-scope of the configured time range).
    :param str schedule
    :param int successful_jobs_history_limit
    :param int failed_jobs_history_limit
    '''
    service: Services = Services.ARTEFACT_ENUMERATOR
    delivery_service_url: str
    components: list[Component]
    compliance_snapshot_grace_period: int = 60 * 60 * 24 # 24h
    schedule: str = '*/5 * * * *' # every 5 minutes
    successful_jobs_history_limit: int = 1
    failed_jobs_history_limit: int = 1


@dataclasses.dataclass(kw_only=True)
class BacklogControllerConfig(ExtensionCfgMixins):
    '''
    :param int max_replicas:
        Maximum number of replicas per extension to which the backlog controller will scale. Note,
        that the maximum number for the issue replicator is always 1 to ensure consistent GitHub
        tracking issues.
    :param int backlog_items_per_replica
        Used to calculate the desired number of replicas.
    :param int remove_claim_after_minutes
        To prevent backlog items from not being processed in an error case because they are claimed
        infinetly by a single pod, the backlog controller will remove the claim again after this
        period.
    '''
    service: Services = Services.BACKLOG_CONTROLLER
    max_replicas: int = 5
    backlog_items_per_replica: int = 3
    remove_claim_after_minutes: int = 30


@dataclasses.dataclass
class Mapping:
    prefix: str


@dataclasses.dataclass
class BDBAMapping(Mapping):
    '''
    :param int group_id:
        BDBA group id to use for scanning.
    :param str aws_secret_name
        Name of the AWS secret element to use to retrieve artefacts from S3.
    :param ProcessingMode processing_mode:
        Defines the scanning behaviour in case there is already an existing scan.
    '''
    group_id: int
    aws_secret_name: str | None
    processing_mode: str = 'rescan'


@dataclasses.dataclass(kw_only=True)
class BDBAConfig(BacklogItemMixins):
    '''
    :param str delivery_service_url
    :param list[BDBAMapping] mappings
    :param int interval:
        Time after which an artefact must be re-scanned at latest.
    :param WarningVerbosities on_unsupported
        Defines the handling if a backlog item should be processed which contains unsupported
        properties, e.g. an unsupported access type.
    '''
    service: Services = Services.BDBA
    delivery_service_url: str
    mappings: list[BDBAMapping]
    interval: int = 60 * 60 * 24 # 24h
    on_unsupported: WarningVerbosities = WarningVerbosities.WARNING

    def mapping(self, name: str, /) -> BDBAMapping:
        for mapping in self.mappings:
            if name.startswith(mapping.prefix):
                return mapping

        raise ValueError(f'No matching mapping entry found for {name=}')

    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            odg.model.ArtefactKind.RESOURCE,
        )
        supported_access_types = (
            ocm.AccessType.OCI_REGISTRY,
            ocm.AccessType.LOCAL_BLOB,
            ocm.AccessType.S3,
        )

        is_supported = True

        if artefact_kind and artefact_kind not in supported_artefact_kinds:
            is_supported = False
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{artefact_kind=} is not supported for BDBA scans, {supported_artefact_kinds=}'
                )

        if access_type and access_type not in supported_access_types:
            is_supported = False
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{access_type=} is not supported for BDBA scans, {supported_access_types=}'
                )

        return is_supported


@dataclasses.dataclass
class BlackDuckLabelRuleSelector:
    host: str | None = None
    policy_violation_id: str | None = None
    license_name: str | None = None

    def matches(
        self,
        host: str,
        policy_violation_id: str,
        license_name: str,
    ) -> bool:
        if self.host is not None:
            if not re.fullmatch(self.host, host, re.IGNORECASE):
                return False

        if self.policy_violation_id is not None:
            if policy_violation_id is None or not re.fullmatch(
                self.policy_violation_id,
                policy_violation_id,
                re.IGNORECASE,
            ):
                return False

        if self.license_name is not None:
            if not re.fullmatch(self.license_name, license_name, re.IGNORECASE):
                return False

        return True


@dataclasses.dataclass
class BlackDuckLabelRule:
    name: str
    selector: BlackDuckLabelRuleSelector


@dataclasses.dataclass
class BlackDuckTarget:
    group_id: str
    host: str


@dataclasses.dataclass
class BlackDuckExtensionMapping(Mapping):
    targets: list[BlackDuckTarget]
    group_id_bdba: int
    aws_secret_name: str | None
    processing_mode: str = 'rescan'


@dataclasses.dataclass(kw_only=True)
class BlackDuckConfig(BacklogItemMixins):
    service: Services = Services.BLACKDUCK
    delivery_service_url: str
    mappings: list[BlackDuckExtensionMapping]
    label_rules: list[BlackDuckLabelRule]
    interval: int = 60 * 60 * 24 # 24h
    on_unsupported: WarningVerbosities = WarningVerbosities.WARNING

    def mapping(self, name: str, /) -> BlackDuckExtensionMapping:
        for mapping in self.mappings:
            if name.startswith(mapping.prefix):
                return mapping

        raise ValueError(f'No matching mapping entry found for {name=}')

    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            odg.model.ArtefactKind.RESOURCE,
        )
        supported_access_types = (
            ocm.AccessType.OCI_REGISTRY,
            ocm.AccessType.LOCAL_BLOB,
            ocm.AccessType.S3,
        )

        is_supported = True

        if artefact_kind and artefact_kind not in supported_artefact_kinds:
            is_supported = False
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{artefact_kind=} is not supported for BD scans, {supported_artefact_kinds=}'
                )

        if access_type and access_type not in supported_access_types:
            is_supported = False
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{access_type=} is not supported for BD scans, {supported_access_types=}'
                )

        return is_supported


@dataclasses.dataclass(frozen=True)
class CachePruningWeights:
    '''
    The individual weights determine how much the respective values are being considered when
    determining those cache entries which should be deleted next (in case the max cache size is
    reached). The greater the weight, the less likely an entry will be considered for deletion.
    Negative values may be also used to express a property which determines that an entry should
    be deleted. 0 means the property does not affect the priority for the next deletion.
    '''
    creation_date_weight: float = 0
    last_update_weight: float = 0
    delete_after_weight: float = 0
    keep_until_weight: float = 0
    last_read_weight: float = 0
    read_count_weight: float = 0
    revision_weight: float = 0
    costs_weight: float = 0
    size_weight: float = 0

    @staticmethod
    def default() -> typing.Self:
        return CachePruningWeights(
            creation_date_weight=0,
            last_update_weight=0,
            delete_after_weight=-1.5, # deletion (i.e. stale) flag -> delete
            keep_until_weight=-1, # keep until has passed -> delete
            last_read_weight=-1, # long time no read -> delete
            read_count_weight=10, # has many reads -> rather not delete
            revision_weight=0,
            costs_weight=10, # is expensive to re-calculate -> rather not delete
            size_weight=0,
        )


class FunctionNames(enum.StrEnum):
    COMPLIANCE_SUMMARY = 'compliance-summary'
    COMPONENT_VERSIONS = 'component-versions'


@dataclasses.dataclass
class PrefillFunctionCaches:
    components: list[Component] = dataclasses.field(default_factory=list)
    functions: list[FunctionNames] = dataclasses.field(default_factory=lambda: [f for f in FunctionNames]) # noqa: E501


@dataclasses.dataclass(kw_only=True)
class CacheManagerConfig(ExtensionCfgMixins):
    '''
    :param int max_cache_size_bytes
    :param int min_pruning_bytes:
        If `max_cache_size_bytes` is reached, existing cache entries will be removed according to
        the `cache_pruning_weights` until `min_pruning_bytes` is available again.
    :param CachePruningWeights cache_pruning_weights
    :param PrefillFunctionCaches prefill_function_caches:
        Configures components for which to pre-calculate and cache the desired functions. If no
        specific functions are set, all available functions will be considered.
    :param str schedule
    :param int successful_jobs_history_limit
    :param int failed_jobs_history_limit
    '''
    service: Services = Services.CACHE_MANAGER
    max_cache_size_bytes: int = 1000000000 # 1Gb
    min_pruning_bytes: int = 100000000 # 100Mb
    cache_pruning_weights: CachePruningWeights = dataclasses.field(default_factory=CachePruningWeights.default) # noqa: E501
    prefill_function_caches: PrefillFunctionCaches = dataclasses.field(default_factory=PrefillFunctionCaches) # noqa: E501
    schedule: str = '*/10 * * * *' # every 10 minutes
    successful_jobs_history_limit: int = 1
    failed_jobs_history_limit: int = 1


@dataclasses.dataclass
class ClamAVMapping(Mapping):
    '''
    :param str aws_secret_name
        Name of the AWS secret element to use to retrieve artefacts from S3.
    '''
    aws_secret_name: str | None


@dataclasses.dataclass(kw_only=True)
class ClamAVConfig(BacklogItemMixins):
    '''
    :param str delivery_service_url
    :param list[ClamAVMapping] mappings
    :param int interval:
        Time after which an artefact must be re-scanned at latest.
    :param WarningVerbosities on_unsupported
        Defines the handling if a backlog item should be processed which contains unsupported
        properties, e.g. an unsupported access type.
    '''
    service: Services = Services.CLAMAV
    delivery_service_url: str
    mappings: list[ClamAVMapping]
    interval: int = 60 * 60 * 24 # 24h
    on_unsupported: WarningVerbosities = WarningVerbosities.WARNING

    def mapping(self, name: str, /) -> ClamAVMapping:
        for mapping in self.mappings:
            if name.startswith(mapping.prefix):
                return mapping

        raise ValueError(f'No matching mapping entry found for {name=}')

    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
        artefact_type: str | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            odg.model.ArtefactKind.RESOURCE,
        )
        supported_access_types = (
            ocm.AccessType.OCI_REGISTRY,
            ocm.AccessType.LOCAL_BLOB,
            ocm.AccessType.S3,
        )
        supported_artefact_types_by_access_type = {
            ocm.AccessType.S3: ('application/tar', 'application/x-tar'),
        }

        is_supported = True

        if artefact_kind and artefact_kind not in supported_artefact_kinds:
            is_supported = False
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{artefact_kind=} is not supported for ClamAV scans, '
                    f'{supported_artefact_kinds=}'
                )

        if access_type and access_type not in supported_access_types:
            is_supported = False
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{access_type=} is not supported for ClamAV scans, {supported_access_types=}'
                )

        if (
            artefact_type
            and access_type
            and (artefact_types := supported_artefact_types_by_access_type.get(access_type))
        ):
            if not any(
                artefact_type.startswith(supported_artefact_type)
                for supported_artefact_type in artefact_types
            ):
                is_supported = False
                if self.on_unsupported is WarningVerbosities.WARNING:
                    logger.warning(
                        f'{artefact_type=} is not supported for ClamAV scans with {access_type=}, '
                        f'{supported_artefact_types_by_access_type=}'
                    )

        return is_supported


@dataclasses.dataclass
class StandardRef:
    '''
    :param str name:
        The name of the standard used to regulate cryptographic usage within software.
    :param str version:
        The version of the standard used to regulate cryptographic usage within software.
    :param SharedCfgReference ref:
        Reference to a configuration file (YAML) which contains a property `standards` that lists
        known regulatory cryptographic standards, which is used to find the standard described by
        `name` and `version`.
    '''
    name: str
    version: str
    ref: (
        odg.shared_cfg.SharedCfgGitHubReference
        | odg.shared_cfg.SharedCfgLocalReference
        | odg.shared_cfg.SharedCfgOCMReference
    )

    def retrieve_standard(
        self,
        shared_cfg_lookup: collections.abc.Callable[[odg.shared_cfg.SharedCfgReference], dict],
    ) -> crypto_extension.config.Standard:
        crypto_cfg_raw = shared_cfg_lookup(self.ref)

        standards_raw = crypto_cfg_raw.get('standards', [])
        for standard_raw in standards_raw:
            if (
                standard_raw['name'] == self.name
                and standard_raw['version'] == self.version
            ):
                return dacite.from_dict(
                    data_class=crypto_extension.config.Standard,
                    data=standard_raw,
                    config=dacite.Config(
                        cast=[enum.Enum],
                    ),
                )

        raise ValueError(f'could not retrieve crypto standard for {self}')


@dataclasses.dataclass
class LibrariesRef:
    '''
    :param SharedCfgReference ref:
        Reference to a configuration file (YAML) which contains a property `libraries` that lists
        known cryptographic libraries by their name.
    '''
    ref: (
        odg.shared_cfg.SharedCfgGitHubReference
        | odg.shared_cfg.SharedCfgLocalReference
        | odg.shared_cfg.SharedCfgOCMReference
    )


@dataclasses.dataclass
class CryptoMapping(Mapping):
    '''
    :param list[StandardRef | Standard] standards:
        References to or inline defined standards the discovered cryptographic assets should be
        validated against.
    :param list[LibrariesRef | str] libraries:
        References to configurations containing a list of cryptographic libraries or inline defined
        known cryptographic libraries which should be used to filter the detected libraries for
        cryptographic ones.
    :param list[CryptoAssetTypes] included_asset_types:
        The asset types which should be extracted from the CBOM. If `None` (!= empty list), all
        available asset types will be reported.
    :param str aws_secret_name:
        Name of the AWS secret element to use to retrieve artefacts from S3.
    '''
    standards: list[StandardRef | crypto_extension.config.Standard]
    libraries: list[LibrariesRef | str]
    included_asset_types: list[odg.model.CryptoAssetTypes] | None
    aws_secret_name: str | None

    def __post_init__(self):
        shared_cfg_lookup = odg.shared_cfg.shared_cfg_lookup()

        self.standards = [
            standard.retrieve_standard(shared_cfg_lookup)
            if isinstance(standard, StandardRef)
            else standard
            for standard in self.standards
        ]

        libraries = []
        for library in self.libraries:
            if isinstance(library, str):
                libraries.append(library)
                continue

            libraries.extend(shared_cfg_lookup(library.ref).get('libraries', []))
        self.libraries = libraries


@dataclasses.dataclass(kw_only=True)
class CryptoConfig(BacklogItemMixins):
    '''
    :param str delivery_service_url
    :param list[CryptoMapping] mappings
    :param int interval:
        Time after which an artefact must be re-scanned at latest.
    :param WarningVerbosities on_unsupported:
        Defines the handling if a backlog item should be processed which contains unsupported
        properties, e.g. an unsupported access type.
    '''
    service: Services = Services.CRYPTO
    delivery_service_url: str
    mappings: list[CryptoMapping]
    interval: int = 60 * 60 * 24 # 24h
    on_unsupported: WarningVerbosities = WarningVerbosities.WARNING

    def mapping(self, name: str, /) -> CryptoMapping:
        for mapping in self.mappings:
            if name.startswith(mapping.prefix):
                return mapping

        raise ValueError(f'No matching mapping entry found for {name=}')

    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
        artefact_type: str | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            odg.model.ArtefactKind.RESOURCE,
        )
        supported_access_types = (
            ocm.AccessType.OCI_REGISTRY,
            ocm.AccessType.LOCAL_BLOB,
            ocm.AccessType.S3,
        )
        supported_artefact_types_by_access_type = {
            ocm.AccessType.OCI_REGISTRY: ('ociImage','ociArtifact'),
            ocm.AccessType.S3: ('application/tar', 'application/x-tar'),
        }

        is_supported = True

        if artefact_kind and artefact_kind not in supported_artefact_kinds:
            is_supported = False
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{artefact_kind=} is not supported for crypto scans, '
                    f'{supported_artefact_kinds=}'
                )

        if access_type and access_type not in supported_access_types:
            is_supported = False
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{access_type=} is not supported for crypto scans, {supported_access_types=}'
                )

        if (
            artefact_type
            and access_type
            and (artefact_types := supported_artefact_types_by_access_type.get(access_type))
        ):
            if not any(
                artefact_type.startswith(supported_artefact_type)
                for supported_artefact_type in artefact_types
            ):
                is_supported = False
                if self.on_unsupported is WarningVerbosities.WARNING:
                    logger.warning(
                        f'{artefact_type=} is not supported for crypto scans with {access_type=}, '
                        f'{supported_artefact_types_by_access_type=}'
                    )

        return is_supported


@dataclasses.dataclass(kw_only=True)
class DeliveryDBBackup(ExtensionCfgMixins):
    '''
    :param str delivery_service_url
    :param str component_name:
        The desired name of the OCM component which will contain the backup resource.
    :param str ocm_repo_url:
        The OCM repository to which the component will be published.
    :param int backup_retention_count:
        The number of backup versions to keep. In case there are more backups, the oldest backups
        will be removed.
    :param str initial_version:
        Upon a new backup, there will be an automatic minor version upgrade. This defines the
        initial version if the backup component does not exist yet.
    :param list[str] extra_pg_dump_args:
        List of arguments that is passed to the `pg_dump` command as-is.
    :param str schedule
    :param int successful_jobs_history_limit
    :param int failed_jobs_history_limit
    '''
    service: Services = Services.DELIVERY_DB_BACKUP
    delivery_service_url: str
    component_name: str
    ocm_repo_url: str
    backup_retention_count: int | None
    initial_version: str = '0.1.0'
    extra_pg_dump_args: list[str] = dataclasses.field(default_factory=list)
    schedule: str = '0 0 * * *' # every day at 12:00 AM
    successful_jobs_history_limit: int = 1
    failed_jobs_history_limit: int = 1


@dataclasses.dataclass
class GitHubInstance:
    hostname: str
    orgs: list[str]


@dataclasses.dataclass(kw_only=True)
class GHASConfig(ExtensionCfgMixins):
    service: Services = Services.GHAS
    delivery_service_url: str
    on_unsupported: WarningVerbosities = WarningVerbosities.WARNING
    github_instances: list[GitHubInstance] = dataclasses.field(default_factory=list)
    schedule: str = '0 0 * * *' # every day at 12:00 AM
    successful_jobs_history_limit: int = 1
    failed_jobs_history_limit: int = 1

    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            odg.model.ArtefactKind.SOURCE,
        )

        if artefact_kind and artefact_kind not in supported_artefact_kinds:
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{artefact_kind=} is not supported for GHAS scans, {supported_artefact_kinds=}'
                )
            return False

        return True


@dataclasses.dataclass
class ExtensionDefinitionOcmReference:
    component_name: str
    component_version: str
    artefact_name: str


@dataclasses.dataclass(kw_only=True)
class OdgOperatorConfig(ExtensionCfgMixins):
    service: Services = Services.ODG_OPERATOR
    required_extension_names: list[str] = dataclasses.field(default_factory=list)
    extension_ocm_references: list[ExtensionDefinitionOcmReference] = dataclasses.field(default_factory=list) # noqa: E501


@dataclasses.dataclass
class IssueReplicatorMapping(Mapping):
    '''
    :param str github_repository
        GitHub repository name where the issues should be created.
    :param list[str] github_issue_labels_to_preserve:
        Labels matching one of these regexes won't be removed upon an issue update.
    :param int number_included_closed_issues:
        Number of closed issues to consider when evaluating creating vs re-opening an issue.
    :param MilestoneConfiguration milestones:
        Configuration to overwrite how the configured sprints are turned into GitHub milestones.
    '''
    github_repository: str
    github_issue_labels_to_preserve: list[str] = dataclasses.field(default_factory=list)
    number_included_closed_issues: int = 100
    milestones: gcmi.MilestoneConfiguration | dict = dataclasses.field(default_factory=gcmi.MilestoneConfiguration) # noqa: E501

    def __post_init__(self):
        if isinstance(self.milestones, dict):
            if milestone_title_cfg := self.milestones.get('title'):
                title_prefix = milestone_title_cfg.get('prefix')
                title_suffix = milestone_title_cfg.get('suffix')
                title_sprint_cfg = milestone_title_cfg.get('sprint')
            else:
                title_prefix = gcmi.MilestoneConfiguration.title_prefix
                title_suffix = gcmi.MilestoneConfiguration.title_suffix
                title_sprint_cfg = None

            if title_sprint_cfg:
                if (sprint_value_type := title_sprint_cfg.get('value_type')) == 'name':
                    title_callback = lambda sprint: sprint.name

                elif sprint_value_type == 'date':
                    name = title_sprint_cfg.get('date_name', 'end_date')
                    str_format = title_sprint_cfg.get('date_string_format', '%Y-%m-%d')

                    title_callback = lambda sprint: sprint.find_sprint_date(name).value.strftime(str_format) # noqa: E501

                else:
                    raise ValueError(f'invalid milestone sprint value type {sprint_value_type}')

            else:
                title_callback = gcmi.MilestoneConfiguration.title_callback

            if milestone_due_date_cfg := self.milestones.get('due_date'):
                name = milestone_due_date_cfg['date_name']
                due_date_callback = lambda sprint: sprint.find_sprint_date(name).value
            else:
                due_date_callback = gcmi.MilestoneConfiguration.due_date_callback

            self.milestones = gcmi.MilestoneConfiguration(
                title_callback=title_callback,
                title_prefix=title_prefix,
                title_suffix=title_suffix,
                due_date_callback=due_date_callback,
            )


@cachetools.cached(cachetools.TTLCache(maxsize=64, ttl=60 * 25)) # gh-token is valid for 30 min
def github_repository(repo: str) -> github3.repos.Repository:
    github_api_lookup = lookups.github_api_lookup()
    github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)

    return github_repo_lookup(repo)


@cachetools.cached(cachetools.TTLCache(maxsize=64, ttl=60 * 25)) # gh-token is valid for 30 min
def github_api(repo: str) -> github3.github.GitHub:
    github_api_lookup = lookups.github_api_lookup()

    return github_api_lookup(repo)


@dataclasses.dataclass(kw_only=True)
class IssueReplicatorConfig(BacklogItemMixins):
    '''
    :param str delivery_service_url
    :param str delivery_dashboard_url
    :param list[IssueReplicatorMapping] mappings
    :param int interval:
        Time after which an issue must be updated at latest.
    '''
    service: Services = Services.ISSUE_REPLICATOR
    delivery_service_url: str
    delivery_dashboard_url: str
    mappings: list[IssueReplicatorMapping]
    interval: int = 60 * 60 # 1h

    def mapping(self, name: str, /) -> IssueReplicatorMapping:
        for mapping in self.mappings:
            if name.startswith(mapping.prefix):
                return mapping

        raise ValueError(f'No matching mapping entry found for {name=}')

    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
    ) -> bool:
        return True # issue replication works independent of any artefact or access type


@dataclasses.dataclass
class ResponsibleConfigRule:
    '''
    :param str name:
        The name of the rule used for logging purposes.
    :param list[FilterBase] filters:
        The specified filters are concatenated using an `AND` expression.
    :param list[StrategyBase] strategies:
        The responsibles determined via the specified `strategies` are concatenated.
    :param ResponsibleAssigneeModes assignee_mode:
        Specifies how to handle an issue that already has assignees different to those determined
        via this rule. If `None` is specified, the `default_assignee_mode` of the respective
        finding-cfg will be used.
    '''
    name: str | None
    filters: list[
        ref.ArtefactFilter
        | ref.ComponentFilter
        | ref.DatatypeFilter
        | ref.MatchAllFilter
    ] = dataclasses.field(default_factory=list)
    strategies: list[
        res.ComponentResponsibles
        | res.StaticResponsibles
    ] = dataclasses.field(default_factory=list)
    assignee_mode: odg.model.ResponsibleAssigneeModes | None = None


@dataclasses.dataclass(kw_only=True)
class ResponsiblesConfig(BacklogItemMixins):
    '''
    :param str delivery_service_url:
    :param int interval:
        Time after which the responsibles for an artefact must be re-determined at latest.
    :param list[ResponsibleConfigRule] rules:
        These rules are used to map desired responsible `strategies` to artefacts and finding types
        using `filters`. The first matching rule "wins". In case no rule matches, the responsibles
        extension will not determine any responsibles and instead the default lookup will take
        precedence (i.e. lookup responsibles in findings and as fallback via delivery-service api).
    '''
    service: Services = Services.RESPONSIBLES
    delivery_service_url: str
    interval: int = 60 * 60 * 12 # 12h
    rules: list[ResponsibleConfigRule] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(kw_only=True)
class SASTConfig(BacklogItemMixins):
    '''
    :param str delivery_service_url
    :param int interval:
        Time after which an artefact must be re-scanned at latest.
    :param WarningVerbosities on_unsupported
        Defines the handling if a backlog item should be processed which contains unsupported
        properties, e.g. an unsupported access type.
    '''
    service: Services = Services.SAST
    delivery_service_url: str
    interval: int = 60 * 60 * 24 # 24h
    on_unsupported: WarningVerbosities = WarningVerbosities.WARNING

    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            odg.model.ArtefactKind.SOURCE,
        )

        if artefact_kind and artefact_kind not in supported_artefact_kinds:
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{artefact_kind=} is not supported for SAST scans, {supported_artefact_kinds=}'
                )
            return False

        return True


@dataclasses.dataclass(kw_only=True)
class OsId(BacklogItemMixins):
    '''
    :param str delivery_service_url
    :param int interval:
        Time after which an artefact must be re-scanned at latest.
    :param WarningVerbosities on_unsupported
        Defines the handling if a backlog item should be processed which contains unsupported
        properties, e.g. an unsupported access type.
    '''
    service: Services = Services.OSID
    delivery_service_url: str
    interval: int = 60 * 60 * 24 # 24h
    on_unsupported: WarningVerbosities = WarningVerbosities.WARNING

    def is_supported(
        self,
        artefact_kind: odg.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
        artefact_type: str | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            odg.model.ArtefactKind.RESOURCE,
        )
        supported_access_types = (
            ocm.AccessType.OCI_REGISTRY,
        )
        supported_artefact_types_by_access_type = {
            ocm.AccessType.OCI_REGISTRY: (ocm.ArtefactType.OCI_IMAGE,),
        }

        is_supported = True

        if access_type and access_type not in supported_access_types:
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{access_type=} is not supported for OS_ID scans, {supported_access_types=}'
                )
            is_supported = False

        if artefact_kind and artefact_kind not in supported_artefact_kinds:
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{artefact_kind=} is not supported for OS_ID scans, {supported_artefact_kinds=}'
                )
            is_supported = False

        if (
            artefact_type
            and access_type
            and (artefact_types := supported_artefact_types_by_access_type.get(access_type))
        ):
            if not any(
                artefact_type.startswith(supported_artefact_type)
                for supported_artefact_type in artefact_types
            ):
                if self.on_unsupported is WarningVerbosities.WARNING:
                    logger.warning(
                        f'{artefact_type=} is not supported for OS_ID scans with {access_type=}, '
                        f'{supported_artefact_types_by_access_type=}'
                    )
                is_supported = False

        return is_supported


@dataclasses.dataclass
class ExtensionsConfiguration:
    access_manager: AccessManagerConfig | None
    artefact_enumerator: ArtefactEnumeratorConfig | None
    bdba: BDBAConfig | None
    blackduck: BlackDuckConfig | None
    cache_manager: CacheManagerConfig | None
    clamav: ClamAVConfig | None
    crypto: CryptoConfig | None
    delivery_db_backup: DeliveryDBBackup | None
    ghas: GHASConfig | None
    issue_replicator: IssueReplicatorConfig | None
    odg_operator: OdgOperatorConfig | None
    osid: OsId | None
    responsibles: ResponsiblesConfig | None
    sast: SASTConfig | None
    backlog_controller: BacklogControllerConfig = dataclasses.field(default_factory=BacklogControllerConfig) # noqa: E501

    @staticmethod
    def from_dict(extensions_cfg_raw: dict) -> typing.Self:
        '''
        Mixes-in properties of `defaults` into extension specific configuration. Extensions
        configured as `None` or an empty object will also be consider as "active" in case they don't
        require any configuration to be provided.
        '''
        # mix-in default values in extension-specific ones
        defaults = extensions_cfg_raw.get('defaults', {})
        for extension, extension_cfg in extensions_cfg_raw.items():
            extensions_cfg_raw[extension] = defaults | (extension_cfg or {})

        return dacite.from_dict(
            data_class=ExtensionsConfiguration,
            data=extensions_cfg_raw,
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )

    @staticmethod
    def from_file(path: str) -> typing.Self:
        with open(path) as file:
            extensions_cfg_raw = yaml.safe_load(file)

        return ExtensionsConfiguration.from_dict(
            extensions_cfg_raw=extensions_cfg_raw,
        )

    def find_extension_cfg(
        self,
        service: Services,
        require_enabled: bool=True,
    ) -> object | None:
        for extension_name in dataclasses.asdict(self).keys():
            if not (extension_cfg := getattr(self, extension_name)):
                continue
            if extension_cfg.service is not service:
                continue
            if require_enabled and not extension_cfg.enabled:
                continue

            return extension_cfg

    def enabled_extensions(
        self,
        convert_to_camel_case: bool=False,
    ) -> collections.abc.Generator[str, None, None]:
        for extension_name in dataclasses.asdict(self).keys():
            if (
                not (extension_cfg := getattr(self, extension_name))
                or not extension_cfg.enabled
            ):
                continue # extension is not configured

            if not convert_to_camel_case:
                yield extension_name
                continue

            first_part, *remaining_parts = extension_name.split('_')
            yield first_part + ''.join(part.title() for part in remaining_parts)
