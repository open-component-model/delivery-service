import collections.abc
import dataclasses
import datetime
import enum
import functools
import logging
import typing

import dacite
import github3.repos
import yaml

import dso.model
import github.compliance.milestone as gcmi
import ocm

import bdba.model as bm
import crypto_extension.config
import lookups
import odg.shared_cfg


logger = logging.getLogger(__name__)


class Services(enum.StrEnum):
    ARTEFACT_ENUMERATOR = 'artefactEnumerator'
    BACKLOG_CONTROLLER = 'backlogController'
    BDBA = 'bdba'
    CACHE_MANAGER = 'cacheManager'
    CLAMAV = 'clamav'
    CRYPTO = 'crypto'
    DELIVERY_DB_BACKUP = 'deliveryDbBackup'
    ISSUE_REPLICATOR = 'issueReplicator'
    SAST = 'sast'


class VersionAliases(enum.StrEnum):
    GREATEST = 'greatest'


class WarningVerbosities(enum.StrEnum):
    FAIL = 'fail'
    IGNORE = 'ignore'
    WARNING = 'warning'


@dataclasses.dataclass(kw_only=True)
class ExtensionCfgMixins:
    enabled: bool = True


@dataclasses.dataclass
class BacklogItemMixins(ExtensionCfgMixins):
    '''
    Defines properties and functions which are shared among those extensions which determine their
    workload using the BacklogItem custom resource.
    '''
    def is_supported(
        self,
        artefact_kind: dso.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
    ) -> bool:
        raise NotImplementedError('function must be implemented by derived classes')


@dataclasses.dataclass
class Component:
    component_name: str
    version: str | None
    ocm_repo_url: str | None
    version_filter: str | None
    timerange_days: int | None
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


@dataclasses.dataclass
class TimeRange:
    days_from: int = -90
    days_to: int = 150

    @property
    def start_date(self) -> datetime.date:
        today = datetime.date.today()
        return today + datetime.timedelta(days=self.days_from)

    @property
    def end_date(self) -> datetime.date:
        today = datetime.date.today()
        return today + datetime.timedelta(days=self.days_to)


@dataclasses.dataclass
class ArtefactEnumeratorConfig(ExtensionCfgMixins):
    '''
    :param str delivery_service_url
    :param list[Component] components:
        Components which are classified as "active" and for which compliance snapshots are created.
    :param TimeRange sprints_relative_time_range:
        Earliest start and latest end date for which compliance snapshots should be created. If not
        set, all available sprints will be considered.
    :param int compliance_snapshot_grace_period:
        Time after which inactive compliance snapshots are deleted from the delivery-db. During this
        period, the inactive snapshots are used to possibly close outdated GitHub issues (i.e. the
        ones which have a due date which is by now out-of-scope of the configured time range).
    :param str schedule
    :param int successful_jobs_history_limit
    :param int failed_jobs_history_limit
    '''
    delivery_service_url: str
    components: list[Component]
    sprints_relative_time_range: TimeRange | None
    compliance_snapshot_grace_period: int = 60 * 60 * 24 # 24h
    schedule: str = '*/5 * * * *' # every 5 minutes
    successful_jobs_history_limit: int = 1
    failed_jobs_history_limit: int = 1


@dataclasses.dataclass
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
    :param str bdba_secret_name:
        Name of the BDBA secret element to use for scanning.
    :param str aws_secret_name
        Name of the AWS secret element to use to retrieve artefacts from S3.
    :param ProcessingMode processing_mode:
        Defines the scanning behaviour in case there is already an existing scan.
    '''
    group_id: int
    bdba_secret_name: str
    aws_secret_name: str | None
    processing_mode: bm.ProcessingMode = bm.ProcessingMode.RESCAN


@dataclasses.dataclass
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
        artefact_kind: dso.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            dso.model.ArtefactKind.RESOURCE,
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


@dataclasses.dataclass
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


@dataclasses.dataclass
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
        artefact_kind: dso.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
        artefact_type: str | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            dso.model.ArtefactKind.RESOURCE,
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
    included_asset_types: list[dso.model.CryptoAssetTypes] | None
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


@dataclasses.dataclass
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
        artefact_kind: dso.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
        artefact_type: str | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            dso.model.ArtefactKind.RESOURCE,
        )
        supported_access_types = (
            ocm.AccessType.OCI_REGISTRY,
            ocm.AccessType.LOCAL_BLOB,
            ocm.AccessType.S3,
        )
        supported_artefact_types_by_access_type = {
            ocm.AccessType.OCI_REGISTRY: ('ociImage',),
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


@dataclasses.dataclass
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

    @functools.cached_property
    def repository(self) -> github3.repos.Repository:
        github_api_lookup = lookups.github_api_lookup()
        github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)

        return github_repo_lookup(self.github_repository)

    @functools.cached_property
    def github_api(self) -> github3.github.GitHub:
        github_api_lookup = lookups.github_api_lookup()

        return github_api_lookup(self.repository.html_url)


@dataclasses.dataclass
class IssueReplicatorConfig(BacklogItemMixins):
    '''
    :param str delivery_service_url
    :param str delivery_dashboard_url
    :param list[IssueReplicatorMapping] mappings
    :param int interval:
        Time after which an issue must be updated at latest.
    '''
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
        artefact_kind: dso.model.ArtefactKind | None=None,
        access_type: ocm.AccessType | None=None,
    ) -> bool:
        return True # issue replication works independent of any artefact or access type


@dataclasses.dataclass
class SASTConfig(BacklogItemMixins):
    '''
    :param str delivery_service_url
    :param int interval:
        Time after which an artefact must be re-scanned at latest.
    :param WarningVerbosities on_unsupported
        Defines the handling if a backlog item should be processed which contains unsupported
        properties, e.g. an unsupported access type.
    '''
    delivery_service_url: str
    interval: int = 60 * 60 * 24 # 24h
    on_unsupported: WarningVerbosities = WarningVerbosities.WARNING

    def is_supported(
        self,
        artefact_kind: dso.model.ArtefactKind | None=None,
    ) -> bool:
        supported_artefact_kinds = (
            dso.model.ArtefactKind.SOURCE,
        )

        if artefact_kind and artefact_kind not in supported_artefact_kinds:
            if self.on_unsupported is WarningVerbosities.WARNING:
                logger.warning(
                    f'{artefact_kind=} is not supported for SAST scans, {supported_artefact_kinds=}'
                )
            return False

        return True


@dataclasses.dataclass
class ExtensionsConfiguration:
    artefact_enumerator: ArtefactEnumeratorConfig | None
    bdba: BDBAConfig | None
    cache_manager: CacheManagerConfig | None
    clamav: ClamAVConfig | None
    crypto: CryptoConfig | None
    delivery_db_backup: DeliveryDBBackup | None
    issue_replicator: IssueReplicatorConfig | None
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
