import collections.abc
import dataclasses
import datetime
import enum
import functools
import logging
import math
import os
import watchdog.events
import watchdog.observers.polling

import aiohttp.web
import dacite
import dateutil.parser
import github3.repos
import yaml

import consts
import ctx_util
import k8s.util
import lookups
import middleware.auth
import middleware.db_session
import odg.extensions_cfg
import odg.findings
import paths
import secret_mgmt
import secret_mgmt.delivery_db
import secret_mgmt.oauth_cfg
import secret_mgmt.signing_cfg
import util
import yp


own_dir = os.path.abspath(os.path.dirname(__file__))
repo_dir = os.path.abspath(os.path.join(own_dir, os.pardir))

logger = logging.getLogger(__name__)
feature_cfgs = []


@dataclasses.dataclass(frozen=True)
class SprintRules:
    '''
    Sprint rules can be used to enrich the special components cfg. The properties
    `frozenFrom` and `frozenUntil` have to be names of valid date fields of the
    `Sprint` object.
    '''
    frozenFrom: str
    frozenUntil: str
    frozenWarningOffsetDays: int | None


class CurrentVersionSourceType(enum.StrEnum):
    GITHUB = 'github'


@dataclasses.dataclass
class CurrentVersionSource:
    type: CurrentVersionSourceType
    repo: str
    relpath: list[dict | str]
    postprocess: bool = False


@dataclasses.dataclass(frozen=True)
class CurrentVersion:
    source: CurrentVersionSource

    def retrieve(self, github_api_lookup) -> str:
        '''
        Returns the currently referenced version of the component, i.e. the one referenced in the
        repository which may be different to the one referenced in the greatest component descriptor
        (e.g. if the release is pending).
        '''
        if not self.source.type is CurrentVersionSourceType.GITHUB:
            raise ValueError(f'{self.source.type=} is not supported')

        repo_url = self.source.repo

        github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)
        _, _, repo = self.source.repo.split('/')
        repo = github_repo_lookup(repo_url)

        # every path in the relpath property which is not the last element has
        # to be a submodule. So, get the referenced submodule with the corresponding
        # commit ref and repeat it until no further submodule is specified
        commit_sha = None
        for path in self.source.relpath[:-1]:
            submodule = repo.file_contents(path, commit_sha)
            commit_sha = submodule.links['git'].split('/')[-1]

            repo = github_repo_lookup(submodule.links['html'])

        # the last element of the relpath property has to be a valid path in the
        # current repository. Thus, the referenced file can be returned (which
        # is expected to be a file only containing the version)
        version = repo.file_contents(
            path=self.source.relpath[-1],
            ref=commit_sha,
        ).decoded.decode('utf-8')

        if self.source.postprocess:
            version += f'-{next(repo.commits(number=1)).sha}'

        return version


@dataclasses.dataclass(frozen=True)
class SpecialComponentDependency:
    name: str
    displayName: str
    currentVersion: CurrentVersion | None


@dataclasses.dataclass
class SpecialComponentsCfg:
    '''
    Represents configuration for a single special component. These are used to
    enrich components with further semantics and they are shown on the landing
    page of the Delivery-Dashboard and as pinned component.

    :param str id:
        (required), unique identifier (i.e. UUID) to be able to relate user-specific cfg made in the
        dashboard to centrally configured special components. If an old special component is
        removed, new ones must not reuse old identifiers as this will cause wrong user-specific cfg
        being related to the new special component.
    :param str name:
        (required), name of the component, e.g. github.com/gardener/gardener
    :param str displayName:
        (required), name of the component used in the navigation bar and on the
        landing page
    :param str type:
        (required), type of the component used to group multiple components
    :param str version:
        (required), version which is selected by default, use `greatest` to
        always refer to the latest version available
    :param SprintRules sprintRules:
        (optional), rules to enrich the component with special conditions based
        on the current sprint
    :param str ocmRepo:
        (optional), OCM repository which should be used instead of the default repo
    :param CurrentVersion currentVersion:
        (optional), specifies where to find the current (not yet) published
        component version
    :param list[SpecialComponentDependency] dependencies:
        (optional), list of dependencies in a certain version which belong to
        the `currentVersion` of the component
    '''
    id: str
    name: str
    displayName: str
    type: str
    version: str | CurrentVersion
    icon: str | None
    releasePipelineUrl: str | None
    sprintRules: SprintRules | None
    ocmRepo: str | None
    currentVersion: CurrentVersion | None
    dependencies: list[SpecialComponentDependency] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class ComponentWithDownloadableTestResults:
    '''
    Represents configuration for a single component which contains test results as asset.

    :param str componentName:
        (required), name of the component, e.g. github.com/gardener/gardener
    :param str description:
        (required), describes the kind of tests and is used as a title in the
        Delivery-Dashboard
    :param list[str] assetNamePrefixes:
        (required), list of prefixes the assets representing the test results start with,
        if no prefixes are specified, it defaults to the defaultAssetNamePrefixes property
        of the feature configuration
    :param str displayName:
        (required), name of the component which is shown in the Delivery-Dashboard, if no
        displayName is specified, it defaults to the name of the component
    :param str downloadableName:
        (required), name of the component which is used to name the download file, it is
        concatenated with the current component version, if no downloadableName is specified,
        it defaults to the name of the component
    '''
    componentName: str
    description: str
    assetNamePrefixes: list[str]
    displayName: str
    downloadableName: str


@dataclasses.dataclass
class Profile:
    name: str
    finding_types: list[str] = dataclasses.field(default_factory=list)
    special_component_ids: list[str] = dataclasses.field(default_factory=list)

    def filter_finding_cfgs(
        self,
        finding_cfgs: list[odg.findings.Finding],
    ) -> list[odg.findings.Finding]:
        return [
            finding_cfg for finding_cfg in finding_cfgs
            if finding_cfg.type in self.finding_types
        ]

    def filter_special_components(
        self,
        special_components: list[SpecialComponentsCfg],
    ) -> list[SpecialComponentsCfg]:
        return [
            special_component for special_component in special_components
            if special_component.id in self.special_component_ids
        ]


class FeatureStates(enum.Enum):
    AVAILABLE = 'available'
    UNAVAILABLE = 'unavailable'


@dataclasses.dataclass(frozen=True)
class FeatureBase:
    state: FeatureStates

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class FeatureAddressbook(FeatureBase):
    name: str = 'addressbook'
    addressbook_relpath: str = None
    github_mappings_relpath: str = None
    github_repo: github3.repos.Repository | None = None

    def get_source(self) -> str:
        if self.github_repo:
            return self.github_repo.url

        return 'incluster-configuration'

    def _get_content(self, relpath: str) -> dict:
        if self.github_repo:
            content = self.github_repo.file_contents(
                path=relpath,
                ref=self.github_repo.default_branch,
            ).decoded
        else:
            # read file from local repository
            content = open(os.path.join(repo_dir, relpath))

        return yaml.safe_load(content)

    def get_addressbook_entries(self) -> list[yp.AddressbookEntry]:
        entries_raw = self._get_content(
            relpath=self.addressbook_relpath,
        )

        return [
            dacite.from_dict(
                data_class=yp.AddressbookEntry,
                data=entry_raw,
            )
            for entry_raw in entries_raw
            if entry_raw.get('github')
        ]

    def get_github_mappings(self) -> list[dict]:
        github_mappings = self._get_content(
            relpath=self.github_mappings_relpath,
        )['github_instances']

        return github_mappings

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


@dataclasses.dataclass(frozen=True)
class FeatureAuthentication(FeatureBase):
    name: str = 'authentication'
    signing_cfgs: list[secret_mgmt.signing_cfg.SigningCfg] = dataclasses.field(default_factory=list)
    oauth_cfgs: list[secret_mgmt.oauth_cfg.OAuthCfg] = dataclasses.field(default_factory=list)

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


@dataclasses.dataclass(frozen=True)
class FeatureClusterAccess(FeatureBase):
    name: str = 'cluster-access'
    namespace: str = None
    kubernetes_cfg_name: str = None
    kubeconfig_path: str = None

    def get_namespace(self) -> str:
        return self.namespace

    @functools.cache
    def get_kubernetes_api(self) -> str:
        if not self.kubernetes_cfg_name:
            return k8s.util.kubernetes_api(kubeconfig_path=self.kubeconfig_path)

        secret_factory = ctx_util.secret_factory()
        kubernetes_cfg = secret_factory.kubernetes(self.kubernetes_cfg_name)
        return k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)


@dataclasses.dataclass(frozen=True)
class FeatureDeliveryDB(FeatureBase):
    name: str = 'delivery-db'
    db_url: str = None

    def get_db_url(self) -> str | None:
        return self.db_url

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


@dataclasses.dataclass(frozen=True)
class FeatureExtensionsConfiguration(FeatureBase):
    name: str = 'extensions-configuration'
    extensions_cfg: odg.extensions_cfg.ExtensionsConfiguration | None = None

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
            'extensions_cfg': util.purge_callables_from_dict(
                data=util.dict_serialisation(self.extensions_cfg),
            ),
        }


@dataclasses.dataclass(frozen=True)
class FeatureFindingConfigurations(FeatureBase):
    name: str = 'finding-configurations'
    finding_cfgs: list[odg.findings.Finding] = dataclasses.field(default_factory=list)

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        if profile:
            finding_cfgs_for_profile = profile.filter_finding_cfgs(
                finding_cfgs=self.finding_cfgs,
            )
        else:
            finding_cfgs_for_profile = self.finding_cfgs

        return {
            'state': self.state,
            'name': self.name,
            'finding_cfgs': finding_cfgs_for_profile,
        }


@dataclasses.dataclass(frozen=True)
class FeatureProfiles(FeatureBase):
    name: str = 'profiles'
    profiles: list[Profile] = dataclasses.field(default_factory=list)

    def find_profile(self, name: str | None) -> Profile | None:
        if not name and self.profiles:
            return self.profiles[0] # if no specific profile is requested, use default one (-> first)

        for profile in self.profiles:
            if profile.name == name:
                return profile

        return None


@dataclasses.dataclass(frozen=True)
class FeatureTests(FeatureBase):
    name: str = 'tests'
    components_with_tests: tuple[ComponentWithDownloadableTestResults] = tuple()

    def get_component_with_tests(
        self,
        component_name,
    ) -> ComponentWithDownloadableTestResults | None:
        for component in self.components_with_tests:
            if component.componentName == component_name:
                return component
        return None


@dataclasses.dataclass(frozen=True)
class FeatureOcmRepositoryCfgs(FeatureBase):
    name: str = 'ocm-repository-cfgs'
    ocm_repository_cfgs: list[lookups.OciOcmRepositoryCfg | lookups.VirtualOcmRepositoryCfg] = None

    def iter_resolved_ocm_repository_cfgs(self) -> collections.abc.Iterable[dict]:
        if self.state is FeatureStates.UNAVAILABLE:
            return

        for ocm_repository_cfg in self.ocm_repository_cfgs:
            ocm_repository_cfg_raw = util.dict_serialisation(ocm_repository_cfg)
            ocm_repository_cfg_raw['repositories'] = list(ocm_repository_cfg.iter_ocm_repositories(
                ocm_repository_cfgs=self.ocm_repository_cfgs,
            ))

            yield ocm_repository_cfg_raw

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
            'ocm_repository_cfgs': list(self.iter_resolved_ocm_repository_cfgs()),
        }


@dataclasses.dataclass(frozen=True)
class FeatureSpecialComponents(FeatureBase):
    name: str = 'special-components'
    special_components: list[SpecialComponentsCfg] = dataclasses.field(default_factory=list)

    def find_special_component(self, id: str) -> SpecialComponentsCfg | None:
        for special_component in self.special_components:
            if special_component.id == id:
                return special_component

        return None

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        github_api_lookup = lookups.github_api_lookup()

        if profile:
            special_components_for_profile = profile.filter_special_components(
                special_components=self.special_components,
            )
        else:
            special_components_for_profile = self.special_components

        special_components = [
            dataclasses.replace(
                special_component,
                version=special_component.version.retrieve(github_api_lookup),
            ) if isinstance(special_component.version, CurrentVersion) else special_component
            for special_component in special_components_for_profile
        ]

        return {
            'state': self.state,
            'name': self.name,
            'specialComponents': special_components,
        }


@dataclasses.dataclass
class SprintsConfiguration:
    '''
    :param str sprint_name_pattern:
        (required), the pattern used to dynamically format the sprint name based on the sprint's end
        date. Format codes are passed-through to Python datetime's "strftime" function, with the
        following (pre-processed) extra-codes:
        - "%S": the sprint number of the year as a zero-padded decimal number, e.g. 01, 02, ..., 13
          note: maximum sprint number depends on the "days_per_sprint" and "cycles" configuration
        - "%C": if "cycles" are configured (i.e. != 0), the current cycle, e.g. a, b, ..., z
    :param date start_date:
        ISO-8601 compatible date starting from which the sprints should be generated
        note: this should be kept constant to ensure the generated sprints remain the same,
        independent of when they were generated
    :param int future_threshold_days:
        the number of days into the future for which sprints should be generated
        note: this should be at least larger than the maximum allowed processing time for any of the
        finding configurations
    :param int days_per_sprint:
        number of days a sprint consist of
    :param int cycles:
        optionally allows to separate a sprint into sub-cycles, indicated by a letter (e.g. "a", "b",
        ...)
        note: set this value to 0 (or 1) to disable it (no cycles is equivalent to one cycle per
        sprint)
    :param int offset:
        allows generation of a sprint based on the sprint end date of another relative sprint, useful
        for example to start with the first sprint only in February and not already in January
    :param SprintMetadata meta:
    '''
    sprint_name_pattern: str
    start_date: datetime.date = datetime.date.fromisoformat('2025-01-08') # noqa: E501 default date is compatible with existing implementations
    future_threshold_days: int = 365
    days_per_sprint: int = 14
    cycles: int = 2
    offset: int = -2
    meta: yp.SprintMetadata = dataclasses.field(default_factory=yp.SprintMetadata)


def iter_sprint_dates(
    start_date: datetime.date,
    end_date: datetime.date,
    days_per_sprint: int,
    offset: int=0,
) -> collections.abc.Iterable[datetime.date]:
    '''
    Yields all dates between (including) `start_date` and (excluding) `end_date` with the interval
    of `days_per_sprint`. If `offset` is specified, the `start_date` will be modified by `offset`
    sprints, e.g. if `offset=-1`, the first yielded sprint will be the sprint before `start_date`
    (this might be helpful to handle corner cases where predecessor and/or successor sprints have to
    be considered as well).
    '''
    start_date += datetime.timedelta(days=days_per_sprint * offset)
    current_date = start_date
    offset = 0

    while current_date < end_date:
        current_date = start_date + datetime.timedelta(days=days_per_sprint * offset)
        offset += 1

        yield current_date


def sprint_number(
    sprint_date: datetime.date,
    days_per_sprint: int,
    cycles: int,
) -> int:
    '''
    Returns the number of the sprint for the provided `sprint_date` based on the configured
    `days_per_sprint` and `cycles`, e.g. if `sprint_date='2025-01-07'` and `days_per_sprint=1` and
    `cycles=3`, the corresponding sprint number would be "3".
    '''
    day_of_year = int(sprint_date.strftime('%j'))
    return math.ceil(day_of_year / (cycles * days_per_sprint))


def sprint_name(
    sprint_name_pattern: str,
    sprint_date: datetime.date,
    sprint_number: int,
    cycle: int,
) -> str:
    '''
    Formats the passed `sprint_date` according to the `sprint_name_pattern`. The format codes are
    passed-through to Python datetime's `strftime` function, with the following (pre-processed)
    extra-codes:
    - `%S`: the sprint number of the year as a zero-padded decimal number, e.g. 01, 02, ..., 13
      note: maximum sprint number depends on the `days_per_sprint` and `cycles` configuration
    - `%C`: if `cycles` are configured, the current cycle, e.g. a, b, ..., z
      note: the maximum cycle depends on the `cycles` configuration
    '''
    cycle_options = 'abcdefghijklmnopqrstuvwxyz'

    custom_sprint_format = sprint_name_pattern \
        .replace('%S', f'{sprint_number:02d}') \
        .replace('%C', cycle_options[cycle % 26])

    return sprint_date.strftime(custom_sprint_format)


def iter_sprints(
    sprints_cfg: SprintsConfiguration,
) -> collections.abc.Iterable[yp.Sprint]:
    end_date = datetime.date.today() + datetime.timedelta(days=sprints_cfg.future_threshold_days)

    sprint_dates = list(iter_sprint_dates(
        start_date=sprints_cfg.start_date,
        end_date=end_date,
        days_per_sprint=sprints_cfg.days_per_sprint,
        offset=sprints_cfg.offset,
    ))

    last_sprint_number = None

    for idx, sprint_date in enumerate(sprint_dates):
        if (
            (effective_idx := idx + sprints_cfg.offset) < 0
            or effective_idx >= len(sprint_dates)
        ):
            # if the effective idx is out of range, just skip it as those dates have been added to
            # the list via `iter_sprint_dates` anyways as padding only
            continue

        effective_sprint_date = sprint_dates[effective_idx]

        current_sprint_number = sprint_number(
            sprint_date=effective_sprint_date,
            days_per_sprint=sprints_cfg.days_per_sprint,
            cycles=sprints_cfg.cycles or 1,
        )

        if current_sprint_number == last_sprint_number:
            current_cycle += 1
        else:
            current_cycle = 0
            last_sprint_number = current_sprint_number

        current_sprint_name = sprint_name(
            sprint_name_pattern=sprints_cfg.sprint_name_pattern,
            sprint_date=effective_sprint_date,
            sprint_number=current_sprint_number,
            cycle=current_cycle,
        )

        yield yp.Sprint(
            name=current_sprint_name,
            end_date=sprint_date,
        )


@dataclasses.dataclass(frozen=True)
class FeatureSprints(FeatureBase):
    name: str = 'sprints'
    sprints_relpath: str | None = None
    github_repo: github3.repos.Repository | None = None
    sprints_cfg: SprintsConfiguration | None = None

    def _get_content(self, relpath: str) -> dict:
        if self.github_repo:
            content = self.github_repo.file_contents(
                path=relpath,
                ref=self.github_repo.default_branch,
            ).decoded
        else:
            # read file from local repository
            content = open(os.path.join(repo_dir, relpath))

        return yaml.safe_load(content)

    def get_sprints_metadata(self) -> yp.SprintMetadata:
        if self.sprints_cfg:
            return self.sprints_cfg.meta

        meta_raw = self._get_content(
            relpath=self.sprints_relpath,
        ).get('meta', {})

        return dacite.from_dict(
            data_class=yp.SprintMetadata,
            data=meta_raw,
        )

    def get_sprints(self) -> list[yp.Sprint]:
        if self.sprints_cfg:
            return list(reversed(list(iter_sprints(self.sprints_cfg))))

        sprints_raw = self._get_content(
            relpath=self.sprints_relpath,
        )['sprints']

        return [
            dacite.from_dict(
                data_class=yp.Sprint,
                data=sprint_raw,
                config=dacite.Config(
                    type_hooks={
                        datetime.datetime: lambda date: dateutil.parser.isoparse(date) if isinstance(date, str) else date, # noqa: E501
                    },
                ),
            ) for sprint_raw in sprints_raw
        ]

    def serialize(self, profile: Profile | None=None) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


@dataclasses.dataclass(frozen=True)
class FeatureUpgradePRs(FeatureBase):
    name: str = 'upgrade-prs'


def get_feature(
    feature_type: type[FeatureBase],
) -> FeatureBase | None:
    for f in feature_cfgs:
        if isinstance(f, feature_type):
            return f
    return None


def deserialise_addressbook(addressbook_raw: dict) -> FeatureAddressbook:
    if github_repo_url := addressbook_raw.get('repoUrl'):
        github_api_lookup = lookups.github_api_lookup()
        github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)
        github_repo = github_repo_lookup(github_repo_url)
        addressbook_relpath = addressbook_raw['addressbookRelpath']
        github_mappings_relpath = addressbook_raw['githubMappingsRelpath']
    else:
        github_repo = None
        addressbook_relpath = paths.addressbook_path(
            path_overwrite=addressbook_raw.get('addressbookRelpath'),
            absent_ok=True,
        )
        github_mappings_relpath = paths.github_mappings_path(
            path_overwrite=addressbook_raw.get('githubMappingsRelpath'),
            absent_ok=True,
        )
        if not addressbook_relpath or not github_mappings_relpath:
            return FeatureAddressbook(FeatureStates.UNAVAILABLE)

    return FeatureAddressbook(
        FeatureStates.AVAILABLE,
        addressbook_relpath=addressbook_relpath,
        github_mappings_relpath=github_mappings_relpath,
        github_repo=github_repo,
    )


def deserialise_profiles(profiles_raw: dict) -> FeatureProfiles:
    return FeatureProfiles(
        FeatureStates.AVAILABLE,
        profiles=[
            dacite.from_dict(
                data_class=Profile,
                data=profile_raw,
            ) for profile_raw in profiles_raw
        ]
    )


def deserialise_ocm_repository_cfgs(
    ocm_repository_cfgs_raw: dict,
) -> FeatureOcmRepositoryCfgs:
    ocm_repository_cfgs = [
        lookups.OcmRepositoryCfgBase.from_dict(ocm_repository_cfg_raw)
        for ocm_repository_cfg_raw in ocm_repository_cfgs_raw
    ]

    # insert default `<auto>` virtual repository configuration if not present
    if not any(
        ocm_repository_cfg.name == lookups.OcmRepositoryCfgNames.AUTO
        for ocm_repository_cfg in ocm_repository_cfgs
        if isinstance(ocm_repository_cfg, lookups.VirtualOcmRepositoryCfg)
    ):
        ocm_repository_cfgs.insert(0, lookups.VirtualOcmRepositoryCfg(
            name=lookups.OcmRepositoryCfgNames.AUTO,
        ))

    return FeatureOcmRepositoryCfgs(
        FeatureStates.AVAILABLE,
        ocm_repository_cfgs=ocm_repository_cfgs,
    )


def deserialise_special_components(special_components_raw: dict) -> FeatureSpecialComponents:
    def deserialise_current_version_source(
        current_version_source: dict,
    ) -> dict:
        relpath = []
        path = ''

        for path_elem in current_version_source['relpath']:
            if 'type' in path_elem and path_elem['type'] == 'submodule':
                path = os.path.join(path, path_elem['name'])
                relpath.append(path)
                path = ''
            else:
                path = os.path.join(path, path_elem)
        relpath.append(path)

        current_version_source['relpath'] = relpath
        return current_version_source

    special_components = [
        dacite.from_dict(
            data_class=SpecialComponentsCfg,
            data=special_component_raw,
            config=dacite.Config(
                type_hooks={
                    CurrentVersionSource: lambda cvs: deserialise_current_version_source(cvs),
                    str: lambda s: str(s), # be backwards compatible -> allow plain integers
                },
                cast=[enum.Enum],
            ),
        ) for special_component_raw in special_components_raw
    ]

    return FeatureSpecialComponents(
        FeatureStates.AVAILABLE,
        special_components=special_components,
    )


def deserialise_sprints(sprints_raw: dict) -> FeatureSprints:
    if sprints_raw.get('sprint_name_pattern'):
        return FeatureSprints(
            state=FeatureStates.AVAILABLE,
            sprints_cfg=dacite.from_dict(
                data_class=SprintsConfiguration,
                data=sprints_raw,
                config=dacite.Config(
                    type_hooks={
                        datetime.date: lambda date: datetime.date.fromisoformat(date) if isinstance(date, str) else date, # noqa: E501
                    },
                ),
            ),
        )
    elif github_repo_url := sprints_raw.get('repoUrl'):
        github_repo_lookup = lookups.github_repo_lookup(
            lookups.github_api_lookup(),
        )
        github_repo = github_repo_lookup(github_repo_url)
        sprints_relpath = sprints_raw['sprintsRelpath']
    else:
        github_repo = None
        sprints_relpath = paths.sprints_path(
            path_overwrite=sprints_raw.get('sprintsRelpath'),
            absent_ok=True,
        )
        if not sprints_relpath:
            return FeatureSprints(FeatureStates.UNAVAILABLE)

    return FeatureSprints(
        FeatureStates.AVAILABLE,
        sprints_relpath=sprints_relpath,
        github_repo=github_repo,
    )


def deserialise_tests(tests_raw: dict) -> FeatureTests:
    components_with_tests = [
        dacite.from_dict(
            data_class=ComponentWithDownloadableTestResults,
            data=component_with_tests,
        )
        for component_with_tests in tests_raw['componentsWithDownloadableTestResults']
    ]

    return FeatureTests(
        FeatureStates.AVAILABLE,
        components_with_tests=components_with_tests,
    )


def deserialise_authentication(
    secret_factory: secret_mgmt.SecretFactory,
) -> FeatureAuthentication:
    try:
        oauth_cfgs = secret_factory.oauth_cfg()
        signing_cfgs = secret_factory.signing_cfg()
    except secret_mgmt.SecretTypeNotFound as e:
        logger.warning(f'Authentication config not found: {e}')
        return FeatureAuthentication(FeatureStates.UNAVAILABLE)

    return FeatureAuthentication(
        state=FeatureStates.AVAILABLE,
        signing_cfgs=signing_cfgs,
        oauth_cfgs=oauth_cfgs,
    )


def deserialise_cfg(raw: dict) -> collections.abc.Generator[FeatureBase, None, None]:
    yield deserialise_addressbook(raw.get('addressbook') or {})

    if special_components := raw.get('specialComponents'):
        yield deserialise_special_components(special_components)
    else:
        yield FeatureSpecialComponents(FeatureStates.UNAVAILABLE)

    yield deserialise_sprints(raw.get('sprints') or {})

    if tests := raw.get('tests'):
        yield deserialise_tests(tests)
    else:
        yield FeatureTests(FeatureStates.UNAVAILABLE)

    if raw.get('upgradePRs'):
        yield FeatureUpgradePRs(FeatureStates.AVAILABLE)
    else:
        yield FeatureUpgradePRs(FeatureStates.UNAVAILABLE)


def apply_raw_cfg():
    global feature_cfgs
    raw = util.parse_yaml_file(paths.features_cfg_path())
    for cfg in deserialise_cfg(raw):
        # remove previous feature cfg of the type and instead add new one as it might have changed
        feature_cfgs = [f for f in feature_cfgs if type(f) is not type(cfg)]
        feature_cfgs.append(cfg)

    if extensions_cfg_path := paths.extensions_cfg_path(absent_ok=True):
        extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
        extensions_cfg_feature = FeatureExtensionsConfiguration(
            state=FeatureStates.AVAILABLE,
            extensions_cfg=extensions_cfg,
        )
    else:
        extensions_cfg_feature = FeatureExtensionsConfiguration(FeatureStates.UNAVAILABLE)

    feature_cfgs = [f for f in feature_cfgs if not isinstance(f, FeatureExtensionsConfiguration)]
    feature_cfgs.append(extensions_cfg_feature)

    if findings_cfg_path := paths.findings_cfg_path(absent_ok=True):
        finding_cfgs = odg.findings.Finding.from_file(findings_cfg_path)
        finding_cfgs_feature = FeatureFindingConfigurations(
            state=FeatureStates.AVAILABLE,
            finding_cfgs=finding_cfgs,
        )
    else:
        finding_cfgs_feature = FeatureFindingConfigurations(FeatureStates.UNAVAILABLE)

    feature_cfgs = [f for f in feature_cfgs if not isinstance(f, FeatureFindingConfigurations)]
    feature_cfgs.append(finding_cfgs_feature)

    if (
        (ocm_repo_mappings_path := paths.ocm_repo_mappings_path(absent_ok=True))
        and (ocm_repository_cfgs_raw := util.parse_yaml_file(ocm_repo_mappings_path))
    ):
        ocm_repository_cfgs_feature = deserialise_ocm_repository_cfgs(
            ocm_repository_cfgs_raw=ocm_repository_cfgs_raw,
        )
    else:
        ocm_repository_cfgs_feature = FeatureOcmRepositoryCfgs(FeatureStates.UNAVAILABLE)

    feature_cfgs = [f for f in feature_cfgs if not isinstance(f, FeatureOcmRepositoryCfgs)]
    feature_cfgs.append(ocm_repository_cfgs_feature)

    if (
        (profiles_path := paths.profiles_path(absent_ok=True))
        and (profiles_raw := util.parse_yaml_file(profiles_path))
    ):
        profiles_feature = deserialise_profiles(profiles_raw=profiles_raw)
    else:
        profiles_feature = FeatureProfiles(FeatureStates.UNAVAILABLE)

    feature_cfgs = [f for f in feature_cfgs if not isinstance(f, FeatureProfiles)]
    feature_cfgs.append(profiles_feature)


class CfgFileChangeEventHandler(watchdog.events.FileSystemEventHandler):
    def dispatch(self, event):
        apply_raw_cfg()


def watch_for_file_changes(
    event_handler: CfgFileChangeEventHandler,
    path: str,
):
    try:
        observer = watchdog.observers.polling.PollingObserver(timeout=60)
        observer.schedule(event_handler, path)
        observer.start()
    except FileNotFoundError:
        logger.warning('Feature config not found')


async def init_features(
    parsed_arguments,
    secret_factory: secret_mgmt.SecretFactory,
    middlewares: collections.abc.Iterable,
) -> list:
    global feature_cfgs
    feature_cfgs = []

    feature_authentication = deserialise_authentication(
        secret_factory=secret_factory,
    )
    if (
        feature_authentication.state is FeatureStates.AVAILABLE
        and not parsed_arguments.shortcut_auth
    ):
        middlewares.append(middleware.auth.auth_middleware(
            signing_cfgs=feature_authentication.signing_cfgs,
            default_auth=middleware.auth.AuthType.BEARER,
        ))
    feature_cfgs.append(feature_authentication)

    cluster_access_feature = FeatureClusterAccess(FeatureStates.UNAVAILABLE)
    if not (k8s_cfg_name := parsed_arguments.k8s_cfg_name):
        k8s_cfg_name = os.environ.get('K8S_CFG_NAME')

    if not (k8s_namespace := parsed_arguments.k8s_namespace):
        k8s_namespace = os.environ.get('K8S_TARGET_NAMESPACE')

    if k8s_namespace:
        cluster_access_feature = FeatureClusterAccess(
            state=FeatureStates.AVAILABLE,
            namespace=k8s_namespace,
            kubernetes_cfg_name=k8s_cfg_name,
            kubeconfig_path=parsed_arguments.kubeconfig,
        )
    else:
        logger.warning(
            'required cfgs for cluster access feature missing, will be disabled; '
            f'{k8s_cfg_name=}, {k8s_namespace=}'
        )

    feature_cfgs.append(cluster_access_feature)

    delivery_db_feature_state = FeatureStates.UNAVAILABLE
    if (db_url := parsed_arguments.delivery_db_url):
        delivery_db_feature_state = FeatureStates.AVAILABLE
    else:

        if cluster_access_feature.state is FeatureStates.AVAILABLE:
            try:
                delivery_db_cfgs = secret_factory.delivery_db()
                if len(delivery_db_cfgs) != 1:
                    raise ValueError(
                        f'There must be exactly one delivery-db secret, found {len(delivery_db_cfgs)}' # noqa: E501
                    )

                delivery_db_cfg: secret_mgmt.delivery_db.DeliveryDB = delivery_db_cfgs[0]
                db_url = delivery_db_cfg.connection_url(
                    namespace=cluster_access_feature.get_namespace(),
                )
                delivery_db_feature_state = FeatureStates.AVAILABLE
            except secret_mgmt.SecretTypeNotFound:
                logger.warning('Delivery database config not found')

        else:
            logger.warning(
                'required cluster-access for delivery-db feature missing, will be disabled'
            )

    if delivery_db_feature_state is FeatureStates.AVAILABLE:
        middlewares.append(await middleware.db_session.db_session_middleware(
            db_url=db_url,
            verify_db_session=False,
        ))

    feature_cfgs.append(FeatureDeliveryDB(delivery_db_feature_state, db_url=db_url))

    event_handler = CfgFileChangeEventHandler()
    watch_for_file_changes(event_handler, paths.features_cfg_path())

    if extensions_cfg_path := paths.extensions_cfg_path(absent_ok=True):
        watch_for_file_changes(event_handler, extensions_cfg_path)
    if findings_cfg_path := paths.findings_cfg_path(absent_ok=True):
        watch_for_file_changes(event_handler, findings_cfg_path)
    if ocm_repo_mappings_path := paths.ocm_repo_mappings_path(absent_ok=True):
        watch_for_file_changes(event_handler, ocm_repo_mappings_path)
    if profiles_path := paths.profiles_path(absent_ok=True):
        watch_for_file_changes(event_handler, profiles_path)

    apply_raw_cfg()

    return middlewares


class Features(aiohttp.web.View):
    async def get(self):
        '''
        ---
        description: Returns a list of available and unavailable features with optional extra cfg.
        tags:
        - Features
        produces:
        - application/json
        parameters:
        - in: query
          name: profile
          type: string
          required: false
        responses:
          "200":
            schema:
              type: object
              required:
              - features
              properties:
                features:
                  type: array
                  items:
                    type: object
                    required:
                    - name
                    - state
                    properties:
                      name:
                        type: string
                      state:
                        type: string
                        enum:
                          - available
                          - unavailable
        '''
        params = self.request.rel_url.query

        profiles_callback = self.request.app[consts.APP_PROFILES_CALLBACK]
        profile = profiles_callback(util.param(params, 'profile'))

        self.feature_cfgs = list(f.serialize(profile) for f in feature_cfgs)

        return aiohttp.web.json_response(
            data={
                'features': self.feature_cfgs,
            },
            dumps=util.dict_to_json_factory,
        )


@middleware.auth.noauth
class Profiles(aiohttp.web.View):
    async def get(self):
        '''
        ---
        description: Returns a list of available profile names.
        tags:
        - Features
        produces:
        - application/json
        responses:
          "200":
            schema:
              type: object
              required:
              - features
              properties:
                profiles:
                  type: array
                  items:
                    type: string
        '''
        profiles_feature = get_feature(FeatureProfiles)

        return aiohttp.web.json_response(
            data={
                'profiles': [profile.name for profile in profiles_feature.profiles],
            },
            dumps=util.dict_to_json_factory,
        )
