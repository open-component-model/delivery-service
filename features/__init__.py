import collections.abc
import dataclasses
import datetime
import enum
import functools
import logging
import os
import re
import watchdog.events
import watchdog.observers.polling

import aiohttp.web
import dacite
import dateutil.parser
import github3.repos
import yaml

import ci.util
import cnudie.retrieve
import ocm

import ctx_util
import k8s.util
import lookups
import middleware.auth
import middleware.db_session
import paths
import secret_mgmt
import secret_mgmt.oauth_cfg
import secret_mgmt.signing_cfg
import util
import rescore.model as rm
import yp


own_dir = os.path.abspath(os.path.dirname(__file__))
repo_dir = os.path.abspath(os.path.join(own_dir, os.pardir))

logger = logging.getLogger(__name__)
feature_cfgs = []


class VersionFilter(enum.StrEnum):
    ALL = 'all'
    RELEASES_ONLY = 'releases_only'


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


class CurrentVersionSourceType(enum.Enum):
    GITHUB = 'github'


@dataclasses.dataclass(frozen=True)
class CurrentVersion:
    @dataclasses.dataclass(frozen=True)
    class CurrentVersionSource:
        type: CurrentVersionSourceType
        repo: str
        relpath: list[dict | str]
        postprocess: bool | None

    source: CurrentVersionSource

    def retrieve(self, github_api_lookup):
        '''
        Returns the currently referenced version of the component, e.g. in the
        Gardener context the current LSSD version for a specific landscape.
        '''
        if not self.source.type is CurrentVersionSourceType.GITHUB:
            raise NotImplementedError()

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
    :param VersionFilter versionFilter:
        (optional), specify which versions to include when resolving the version
        alias `greatest`; if not set it defaults to only consider
        release versions according to SemVer (no suffix/snapshot)
    :param SprintRules sprintRules:
        (optional), rules to enrich the component with special conditions based
        on the current sprint
    :param str repoContextUrl:
        (optional), repo context which should be used instead of the default repo
    :param CurrentVersion currentVersion:
        (optional), specifies where to find the current (not yet) published
        component version
    :param list[SpecialComponentDependency] dependencies:
        (optional), list of dependencies in a certain version which belong to
        the `currentVersion` of the component
    '''
    id: int
    name: str
    displayName: str
    type: str
    version: str | CurrentVersion
    versionFilter: VersionFilter | None
    icon: str | None
    releasePipelineUrl: str | None
    sprintRules: SprintRules | None
    repoContextUrl: str | None
    currentVersion: CurrentVersion | None
    dependencies: list[SpecialComponentDependency] | None


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


@dataclasses.dataclass(frozen=True)
class SprintDateNameMapping:
    dateName: str
    displayName: str


class FeatureStates(enum.Enum):
    AVAILABLE = 'available'
    UNAVAILABLE = 'unavailable'


@dataclasses.dataclass(frozen=True)
class FeatureBase:
    state: FeatureStates

    def serialize(self) -> dict[str, any]:
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

        return 'local-configuration'

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

    def serialize(self) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


@dataclasses.dataclass(frozen=True)
class FeatureAuthentication(FeatureBase):
    name: str = 'authentication'
    signing_cfgs: list[secret_mgmt.signing_cfg.SigningCfg] = dataclasses.field(default_factory=list)
    oauth_cfgs: list[secret_mgmt.oauth_cfg.OAuthCfg] = dataclasses.field(default_factory=list)

    def serialize(self) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


@dataclasses.dataclass(frozen=True)
class FeatureDeliveryDB(FeatureBase):
    name: str = 'delivery-db'
    db_url: str = None

    def get_db_url(self) -> str | None:
        return self.db_url

    def serialize(self) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


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
class FeatureRepoContexts(FeatureBase):
    name: str = 'repo-contexts'
    ocm_repo_mappings: list[cnudie.retrieve.OcmRepositoryMappingEntry] = None

    def get_ocm_repo_mappings(self) -> list[cnudie.retrieve.OcmRepositoryMappingEntry]:
        if self.state is FeatureStates.AVAILABLE:
            return self.ocm_repo_mappings

    def get_ocm_repos(self) -> collections.abc.Generator[ocm.OciOcmRepository, None, None] | None:
        if self.state is FeatureStates.UNAVAILABLE:
            return None

        yield from { # use set for deduplication
            ocm.OciOcmRepository(baseUrl=mapping.repository)
            for mapping in self.ocm_repo_mappings
        }

    def serialize(self) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
            'cfg': {
                'repoContexts': list(self.get_ocm_repos()),
            },
        }


@dataclasses.dataclass(frozen=True)
class FeatureServiceExtensions(FeatureBase):
    name: str = 'service-extensions'
    services: tuple[str] = tuple()
    namespace: str = None
    kubernetes_cfg_name: str = None
    kubeconfig_path: str = None

    def get_services(self) -> tuple[str]:
        return self.services

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
class FeatureSpecialComponents(FeatureBase):
    name: str = 'special-components'
    cfg: dict[str, any] = None

    def get_special_component(self, component_name: str) -> SpecialComponentsCfg | None:
        return next(
            (
                component for component in self.cfg['specialComponents']
                if component.name == component_name
            ),
            None,
        )

    def serialize(self) -> dict[str, any]:
        cfg = self.cfg.copy()
        github_api_lookup = lookups.github_api_lookup()
        for component in cfg['specialComponents']:
            if isinstance(component.version, CurrentVersion):
                component.version = component.version.retrieve(
                    github_api_lookup=github_api_lookup,
                )
        return {
            'state': self.state,
            'name': self.name,
            'cfg': cfg,
        }


@dataclasses.dataclass(frozen=True)
class FeatureRescoring(FeatureBase):
    name: str = 'rescoring'
    default_rule_sets: list[rm.DefaultRuleSet] = dataclasses.field(default_factory=list)
    rescoring_rule_sets: list[rm.RuleSet] = dataclasses.field(default_factory=list)
    cve_categorisation_label_url: str = None
    cve_severity_url: str = None

    def find_rule_set(
        self,
        name: str,
        rule_set_type: rm.RuleSetType,
    ) -> rm.RuleSet | None:
        for rs in self.rescoring_rule_sets:
            if (
                rs.name == name
                and rs.type is rule_set_type
            ):
                return rs
        return None


@dataclasses.dataclass(frozen=True)
class FeatureSprints(FeatureBase):
    name: str = 'sprints'
    sprints_relpath: str = None
    sprint_date_display_name_mappings: tuple[SprintDateNameMapping] = tuple()
    github_repo: github3.repos.Repository | None = None

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
        meta_raw = self._get_content(
            relpath=self.sprints_relpath,
        )['meta']

        return dacite.from_dict(
            data_class=yp.SprintMetadata,
            data=meta_raw,
        )

    def get_sprints(self) -> list[yp.Sprint]:
        sprints_raw = self._get_content(
            relpath=self.sprints_relpath,
        )['sprints']

        return [
            dacite.from_dict(
                data_class=yp.Sprint,
                data=sprint_raw,
                config=dacite.Config(
                    type_hooks={
                        datetime.datetime: lambda date: dateutil.parser.isoparse(date),
                    },
                ),
            ) for sprint_raw in sprints_raw
        ]

    def get_sprint_date_display_name(self, sprint_date_name: str) -> str:
        for sprint_date_display_name_mapping in self.sprint_date_display_name_mappings:
            if sprint_date_name == sprint_date_display_name_mapping.dateName:
                return sprint_date_display_name_mapping.displayName
        return sprint_date_name

    def serialize(self) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


class UPRIdentificationMethods(enum.Enum):
    TITLE = 'title'


@dataclasses.dataclass(frozen=True)
class FeatureUpgradePRs(FeatureBase):
    name: str = 'upgrade-prs'
    regex: re.Pattern = None,

    def get_regex(self) -> re.Pattern | None:
        return self.regex

    def serialize(self) -> dict[str, any]:
        return {
            'state': self.state,
            'name': self.name,
        }


@dataclasses.dataclass(frozen=True)
class FeatureVersionFilter(FeatureBase):
    name: str = 'version-filter'
    version_filter: VersionFilter = VersionFilter.RELEASES_ONLY

    def get_version_filter(self) -> VersionFilter:
        return self.version_filter


def get_feature(
    feature_type: type[FeatureBase],
) -> FeatureBase | None:
    for f in feature_cfgs:
        if isinstance(f, feature_type):
            return f
    return None


def deserialise_addressbook(addressbook_raw: dict) -> FeatureAddressbook:
    if not (addressbook_relpath := addressbook_raw.get('addressbookRelpath')):
        return FeatureAddressbook(FeatureStates.UNAVAILABLE)

    if not (github_mappings_relpath := addressbook_raw.get('githubMappingsRelpath')):
        return FeatureAddressbook(FeatureStates.UNAVAILABLE)

    if github_repo_url := addressbook_raw.get('repoUrl'):
        github_repo_lookup = lookups.github_repo_lookup(
            lookups.github_api_lookup(),
        )
        github_repo = github_repo_lookup(github_repo_url)
    else:
        github_repo = None

    return FeatureAddressbook(
        FeatureStates.AVAILABLE,
        addressbook_relpath=addressbook_relpath,
        github_mappings_relpath=github_mappings_relpath,
        github_repo=github_repo,
    )


def deserialise_repo_contexts(
    ocm_repo_mappings_raw: dict,
) -> FeatureRepoContexts:
    ocm_repo_mappings = [
        dacite.from_dict(
            data_class=cnudie.retrieve.OcmRepositoryMappingEntry,
            data=raw_mapping,
        ) for raw_mapping in ocm_repo_mappings_raw
    ]

    return FeatureRepoContexts(
        FeatureStates.AVAILABLE,
        ocm_repo_mappings=ocm_repo_mappings,
    )


def deserialise_special_components(special_components_raw: dict) -> FeatureSpecialComponents:
    def deserialise_current_version_source(
        current_version_source: CurrentVersion.CurrentVersionSource,
    ) -> CurrentVersion.CurrentVersionSource:
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
        current_version_source['type'] = CurrentVersionSourceType(current_version_source['type'])

        return current_version_source

    special_components = [
        dacite.from_dict(
            data_class=SpecialComponentsCfg,
            data=special_component_raw,
            config=dacite.Config(
                type_hooks={
                    CurrentVersion.CurrentVersionSource:
                        lambda cvs: deserialise_current_version_source(cvs),
                },
                cast=[VersionFilter],
            ),
        )
        for special_component_raw in special_components_raw
    ]

    return FeatureSpecialComponents(
        FeatureStates.AVAILABLE,
        cfg={
            'specialComponents': special_components,
        },
    )


def deserialise_rescoring(rescoring_raw: dict) -> FeatureRescoring:
    cve_rescoring_rule_sets = tuple(
        # Pylint struggles with generic dataclasses, see: github.com/pylint-dev/pylint/issues/9488
        rm.CveRescoringRuleSet( #noqa:E1123
            name=rule_set_raw['name'],
            description=rule_set_raw.get('description'),
            rules=list(
                rm.cve_rescoring_rules_from_dicts(rule_set_raw['rules'])
            )
        )
        for rule_set_raw in rescoring_raw['rescoringRuleSets']
        if rule_set_raw['type'] == rm.RuleSetType.CVE
    )
    sast_rescoring_rule_sets = tuple(
        # Pylint struggles with generic dataclasses, see: github.com/pylint-dev/pylint/issues/9488
        rm.SastRescoringRuleSet( #noqa:E1123
            name=rule_set_raw['name'],
            description=rule_set_raw.get('description'),
            rules=list(
                rm.sast_rescoring_rules_from_dict(rule_set_raw['rules'])
            )
        )
        for rule_set_raw in rescoring_raw['rescoringRuleSets']
        if rule_set_raw['type'] is rm.RuleSetType.SAST.value
    )
    default_rule_sets = [
        dacite.from_dict(
            data_class=rm.DefaultRuleSet,
            data=default_rule_set_raw,
            config=dacite.Config(
                cast=[rm.RuleSetType],
            )
        )
        for default_rule_set_raw in rescoring_raw['defaultRuleSetNames']
    ]

    return FeatureRescoring(
        state=FeatureStates.AVAILABLE,
        default_rule_sets=default_rule_sets,
        rescoring_rule_sets=cve_rescoring_rule_sets + sast_rescoring_rule_sets,
        cve_categorisation_label_url=rescoring_raw.get('cveCategorisationLabelUrl'),
        cve_severity_url=rescoring_raw.get('cveSeverityUrl'),
    )


def deserialise_sprints(sprints_raw: dict) -> FeatureSprints:
    def deserialise_sprint_date_display_name_mappings() -> tuple[SprintDateNameMapping]:
        sprint_date_name_mappings_raw = sprints_raw.get('sprintDateNameMappings', tuple())
        sprint_date_name_mappings = tuple(
            dacite.from_dict(
                data_class=SprintDateNameMapping,
                data=sprint_date_name_mapping,
            )
            for sprint_date_name_mapping in sprint_date_name_mappings_raw
        )
        return sprint_date_name_mappings

    if not (sprints_relpath := sprints_raw.get('sprintsRelpath')):
        return FeatureSprints(FeatureStates.UNAVAILABLE)

    if github_repo_url := sprints_raw.get('repoUrl'):
        github_repo_lookup = lookups.github_repo_lookup(
            lookups.github_api_lookup(),
        )
        github_repo = github_repo_lookup(github_repo_url)
    else:
        github_repo = None

    return FeatureSprints(
        FeatureStates.AVAILABLE,
        sprints_relpath=sprints_relpath,
        sprint_date_display_name_mappings=deserialise_sprint_date_display_name_mappings(),
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


def deserialise_upgrade_prs(upgrade_prs_raw: dict) -> FeatureUpgradePRs:
    # If no further configuration is provided, fallback to default configuration
    # which is identification via Gardener's UPR title pattern
    if not upgrade_prs_raw:
        return FeatureUpgradePRs(FeatureStates.AVAILABLE, regex=None)

    identification_method = UPRIdentificationMethods(upgrade_prs_raw['identificationMethod'])
    if identification_method == UPRIdentificationMethods.TITLE:
        regex = re.compile(r'' + upgrade_prs_raw['titleRegex'])
        return FeatureUpgradePRs(
            FeatureStates.AVAILABLE,
            regex=regex,
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
    addressbook = raw.get(
        'addressbook',
        FeatureAddressbook(FeatureStates.UNAVAILABLE),
    )
    if isinstance(addressbook, FeatureAddressbook):
        yield addressbook
    else:
        yield deserialise_addressbook(addressbook)

    ocm_repo_mappings = raw.get(
        'ocmRepoMappings',
        FeatureRepoContexts(FeatureStates.UNAVAILABLE),
    )
    if isinstance(ocm_repo_mappings, FeatureRepoContexts):
        yield ocm_repo_mappings
    else:
        yield deserialise_repo_contexts(ocm_repo_mappings)

    special_components = raw.get(
        'specialComponents',
        FeatureSpecialComponents(FeatureStates.UNAVAILABLE),
    )
    if isinstance(special_components, FeatureSpecialComponents):
        yield special_components
    else:
        yield deserialise_special_components(special_components)

    rescoring = raw.get(
        'rescoring',
        FeatureRescoring(FeatureStates.UNAVAILABLE),
    )
    if isinstance(rescoring, FeatureRescoring):
        yield rescoring
    else:
        yield deserialise_rescoring(rescoring)

    sprints = raw.get(
        'sprints',
        FeatureSprints(FeatureStates.UNAVAILABLE),
    )
    if isinstance(sprints, FeatureSprints):
        yield sprints
    else:
        yield deserialise_sprints(sprints)

    tests = raw.get(
        'tests',
        FeatureTests(FeatureStates.UNAVAILABLE),
    )
    if isinstance(tests, FeatureTests):
        yield tests
    else:
        yield deserialise_tests(tests)

    upgrade_prs = raw.get(
        'upgradePRs',
        FeatureUpgradePRs(FeatureStates.UNAVAILABLE),
    )
    if isinstance(upgrade_prs, FeatureUpgradePRs):
        yield upgrade_prs
    else:
        yield deserialise_upgrade_prs(upgrade_prs)

    # if no custom config is provided, fallback to default config of feature
    version_filter = raw.get(
        'versionFilter',
        FeatureVersionFilter(state=FeatureStates.AVAILABLE),
    )
    if isinstance(version_filter, FeatureVersionFilter):
        yield version_filter
    else:
        yield FeatureVersionFilter(
            state=FeatureStates.AVAILABLE,
            version_filter=VersionFilter(version_filter),
        )


def apply_raw_cfg():
    global feature_cfgs
    raw = ci.util.parse_yaml_file(paths.features_cfg_path())
    for cfg in deserialise_cfg(raw):
        feature_cfgs = [f for f in feature_cfgs if type(f) is not type(cfg)]
        feature_cfgs.append(cfg)


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

    delivery_db_feature_state = FeatureStates.UNAVAILABLE
    if (db_url := parsed_arguments.delivery_db_url):
        delivery_db_feature_state = FeatureStates.AVAILABLE
    else:
        try:
            db_cfg = secret_factory.delivery_db(parsed_arguments.delivery_db_cfg)
            db_url = db_cfg.url
            delivery_db_feature_state = FeatureStates.AVAILABLE
        except (secret_mgmt.SecretTypeNotFound, secret_mgmt.SecretElementNotFound):
            logger.warning('Delivery database config not found')

    if delivery_db_feature_state is FeatureStates.AVAILABLE:
        middlewares.append(await middleware.db_session.db_session_middleware(
            db_url=db_url,
            verify_db_session=False,
        ))

    feature_cfgs.append(FeatureDeliveryDB(delivery_db_feature_state, db_url=db_url))

    extension_feature = FeatureServiceExtensions(FeatureStates.UNAVAILABLE)
    if services := parsed_arguments.service_extensions:
        k8s_cfg_name = parsed_arguments.k8s_cfg_name
        if not k8s_cfg_name:
            k8s_cfg_name = os.environ.get('K8S_CFG_NAME')

        kubeconfig_path = parsed_arguments.kubeconfig

        k8s_namespace = parsed_arguments.k8s_namespace
        if not k8s_namespace:
            k8s_namespace = os.environ.get('K8S_TARGET_NAMESPACE')

        if k8s_namespace:
            extension_feature = FeatureServiceExtensions(
                state=FeatureStates.AVAILABLE,
                services=tuple(services),
                namespace=k8s_namespace,
                kubernetes_cfg_name=k8s_cfg_name,
                kubeconfig_path=kubeconfig_path,
            )
        else:
            logger.warning(
                'required cfgs for service-extension feature missing, will be disabled; '
                f'{k8s_cfg_name=}, {k8s_namespace=}'
            )

    feature_cfgs.append(extension_feature)

    event_handler = CfgFileChangeEventHandler()
    watch_for_file_changes(event_handler, paths.features_cfg_path())
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
        self.feature_cfgs = list(f.serialize() for f in feature_cfgs)

        return aiohttp.web.json_response(
            data={
                'features': self.feature_cfgs,
            },
            dumps=util.dict_to_json_factory,
        )
