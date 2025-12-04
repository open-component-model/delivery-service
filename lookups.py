import abc
import collections.abc
import dacite
import dataclasses
import datetime
import enum
import functools
import logging
import re
import typing
import urllib.parse

import aiohttp
import aiohttp.web
import github3.apps
import github3.github
import github3.repos
import requests
import requests.adapters

import cnudie.retrieve
import cnudie.retrieve_async
import cnudie.util
import delivery.client
import oci.client
import oci.client_async
import ocm
import version as versionutil

import ctx_util
import deliverydb_cache.model as dcm
import deliverydb_cache.util as dcu
import paths
import secret_mgmt
import secret_mgmt.github
import secret_mgmt.oci_registry
import util


logger = logging.getLogger(__name__)


class OcmRepositoryCfgNames(enum.StrEnum):
    AUTO = '<auto>'


class VersionFilter(enum.StrEnum):
    ANY = 'any'
    SEMVER_ANY = 'semver_any'
    SEMVER_NON_RELEASES = 'semver_non_releases'
    SEMVER_RELEASES = 'semver_releases'


class OcmRepositoryCfgType(enum.StrEnum):
    OCI = 'oci'
    VIRTUAL = 'virtual'


@dataclasses.dataclass
class OcmRepositoryCfgBase:
    type: OcmRepositoryCfgType

    @staticmethod
    def from_dict(raw: dict) -> typing.Union['OciOcmRepositoryCfg', 'VirtualOcmRepositoryCfg']:
        data_class = {
            OcmRepositoryCfgType.OCI: OciOcmRepositoryCfg,
            OcmRepositoryCfgType.VIRTUAL: VirtualOcmRepositoryCfg,
        }[OcmRepositoryCfgType(raw.get('type', OcmRepositoryCfgType.OCI))]

        return dacite.from_dict(
            data_class=data_class,
            data=raw,
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )

    @abc.abstractmethod
    def iter_ocm_repository_cfgs(
        self,
        ocm_repository_cfgs: collections.abc.Sequence[typing.Self],
    ) -> collections.abc.Iterable[typing.Self]:
        raise NotImplementedError('must be implemented by its subclasses')

    def iter_ocm_repositories(
        self,
        ocm_repository_cfgs: collections.abc.Sequence[typing.Self],
    ) -> collections.abc.Iterable[str]:
        for ocm_repository_cfg in self.iter_ocm_repository_cfgs(
            ocm_repository_cfgs=ocm_repository_cfgs,
        ):
            yield ocm_repository_cfg.repository


@dataclasses.dataclass(kw_only=True)
class OciOcmRepositoryCfg(OcmRepositoryCfgBase):
    type: OcmRepositoryCfgType = OcmRepositoryCfgType.OCI
    repository: str
    prefix: list[str] | str | None = None # for backwards compatibility -> TODO drop eventually
    prefixes: list[str] | str | None = None
    labels: list[str] | str | None = None
    version_filter: VersionFilter | str = VersionFilter.ANY

    def __post_init__(self):
        if self.prefix and not self.prefixes:
            self.prefixes = self.prefix # for backwards compatibility -> TODO drop eventually

        if isinstance(self.prefixes, str):
            self.prefixes = [self.prefixes]
        if isinstance(self.labels, str):
            self.labels = [self.labels]

    @property
    def ocm_repository(self) -> ocm.OciOcmRepository:
        return ocm.OciOcmRepository(
            baseUrl=self.repository,
        )

    def labels_match(
        self,
        labels: collections.abc.Iterable[str],
    ) -> bool:
        if self.labels is None:
            return False

        return set(labels).issubset(set(self.labels))

    def prefix_matches(
        self,
        component_name: str,
    ) -> bool:
        if self.prefixes is None:
            return True

        for prefix in self.prefixes:
            if component_name.startswith(prefix):
                return True

        return False

    def iter_matching_versions(
        self,
        versions: collections.abc.Iterable[str],
        version_filter_overwrite: VersionFilter | str | None=None,
    ) -> collections.abc.Iterable[str]:
        version_filter = version_filter_overwrite or self.version_filter

        for version in versions:
            version_semver = versionutil.parse_to_semver(
                version=version,
                invalid_semver_ok=True,
            )

            if version_filter is VersionFilter.ANY:
                pass # all versions are included

            elif version_filter is VersionFilter.SEMVER_ANY:
                if not version_semver:
                    continue

            elif version_filter is VersionFilter.SEMVER_NON_RELEASES:
                if not version_semver or not (version_semver.prerelease or version_semver.build):
                    continue

            elif version_filter is VersionFilter.SEMVER_RELEASES:
                if not version_semver or version_semver.prerelease or version_semver.build:
                    continue

            elif isinstance(version_filter, str):
                try:
                    if not re.fullmatch(version_filter, version):
                        continue
                except Exception:
                    raise aiohttp.web.HTTPBadRequest(
                        reason=f'Invalid regular expression as version filter: {version_filter}',
                    )

            else:
                raise TypeError(version_filter)

            yield version

    def iter_ocm_repository_cfgs(
        self,
        ocm_repository_cfgs: collections.abc.Sequence[typing.Self],
    ) -> collections.abc.Iterable[typing.Self]:
        yield self


@dataclasses.dataclass
class VirtualOcmRepositoryCfgSelector:
    required_labels: list[str] | str | None = None
    version_filter_overwrite: VersionFilter | str | None = None

    def __post_init__(self):
        if isinstance(self.required_labels, str):
            self.required_labels = [self.required_labels]


@dataclasses.dataclass(kw_only=True)
class VirtualOcmRepositoryCfg(OcmRepositoryCfgBase):
    type: OcmRepositoryCfgType = OcmRepositoryCfgType.VIRTUAL
    name: str
    selectors: list[VirtualOcmRepositoryCfgSelector] | VirtualOcmRepositoryCfgSelector | None = None

    def __post_init__(self):
        if isinstance(self.selectors, VirtualOcmRepositoryCfgSelector):
            self.selectors = [self.selectors]
        elif self.selectors is None:
            self.selectors = [VirtualOcmRepositoryCfgSelector()] # match all

    def iter_ocm_repository_cfgs(
        self,
        ocm_repository_cfgs: collections.abc.Sequence[OciOcmRepositoryCfg],
    ) -> collections.abc.Iterable[OciOcmRepositoryCfg]:
        for selector in self.selectors:
            found = False

            for ocm_repository_cfg in ocm_repository_cfgs:
                if not isinstance(ocm_repository_cfg, OciOcmRepositoryCfg):
                    continue # skip other virtual repository configurations

                if (
                    selector.required_labels
                    and not ocm_repository_cfg.labels_match(selector.required_labels)
                ):
                    continue # required labels do not match

                found = True
                yield dataclasses.replace(
                    ocm_repository_cfg,
                    version_filter=(
                        selector.version_filter_overwrite
                        or ocm_repository_cfg.version_filter
                    ),
                )

            if not found:
                raise ValueError(f'Could not resolve {selector=} in {ocm_repository_cfgs=}')


@functools.cache
def parse_ocm_repository_cfgs(
    default_repo: VirtualOcmRepositoryCfg=VirtualOcmRepositoryCfg(name=OcmRepositoryCfgNames.AUTO),
) -> tuple[OciOcmRepositoryCfg | VirtualOcmRepositoryCfg]:
    '''
    Reads and parses the OCM repository configurations from the known default locations. In case no
    `<auto>` virtual repository configuration is found, the default one is added.
    '''
    ocm_repository_cfgs_path = paths.ocm_repo_mappings_path()
    ocm_repository_cfgs_raw = util.parse_yaml_file(ocm_repository_cfgs_path) or ()

    ocm_repository_cfgs = [
        OcmRepositoryCfgBase.from_dict(ocm_repository_cfg_raw)
        for ocm_repository_cfg_raw in ocm_repository_cfgs_raw
    ]

    # insert default `<auto>` virtual repository configuration if not present
    if not any(
        ocm_repository_cfg.name == OcmRepositoryCfgNames.AUTO
        for ocm_repository_cfg in ocm_repository_cfgs
        if isinstance(ocm_repository_cfg, VirtualOcmRepositoryCfg)
    ):
        ocm_repository_cfgs.insert(0, default_repo)

    return tuple(ocm_repository_cfgs)


def filter_ocm_repository_cfgs(
    ocm_repo: str | None,
    ocm_repository_cfgs: collections.abc.Iterable[VirtualOcmRepositoryCfg | OciOcmRepositoryCfg],
) -> collections.abc.Iterable[VirtualOcmRepositoryCfg | OciOcmRepositoryCfg]:
    '''
    Filters the provided `ocm_repository_cfgs` based on the passed `ocm_repo` parameter. In case of
    virtual repository configurations, the `name` attribute is used for filtering. Otherwise, it is
    filtered based on the `repository` attribute.
    '''
    for ocm_repository_cfg in ocm_repository_cfgs:
        if isinstance(ocm_repository_cfg, VirtualOcmRepositoryCfg):
            if ocm_repo is None and ocm_repository_cfg.name == OcmRepositoryCfgNames.AUTO:
                yield ocm_repository_cfg

            elif ocm_repository_cfg.name == ocm_repo:
                yield ocm_repository_cfg

        elif isinstance(ocm_repository_cfg, OciOcmRepositoryCfg):
            if ocm_repository_cfg.repository == ocm_repo:
                yield ocm_repository_cfg

        else:
            raise TypeError(ocm_repository_cfg)


def resolve_ocm_repository_cfgs(
    ocm_repo: ocm.OciOcmRepository | str | None=None,
    ocm_repository_cfgs: collections.abc.Iterable[VirtualOcmRepositoryCfg | OciOcmRepositoryCfg] | None=None, # noqa: E501
) -> collections.abc.Iterable[OciOcmRepositoryCfg]:
    '''
    Filters the existing `ocm_repository_cfgs` (either passed-in or read from default file location)
    based on the passed `ocm_repo` parameter, and resolves virtual repository configurations to
    concrete ones. If the `ocm_repo` is not specified, the default `<auto>` virtual repository will
    be used.
    '''
    if not ocm_repository_cfgs:
        ocm_repository_cfgs = parse_ocm_repository_cfgs()

    if isinstance(ocm_repo, ocm.OciOcmRepository):
        ocm_repo = ocm_repo.oci_ref

    filtered_ocm_repository_cfgs = list(filter_ocm_repository_cfgs(
        ocm_repo=ocm_repo,
        ocm_repository_cfgs=ocm_repository_cfgs,
    ))

    if not filtered_ocm_repository_cfgs:
        logger.warning(f'No OCM repository configurations found for {ocm_repo=}, using default cfg')
        filtered_ocm_repository_cfgs.append(OciOcmRepositoryCfg(repository=ocm_repo))

    for ocm_repository_cfg in filtered_ocm_repository_cfgs:
        yield from ocm_repository_cfg.iter_ocm_repository_cfgs(
            ocm_repository_cfgs=ocm_repository_cfgs,
        )


def init_ocm_repository_lookup(
    ocm_repo: ocm.OciOcmRepository | str | None=None,
    ocm_repository_cfgs: collections.abc.Iterable[VirtualOcmRepositoryCfg | OciOcmRepositoryCfg] | None=None, # noqa: E501
) -> ocm.OcmRepositoryLookup:
    resolved_ocm_repository_cfgs = list(resolve_ocm_repository_cfgs(
        ocm_repo=ocm_repo,
        ocm_repository_cfgs=ocm_repository_cfgs,
    ))

    def ocm_repository_lookup(
        component: ocm.ComponentName,
        /,
    ) -> collections.abc.Iterable[str]:
        component_name = cnudie.util.to_component_name(component)
        repositories = set()

        for ocm_repository_cfg in resolved_ocm_repository_cfgs:
            if not ocm_repository_cfg.prefix_matches(component_name):
                continue

            repositories.add(ocm_repository_cfg.repository)

        yield from repositories

    return ocm_repository_lookup


@functools.cache
def semver_sanitising_oci_client(
    secret_factory: secret_mgmt.SecretFactory=None,
    http_connection_pool_size: int=16,
) -> oci.client.Client:
    if not secret_factory:
        secret_factory = ctx_util.secret_factory()

    credentials_lookup = secret_mgmt.oci_registry.oci_cfg_lookup(
        secret_factory=secret_factory,
    )

    routes = oci.client.OciRoutes()

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=http_connection_pool_size,
        pool_maxsize=http_connection_pool_size,
    )
    session.mount('https://', adapter)

    return oci.client.Client(
        credentials_lookup=credentials_lookup,
        routes=routes,
        session=session,
        tag_preprocessing_callback=cnudie.util.sanitise_version,
        tag_postprocessing_callback=cnudie.util.desanitise_version,
    )


@functools.cache
def semver_sanitising_oci_client_async(
    secret_factory: secret_mgmt.SecretFactory=None,
    http_connection_pool_size: int | None=None,
) -> oci.client_async.Client:
    if not secret_factory:
        secret_factory = ctx_util.secret_factory()

    credentials_lookup = secret_mgmt.oci_registry.oci_cfg_lookup(
        secret_factory=secret_factory,
    )

    routes = oci.client.OciRoutes()

    if http_connection_pool_size is None: # 0 is a valid value here (meaning no limitation)
        connector = aiohttp.TCPConnector()
    else:
        connector = aiohttp.TCPConnector(
            limit=http_connection_pool_size,
        )

    session = aiohttp.ClientSession(
        connector=connector,
    )

    return oci.client_async.Client(
        credentials_lookup=credentials_lookup,
        routes=routes,
        session=session,
        tag_preprocessing_callback=cnudie.util.sanitise_version,
        tag_postprocessing_callback=cnudie.util.desanitise_version,
    )


def db_cache_component_descriptor_lookup_async(
    db_url: str,
    ocm_repository_lookup: cnudie.retrieve.OcmRepositoryLookup=None,
    encoding_format: dcm.EncodingFormat=dcm.EncodingFormat.PICKLE,
    ttl_seconds: int=0,
    keep_at_least_seconds: int=0,
    max_size_octets: int=0,
) -> cnudie.retrieve_async.ComponentDescriptorLookupById:
    '''
    Used to lookup referenced component descriptors in the database cache. In case of a cache miss,
    the required component descriptor can be added to the cache by using the writeback function.

    @param db_url:
        url of the database containing the cache relation
    @param ocm_repository_lookup:
        lookup for OCM repositories
    @param encoding_format:
        format used to store the serialised component descriptor (this will have an impact on
        (de-)serialisation efficiency and storage size
    @param ttl_seconds:
        the maximum allowed time a cache item is valid in seconds
    @param keep_at_least_seconds:
        the minimum time a cache item should be kept
    @param max_size_octets:
        the maximum size of an individual cache entry, if the result exceeds this limit, it is not
        persistet in the database cache
    '''
    # late import to not require it in extensions which don't use async lookup
    import deliverydb.cache
    import deliverydb.model

    if ttl_seconds and ttl_seconds < keep_at_least_seconds:
        raise ValueError(
            'If time-to-live (`ttl_seconds`) and `keep_at_least_seconds` are both specified, '
            '`ttl_seconds` must be greater or equal than `keep_at_least_seconds`.'
        )

    async def writeback(
        component_id: ocm.ComponentIdentity,
        component_descriptor: ocm.ComponentDescriptor,
        start: datetime.datetime,
    ):
        descriptor = dcm.CachedComponentDescriptor(
            encoding_format=encoding_format,
            component_name=component_id.name,
            component_version=component_id.version,
            ocm_repository=component_descriptor.component.current_ocm_repo,
        )

        value = dcu.serialise_cache_value(
            value=util.dict_serialisation(dataclasses.asdict(component_descriptor)),
            encoding_format=encoding_format,
        )

        if max_size_octets > 0 and len(value) > max_size_octets:
            # don't store result in cache if it exceeds max size for an individual cache entry
            return

        now = datetime.datetime.now(datetime.timezone.utc)
        cache_entry = deliverydb.model.DBCache(
            id=descriptor.id,
            descriptor=util.dict_serialisation(dataclasses.asdict(descriptor)),
            delete_after=now + datetime.timedelta(seconds=ttl_seconds) if ttl_seconds else None,
            keep_until=now + datetime.timedelta(seconds=keep_at_least_seconds),
            costs=int((now - start).total_seconds() * 1000),
            size=len(value),
            value=value,
        )

        db_session = await deliverydb.sqlalchemy_session(db_url)
        try:
            await deliverydb.cache.add_or_update_cache_entry(
                db_session=db_session,
                cache_entry=cache_entry,
            )
        except Exception:
            raise
        finally:
            await db_session.close()

    async def lookup(
        component_id: cnudie.util.ComponentId,
        ocm_repository_lookup: cnudie.retrieve.OcmRepositoryLookup=ocm_repository_lookup,
    ):
        component_id = cnudie.util.to_component_id(component_id)

        ocm_repos = cnudie.retrieve.iter_ocm_repositories(
            component_id,
            ocm_repository_lookup,
        )

        db_session = await deliverydb.sqlalchemy_session(db_url)
        try:
            for ocm_repo in ocm_repos:
                if isinstance(ocm_repo, str):
                    ocm_repo = ocm.OciOcmRepository(
                        baseUrl=ocm_repo,
                    )

                if not isinstance(ocm_repo, ocm.OciOcmRepository):
                    raise NotImplementedError(ocm_repo)

                descriptor = dcm.CachedComponentDescriptor(
                    encoding_format=encoding_format,
                    component_name=component_id.name,
                    component_version=component_id.version,
                    ocm_repository=ocm_repo,
                )

                if value := await deliverydb.cache.find_cached_value(
                    db_session=db_session,
                    id=descriptor.id,
                ):
                    return ocm.ComponentDescriptor.from_dict(
                        component_descriptor_dict=dcu.deserialise_cache_value(
                            value=value,
                            encoding_format=encoding_format,
                        ),
                    )
        except Exception:
            raise
        finally:
            await db_session.close()

        # component descriptor not found in lookup
        start = datetime.datetime.now(tz=datetime.timezone.utc)
        return cnudie.retrieve_async.WriteBack(functools.partial(writeback, start=start))

    return lookup


def init_component_descriptor_lookup(
    ocm_repository_lookup: cnudie.retrieve.OcmRepositoryLookup=None,
    cache_dir: str=None,
    delivery_client: delivery.client.DeliveryServiceClient=None,
    oci_client: oci.client.Client=None,
    default_absent_ok: bool=False,
) -> cnudie.retrieve.ComponentDescriptorLookupById:
    '''
    convenience function to create a composite component descriptor lookup consisting of:
    - in-memory cache lookup
    - file-system cache lookup (if `cache_dir` is specified)
    - delivery-client lookup (if `delivery_client` is specified)
    - oci-client lookup
    '''
    if not ocm_repository_lookup:
        ocm_repository_lookup = init_ocm_repository_lookup()

    if not oci_client:
        oci_client = semver_sanitising_oci_client()

    lookups = [cnudie.retrieve.in_memory_cache_component_descriptor_lookup(
        ocm_repository_lookup=ocm_repository_lookup,
    )]

    if cache_dir:
        lookups.append(cnudie.retrieve.file_system_cache_component_descriptor_lookup(
            ocm_repository_lookup=ocm_repository_lookup,
            cache_dir=cache_dir,
        ))

    if delivery_client:
        lookups.append(cnudie.retrieve.delivery_service_component_descriptor_lookup(
            ocm_repository_lookup=ocm_repository_lookup,
            delivery_client=delivery_client,
        ))

    lookups.append(cnudie.retrieve.oci_component_descriptor_lookup(
        ocm_repository_lookup=ocm_repository_lookup,
        oci_client=oci_client,
    ))

    return cnudie.retrieve.composite_component_descriptor_lookup(
        lookups=lookups,
        ocm_repository_lookup=ocm_repository_lookup,
        default_absent_ok=default_absent_ok,
    )


def init_component_descriptor_lookup_async(
    ocm_repository_lookup: cnudie.retrieve.OcmRepositoryLookup=None,
    cache_dir: str=None,
    db_url: str=None,
    delivery_client: delivery.client.DeliveryServiceClient=None,
    oci_client: oci.client_async.Client=None,
    default_absent_ok: bool=False,
) -> cnudie.retrieve_async.ComponentDescriptorLookupById:
    '''
    convenience function to create a composite component descriptor lookup consisting of:
    - in-memory cache lookup
    - file-system cache lookup (if `cache_dir` is specified)
    - database (persistent) cache lookup (if `db_url` is specified)
    - delivery-client lookup (if `delivery_client` is specified)
    - oci-client lookup
    '''
    if not ocm_repository_lookup:
        ocm_repository_lookup = init_ocm_repository_lookup()

    if not oci_client:
        oci_client = semver_sanitising_oci_client_async()

    lookups = [cnudie.retrieve_async.in_memory_cache_component_descriptor_lookup(
        ocm_repository_lookup=ocm_repository_lookup,
    )]

    if cache_dir:
        lookups.append(cnudie.retrieve_async.file_system_cache_component_descriptor_lookup(
            ocm_repository_lookup=ocm_repository_lookup,
            cache_dir=cache_dir,
        ))

    if db_url:
        lookups.append(db_cache_component_descriptor_lookup_async(
            db_url=db_url,
            ocm_repository_lookup=ocm_repository_lookup,
        ))

    if delivery_client:
        lookups.append(cnudie.retrieve_async.delivery_service_component_descriptor_lookup(
            ocm_repository_lookup=ocm_repository_lookup,
            delivery_client=delivery_client,
        ))

    lookups.append(cnudie.retrieve_async.oci_component_descriptor_lookup(
        ocm_repository_lookup=ocm_repository_lookup,
        oci_client=oci_client,
    ))

    return cnudie.retrieve_async.composite_component_descriptor_lookup(
        lookups=lookups,
        ocm_repository_lookup=ocm_repository_lookup,
        default_absent_ok=default_absent_ok,
    )


def github_api_lookup(
    secret_factory: secret_mgmt.SecretFactory=None
) -> collections.abc.Callable[[str], github3.github.GitHub | None]:
    '''
    creates a github-api-lookup. ideally, this lookup should be created at application launch, and
    passed to consumers.
    '''
    if not secret_factory:
        secret_factory = ctx_util.secret_factory()

    def github_api_lookup(
        repo_url: str,
        /,
        absent_ok: bool=False,
    ) -> github3.github.GitHub | None:
        '''
        returns an initialised and authenticated apiclient object suitable for
        the passed repository URL

        raises ValueError if no configuration (credentials) is found for the given repository url
        unless absent_ok is set to a truthy value, in which case None is returned instead.
        '''
        return secret_mgmt.github.github_api(
            secret_factory=secret_factory,
            repo_url=repo_url,
            absent_ok=absent_ok,
        )

    return github_api_lookup


def github_repo_lookup(
    github_api_lookup,
) -> collections.abc.Callable[[str], github3.repos.Repository | None]:
    def github_repo_lookup(
        repo_url: str,
        /,
        absent_ok: bool=False,
    ) -> github3.repos.Repository | None:
        if not '://' in repo_url:
            repo_url = f'x://{repo_url}'

        parsed = urllib.parse.urlparse(repo_url)
        org, repo = parsed.path.strip('/').split('/')[:2]

        gh_api = github_api_lookup(
            repo_url,
            absent_ok=absent_ok,
        )

        if not gh_api and absent_ok:
            return None

        return gh_api.repository(org, repo)

    return github_repo_lookup


def github_auth_token_lookup(url: str, /) -> str | None:
    '''
    an implementation of delivery.client.AuthTokenLookup
    '''
    secret_factory = ctx_util.secret_factory()

    github_app_cfg = secret_mgmt.github.find_app_cfg(
        secret_factory=secret_factory,
        repo_url=url,
        absent_ok=True,
    )

    if not github_app_cfg:
        # XXX remove this case eventually when removing support for GitHub service accounts
        github_cfg = secret_mgmt.github.find_cfg(
            secret_factory=secret_factory,
            repo_url=url,
            absent_ok=True,
        )

        if not github_cfg:
            return None

        return github_cfg.auth_token

    if not github_app_cfg:
        # this conditional branch will become effectively once above legacy branch is removed
        return None

    return github3.apps.create_token(
        private_key_pem=github_app_cfg.private_key.encode('utf-8'),
        app_id=github_app_cfg.app_id,
    )
