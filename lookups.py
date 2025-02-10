import collections.abc
import dacite
import dataclasses
import datetime
import functools
import logging
import urllib.parse

import aiohttp
import requests
import requests.adapters

import cnudie.retrieve
import cnudie.retrieve_async
import cnudie.util
import delivery.client
import oci.auth
import oci.client
import oci.client_async
import ocm

import ctx_util
import deliverydb_cache.model as dcm
import deliverydb_cache.util as dcu
import paths
import secret_mgmt
import secret_mgmt.github
import secret_mgmt.oci_registry
import util


logger = logging.getLogger(__name__)


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


@functools.cache
def init_ocm_repository_lookup() -> cnudie.retrieve.OcmRepositoryLookup:
    if ocm_repo_mappings_path := paths.ocm_repo_mappings_path(absent_ok=True):
        ocm_repo_mappings_raw = util.parse_yaml_file(ocm_repo_mappings_path) or tuple()
    else:
        ocm_repo_mappings_raw = tuple()

    ocm_repo_mappings = tuple(
        dacite.from_dict(
            data_class=cnudie.retrieve.OcmRepositoryMappingEntry,
            data=raw_mapping,
        ) for raw_mapping in ocm_repo_mappings_raw
    )

    def ocm_repository_lookup(component: ocm.ComponentIdentity, /):
        for mapping in ocm_repo_mappings:
            if not mapping.prefix:
                yield mapping.repository
                continue

            component_name = cnudie.util.to_component_name(component)
            if component_name.startswith(mapping.prefix):
                yield mapping.repository

    return ocm_repository_lookup


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


def init_version_lookup(
    ocm_repository_lookup: cnudie.retrieve.OcmRepositoryLookup=None,
    oci_client: oci.client.Client=None,
    default_absent_ok: bool=False,
) -> cnudie.retrieve.VersionLookupByComponent:
    if not ocm_repository_lookup:
        ocm_repository_lookup = init_ocm_repository_lookup()

    if not oci_client:
        oci_client = semver_sanitising_oci_client()

    return cnudie.retrieve.version_lookup(
        ocm_repository_lookup=ocm_repository_lookup,
        oci_client=oci_client,
        default_absent_ok=default_absent_ok,
    )


def init_version_lookup_async(
    ocm_repository_lookup: cnudie.retrieve.OcmRepositoryLookup=None,
    oci_client: oci.client_async.Client=None,
    default_absent_ok: bool=False,
) -> cnudie.retrieve_async.VersionLookupByComponent:
    if not ocm_repository_lookup:
        ocm_repository_lookup = init_ocm_repository_lookup()

    if not oci_client:
        oci_client = semver_sanitising_oci_client_async()

    return cnudie.retrieve_async.version_lookup(
        ocm_repository_lookup=ocm_repository_lookup,
        oci_client=oci_client,
        default_absent_ok=default_absent_ok,
    )


def github_api_lookup(
    secret_factory: secret_mgmt.SecretFactory=None
) -> 'collections.abc.Callable[[str], github3.github.GitHub | None]': # avoid import
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
    ) -> 'github3.github.GitHub | None': # avoid import
        '''
        returns an initialised and authenticated apiclient object suitable for
        the passed repository URL

        raises ValueError if no configuration (credentials) is found for the given repository url
        unless absent_ok is set to a truthy value, in which case None is returned instead.
        '''
        try:
            return secret_mgmt.github.github_api(
                secret_factory=secret_factory,
                repo_url=repo_url,
            )
        except:
            if not absent_ok:
                raise
            else:
                return None

    return github_api_lookup


def github_repo_lookup(
    github_api_lookup,
):
    def github_repo_lookup(
        repo_url: str, /,
    ):
        if not '://' in repo_url:
            repo_url = f'x://{repo_url}'

        parsed = urllib.parse.urlparse(repo_url)
        org, repo = parsed.path.strip('/').split('/')[:2]

        gh_api = github_api_lookup(repo_url)

        return gh_api.repository(org, repo)

    return github_repo_lookup


def github_auth_token_lookup(url: str, /) -> str | None:
    '''
    an implementation of delivery.client.AuthTokenLookup
    '''
    secret_factory = ctx_util.secret_factory()

    github_cfg = secret_mgmt.github.find_cfg(
        secret_factory=secret_factory,
        repo_url=url,
    )

    if not github_cfg:
        return None

    return github_cfg.auth_token
