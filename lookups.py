import collections.abc
import dacite
import functools
import urllib.parse

import ccc.oci
import ci.util
import cnudie.retrieve
import cnudie.util
import delivery.client
import oci.client
import ocm

import ctx_util
import paths


def semver_sanitised_oci_client(
    cfg_factory=None,
) -> oci.client.Client:
    if not cfg_factory:
        cfg_factory = ctx_util.cfg_factory()

    return ccc.oci.oci_client(
        cfg_factory=cfg_factory,
        tag_preprocessing_callback=cnudie.util.sanitise_version,
        tag_postprocessing_callback=cnudie.util.desanitise_version,
    )


@functools.cache
def init_ocm_repository_lookup() -> cnudie.retrieve.OcmRepositoryLookup:
    if features_cfg_path := paths.features_cfg_path():
        features_cfg_raw = ci.util.parse_yaml_file(features_cfg_path)
        ocm_repo_mappings_raw = features_cfg_raw.get('ocmRepoMappings', tuple())
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
        oci_client = semver_sanitised_oci_client()

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


def init_version_lookup(
    ocm_repository_lookup: cnudie.retrieve.OcmRepositoryLookup=None,
    oci_client: oci.client.Client=None,
    default_absent_ok: bool=False,
) -> cnudie.retrieve.VersionLookupByComponent:
    if not ocm_repository_lookup:
        ocm_repository_lookup = init_ocm_repository_lookup()

    if not oci_client:
        oci_client = semver_sanitised_oci_client()

    return cnudie.retrieve.version_lookup(
        ocm_repository_lookup=ocm_repository_lookup,
        oci_client=oci_client,
        default_absent_ok=default_absent_ok,
    )


def github_api_lookup(
    cfg_factory=None,
) -> 'collections.abc.Callable[[str], github3.github.GitHub]': # avoid import
    '''
    creates a github-api-lookup. ideally, this lookup should be created at application launch, and
    passed to consumers.
    '''
    if not cfg_factory:
        cfg_factory = ctx_util.cfg_factory()

    def github_api_lookup(
        repo_url: str,
        /,
        absent_ok: bool=False,
    ) -> 'github3.github.GitHub | None': # avoid import
        '''
        returns an initialised and authenticated apiclient object suitable for
        the passed repository URL

        The implementation currently delegates lookup to `ccc.github.github_api`. Consistently using
        this wrapper will however allow for later decoupling.

        raises ValueError if no configuration (credentials) is found for the given repository url
        unless absent_ok is set to a truthy value, in which case None is returned instead.
        '''
        import ccc.github
        try:
            return ccc.github.github_api(
                repo_url=repo_url,
                cfg_factory=cfg_factory,
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
