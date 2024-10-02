import collections.abc
import dataclasses
import datetime
import dataclasses_json
import enum
import http
import io
import logging
import tarfile

import aiohttp.web
import dacite.exceptions
import dateutil.parser
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.orm.query as sq
import yaml

import ci.util
import cnudie.iter
import cnudie.iter_async
import cnudie.retrieve
import cnudie.retrieve_async
import cnudie.util
import dso.model
import gci.oci
import github.util
import oci.client_async
import oci.model as om
import ocm
import version as versionutil

import compliance_summary as cs
import consts
import deliverydb.model as dm
import deliverydb.util
import features
import lookups
import responsibles
import responsibles.github_statistics
import responsibles.labels
import util
import yp


logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class ComponentVector:
    '''
    Holds two component objects of the same Component, but different Versions.
    Represents a change in the component version from old_component to new_component.
    '''
    start: ocm.Component
    end: ocm.Component


cache_existing_components = []


async def check_if_component_exists(
    component_name: str,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent,
    raise_http_error: bool=False,
):
    if component_name in cache_existing_components:
        return True

    for _ in await version_lookup(component_name, None):
        cache_existing_components.append(component_name)
        return True

    if raise_http_error:
        raise aiohttp.web.HTTPNotFound(text=f'{component_name=} not found')
    return False


def get_creation_date(component: ocm.Component) -> datetime.datetime:
    '''
    Trys to extract creation date from creationTime attribute and if not set from label with name
    "cloud.gardener/ocm/creation-date".
    Raises KeyError, if both is not successful.
    '''

    if (creationTime := component.creationTime):
        return dateutil.parser.isoparse(creationTime)

    creation_label: ocm.Label | None = component.find_label('cloud.gardener/ocm/creation-date')

    if not creation_label:
        raise KeyError(
            'The attribute creation time, as well as the',
            'label named "cloud.gardener/ocm/creation-date", were not set.',
        )
    else:
        return dateutil.parser.isoparse(creation_label.value)


async def greatest_version_if_none(
    component_name: str,
    version: str,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent=None,
    ocm_repo: ocm.OcmRepository=None,
    oci_client: oci.client_async.Client=None,
    version_filter: features.VersionFilter=features.VersionFilter.RELEASES_ONLY,
    invalid_semver_ok: bool=False,
):
    if version is None:
        version = await greatest_component_version(
            component_name=component_name,
            version_lookup=version_lookup,
            ocm_repo=ocm_repo,
            oci_client=oci_client,
            version_filter=version_filter,
            invalid_semver_ok=invalid_semver_ok,
        )

    if not version:
        raise aiohttp.web.HTTPNotFound(
            reason='No greatest version found',
            text=f'No greatest version found for {component_name=}; {version_filter=}',
        )

    return version


async def _component_descriptor(
    params: dict,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent,
    version_filter: features.VersionFilter,
    invalid_semver_ok: bool=False,
) -> ocm.ComponentDescriptor:
    component_name = util.param(params, 'component_name', required=True)

    ocm_repo_url = util.param(params, 'ocm_repo_url')
    ocm_repo = ocm.OciOcmRepository(baseUrl=ocm_repo_url) if ocm_repo_url else None

    version = util.param(params, 'version', default='greatest')
    raw = util.param_as_bool(params, 'raw')
    ignore_cache = util.param_as_bool(params, 'ignore_cache')

    version_filter = util.param(params, 'version_filter', default=version_filter)
    util.get_enum_value_or_raise(version_filter, features.VersionFilter)

    if version == 'greatest':
        version = await greatest_version_if_none(
            component_name=component_name,
            version=None,
            version_lookup=version_lookup,
            ocm_repo=ocm_repo,
            version_filter=version_filter,
            invalid_semver_ok=invalid_semver_ok,
        )

    component_id = ocm.ComponentIdentity(
        name=component_name,
        version=version,
    )

    if ocm_repo_url:
        ocm_repos = (ocm_repo_url,)
    else:
        if not (lookup := lookups.init_ocm_repository_lookup()):
            raise ValueError('either ocm_repo_url, or ocm_repository_lookup must be passed')

        ocm_repos = cnudie.retrieve.iter_ocm_repositories(
            component_id,
            lookup,
        )

    if raw or ignore_cache:
        # in both cases fetch directly from oci-registry
        try:
            raw = await cnudie.retrieve_async.raw_component_descriptor_from_oci(
                component_id=component_id,
                ocm_repos=ocm_repos,
                oci_client=lookups.semver_sanitised_oci_client_async(),
            )

        except om.OciImageNotFoundException:
            raise aiohttp.web.HTTPNotFound(
                reason='Component descriptor not found',
                text=(
                    f'Component descriptor "{component_id.name}" in version '
                    f'"{component_id.version}" not found in {ocm_repo=}'
                ),
            )

        # wrap in fobj
        blob_fobj = io.BytesIO(raw)

        with tarfile.open(fileobj=blob_fobj, mode='r') as tf:
            component_descriptor_info = tf.getmember(gci.oci.component_descriptor_fname)
            component_descriptor_bytes = tf.extractfile(component_descriptor_info).read()

        if raw:
            component_descriptor = component_descriptor_bytes.decode()

        else:
            try:
                component_descriptor = ocm.ComponentDescriptor.from_dict(
                    yaml.safe_load(component_descriptor_bytes),
                )
            except dacite.exceptions.MissingValueError as e:
                raise aiohttp.web.HTTPFailedDependency(
                    reason=str(e),
                )

        return component_descriptor

    try:
        descriptor = await util.retrieve_component_descriptor(
            component_id,
            component_descriptor_lookup=component_descriptor_lookup,
            ocm_repo=ocm_repo,
        )
    except dacite.exceptions.MissingValueError as e:
        raise aiohttp.web.HTTPFailedDependency(
            reason=str(e),
        )

    return descriptor


class Component(aiohttp.web.View):
    async def get(self):
        params = self.request.rel_url.query

        component_descriptor = await _component_descriptor(
            params=params,
            component_descriptor_lookup=self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP],
            version_lookup=self.request.app[consts.APP_VERSION_LOOKUP],
            version_filter=self.request.app[consts.APP_VERSION_FILTER_CALLBACK](),
            invalid_semver_ok=self.request.app[consts.APP_INVALID_SEMVER_OK],
        )

        return aiohttp.web.json_response(
            data=component_descriptor,
            dumps=util.dict_to_json_factory,
        )


class ComponentDependencies(aiohttp.web.View):
    async def get(self):
        params = self.request.rel_url.query

        component_name = util.param(params, 'component_name', required=True)

        populate = util.param(params, 'populate', default='all')

        ocm_repo_url = util.param(params, 'ocm_repo_url')
        ocm_repo = ocm.OciOcmRepository(baseUrl=ocm_repo_url) if ocm_repo_url else None

        version = util.param(params, 'version', default='greatest')

        version_filter = util.param(
            params=params,
            name='version_filter',
            default=self.request.app[consts.APP_VERSION_FILTER_CALLBACK](),
        )
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        if version == 'greatest':
            version = await greatest_version_if_none(
                component_name=component_name,
                version=None,
                version_lookup=self.request.app[consts.APP_VERSION_LOOKUP],
                ocm_repo=ocm_repo,
                version_filter=version_filter,
                invalid_semver_ok=self.request.app[consts.APP_INVALID_SEMVER_OK],
            )

        component_dependencies = resolve_component_dependencies(
            component_name=component_name,
            component_version=version,
            component_descriptor_lookup=self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP],
            ocm_repo=ocm_repo,
        )

        filtered_component_dependencies = []
        async for component_node in component_dependencies:
            if populate == 'componentReferences':
                component_dependency = {
                    'name': component_node.component.name,
                    'version': component_node.component.version,
                    'repositoryContexts': component_node.component.repositoryContexts,
                }
            elif populate == 'all':
                component_dependency = dataclasses.asdict(component_node.component)
            else:
                raise aiohttp.web.HTTPBadRequest(text=f'{populate} not implemented')

            component_dependency['comp_ref'] = [
                {
                    'name': ref.component.name,
                    'version': ref.component.version,
                    'repositoryContexts': ref.component.repositoryContexts,
                }
                for ref in component_node.path
            ]
            filtered_component_dependencies.append(component_dependency)

        return aiohttp.web.json_response(
            data={
                'componentDependencies': filtered_component_dependencies,
            },
            dumps=util.dict_to_json_factory,
        )


class ComponentResponsibles(aiohttp.web.View):
    async def get(self):
        '''
        returns a list of user-identities responsible for the given component or resource

        **expected query parameters:**

            - component_name (required) \n
            - version (optional) \n
            - version_filter (optional) \n
            - ocm_repo_url (optional, defaults to delivery-service's global default ctx) \n
            - artifact_name (optional)

        if artifact_name is given, and specific responsibles are configured for the given resource
        (using label `cloud.gardener.cnudie/responsibles`), then those take precedence over
        component-wide responsibles.

        **response:**

            responsibles: \n
            - source: ... \n
              type: ... \n
              <type-specific-attributes>
            statuses: \n
            - type: <str> \n
              msg: <str> \n

        each user-identity consists of a list of typed userinfo-entries. callers should ignore
        types they do not know or care about. known types w/ examples:

            githubUser: \n
                source: <github-url> \n
                username: ... \n
                type: githubUser \n
                githubHostname: ... \n
            emailAddress: \n
                source: <url> \n
                email: ... \n
                type: emailAddress \n
            personalName: \n
                source: <url> \n
                firstName: ... \n
                lastName: ... \n
                type: personalName \n

        statuses allows to provide additional information to caller.
        e.g. to communicate that responsible label was malformed and heuristic was used as fallback
        '''
        params = self.request.rel_url.query
        statuses: list[responsibles.Status] = []

        component_descriptor = await _component_descriptor(
            params=params,
            component_descriptor_lookup=self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP],
            version_lookup=self.request.app[consts.APP_VERSION_LOOKUP],
            version_filter=self.request.app[consts.APP_VERSION_FILTER_CALLBACK](),
            invalid_semver_ok=self.request.app[consts.APP_INVALID_SEMVER_OK],
        )
        component = component_descriptor.component
        main_source = cnudie.util.main_source(component_descriptor.component)
        artifact_name = util.param(params, 'artifact_name')

        def _responsibles_label(
            component: ocm.Component,
            artifact_name: str | None=None,
            owners_label: str='cloud.gardener.cnudie/responsibles',
        ) -> responsibles.labels.ResponsiblesLabel | None:
            '''
            Returns the most specific ResponsiblesLabel for the given component and artifact name,
            or `None` if no label is found.

            If `artifact_name` is given, a fitting artifact with an owner label is looked up and
            the attached label is returned. Otherwise, a fallback to component-level owner-label
            happens.
            '''
            if artifact_name:
                matching_artifacts = [
                    a for a in component.resources + component.sources
                    if a.name == artifact_name
                ]
                if not matching_artifacts:
                    raise aiohttp.web.HTTPNotFound(
                        text=f'{component.name}:{component.version} has no {artifact_name=}'
                    )

                for artifact in matching_artifacts:
                    artifact: ocm.Artifact
                    # hack: hard-code to using first matching artifact with label for now
                    if responsibles_label := artifact.find_label(name=owners_label):
                        return responsibles.labels.ResponsiblesLabel.from_dict(
                            data_dict=dataclasses.asdict(responsibles_label),
                        )

            if responsibles_label := component.find_label(name=owners_label):
                return responsibles.labels.ResponsiblesLabel.from_dict(
                    data_dict=dataclasses.asdict(responsibles_label),
                )

            return None

        try:
            responsibles_label = _responsibles_label(
                component=component,
                artifact_name=artifact_name,
            )
        except (
            dacite.exceptions.UnionMatchError,
            dacite.exceptions.WrongTypeError,
            dacite.exceptions.UnexpectedDataError,
        ):
            responsibles_label = None # fallback to heuristic
            statuses.append(responsibles.Status(
                type='error',
                msg='responsibles-label malformed, falling back to responsibles-heuristic',
            ))
            logger.warning(
                'encountered errors while processing responsibles-label for '
                f'{component.identity()=}, {artifact_name=}'
            )

        if responsibles_label:
            user_identities = tuple(responsibles.user_identities_from_responsibles_label(
                responsibles_label=responsibles_label,
                source=main_source,
                component_identity=component_descriptor.component.identity(),
                github_api_lookup=self.request.app[consts.APP_GITHUB_API_LOOKUP],
            ))
        else:
            try:
                user_identities = responsibles.user_identities_from_source(
                    source=main_source,
                    github_api_lookup=self.request.app[consts.APP_GITHUB_API_LOOKUP],
                )
            except ValueError:
                user_identities = []
                statuses.append(responsibles.Status(
                    type='error',
                    msg='responsibles-heuristic was not able to determine responsibles as '
                        '(github) statistics are incomplete',
                ))

        if user_identities is None: # can be falsy
            # github statistics pending, client should retry
            return aiohttp.web.Response(
                status=http.HTTPStatus.ACCEPTED,
            )

        user_identities = [
            yp.inject(
                addressbook_source=self.request.app[consts.APP_ADDRESSBOOK_SOURCE],
                addressbook_entries=self.request.app[consts.APP_ADDRESSBOOK_ENTRIES],
                addressbook_github_mappings=self.request.app[consts.APP_ADDRESSBOOK_GITHUB_MAPPINGS],
                user_id=user_id,
            ).identifiers
            for user_id in user_identities
        ]

        return aiohttp.web.json_response(
            data={
                'responsibles': user_identities,
                'statuses': [dataclasses.asdict(s) for s in statuses],
            },
            dumps=util.dict_to_json_factory,
        )


async def component_versions(
    component_name: str,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent=None,
    ocm_repo: ocm.OcmRepository=None,
    oci_client: oci.client_async.Client=None,
) -> list[str]:
    if not ocm_repo and not version_lookup:
        raise ValueError('At least one of `ocm_repo` and `version_lookup` must be specified')

    if ocm_repo:
        if not isinstance(ocm_repo, ocm.OciOcmRepository):
            raise NotImplementedError(ocm_repo)

        if not oci_client:
            oci_client = lookups.semver_sanitised_oci_client_async()

        try:
            return await cnudie.retrieve_async.component_versions(
                component_name=component_name,
                ctx_repo=ocm_repo,
                oci_client=oci_client,
            )
        except aiohttp.ClientResponseError:
            return []

    return await version_lookup(
        component_id=ocm.ComponentIdentity(
            name=component_name,
            version=None
        ),
    )


async def greatest_component_version(
    component_name: str,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent=None,
    ocm_repo: ocm.OcmRepository=None,
    oci_client: oci.client_async.Client=None,
    version_filter: features.VersionFilter=features.VersionFilter.RELEASES_ONLY,
    invalid_semver_ok: bool=False,
) -> str | None:
    versions = await component_versions(
        component_name=component_name,
        version_lookup=version_lookup,
        ocm_repo=ocm_repo,
        oci_client=oci_client,
    )

    greatest_candidate = None
    greatest_candidate_semver = None
    for candidate in versions:
        if isinstance(candidate, str):
            candidate_semver = versionutil.parse_to_semver(
                version=candidate,
                invalid_semver_ok=invalid_semver_ok,
            )

            if not candidate_semver:
                continue
        else:
            candidate_semver = candidate

        if (
            version_filter == features.VersionFilter.RELEASES_ONLY
            and (candidate_semver.prerelease or candidate_semver.build)
        ):
            continue

        if not greatest_candidate_semver:
            greatest_candidate_semver = candidate_semver
            greatest_candidate = candidate
            continue

        if candidate_semver > greatest_candidate_semver:
            greatest_candidate_semver = candidate_semver
            greatest_candidate = candidate

    return greatest_candidate


async def greatest_component_versions(
    component_name: str,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    ocm_repo: ocm.OcmRepository=None,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent=None,
    max_versions: int=5,
    greatest_version: str=None,
    oci_client: oci.client_async.Client=None,
    version_filter: features.VersionFilter=features.VersionFilter.RELEASES_ONLY,
    invalid_semver_ok: bool=False,
    start_date: datetime.date=None,
    end_date: datetime.date=None,
) -> list[str]:
    versions = await component_versions(
        component_name=component_name,
        version_lookup=version_lookup,
        ocm_repo=ocm_repo,
        oci_client=oci_client,
    )

    if not versions:
        return []

    versions = [
        v for v in versions
        if versionutil.parse_to_semver(
            version=v,
            invalid_semver_ok=invalid_semver_ok,
        )
    ]

    if version_filter == features.VersionFilter.RELEASES_ONLY:
        versions = [
            v for v in versions
            if not (pv := versionutil.parse_to_semver(
                version=v,
                invalid_semver_ok=invalid_semver_ok,
            )).prerelease and not pv.build
        ]

    versions = sorted(versions, key=lambda v: versionutil.parse_to_semver(
        version=v,
        invalid_semver_ok=invalid_semver_ok,
    ))

    # If no end_date is provided, default to now
    if not end_date:
        end_date = datetime.date.today().isoformat()

    # Handle date range filtering only if start_date is provided
    if start_date:
        def filter_by_date_range(versions):
            for version in reversed(versions):
                component_descriptor = util.retrieve_component_descriptor(
                    ocm.ComponentIdentity(
                        name=component_name,
                        version=version,
                    ),
                    component_descriptor_lookup
                )
                creation_date = get_creation_date(
                    component_descriptor.component
                ).strftime('%Y-%m-%d')

                if creation_date > end_date:
                    continue

                if creation_date < start_date:
                    break

                yield version

        versions = list(filter_by_date_range(versions))

    if greatest_version:
        versions = versions[:versions.index(greatest_version) + 1]

    if not start_date:
        return versions[-max_versions:]

    return versions


class GreatestComponentVersions(aiohttp.web.View):
    async def get(self):
        params = self.request.rel_url.query

        component_name = util.param(params, 'component_name', required=True)
        max_version = util.param(params, 'max', default=5)
        start_date = util.param(params, 'start_date')
        end_date = util.param(params, 'end_date')
        version = util.param(params, 'version')

        ocm_repo_url = util.param(params, 'ocm_repo_url')
        ocm_repo = ocm.OciOcmRepository(baseUrl=ocm_repo_url) if ocm_repo_url else None

        version_filter = util.param(
            params=params,
            name='version_filter',
            default=self.request.app[consts.APP_VERSION_FILTER_CALLBACK](),
        )
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        try:
            versions = await greatest_component_versions(
                component_name=component_name,
                component_descriptor_lookup=self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP],
                ocm_repo=ocm_repo,
                version_lookup=self.request.app[consts.APP_VERSION_LOOKUP],
                max_versions=int(max_version),
                greatest_version=version,
                version_filter=version_filter,
                invalid_semver_ok=self.request.app[consts.APP_INVALID_SEMVER_OK],
                start_date=start_date,
                end_date=end_date,
            )
        except ValueError:
            raise aiohttp.web.HTTPNotFound(text=f'Version {version} not found')

        return aiohttp.web.json_response(
            data=versions,
            dumps=util.dict_to_json_factory,
        )


async def resolve_component_dependencies(
    component_name: str,
    component_version: str,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    ocm_repo: ocm.OcmRepository=None,
    recursion_depth: int=-1,
) -> collections.abc.AsyncGenerator[cnudie.iter.ComponentNode, None, None]:
    descriptor = await util.retrieve_component_descriptor(
        ocm.ComponentIdentity(
            name=component_name,
            version=component_version,
        ),
        component_descriptor_lookup=component_descriptor_lookup,
        ocm_repo=ocm_repo,
    )
    component = descriptor.component

    try:
        component_nodes = await _components(
            component_name=component.name,
            component_version=component.version,
            component_descriptor_lookup=component_descriptor_lookup,
            ocm_repo=ocm_repo,
            recursion_depth=recursion_depth,
        )
    except dacite.exceptions.MissingValueError as e:
        raise aiohttp.web.HTTPFailedDependency(text=str(e))

    # add repo classification label if not present in component labels
    async for component_node in component_nodes:
        label_present = False
        # if no sources present we cannot add the source
        if not len(component_node.component.sources) > 0:
            continue

        for source in component_node.component.sources:
            if 'cloud.gardener/cicd/source' in [label.name for label in source.labels]:
                label_present = True
                break
        if not label_present:
            component_node.component.sources[0].labels.append(ocm.Label(
                name='cloud.gardener/cicd/source',
                value={'repository-classification': 'main'},
            ))

        yield component_node


class UpgradePRs(aiohttp.web.View):
    required_features = (features.FeatureUpgradePRs,)

    async def get(self):
        params = self.request.rel_url.query

        component_name = util.param(params, 'componentName')
        component_version = util.param(params, 'componentVersion')
        repo_url = util.param(params, 'repoUrl')
        pr_state = util.param(params, 'state', default='open')

        ocm_repo_url = util.param(params, 'ocmRepo')
        ocm_repo = ocm.OciOcmRepository(baseUrl=ocm_repo_url) if ocm_repo_url else None

        version_filter = util.param(
            params=params,
            name='version_filter',
            default=self.request.app[consts.APP_VERSION_FILTER_CALLBACK](),
        )
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        if not (bool(component_name) ^ bool(repo_url)):
            raise aiohttp.web.HTTPBadRequest(
                text='Exactly one of componentName and repoUrl must be passed',
            )

        if component_name:
            component_version = await greatest_version_if_none(
                component_name=component_name,
                version=component_version,
                version_lookup=self.request.app[consts.APP_VERSION_LOOKUP],
                ocm_repo=ocm_repo,
                version_filter=version_filter,
                invalid_semver_ok=self.request.app[consts.APP_INVALID_SEMVER_OK],
            )

            component_descriptor = await util.retrieve_component_descriptor(
                ocm.ComponentIdentity(
                    name=component_name,
                    version=component_version,
                ),
                component_descriptor_lookup=self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP],
                ocm_repo=ocm_repo,
            )
            component = component_descriptor.component
            source = cnudie.util.main_source(
                component=component,
                absent_ok=True,
            )

            repo_url = source.access.repoUrl if source else component_name

        gh_api = self.request.app[consts.APP_GITHUB_API_LOOKUP](
            repo_url,
            absent_ok=True,
        )
        if not gh_api:
            # todo: rather raise/return http-error?
            logger.warning(f'no github-cfg found for {repo_url=}')
            return aiohttp.web.json_response(
                data=[],
            )

        parsed_url = ci.util.urlparse(repo_url)
        org, repo = parsed_url.path.strip('/').split('/')

        try:
            pr_helper = github.util.PullRequestUtil(
                owner=org,
                name=repo,
                github_api=gh_api,
            )
        except RuntimeError:
            # Component source repository not found
            return aiohttp.web.json_response(
                data=[],
            )

        upgrade_prs: collections.abc.Iterable[github.util.UpgradePullRequest] = pr_helper.enumerate_upgrade_pull_requests( # noqa:E501
            state=pr_state,
            pattern=self.request.app[consts.APP_UPR_REGEX_CALLBACK](),
        )

        def upgrade_pr_to_dict(upgrade_pr):
            from_ref: ocm.ComponentReference = upgrade_pr.from_ref
            to_ref: ocm.ComponentReference = upgrade_pr.to_ref
            pr = upgrade_pr.pull_request

            return {
                'from': {
                    'name': from_ref.name,
                    'version': from_ref.version,
                },
                'to': {
                    'name': to_ref.name,
                    'version': to_ref.version,
                },
                'pr': {
                    'title': pr.title,
                    'url': pr.url,
                    'html_url': pr.html_url,
                    'number': pr.number,
                }
            }

        return aiohttp.web.json_response(
            data=[upgrade_pr_to_dict(upgrade_pr) for upgrade_pr in upgrade_prs],
            dumps=util.dict_to_json_factory,
        )


class Issues(aiohttp.web.View):
    required_features = (features.FeatureIssues,)

    async def get(self):
        params = self.request.rel_url.query

        component_name = util.param(params, 'componentName', required=True)
        state = util.param(params, 'state', default='open')
        since = util.param(params, 'since')

        issue_repo = self.request.app[consts.APP_ISSUE_REPO_CALLBACK](component_name)

        if not issue_repo:
            return aiohttp.web.json_response(
                data=[],
            )

        ls_repo = self.request.app[consts.APP_GITHUB_REPO_LOOKUP](issue_repo)

        issues = ls_repo.issues(state=state, since=since)
        return aiohttp.web.json_response(
            data=[
                {
                    'id': issue.number,
                    'title': issue.title,
                    'state': issue.state,
                    'created_at': issue.created_at.isoformat(),
                    'url': issue.html_url,
                    'label': [
                        {
                            'id': label.id,
                            'name': label.name,
                            'color': label.color,
                            'description': label.description,
                        } for label in issue.labels()
                    ]
                } for issue in issues if 'pull_request' not in issue.as_dict()
            ],
            dumps=util.dict_to_json_factory,
        )


@dataclasses_json.dataclass_json
@dataclasses.dataclass
class ComponentRef:
    name: str
    version: str


@dataclasses_json.dataclass_json
@dataclasses.dataclass
class ComponentDiffRequest:
    left_component: ComponentRef
    right_component: ComponentRef


class ComponentDescriptorDiff(aiohttp.web.View):
    async def options(self):
        return aiohttp.web.Response()

    async def post(self):
        diff_request = ComponentDiffRequest.from_dict(await self.request.json())

        left_component_ref: ComponentRef = diff_request.left_component
        right_component_ref: ComponentRef = diff_request.right_component

        component_descriptor_lookup = self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP]

        left_descriptor = await util.retrieve_component_descriptor(
            ocm.ComponentIdentity(
                name=left_component_ref.name,
                version=left_component_ref.version,
            ),
            component_descriptor_lookup=component_descriptor_lookup,
        )
        right_descriptor = await util.retrieve_component_descriptor(
            ocm.ComponentIdentity(
                name=right_component_ref.name,
                version=right_component_ref.version,
            ),
            component_descriptor_lookup=component_descriptor_lookup,
        )

        try:
            diff = await cnudie.retrieve_async.component_diff(
                left_component=left_descriptor,
                right_component=right_descriptor,
                component_descriptor_lookup=component_descriptor_lookup,
            )
        except om.OciImageNotFoundException:
            err_str = 'Error occurred during calculation of component diff of ' \
            f'{left_descriptor.component.name=} in {left_descriptor.component.version=} and ' \
            f'{right_descriptor.component.name=} in {right_descriptor.component.version=}'
            logger.warning(err_str)
            raise aiohttp.web.HTTPUnprocessableEntity(
                reason='Error occurred during calculation of component diff',
                text=err_str,
            )

        def component_ref(component: ocm.Component):
            return {'name': component.name, 'version': component.version}

        def changed_component_info(left_comp: ocm.Component, right_comp: ocm.Component):
            resource_diff: cnudie.util.ResourceDiff = cnudie.util.diff_resources(
                left_component=left_comp,
                right_component=right_comp,
            )

            left = component_ref(left_comp)
            right = component_ref(right_comp)

            right['resources'] = {
                'added': [r for r in resource_diff.resource_refs_only_right],
                'removed': [r for r in resource_diff.resource_refs_only_left],
                'changed': [
                    changed_resource_info(left_resource, right_resource)
                    for left_resource, right_resource in resource_diff.resourcepairs_version_changed
                ],
            }
            right['label_diff'] = cnudie.util.diff_labels(left_comp.labels, right_comp.labels)

            return {
                'left': left,
                'right': right,
            }

        def changed_resource_info(left_resource: ocm.Resource, right_resource: ocm.Resource):
            label_diff: cnudie.util.LabelDiff = cnudie.util.diff_labels(
                left_labels=left_resource.labels,
                right_labels=right_resource.labels,
            )

            left_resource = dataclasses.asdict(left_resource)
            right_resource = dataclasses.asdict(right_resource)

            right_resource['label_diff'] = {
                'added': [r for r in label_diff.labels_only_right],
                'removed': [r for r in label_diff.labels_only_left],
                'changed': [
                    {
                        'from': left_label,
                        'to': right_label,
                    } for left_label, right_label in label_diff.label_pairs_changed
                ]
            }

            return {
                'from': left_resource,
                'to': right_resource,
            }

        identity_names_only_left = [i.name for i in diff.cidentities_only_left]
        identity_names_only_right = [i.name for i in diff.cidentities_only_right]

        # filtering is not 100% accurate: if more than one component of the same version were
        # contained, removal/addition would not be detected.
        return aiohttp.web.json_response(
            data={
                'components_added': [
                    component_ref(c) for c in diff.cidentities_only_right
                    if c.name not in identity_names_only_left
                ],
                'components_removed': [
                    component_ref(c) for c in diff.cidentities_only_left
                    if c.name not in identity_names_only_right
                ],

                'components_changed': [
                    changed_component_info(left_comp=left_comp, right_comp=right_comp)
                    for left_comp, right_comp in diff.cpairs_version_changed
                ],
            },
            dumps=util.dict_to_json_factory,
        )


async def _components(
    component_name: str,
    component_version: str,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    ocm_repo: ocm.OcmRepository=None,
    recursion_depth: int=-1,
) -> collections.abc.AsyncGenerator[cnudie.iter.ComponentNode, None, None]:
    component_descriptor = await util.retrieve_component_descriptor(
        ocm.ComponentIdentity(
            name=component_name,
            version=component_version,
        ),
        component_descriptor_lookup=component_descriptor_lookup,
        ocm_repo=ocm_repo,
    )

    try:
        return cnudie.iter_async.iter(
            component=component_descriptor,
            lookup=component_descriptor_lookup,
            recursion_depth=recursion_depth,
            prune_unique=False,
            node_filter=cnudie.iter.Filter.components,
        )
    except om.OciImageNotFoundException:
        err_str = 'Error occurred during retrieval of component dependencies of ' \
        f'{component_descriptor.component.name=} in {component_descriptor.component.version=}'
        logger.warning(err_str)
        raise aiohttp.web.HTTPUnprocessableEntity(
            reason='Error occurred during retrieval of component dependencies',
            text=err_str,
        )


class ComplianceSummary(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    async def get(self):
        '''
        returns most critical severity for artefact-metadata types, for all component-dependencies

        compliance-summaries contain severities and scan-statuses for artefact-metadata types.

        **expected query parameters:**

            - component_name (required) \n
            - version (required) \n
            - version_filter (optional) \n
            - ocm_repo_url (optional) \n
            - recursion_depth (optional) \n

        **response:**

            complianceSummary: \n
                componentId: \n
                    name: ... \n
                    version: ... \n
                entries: \n
                  - type: artefact-metadata type, e.g. finding/vulnerability \n
                    source: ... \n
                    severity: ... \n
                    scanStatus: ... \n
                artefacts: \n
                  - artefact: \n
                        component_name: ... \n
                        component_version: ... \n
                        artefact_kind: ... \n
                        artefact: \n
                            artefact_name: ... \n
                            artefact_version: ... \n
                            artefact_type: ... \n
                            artefact_extra_id: ... \n
                    entries: \n
                      - type: artefact-metadata type, e.g. finding/vulnerability \n
                        source: ... \n
                        severity: ... \n
                        scanStatus: ... \n
        '''
        params = self.request.rel_url.query
        artefact_metadata_cfg_by_type = self.request.app[consts.APP_ARTEFACT_METADATA_CFG]
        component_descriptor_lookup = self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP]
        eol_client = self.request.app[consts.APP_EOL_CLIENT]
        invalid_semver_ok = self.request.app[consts.APP_INVALID_SEMVER_OK]
        version_filter_callback = self.request.app[consts.APP_VERSION_FILTER_CALLBACK]
        version_lookup = self.request.app[consts.APP_VERSION_LOOKUP]

        component_name = util.param(params, 'component_name', required=True)

        ocm_repo_url = util.param(params, 'ocm_repo_url')
        ocm_repo = ocm.OciOcmRepository(baseUrl=ocm_repo_url) if ocm_repo_url else None

        version = util.param(params, 'version', required=True)

        version_filter = util.param(params, 'version_filter', default=version_filter_callback())
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        recursion_depth = int(util.param(params, 'recursion_depth', default=-1))

        if version == 'greatest':
            version = await greatest_version_if_none(
                component_name=component_name,
                version=None,
                version_lookup=version_lookup,
                ocm_repo=ocm_repo,
                version_filter=version_filter,
                invalid_semver_ok=invalid_semver_ok,
            )

        components_dependencies = resolve_component_dependencies(
            component_name=component_name,
            component_version=version,
            component_descriptor_lookup=component_descriptor_lookup,
            ocm_repo=ocm_repo,
            recursion_depth=recursion_depth,
        )

        components = [
            component_node.component
            async for component_node in components_dependencies
        ]

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        type_filter = (
            dso.model.Datatype.ARTEFACT_SCAN_INFO,
            dso.model.Datatype.LICENSE,
            dso.model.Datatype.VULNERABILITY,
            dso.model.Datatype.OS_IDS,
            dso.model.Datatype.CODECHECKS_AGGREGATED,
            dso.model.Datatype.MALWARE_FINDING,
        )

        db_statement_findings = sa.select(dm.ArtefactMetaData).where(
            sa.or_(*[
                query async for query in deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=components,
                    component_descriptor_lookup=component_descriptor_lookup,
                )
            ]),
            dm.ArtefactMetaData.type.in_(type_filter),
        )
        db_statement_rescorings = sa.select(dm.ArtefactMetaData).where(
            dm.ArtefactMetaData.type == dso.model.Datatype.RESCORING,
            sa.or_(*[
                query async for query in deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=components,
                    none_ok=True,
                    component_descriptor_lookup=component_descriptor_lookup,
                )
            ]),
            deliverydb.util.ArtefactMetadataFilters.filter_for_rescoring_type(type_filter),
        )

        db_stream_findings = await db_session.stream(db_statement_findings)
        findings = [
            deliverydb.util.db_artefact_metadata_row_to_dso(row)
            async for partition in db_stream_findings.partitions(size=50)
            for row in partition
        ]

        db_stream_rescorings = await db_session.stream(db_statement_rescorings)
        rescorings = [
            deliverydb.util.db_artefact_metadata_row_to_dso(row)
            async for partition in db_stream_rescorings.partitions(size=50)
            for row in partition
        ]

        return aiohttp.web.json_response(
            data={
                'complianceSummary': [
                    dataclasses.asdict(
                        obj=summary,
                        dict_factory=util.dict_factory_enum_name_serialisiation,
                    )
                    async for summary in cs.component_summaries(
                        findings=findings,
                        rescorings=rescorings,
                        components=components,
                        eol_client=eol_client,
                        artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
                    )
                ]
            },
            dumps=util.dict_to_json_factory,
        )


class Select(enum.Enum):
    GREATEST = 'greatestVersion'
    LATEST = 'latestData'


class ComponentMetadata(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    def _latest_metadata_query(
        self,
        metadata_types: collections.abc.Iterable[str],
        component_version: str | None,
        component_name: str,
    ) -> sq.Query:
        # The following is a nested query. First, in the subquery, the relevant entries in the table
        # are partitioned by metadata, sorted, and a rank-column is assigned to each row in the
        # resulting partitions.
        # Then, the actual query returns the rows where rank equals '1' from the subquery.
        subquery = sa.select(
            dm.ArtefactMetaData,
            sa.func.rank().over(
                order_by=dm.ArtefactMetaData.creation_date.desc(),
                partition_by=dm.ArtefactMetaData.type,
            ).label('rank')
        ).where(
            sa.and_(
                dm.ArtefactMetaData.component_name == component_name,
                (
                    # if no version is given, set this predicate to 'True' to avoid filtering
                    dm.ArtefactMetaData.component_version == component_version
                    if component_version else True
                ),
                # similarly, return results for all metadata types if no collection is given
                dm.ArtefactMetaData.type.in_(metadata_types) if metadata_types else True,
            )
        ).subquery()
        return sa.select(subquery).where(subquery.c.rank == 1)

    def _metadata_query_for_version(
        self,
        metadata_types: collections.abc.Iterable[str],
        component_version: str,
        component_name: str,
    ) -> sq.Query:
        subquery = sa.select(dm.ArtefactMetaData).where(
            sa.and_(
                dm.ArtefactMetaData.component_name == component_name,
                # return results for all metadata types if no collection (or an empty one) is given
                dm.ArtefactMetaData.type.in_(metadata_types) if metadata_types else True,
                dm.ArtefactMetaData.component_version == component_version,
            ),
        ).subquery()
        return sa.select(subquery)

    async def get(self):
        '''
        returns a list of artifact-metadata for the given component with optional filters

        **expected query parameters:**

            - name (required) \n
            - type (optional): The metadata-types to retrieve. Can be given multiple times. If \n
                no type is given, all relevant metadata will be returned. \n
            - select (optional): Currently either `greatestVersion` or `latestDate`. \n
            - version (optional): The component version to consider. \n
            - version_filter (optional) \n

        One of 'select' and 'version' must be given. However, if 'select' is given as
        `greatestVersion` 'version' must _not_ be given.

        **response:**

            - artefact: <object> \n
                component_name: <str> \n
                component_version: <str> \n
                artefact_kind: <str> \n
                artefact: <object> \n
                    artefact_name: <str> \n
                    artefact_version: <str> \n
                    artefact_type: <str> \n
                    artefact_extra_id: <object> \n
            meta: <object> \n
                type: <str> \n
                datasource: <str> \n
            data: <object> # schema depends on meta.type \n
        '''
        params = self.request.rel_url.query
        invalid_semver_ok = self.request.app[consts.APP_INVALID_SEMVER_OK]
        version_filter_callback = self.request.app[consts.APP_VERSION_FILTER_CALLBACK]
        version_lookup = self.request.app[consts.APP_VERSION_LOOKUP]

        component_name = util.param(params, 'name', required=True)
        component_version = util.param(params, 'version')

        version_filter = util.param(params, 'version_filter', default=version_filter_callback())
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        data_types = params.getall('type', default=[])
        select = util.param(params, 'select')

        if select:
            try:
                select = Select(select)
            except ValueError:
                raise aiohttp.web.HTTPBadRequest(
                    reason='Invalid parameter',
                    text=(
                        'The value of the parameter select must be a one of '
                        f'{[m.value for m in Select]}'
                    ),
                )

        if not component_version and not select:
            raise aiohttp.web.HTTPBadRequest(text='One of "version" and "select" must be given.')

        if component_version and select and select is Select.GREATEST:
            raise aiohttp.web.HTTPBadRequest(
                text=f'"select" must not be "{Select.GREATEST.value}" if "version" is given',
            )

        if select is Select.GREATEST:
            component_version = await greatest_component_version(
                component_name=component_name,
                version_lookup=version_lookup,
                version_filter=version_filter,
                invalid_semver_ok=invalid_semver_ok,
            )

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        if component_version:
            db_statement = self._metadata_query_for_version(
                metadata_types=data_types,
                component_version=component_version,
                component_name=component_name,
            )
        else:
            db_statement = self._latest_metadata_query(
                metadata_types=data_types,
                component_version=component_version,
                component_name=component_name,
            )

        db_stream = await db_session.stream(db_statement)

        return aiohttp.web.json_response(
            data=[
                deliverydb.util.db_artefact_metadata_to_dict(result)
                async for partition in db_stream.partitions(size=50)
                for result in partition
            ],
            dumps=util.dict_to_json_factory,
        )
