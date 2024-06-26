import dataclasses
import datetime
import dataclasses_json
import enum
import logging
import typing

import cachetools
import cachetools.keys
import dacite.exceptions
import dateutil.parser
import falcon
import falcon.media.validators
import requests
import sqlalchemy as sa
import sqlalchemy.orm.query as sq
import sqlalchemy.orm.session as ss

import ccc.oci
import ci.util
import cnudie.iter
import cnudie.util
import cnudie.retrieve
import dso.model
import gci.componentmodel as cm
import github.util
import oci.client
import oci.model as om
import version as versionutil

import compliance_summary as cs
import ctx_util
import deliverydb.model as dm
import deliverydb.util
import eol
import features
import lookups
import responsibles
import responsibles.github_statistics
import responsibles.labels
import responsibles
import util
import yp

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class ComponentVector:
    '''
    Holds two component objects of the same Component, but different Versions.
    Represents a change in the component version from old_component to new_component.
    '''
    start: cm.Component
    end: cm.Component


def _cache_key_gen_dependency_updates(
    component_vector: ComponentVector,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    dependency_name_filter: list[str] = (),
    only_rising_changes: bool = False
):
    return cachetools.keys.hashkey(
        component_vector.start.name,
        component_vector.end.name,
        component_vector.start.version,
        component_vector.end.version,
        tuple(dependency_name_filter),
        only_rising_changes,
    )


cache_existing_components = []


def check_if_component_exists(
        component_name: str,
        version_lookup: cnudie.retrieve.VersionLookupByComponent,
        raise_http_error: bool = False,
):
    if component_name in cache_existing_components:
        return True

    for _ in version_lookup(component_name, None):
        cache_existing_components.append(component_name)
        return True

    if raise_http_error:
        # pylint: disable=E1101
        raise falcon.HTTPNotFound(title=f'{component_name=} not found')
    return False


def get_creation_date(component: cm.Component) -> datetime.datetime:
    '''
    Trys to extract creation date from creationTime attribute and if not set from label with name
    "cloud.gardener/ocm/creation-date".
    Raises KeyError, if both is not successful.
    '''

    if (creationTime := component.creationTime):
        return dateutil.parser.isoparse(creationTime)

    creation_label: cm.Label | None = component.find_label('cloud.gardener/ocm/creation-date')

    if not creation_label:
        raise KeyError(
            'The attribute creation time, as well as the',
            'label named "cloud.gardener/ocm/creation-date", were not set.',
        )
    else:
        return dateutil.parser.isoparse(creation_label.value)


def greatest_version_if_none(
    component_name: str,
    version: str,
    version_lookup: cnudie.retrieve.VersionLookupByComponent=None,
    ocm_repo: cm.OcmRepository=None,
    oci_client: oci.client.Client=None,
    version_filter: features.VersionFilter=features.VersionFilter.RELEASES_ONLY,
    invalid_semver_ok: bool=False,
):
    if version is None:
        version = greatest_component_version(
            component_name=component_name,
            version_lookup=version_lookup,
            ocm_repo=ocm_repo,
            oci_client=oci_client,
            version_filter=version_filter,
            invalid_semver_ok=invalid_semver_ok,
        )

    if not version:
        raise falcon.HTTPNotFound(
            title='no greatest version found',
            description=f'{component_name=}; {version_filter=}',
        )

    return version


def _component_descriptor(
    req: falcon.Request,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    version_lookup: cnudie.retrieve.VersionLookupByComponent,
    version_filter: features.VersionFilter,
    invalid_semver_ok: bool=False,
) -> cm.ComponentDescriptor:
    component_name = req.get_param('component_name', True)

    # TODO remove `ctx_repo_url` once all usages are updated
    ocm_repo_url = req.get_param(
        name='ocm_repo_url',
        required=False,
        default=req.get_param('ctx_repo_url', False),
    )
    if ocm_repo_url:
        ocm_repo = cm.OciOcmRepository(baseUrl=ocm_repo_url)
    else:
        ocm_repo = None

    version = req.get_param('version', True)

    version_filter = req.get_param('version_filter', False, default=version_filter)
    util.get_enum_value_or_raise(version_filter, features.VersionFilter)

    if version == 'greatest':
        version = greatest_version_if_none(
            component_name=component_name,
            version=None,
            version_lookup=version_lookup,
            ocm_repo=ocm_repo,
            version_filter=version_filter,
            invalid_semver_ok=invalid_semver_ok,
        )

    try:
        descriptor = util.retrieve_component_descriptor(
            cm.ComponentIdentity(
                name=component_name,
                version=version,
            ),
            component_descriptor_lookup=component_descriptor_lookup,
            ctx_repo=ocm_repo,
        )
    except dacite.exceptions.MissingValueError as e:
        raise falcon.HTTPFailedDependency(title=str(e))

    return descriptor


class Component:
    def __init__(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        version_lookup: cnudie.retrieve.VersionLookupByComponent,
        version_filter_callback,
        invalid_semver_ok: bool=False,
    ):
        self._component_descriptor_lookup = component_descriptor_lookup
        self._version_lookup = version_lookup
        self._version_filter_callback = version_filter_callback
        self._invalid_semver_ok = invalid_semver_ok

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        resp.media = _component_descriptor(
            req=req,
            component_descriptor_lookup=self._component_descriptor_lookup,
            version_lookup=self._version_lookup,
            version_filter=self._version_filter_callback(),
            invalid_semver_ok=self._invalid_semver_ok,
        )


class ComponentDependencies:
    def __init__(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        version_lookup: cnudie.retrieve.VersionLookupByComponent,
        version_filter_callback,
        invalid_semver_ok: bool=False,
    ):
        self._component_descriptor_lookup = component_descriptor_lookup
        self._version_lookup = version_lookup
        self._version_filter_callback = version_filter_callback
        self._invalid_semver_ok = invalid_semver_ok

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        component_name = req.get_param('component_name', True)

        populate = req.get_param(
            name='populate',
            required=False,
            default='all',
        )

        # TODO remove `ctx_repo_url` once all usages are updated
        ocm_repo_url = req.get_param(
            name='ocm_repo_url',
            required=False,
            default=req.get_param('ctx_repo_url', False),
        )
        if ocm_repo_url:
            ocm_repo = cm.OciOcmRepository(baseUrl=ocm_repo_url)
        else:
            ocm_repo = None

        version = req.get_param('version', True)

        version_filter = req.get_param(
            name='version_filter',
            required=False,
            default=self._version_filter_callback(),
        )
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        if version == 'greatest':
            version = greatest_version_if_none(
                component_name=component_name,
                version=None,
                version_lookup=self._version_lookup,
                ocm_repo=ocm_repo,
                version_filter=version_filter,
                invalid_semver_ok=self._invalid_semver_ok,
            )

        component_dependencies = resolve_component_dependencies(
            component_name=component_name,
            component_version=version,
            component_descriptor_lookup=self._component_descriptor_lookup,
            ctx_repo=ocm_repo,
        )

        filtered_component_dependencies = []
        for component in component_dependencies:
            if populate == 'componentReferences':
                component_dependency = {
                    'name': component.component.name,
                    'version': component.component.version,
                    'repositoryContexts': component.component.repositoryContexts,
                }
            elif populate == 'all':
                component_dependency = dataclasses.asdict(component.component)
            else:
                raise falcon.HTTPBadRequest(f'{populate=} not implemented')

            component_dependency['comp_ref'] = [
                {
                    'name': ref.component.name,
                    'version': ref.component.version,
                    'repositoryContexts': ref.component.repositoryContexts,
                }
                for ref in component.path
            ]
            filtered_component_dependencies.append(component_dependency)

        resp.media = {'componentDependencies': filtered_component_dependencies}


class ComponentResponsibles:
    def __init__(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        version_lookup: cnudie.retrieve.VersionLookupByComponent,
        github_api_lookup,
        addressbook_repo_callback,
        addressbook_relpath_callback,
        github_mappings_relpath_callback,
        version_filter_callback,
        invalid_semver_ok: bool=False,
    ):
        self._component_descriptor_lookup = component_descriptor_lookup
        self._version_lookup = version_lookup
        self.github_api_lookup = github_api_lookup
        self.addressbook_repo_callback = addressbook_repo_callback
        self.addressbook_relpath_callback = addressbook_relpath_callback
        self.github_mappings_relpath_callback = github_mappings_relpath_callback
        self._version_filter_callback = version_filter_callback
        self._invalid_semver_ok = invalid_semver_ok

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        '''
        returns a list of user-identities responsible for the given component or resource

        **expected query parameters:**

            - component_name (required) \n
            - version (required) \n
            - version_filter (optional) \n
            - ctx_repo_url (optional, defaults to delivery-service's global default ctx) \n
            - resource_name (optional)

        if resource_name is given, and specific responsibles are configured for the given resource
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
        statuses: list[responsibles.Status] = []

        component_descriptor = _component_descriptor(
            req=req,
            component_descriptor_lookup=self._component_descriptor_lookup,
            version_lookup=self._version_lookup,
            version_filter=self._version_filter_callback(),
            invalid_semver_ok=self._invalid_semver_ok,
        )
        component = component_descriptor.component
        main_source = cnudie.util.main_source(component_descriptor.component)
        artifact_name = req.get_param('artifact_name', False)

        def _responsibles_label(
            component: cm.Component,
            artifact_name: typing.Optional[str] = None,
            owners_label: str = 'cloud.gardener.cnudie/responsibles',
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
                    raise falcon.HTTPNotFound(
                        description=(
                            f'{component.name} in version {component.version} has no '
                            f'{artifact_name=}'
                        )
                    )

                for artifact in matching_artifacts:
                    artifact: cm.Artifact
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
                github_api_lookup=self.github_api_lookup,
            ))
        else:
            try:
                user_identities = responsibles.user_identities_from_source(
                    source=main_source,
                    github_api_lookup=self.github_api_lookup,
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
            resp.status = falcon.HTTP_ACCEPTED
            return

        addressbook_entries = yp.addressbook_entries(
            repo=self.addressbook_repo_callback(),
            relpath=self.addressbook_relpath_callback(),
        )

        user_identities = [
            yp.inject(
                addressbook_entries=addressbook_entries,
                user_id=user_id,
                repo=self.addressbook_repo_callback(),
                mappingfile_relpath=self.github_mappings_relpath_callback(),
            ).identifiers
            for user_id in user_identities
        ]

        resp.media = {
            'responsibles': user_identities,
            'statuses': [dataclasses.asdict(s) for s in statuses],
        }


def component_versions(
    component_name: str,
    version_lookup: cnudie.retrieve.VersionLookupByComponent=None,
    ocm_repo: cm.OcmRepository=None,
    oci_client: oci.client.Client=None,
) -> list[str]:
    if not ocm_repo and not version_lookup:
        raise ValueError('At least one of `ocm_repo` and `version_lookup` must be specified')

    if ocm_repo:
        if not isinstance(ocm_repo, cm.OciOcmRepository):
            raise NotImplementedError(ocm_repo)

        if not oci_client:
            oci_client = ccc.oci.oci_client(cfg_factory=ctx_util.cfg_factory())

        try:
            return cnudie.retrieve.component_versions(
                component_name=component_name,
                ctx_repo=ocm_repo,
                oci_client=oci_client,
            )
        except requests.exceptions.HTTPError:
            return []

    return version_lookup(
        component_id=cm.ComponentIdentity(
            name=component_name,
            version=None
        ),
    )


def greatest_component_version(
    component_name: str,
    version_lookup: cnudie.retrieve.VersionLookupByComponent=None,
    ocm_repo: cm.OcmRepository=None,
    oci_client: oci.client.Client=None,
    version_filter: features.VersionFilter=features.VersionFilter.RELEASES_ONLY,
    invalid_semver_ok: bool=False,
) -> str | None:
    versions = component_versions(
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


def greatest_component_versions(
    component_name: str,
    ocm_repo: cm.OcmRepository=None,
    version_lookup: cnudie.retrieve.VersionLookupByComponent=None,
    max_versions: int=5,
    greatest_version: str=None,
    oci_client: oci.client.Client=None,
    version_filter: features.VersionFilter=features.VersionFilter.RELEASES_ONLY,
    invalid_semver_ok: bool=False,
) -> list[str]:
    versions = component_versions(
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

    if greatest_version:
        versions = versions[:versions.index(greatest_version)+1]

    return versions[-max_versions:]


class GreatestComponentVersions:
    def __init__(
        self,
        version_lookup: cnudie.retrieve.VersionLookupByComponent,
        version_filter_callback,
        invalid_semver_ok: bool=False,
    ):
        self.version_lookup = version_lookup
        self._version_filter_callback = version_filter_callback
        self._invalid_semver_ok = invalid_semver_ok

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        component_name = req.get_param('component_name', True)
        max_version = req.get_param('max', False, default=5)
        version = req.get_param('version', False, default=None)

        # TODO remove `ctx_repo_url` once all usages are updated
        ocm_repo_url = req.get_param(
            name='ocm_repo_url',
            required=False,
            default=req.get_param('ctx_repo_url', False),
        )
        if ocm_repo_url:
            ocm_repo = cm.OciOcmRepository(baseUrl=ocm_repo_url)
        else:
            ocm_repo = None

        version_filter = req.get_param(
            name='version_filter',
            required=False,
            default=self._version_filter_callback(),
        )
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        try:
            versions = greatest_component_versions(
                component_name=component_name,
                ocm_repo=ocm_repo,
                version_lookup=self.version_lookup,
                max_versions=int(max_version),
                greatest_version=version,
                version_filter=version_filter,
                invalid_semver_ok=self._invalid_semver_ok,
            )
        except ValueError:
            raise falcon.HTTPNotFound(description=f'version {version} not found')

        resp.media = versions


def resolve_component_dependencies(
    component_name: str,
    component_version: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    ctx_repo: cm.OcmRepository=None,
) -> list[cnudie.iter.ComponentNode]:
    descriptor = util.retrieve_component_descriptor(
        cm.ComponentIdentity(
            name=component_name,
            version=component_version,
        ),
        component_descriptor_lookup=component_descriptor_lookup,
        ctx_repo=ctx_repo,
    )
    component = descriptor.component

    try:
        components: list[cnudie.iter.ComponentNode] = list(_components(
            component_name=component.name,
            component_version=component.version,
            component_descriptor_lookup=component_descriptor_lookup,
            ctx_repo=ctx_repo,
        ))
    except dacite.exceptions.MissingValueError as e:
        raise falcon.HTTPFailedDependency(title=str(e))

    # add repo classification label if not present in component labels
    for component in components:

        label_present = False
        # if no sources present we cannot add the source
        if not len(component.component.sources) > 0:
            continue

        for source in component.component.sources:
            if 'cloud.gardener/cicd/source' in [label.name for label in source.labels]:
                label_present = True
                break
        if not label_present:
            component.component.sources[0].labels.append(cm.Label(
                name='cloud.gardener/cicd/source',
                value={'repository-classification': 'main'},
            ))

    return components


class UpgradePRs:
    required_features = (features.FeatureUpgradePRs,)

    def __init__(
        self,
        upr_regex_callback,
        component_descriptor_lookup,
        github_api_lookup,
        version_lookup,
        version_filter_callback,
        invalid_semver_ok,
    ):
        self.upr_regex_callback = upr_regex_callback
        self._component_descriptor_lookup = component_descriptor_lookup
        self.github_api_lookup = github_api_lookup
        self._version_lookup = version_lookup
        self._version_filter_callback = version_filter_callback
        self._invalid_semver_ok = invalid_semver_ok

    def on_get(self, req, resp):
        component_name: str = req.get_param('componentName', default=None)
        component_version: str = req.get_param('componentVersion', default=None)
        repo_url: str = req.get_param('repoUrl', default=None)
        pr_state: str = req.get_param('state', default='open')

        ocm_repo_url = req.get_param('ocmRepo', default=None)
        if ocm_repo_url:
            ocm_repo = cm.OciOcmRepository(baseUrl=ocm_repo_url)
        else:
            ocm_repo = None

        version_filter = req.get_param(
            name='version_filter',
            required=False,
            default=self._version_filter_callback(),
        )
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        if not (bool(component_name) ^ bool(repo_url)):
           raise falcon.HTTPBadRequest(title='exactly one of componentName, repoUrl must be passed')

        if component_name:
            component_version = greatest_version_if_none(
                component_name=component_name,
                version=component_version,
                version_lookup=self._version_lookup,
                ocm_repo=ocm_repo,
                version_filter=version_filter,
                invalid_semver_ok=self._invalid_semver_ok,
            )

            component_descriptor = util.retrieve_component_descriptor(
                cm.ComponentIdentity(
                    name=component_name,
                    version=component_version,
                ),
                component_descriptor_lookup=self._component_descriptor_lookup,
                ctx_repo=ocm_repo,
            )
            component = component_descriptor.component
            source = cnudie.util.main_source(
                component=component,
                absent_ok=True,
            )

            if source:
                repo_url = source.access.repoUrl

            else:
                repo_url = component_name

        gh_api = self.github_api_lookup(
            repo_url,
            absent_ok=True,
        )
        if not gh_api:
            # todo: rather raise/return http-error?
            logger.warning(f'no github-cfg found for {repo_url=}')
            resp.media = []
            return

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
            resp.media = []
            return

        upgrade_prs: typing.Iterable[github.util.UpgradePullRequest] = pr_helper.enumerate_upgrade_pull_requests( # noqa:E501
            state=pr_state,
            pattern=self.upr_regex_callback(),
        )

        def upgrade_pr_to_dict(upgrade_pr):
            from_ref: cm.ComponentReference = upgrade_pr.from_ref
            to_ref: cm.ComponentReference = upgrade_pr.to_ref
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

        resp.media = [upgrade_pr_to_dict(upgrade_pr) for upgrade_pr in upgrade_prs]


class Issues:
    required_features = (features.FeatureIssues,)

    def __init__(
        self,
        issue_repo_callback,
        github_api_lookup,
    ):
        self.issue_repo_callback = issue_repo_callback
        self.github_api_lookup = github_api_lookup
        self.github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)

    def on_get(self, req, resp):
        component_name: str = req.get_param('componentName', required=True)
        state: str = req.get_param('state', 'open')
        since: str = req.get_param('since', required=False)

        issue_repo = self.issue_repo_callback(component_name)

        if not issue_repo:
            resp.media = []
            return

        ls_repo = self.github_repo_lookup(issue_repo)

        issues = ls_repo.issues(state=state, since=since)
        resp.media = [
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
        ]


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


class ComponentDescriptorDiff:
    def __init__(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    ):
        self._component_descriptor_lookup = component_descriptor_lookup

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        diff_request = ComponentDiffRequest.from_dict(req.media)

        left_component_ref: ComponentRef = diff_request.left_component
        right_component_ref: ComponentRef = diff_request.right_component

        left_descriptor = util.retrieve_component_descriptor(
            cm.ComponentIdentity(
                name=left_component_ref.name,
                version=left_component_ref.version,
            ),
            component_descriptor_lookup=self._component_descriptor_lookup,
        )
        right_descriptor = util.retrieve_component_descriptor(
            cm.ComponentIdentity(
                name=right_component_ref.name,
                version=right_component_ref.version,
            ),
            component_descriptor_lookup=self._component_descriptor_lookup,
        )

        try:
            diff = cnudie.retrieve.component_diff(
                left_component=left_descriptor,
                right_component=right_descriptor,
                component_descriptor_lookup=self._component_descriptor_lookup,
            )
        except om.OciImageNotFoundException as e:
            err_str = 'error occurred during calculation of component diff of ' \
            f'{left_descriptor.component.name=} in {left_descriptor.component.version=} and ' \
            f'{right_descriptor.component.name=} in {right_descriptor.component.version=}'
            logger.warning(err_str)
            raise falcon.HTTPUnprocessableEntity(
                title='error occurred during calculation of component diff',
                description=err_str,
            ) from e

        def component_ref(component: cm.Component):
            return {'name': component.name, 'version': component.version}

        def changed_component_info(left_comp: cm.Component, right_comp: cm.Component):
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

        def changed_resource_info(left_resource: cm.Resource, right_resource: cm.Resource):
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
        resp.media = {
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
        }


def _components(
    component_name: str,
    component_version: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    ctx_repo: cm.OcmRepository=None,
) -> tuple[Component]:
    component_descriptor = util.retrieve_component_descriptor(
        cm.ComponentIdentity(
            name=component_name,
            version=component_version,
        ),
        component_descriptor_lookup=component_descriptor_lookup,
        ctx_repo=ctx_repo,
    )

    try:
        return tuple(cnudie.iter.iter(
            component=component_descriptor,
            lookup=component_descriptor_lookup,
            prune_unique=False,
            node_filter=lambda node: isinstance(node, cnudie.iter.ComponentNode),
        ))
    except om.OciImageNotFoundException as e:
        err_str = 'error occurred during retrieval of component dependencies of ' \
        f'{component_descriptor.component.name=} in {component_descriptor.component.version=}'
        logger.warning(err_str)
        raise falcon.HTTPUnprocessableEntity(
            title='error occurred during retrieval of component dependencies',
            description=err_str,
        ) from e


class ComplianceSummary:
    required_features = (features.FeatureDeliveryDB,)

    def __init__(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        version_lookup: cnudie.retrieve.VersionLookupByComponent,
        eol_client: eol.EolClient,
        artefact_metadata_cfg_by_type: dict,
        version_filter_callback,
        invalid_semver_ok: bool=False,
    ):
        self._component_descriptor_lookup = component_descriptor_lookup
        self._version_lookup = version_lookup
        self.eol_client = eol_client
        self.artefact_metadata_cfg_by_type = artefact_metadata_cfg_by_type
        self._version_filter_callback = version_filter_callback
        self._invalid_semver_ok = invalid_semver_ok

    def on_get(self, req, resp):
        '''
        returns most critical severity for artefact-metadata types, for all component-dependencies

        compliance-summaries contain severities and scan-statuses for artefact-metadata types.

        **expected query parameters:**

            - component_name (required) \n
            - version (required) \n
            - version_filter (optional) \n
            - ctx_repo_url (optional)

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
        '''

        component_name = req.get_param('component_name', True)

        # TODO remove `ctx_repo_url` once all usages are updated
        ocm_repo_url = req.get_param(
            name='ocm_repo_url',
            required=False,
            default=req.get_param('ctx_repo_url', False),
        )
        if ocm_repo_url:
            ocm_repo = cm.OciOcmRepository(baseUrl=ocm_repo_url)
        else:
            ocm_repo = None

        version = req.get_param('version', True)

        version_filter = req.get_param(
            name='version_filter',
            required=False,
            default=self._version_filter_callback(),
        )
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        if version == 'greatest':
            version = greatest_version_if_none(
                component_name=component_name,
                version=None,
                version_lookup=self._version_lookup,
                ocm_repo=ocm_repo,
                version_filter=version_filter,
                invalid_semver_ok=self._invalid_semver_ok,
            )

        components_dependencies = resolve_component_dependencies(
            component_name=component_name,
            component_version=version,
            component_descriptor_lookup=self._component_descriptor_lookup,
            ctx_repo=ocm_repo,
        )

        component_ids = tuple(
            cm.ComponentIdentity(
                name=component.component.name,
                version=component.component.version,
            ) for component in components_dependencies
        )

        session: ss.Session = req.context.db_session

        type_filter = (
            dso.model.Datatype.ARTEFACT_SCAN_INFO,
            dso.model.Datatype.LICENSE,
            dso.model.Datatype.VULNERABILITY,
            dso.model.Datatype.OS_IDS,
            dso.model.Datatype.CODECHECKS_AGGREGATED,
            dso.model.Datatype.MALWARE_FINDING,
        )

        findings_query = session.query(dm.ArtefactMetaData).filter(
            sa.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                components=component_ids,
            )),
            dm.ArtefactMetaData.type.in_(type_filter),
        )
        rescorings_query = session.query(dm.ArtefactMetaData).filter(
            dm.ArtefactMetaData.type == dso.model.Datatype.RESCORING,
            sa.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                components=component_ids,
                none_ok=True,
            )),
            deliverydb.util.ArtefactMetadataFilters.filter_for_rescoring_type(type_filter),
        )

        findings_raw = findings_query.all()
        findings = [
            deliverydb.util.db_artefact_metadata_to_dso(raw)
            for raw in findings_raw
        ]

        rescorings_raw = rescorings_query.all()
        rescorings = [
            deliverydb.util.db_artefact_metadata_to_dso(raw)
            for raw in rescorings_raw
        ]

        resp.media = {
            'complianceSummary': [
                dataclasses.asdict(
                    obj=summary,
                    dict_factory=util.dict_factory_enum_name_serialisiation,
                )
                for summary in cs.component_summaries(
                    findings=findings,
                    rescorings=rescorings,
                    component_ids=component_ids,
                    eol_client=self.eol_client,
                    artefact_metadata_cfg_by_type=self.artefact_metadata_cfg_by_type,
                )
            ]
        }


class Select(enum.Enum):
    GREATEST = 'greatestVersion'
    LATEST = 'latestData'


class ComponentMetadata:
    required_features = (features.FeatureDeliveryDB,)

    def __init__(
        self,
        version_lookup: cnudie.retrieve.VersionLookupByComponent,
        version_filter_callback,
        invalid_semver_ok: bool=False,
    ):
        self.version_lookup = version_lookup
        self._version_filter_callback = version_filter_callback
        self._invalid_semver_ok = invalid_semver_ok

    def _latest_metadata_query(
        self,
        session: ss.Session,
        metadata_types: typing.Iterable[str],
        component_version: str | None,
        component_name: str,
    ) -> sq.Query:
        # The following is a nested query. First, in the subquery, the relevant entries in the table
        # are partitioned by metadata, sorted, and a rank-column is assigned to each row in the
        # resulting partitions.
        # Then, the actual query returns the rows where rank equals '1' from the subquery.
        subquery = session.query(
            dm.ArtefactMetaData,
            sa.func.rank().over(
                order_by=dm.ArtefactMetaData.creation_date.desc(),
                partition_by=dm.ArtefactMetaData.type,
            ).label('rank')
        ).filter(
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
        return session.query(subquery).filter(subquery.c.rank == 1)

    def _metadata_query_for_version(
        self,
        session: ss.Session,
        metadata_types: typing.Iterable[str],
        component_version: str,
        component_name: str,
    ) -> sq.Query:
        return session.query(
            dm.ArtefactMetaData
        ).filter(
            sa.and_(
                dm.ArtefactMetaData.component_name == component_name,
                # return results for all metadata types if no collection (or an empty one) is given
                dm.ArtefactMetaData.type.in_(metadata_types) if metadata_types else True,
                dm.ArtefactMetaData.component_version == component_version,
            )
        )

    def on_get(self, req: falcon.Request, resp: falcon.Response):
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
        component_name = req.get_param(name='name', required=True)
        component_version = req.get_param(name='version', required=False)

        version_filter = req.get_param(
            name='version_filter',
            required=False,
            default=self._version_filter_callback(),
        )
        util.get_enum_value_or_raise(version_filter, features.VersionFilter)

        # if given by the user without value, data_types will be a list with an empty string
        # in it. If not given at all, it will be None.
        data_types = req.get_param_as_list(name='type', required=False)
        select = req.get_param(name='select', required=False)

        if select:
            try:
                select = Select(select)
            except ValueError:
                raise falcon.HTTPInvalidParam(
                    param_name='select',
                    msg=f'Valid values are: {[m.value for m in Select]}',
                )

        if data_types is None:
            data_types = []

        if not component_version and not select:
            raise falcon.HTTPBadRequest(description="One of 'version' and 'select' must be given.")

        if component_version and select and select is Select.GREATEST:
            raise falcon.HTTPBadRequest(
                description=f"'select' must not be '{Select.GREATEST.value}' if 'version' is given"
            )

        if select is Select.GREATEST:
            component_version = greatest_component_version(
                component_name=component_name,
                version_lookup=self.version_lookup,
                version_filter=version_filter,
                invalid_semver_ok=self._invalid_semver_ok,
            )

        session: ss.Session = req.context.db_session

        if component_version:
            query = self._metadata_query_for_version(
                session=session,
                metadata_types=data_types,
                component_version=component_version,
                component_name=component_name,
            )
        else:
            query = self._latest_metadata_query(
                session=session,
                metadata_types=data_types,
                component_version=component_version,
                component_name=component_name,
            )

        query_results = query.all()

        results = [
            deliverydb.util.db_artefact_metadata_to_dict(
                artefact_metadata=artefact_metadata,
            )
            for artefact_metadata in query_results
        ]

        resp.media = results
