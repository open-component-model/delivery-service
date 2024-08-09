import asyncio
import collections
import collections.abc
import dataclasses
import datetime
import functools
import statistics
import typing
import urllib.parse

import aiohttp.web
import cachetools.keys
import cnudie.iter_async
import dateutil.parser
import dora_result_calcs
import ocm
import github3

import ci.util
import cnudie.retrieve
import cnudie.util
import semver
import version as versionutil

import caching
import components
import consts
import middleware
import middleware.auth
import util


def _cache_key_gen_all_versions_sorted(
    component: cnudie.retrieve.ComponentName,
    version_lookup: cnudie.retrieve.VersionLookupByComponent,
    only_releases: bool = True,
    invalid_semver_ok: bool = False,
    sorting_direction: typing.Literal['asc', 'desc'] = 'desc',
):
    return cachetools.keys.hashkey(
        cnudie.util.to_component_name(component),
        only_releases,
        invalid_semver_ok,
        sorting_direction,
    )


@caching.async_cached(
    cache=caching.TTLFilesystemCache(ttl=60 * 60 * 24, max_total_size_mib=128), # 1 day
    key_func=_cache_key_gen_all_versions_sorted,
)
async def all_versions_sorted(
    component: cnudie.retrieve.ComponentName,
    version_lookup: cnudie.retrieve.VersionLookupByComponent,
    only_releases: bool = True,
    invalid_semver_ok: bool = False,
    sorting_direction: typing.Literal['asc', 'desc'] = 'desc'
) -> list[str]:
    '''
    Retrieve all versions of a specific component, sorted according to specified parameters.

    Returns:
        A list of version strings sorted according to the specified parameters.

    Notes:
        - 'asc' sorting means old to new => [0.102.0, ..., 0.321.2]
        - 'desc' sorting means new to old => [0.321.2, ..., 0.102.0]
    '''
    component_name = cnudie.util.to_component_name(component)

    def filter_version(version: str, invalid_semver_ok: bool, only_releases:bool):
        if not (parsed_version := versionutil.parse_to_semver(
            version=version,
            invalid_semver_ok=invalid_semver_ok,
        )):
            return False

        if only_releases:
            return versionutil.is_final(parsed_version)

        return True

    versions = (
        version for version
        in await version_lookup(component_name)
        if filter_version(version, invalid_semver_ok, only_releases)
    )

    versions = sorted(
        versions,
        key=lambda v: versionutil.parse_to_semver(
            version=v,
            invalid_semver_ok=invalid_semver_ok,
        ),
        reverse=sorting_direction == 'desc',
    )

    return versions


async def filter_versions_newer_than(
        component: cnudie.retrieve.ComponentName,
        all_versions: list[semver.VersionInfo],
        date: datetime.datetime,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
) -> list[semver.VersionInfo]:
    '''
    Filter list of versions of a component for versions that are newer than a specified date.

    Returns:
        A list of version information objects representing versions newer than the specified date.
    '''
    all_versions = sorted(
        all_versions,
        key=lambda v: versionutil.parse_to_semver(v),
        reverse=True,
    )

    component_versions: list[semver.VersionInfo] = []

    for version in all_versions:
        descriptor: ocm.ComponentDescriptor = await component_descriptor_lookup(
            ocm.ComponentIdentity(
                name=cnudie.util.to_component_name(component),
                version=version,
            )
        )
        creation_date = components.get_creation_date(descriptor.component)

        date = date.astimezone(datetime.timezone.utc)
        creation_date = creation_date.astimezone(datetime.timezone.utc)

        if creation_date > date:
            component_versions.append(version)
        else:
            break

    return component_versions


def _cache_key_gen_latest_componentversions_in_tree(
    component: ocm.Component,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
):
    return cachetools.keys.hashkey(
        cnudie.util.to_component_name(component),
        component.identity()
    )


@caching.async_cached(
    cache=caching.TTLFilesystemCache(ttl=60*60*24, max_total_size_mib=128), #1 day TODO
    key_func=_cache_key_gen_latest_componentversions_in_tree,
)
async def latest_referenced_component_versions(
    component: ocm.Component,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
) -> dict[str, ocm.Component]:
    '''
    Retrieve the latest versions of all components referenced in the component tree.

    Args:
        component: The root component from which to traverse and collect referenced components.
        component_descriptor_lookup: A function to lookup component descriptors by identity.

    Returns:
        A dictionary mapping component names to their highest versioned Component object.

    Notes:
        - Only the highest version of each component is retained.
 
    '''
    def default_factory():
        return None
    components_by_name = collections.defaultdict(default_factory)

    referenced_components = [
        c.component async for c in cnudie.iter_async.iter(
            component=component,
            lookup=component_descriptor_lookup,
            node_filter=cnudie.iter.Filter.components,
        )
    ]

    def version_key(c):
        if c is not None:
            return versionutil.parse_to_semver(c.version)
        else:
            return semver.VersionInfo(0, 0, 0)

    for referenced_component in referenced_components:
        components_by_name[referenced_component.name] = max(
            components_by_name[referenced_component.name],
            referenced_component,
            key=version_key,
        )

    return dict(components_by_name)


@dataclasses.dataclass(frozen=True)
class ComponentVersionUpdate:
    '''
    Data class representing version updates of a target component and its referenced component.

    Attributes:
        target_component: The target component name.
        target_component_version_old: The previous version of the target component.
        target_component_version_new: The new version of the target component.
        referenced_component: The name of the referenced component.
        referenced_component_version_older_release: The version of the referenced component in the older targer component.
        referenced_component_version_newer_release: The version of the referenced component in the newer target component.
    '''
    target_component: cnudie.retrieve.ComponentName
    target_component_version_old: str
    target_component_version_new: str
    referenced_component: cnudie.retrieve.ComponentName
    referenced_component_version_older_release: str
    referenced_component_version_newer_release: str

    def to_dict(self) -> dict[str, typing.Any]:
        return {
            'target_component': cnudie.util.to_component_name(self.target_component),
            'target_component_versions_old': str(self.target_component_version_old),
            'target_component_versions_new': str(self.target_component_version_new),
            'referenced_component': cnudie.util.to_component_name(self.referenced_component),
            'referenced_component_version_older': str(self.referenced_component_version_older_release),
            'referenced_component_version_newer': str(self.referenced_component_version_newer_release),
        }


def can_process(dependency_update: components.ComponentVector):
    old_main_source = cnudie.util.main_source(dependency_update.start)
    new_main_source = cnudie.util.main_source(dependency_update.end)

    if (
        not isinstance(old_main_source.access, ocm.GithubAccess)
        or not isinstance(new_main_source.access, ocm.GithubAccess)
    ):
        return False

    if (
        not isinstance(old_main_source.access.commit, str)
        or not isinstance(new_main_source.access.commit, str)
    ):
        return False

    return True


def _cache_key_gen_commits_between(
    older_commit: str,
    newer_commit: str,
    github_repo: github3.repos.Repository,
):
    return cachetools.keys.hashkey(
        older_commit,
        newer_commit,
    )


@caching.cached(
    cache=caching.LFUFilesystemCache(max_total_size_mib=256),
    key_func=_cache_key_gen_commits_between,
)
def commits_between(
    older_commit: str,
    newer_commit: str,
    github_repo: github3.repos.Repository,
) -> tuple[github3.github.repo.commit.ShortCommit]:
    '''
    Retrieve commits between two specified commits from a GitHub repository.
    '''
    commits: tuple[github3.github.repo.commit.ShortCommit] = tuple(
        github_repo.compare_commits(
            older_commit,
            newer_commit,
        ).commits()
    )

    return commits


async def create_deployment_objects(
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
    github_api_lookup,
    target_component_name: str,
    time_span_days: int,
    filter_component_name: str,
    target_updates: list[ComponentVersionUpdate],
) -> list[dora_result_calcs.ReturnDeploymentObject]:
    '''
    Create objects containing the information about the target component updates in which the referenced component was updated.
    '''

    deployment_objects: list[dora_result_calcs.ReturnDeploymentObject] = []

    _github_api = functools.cache(github_api_lookup)

    @functools.cache
    def _github_repo(repo_url: urllib.parse.ParseResult):
        github = _github_api(repo_url)
        org, repo = repo_url.path.strip('/').split('/')
        return github.repository(org, repo)

    async def create_deployment_object_for_update(
        target_update: ComponentVersionUpdate,
    ):
        old_ref_component: ocm.Component = (await component_descriptor_lookup(
            ocm.ComponentIdentity(
                name=cnudie.util.to_component_name(target_update.referenced_component),
                version=target_update.referenced_component_version_older_release,
            )
        )).component

        new_ref_component: ocm.Component = (await component_descriptor_lookup(
            ocm.ComponentIdentity(
                name=cnudie.util.to_component_name(target_update.referenced_component),
                version=target_update.referenced_component_version_newer_release,
            )
        )).component

        if not old_ref_component or not new_ref_component:
            print ("ERROR, bad input data")

        if not can_process(
            components.ComponentVector(
                start=old_ref_component,
                end=new_ref_component,
            )
        ):
            print("can't process")
            return

        old_access = cnudie.util.main_source(old_ref_component).access
        new_access = cnudie.util.main_source(new_ref_component).access

        old_repo_url = ci.util.urlparse(old_access.repoUrl)
        new_repo_url = ci.util.urlparse(new_access.repoUrl)

        if not old_repo_url == new_repo_url:
            print("repo urls are not equal")
            return # ensure there was no repository-change between component-versions

        old_commit = old_access.commit or old_access.ref
        new_commit = new_access.commit or new_access.ref

        github_repo = _github_repo(
            repo_url=old_repo_url, # already checked for equality; choose either
        )

        commits = commits_between(
            older_commit=old_commit,
            newer_commit=new_commit,
            github_repo=github_repo,
        )

        deployment_date = components.get_creation_date(
            (await component_descriptor_lookup(
                ocm.ComponentIdentity(
                    name=cnudie.util.to_component_name(target_component_name),
                    version=target_update.target_component_version_new,
                ),
            )).component
        )

        for commit in commits:
            commit_objects: list[dora_result_calcs.ReturnCommitObject] = []
            for commit in commits:
                if (
                    (
                        commit_date := components.ensure_utc(dateutil.parser.isoparse(commit.commit.author['date']))
                    ) > (
                        datetime.datetime.now(datetime.timezone.utc) -
                        datetime.timedelta(days=time_span_days)
                    )
                ):
                    commit_objects.append(
                        dora_result_calcs.ReturnCommitObject(
                            commitDate=commit_date,
                            commitSha=commit.sha,
                            deploymentDate=deployment_date,
                            leadTime=(deployment_date - commit_date),
                            url=commit.html_url,
                        ),
                    )

        deployment_objects.append(
            dora_result_calcs.ReturnDeploymentObject(
                targetComponentVersionNew=target_update.target_component_version_new,
                targetComponentVersionOld=target_update.target_component_version_old,
                deployedComponentVersion=target_update.referenced_component_version_newer_release,
                oldComponentVersion=target_update.referenced_component_version_older_release,
                deploymentDate=deployment_date,
                commits=commit_objects
            )
        )

    tasks = [
        create_deployment_object_for_update(target_version_change_with_ref_change)
        for target_version_change_with_ref_change in target_updates
    ]

    await asyncio.gather(*tasks)
    return deployment_objects

@middleware.auth.noauth
class DoraMetrics(aiohttp.web.View):
    async def get(self):
        '''
        ---
        description:
          Retrieve DORA metrics for a target component over a specified time span.
        tags:
        - DORA
        produces:
        - application/json
        parameters:
        - in: query
          name: target_component_name
          type: string
          required: true
          description: The name of the target component.
        - in: query
          name: time_span_days
          type: integer
          required: false
          default: 90
          description: The number of days for the time span (default is 90).
        - in: query
          name: filter_component_name
          type: string
          required: true
          description: The name of the component to calculate the Dora Metrics for.
                responses:
          responses:
          "200":
            description: Successful operation. Returns DORA metrics for the specified components.
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    targetComponentName:
                      type: string
                      description: The name of the target component.
                    timePeriod:
                      type: number
                      format: float
                      description: The time period over which metrics were calculated.
                    componentName:
                      type: string
                      description: The name of the component for which DORA metrics are calculated.
                    medianDeploymentFrequency:
                      type: number
                      format: float
                      description: Median deployment frequency.
                    medianLeadTime:
                      type: number
                      format: float
                      description: Median lead time in seconds.
                    deploymentsPerMonth:
                      type: object
                      additionalProperties:
                        type: integer
                      description: Deployments per month.
                    deploymentsPerWeek:
                      type: object
                      additionalProperties:
                        type: integer
                      description: Deployments per week.
                    deploymentsPerDay:
                      type: object
                      additionalProperties:
                        type: integer
                      description: Deployments per day.
                    leadTimePerMonth:
                      type: object
                      additionalProperties:
                        type: number
                        format: float
                      description: Median lead time per month in seconds.
                    leadTimePerWeek:
                      type: object
                      additionalProperties:
                        type: number
                        format: float
                      description: Median lead time per week in seconds.
                    leadTimePerDay:
                      type: object
                      additionalProperties:
                        type: number
                        format: float
                      description: Median lead time per day in seconds.
                    deployments:
                      type: array
                      items:
                        type: object
                        properties:
                          targetComponentVersionNew:
                            type: string
                            description: New version of the target component.
                          targetComponentVersionOld:
                            type: string
                            description: Previous version of the target component.
                          deployedComponentVersion:
                            type: string
                            description: New version of the deployed component.
                          oldComponentVersion:
                            type: string
                            description: Previous version of the deployed component.
                          deploymentDate:
                            type: string
                            format: date-time
                            description: Date and time of deployment.
                          commits:
                            type: array
                            items:
                              type: object
                              properties:
                                commitSha:
                                  type: string
                                  description: SHA of the commit.
                                commitDate:
                                  type: string
                                  format: date-time
                                  description: Date of the commit.
                                deploymentDate:
                                  type: string
                                  format: date-time
                                  description: Date of deployment.
                                leadTime:
                                  type: number
                                  format: float
                                  description: Lead time in seconds.
                                url:
                                  type: string
                                  format: uri
                                  description: URL to the commit.
                      description: List of deployments with associated commits.
          "202":
            description: Dora metric calculation pending, client should retry.
        '''

        params = self.request.rel_url.query

        target_component_name: str = util.param(
            params,
           'target_component_name',
           required=True
        )

        time_span_days: int = int(util.param(
            params,
            'time_span_days',
            default=90,
        ))

        filter_component_name: str = util.param(
            params,
            'filter_component_name',
            required=True,
        )

        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById = self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP]
        version_lookup: cnudie.retrieve.VersionLookupByComponent = self.request.app[consts.APP_VERSION_LOOKUP]
        github_api_lookup = self.request.app[consts.APP_GITHUB_API_LOOKUP]

        await components.check_if_component_exists(
            component_name=target_component_name,
            version_lookup=version_lookup,
            raise_http_error=True,
        )

        await components.check_if_component_exists(
            component_name=filter_component_name,
            version_lookup=version_lookup,
            raise_http_error=True,
        )

        all_target_component_versions = await all_versions_sorted(
            component=target_component_name,
            version_lookup=version_lookup,
        )

        target_component_versions = await filter_versions_newer_than(
            component=target_component_name,
            all_versions=all_target_component_versions,
            date=datetime.datetime.now() - datetime.timedelta(days=time_span_days),
            component_descriptor_lookup=component_descriptor_lookup,
        )

        target_component_verisons_amount = len(target_component_versions)

        # add the last version out of the date range to the list, else it would not be possible to check if 
        # there where any version changes within the last release within the date range
        if target_component_verisons_amount != len(all_target_component_versions):
            target_component_versions.append(all_target_component_versions[len(target_component_versions)])
        # TODO how to handle if first release of target component is within the date range

        target_version_updates: list[ComponentVersionUpdate] = []

        for id in range(0, target_component_verisons_amount - 1):

            target_version_new = target_component_versions[id]
            target_version_old = target_component_versions[id + 1]

            old_target_component: ocm.Component = (
                await component_descriptor_lookup(
                    ocm.ComponentIdentity(
                        name=cnudie.util.to_component_name(
                            target_component_name
                        ),
                        version=versionutil.parse_to_semver(
                            target_version_old
                        ),
                    )
                )
            ).component

            old_target_component_tree = await latest_referenced_component_versions(
                component=old_target_component,
                component_descriptor_lookup=component_descriptor_lookup,
            )

            referenced_component_version_older_release = old_target_component_tree[
                filter_component_name
            ].version

            new_target_component = (await component_descriptor_lookup(
                ocm.ComponentIdentity(
                    name=cnudie.util.to_component_name(target_component_name),
                    version=versionutil.parse_to_semver(target_version_new),
                )
            )).component

            new_target_component_tree = await latest_referenced_component_versions(
                component=new_target_component,
                component_descriptor_lookup=component_descriptor_lookup,
            )

            referenced_component_version_newer_release = new_target_component_tree[
                filter_component_name
            ].version

            target_version_updates.append(
                ComponentVersionUpdate(
                    target_component=target_component_name,
                    target_component_version_old=target_version_old,
                    target_component_version_new=target_version_new,
                    referenced_component=filter_component_name,
                    referenced_component_version_older_release=referenced_component_version_older_release,
                    referenced_component_version_newer_release=referenced_component_version_newer_release,
                )
            )

        # filter out target version updates where the referenced component version did not change
        target_update_with_ref_updates = [
            target_version_update
            for target_version_update in target_version_updates
            if target_version_update.referenced_component_version_older_release
            < target_version_update.referenced_component_version_newer_release
        ]

        deployment_objects = await create_deployment_objects(
            component_descriptor_lookup=component_descriptor_lookup,
            component_version_lookup=version_lookup,
            github_api_lookup=github_api_lookup,
            target_component_name=target_component_name,
            time_span_days=time_span_days,
            filter_component_name=filter_component_name,
            target_updates=target_update_with_ref_updates,
        )

        deployments_per = dora_result_calcs.calc_deployments_per(
            deployment_objects=deployment_objects,
        )

        median_deployment_frequency = statistics.mean(deployments_per['deploymentsPerMonth'].values())

        lead_time_per = dora_result_calcs.calc_lead_time_per(
            deployment_objects=deployment_objects,
        )

        median_lead_time = statistics.median(
            lead_time_per['medianLeadTimePerMonth'].values()
        )

        return_object = dora_result_calcs.ReturnObject(
            targetComponentName=target_component_name,
            timePeriod=time_span_days,
            componentName=filter_component_name,
            deploymentsPerMonth=deployments_per['deploymentsPerMonth'],
            deploymentsPerWeek=deployments_per['deploymentsPerWeek'],
            deploymentsPerDay=deployments_per['deploymentsPerDay'],
            medianDeploymentFrequency=median_deployment_frequency,
            leadTimePerMonth=lead_time_per['medianLeadTimePerMonth'],
            leadTimePerWeek=lead_time_per['medianLeadTimePerWeek'],
            leadTimePerDay=lead_time_per['medianLeadTimePerDay'],
            medianLeadTime=median_lead_time,
            deployments=deployment_objects
        )

        return aiohttp.web.json_response(
            data=return_object.to_dict(),
            dumps=util.dict_to_json_factory,
        )
