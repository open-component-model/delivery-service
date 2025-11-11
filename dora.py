import collections
import collections.abc
import concurrent.futures
import dataclasses
import datetime
import enum
import functools
import http
import logging
import statistics
import typing
import urllib.parse

import aiohttp.web
import cachetools.keys
import dateutil.parser
import github3
import sqlalchemy.ext.asyncio as sqlasync

import cnudie.retrieve_async
import cnudie.util
import ocm
import ocm.iter
import ocm.iter_async
import version as versionutil

import caching
import components
import consts
import util


logger = logging.getLogger(__name__)
changes_by_dependencies_cache = dict()


@dataclasses.dataclass(frozen=True)
class CodeChange:
    '''
    Represents a code change with its commit data and deployment date
    '''
    commit_sha: str
    commit_date: datetime.datetime
    deployment_date: datetime.datetime


@dataclasses.dataclass(frozen=True)
class ComponentDependencyChangeWithCommits:
    '''
    Holds a Dependency Change for a specific Component as well as the commits included within the
    Dependency Change
    '''
    component: ocm.Component
    dependency_component_vector: components.ComponentVector
    commits: list[github3.github.repo.commit.ShortCommit]


@dataclasses.dataclass(frozen=True)
class ComponentWithDependencyChanges:
    '''
    Holds a component descriptor as well as a list of dependency updates, which
    where introduced in this component Version
    '''
    component_descriptor: ocm.ComponentDescriptor
    dependency_changes: list[components.ComponentVector]


class CalculationType(enum.StrEnum):
    MEDIAN = 'median'
    AVERAGE = 'average'


class DeploymentFrequencyBuckets(enum.StrEnum):
    '''
    Typical Buckets to which a deplyoment Frequency can be assigned
    '''
    daily = 'daily'
    weekly = 'weekly'
    monthly = 'monthly'
    yearly = 'yearly'


@dataclasses.dataclass(frozen=True)
class DoraDeploymentsResponse:
    '''
    Helper datacalss for creating JSON response for the DoraMetrics Route
    '''
    target_deployment_version: str
    component_version: str
    deployment_date: datetime.datetime
    median_change_lead_time: float
    changes: list[CodeChange]


@dataclasses.dataclass(frozen=True)
class DoraMonthlyResponse:
    '''
    Helper datacalss for creating JSON response for the DoraMetrics Route
    '''
    year: int
    month: int
    median_change_lead_time: float
    changes: list[CodeChange]


@dataclasses.dataclass(frozen=True)
class DoraDependencyResponse:
    '''
    Helper datacalss for creating JSON response for the DoraMetrics Route
    '''
    change_lead_time_median: float
    change_lead_time_average: float
    deployment_frequency: float
    changes_monthly: list[DoraMonthlyResponse]
    deployments: list[DoraDeploymentsResponse]
    all_changes: list[CodeChange]
    repo_url: str


@dataclasses.dataclass(frozen=True)
class DoraResponse:
    '''
    Helper datacalss for creating JSON response for the DoraMetrics Route
    '''
    change_lead_time_median: float
    change_lead_time_average: float
    dependencies: dict[str, DoraDependencyResponse]


async def versions_descriptors_newer_than(
    component_name: str,
    date: datetime.datetime,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    sorting_direction: typing.Literal['asc', 'desc'] = 'desc',
    db_session: sqlasync.session.AsyncSession=None,
) -> list[ocm.ComponentDescriptor]:
    '''
    This function retrieves the component descriptors for the versions
    of a specific Component, which are newer then the given date.

    asc-sorting means old to new => [0.102.0 ... 0.321.2]

    desc-sorting means new to old => [0.321.2 ... 0.102.0]
    '''

    def _filter_component_newer_than_date(
        descriptor: ocm.ComponentDescriptor,
        date: datetime.datetime,
    ) -> bool:
        creation_date: datetime.datetime = util.get_creation_date(descriptor.component)
        return creation_date > date

    versions = await all_versions_sorted(
        component=component_name,
        sorting_direction='desc',
        db_session=db_session,
    )

    descriptors: list[ocm.ComponentDescriptor] = []

    for version in versions:
        descriptor = await component_descriptor_lookup((component_name, version))
        try:
            if not _filter_component_newer_than_date(descriptor, date):
                break
        except KeyError:
            continue
        descriptors.append(descriptor)

    if sorting_direction == 'asc':
        descriptors.reverse()

    return descriptors


def _cache_key_gen_all_versions_sorted(
    component: cnudie.util.ComponentName,
    sorting_direction: typing.Literal['asc', 'desc'] = 'desc',
    db_session: sqlasync.session.AsyncSession=None,
):
    return cachetools.keys.hashkey(
        cnudie.util.to_component_name(component),
        sorting_direction,
    )


@caching.async_cached(
    cache=caching.TTLFilesystemCache(ttl=60 * 60 * 24, max_total_size_mib=128), # 1 day
    key_func=_cache_key_gen_all_versions_sorted,
)
async def all_versions_sorted(
    component: cnudie.util.ComponentName,
    sorting_direction: typing.Literal['asc', 'desc'] = 'desc',
    db_session: sqlasync.session.AsyncSession=None,
) -> list[str]:
    '''
    This is a convenience function for looking up all versions of a specific
    component.

    asc-sorting means old to new => [0.102.0 ... 0.321.2]
    desc-sorting means new to old => [0.321.2 ... 0.102.0]
    '''
    component_name = cnudie.util.to_component_name(component)

    versions = await components.component_versions(
        component_name=component_name,
        db_session=db_session,
    )

    def version_key(version: str) -> str:
        try:
            version = versionutil.parse_to_semver(version)
        except ValueError:
            version = versionutil.parse_to_semver('0.0')

        return version

    return sorted(
        versions,
        key=version_key,
        reverse=sorting_direction == 'desc',
    )


async def get_next_older_descriptor(
    component_id: ocm.ComponentIdentity,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    db_session: sqlasync.session.AsyncSession=None,
) -> ocm.ComponentDescriptor | None:
    all_versions = await all_versions_sorted(
        component=component_id,
        sorting_direction='desc',
        db_session=db_session,
    )

    if (version_index := all_versions.index(component_id.version)) != len(all_versions) - 1:
        old_target_version = all_versions[version_index + 1]
    else:
        return None

    return await component_descriptor_lookup(
        ocm.ComponentIdentity(
            name=component_id.name,
            version=old_target_version,
        ),
    )


def next_older_month(date: datetime.datetime) -> datetime.datetime:
    month = 12 if date.month == 1 else date.month - 1
    year = date.year - 1 if date.month == 1 else date.year
    older_month_date = datetime.datetime(year, month, 1, tzinfo=datetime.UTC)
    return older_month_date


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


def _cache_key_gen_component_vector_and_lookup(
    left_commit: str,
    right_commit: str,
    github_repo,
):
    return cachetools.keys.hashkey(
        left_commit,
        right_commit,
    )


@caching.cached(
    cache=caching.LFUFilesystemCache(max_total_size_mib=256),
    key_func=_cache_key_gen_component_vector_and_lookup,
)
def commits_for_component_change(
    left_commit: str,
    right_commit: str,
    github_repo: github3.repos.Repository,
) -> tuple[github3.github.repo.commit.ShortCommit]:
    '''
    returns commits between passed-on commits. results are read from github-api and cached.
    passed-on commits must exist in repository referenced by passed-in github_repo.
    '''
    return tuple(github_repo.compare_commits(
        left_commit,
        right_commit,
    ).commits())


def _cache_key_changes_by_dependencies(
    target_descriptors_with_updates: tuple[ComponentWithDependencyChanges],
):
    return cachetools.keys.hashkey(''.join([(
        f'{target_descriptor_with_updates.component_descriptor.component.name}'
        f'{target_descriptor_with_updates.component_descriptor.component.version}'
    ) for target_descriptor_with_updates in target_descriptors_with_updates]))


def categorize_by_changed_component(
    target_descriptors_with_updates: tuple[ComponentWithDependencyChanges],
    github_api_lookup,
) -> dict[str, list[ComponentDependencyChangeWithCommits]]:
    dependencies: dict[str, list[ComponentDependencyChangeWithCommits]] = (
        collections.defaultdict(list[ComponentDependencyChangeWithCommits])
    )

    _github_api = functools.cache(github_api_lookup)

    @functools.cache
    def _github_repo(repo_url: urllib.parse.ParseResult):
        github = _github_api(repo_url)
        org, repo = repo_url.path.strip('/').split('/')

        return github.repository(org, repo)

    def resolve_changes(
        target_descriptor_with_updates: ComponentWithDependencyChanges,
    ):
        for dependency_update in target_descriptor_with_updates.dependency_changes:
            target_component = target_descriptor_with_updates.component_descriptor.component
            dependency_component_name = dependency_update.end.name

            left_component = dependency_update.start
            right_component = dependency_update.end

            left_src = cnudie.util.main_source(
                left_component,
                absent_ok=True,
            )
            right_src = cnudie.util.main_source(
                right_component,
                absent_ok=True,
            )

            if not left_src or not right_src:
                continue

            left_access = left_src.access
            right_access = right_src.access

            if not left_access.type is ocm.AccessType.GITHUB:
                continue
            if not right_access.type is ocm.AccessType.GITHUB:
                continue

            left_repo_url = util.urlparse(left_access.repoUrl)
            right_repo_url = util.urlparse(right_access.repoUrl)

            if not left_repo_url == right_repo_url:
                continue # ensure there was no repository-change between component-versions

            left_commit = left_access.commit or left_access.ref
            right_commit = right_access.commit or right_access.ref

            github_repo = _github_repo(
                repo_url=left_repo_url, # already checked for equality; choose either
            )

            dependencies[dependency_component_name].append(
                ComponentDependencyChangeWithCommits(
                    component=target_component,
                    dependency_component_vector=dependency_update,
                    commits=commits_for_component_change(
                        left_commit=left_commit,
                        right_commit=right_commit,
                        github_repo=github_repo,
                    ),
                )
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as tpe:
        futures = {
            tpe.submit(resolve_changes, target_descriptor_with_updates)
            for target_descriptor_with_updates in target_descriptors_with_updates
        }
        concurrent.futures.wait(futures)

    key = _cache_key_changes_by_dependencies(target_descriptors_with_updates)
    changes_by_dependencies_cache[key] = dependencies

    return dependencies


def _cache_key_gen_dora(
    component_dependency_changes_with_commits: list[
        ComponentDependencyChangeWithCommits
    ],
    time_span_days: int | None = None,
    calculation_type: CalculationType | None = None
):
    component_versions = tuple(
        component_dependency_change_with_commits.component.version
        for component_dependency_change_with_commits in component_dependency_changes_with_commits
    )
    hashkey_elements = (
        component_dependency_changes_with_commits[0].component.name,
        component_dependency_changes_with_commits[0].dependency_component_vector.start.name,
        component_dependency_changes_with_commits[0].dependency_component_vector.end.name,
        component_dependency_changes_with_commits[0].dependency_component_vector.start.version,
        component_dependency_changes_with_commits[0].dependency_component_vector.end.version,
        component_versions,
    )
    if time_span_days: hashkey_elements += (time_span_days, datetime.date.today())
    if calculation_type: hashkey_elements += (calculation_type,)

    return cachetools.keys.hashkey(*hashkey_elements)


@caching.cached(
    cache=caching.LFUFilesystemCache(max_total_size_mib=128),
    key_func=_cache_key_gen_dora,
)
def calculate_change_lead_time(
    component_dependency_changes_with_commits: list[
        ComponentDependencyChangeWithCommits
    ],
    time_span_days: int,
    calculation_type: CalculationType,
) -> datetime.timedelta:
    time_differences: list[datetime.timedelta] = []

    for component_dependency_change_with_commits in component_dependency_changes_with_commits:
        deployment_date = util.get_creation_date(
            component_dependency_change_with_commits.component
        )
        for commit in component_dependency_change_with_commits.commits:
            if (
                    (
                            commit_date := dateutil.parser.isoparse(commit.commit.author['date'])
                    ) > (
                    datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(days=time_span_days)
            )
            ):
                time_differences.append(deployment_date -  commit_date)

    if not time_differences:
        time_differences.append(datetime.timedelta(seconds=-1))
    if calculation_type is CalculationType.MEDIAN:
        result_in_seconds: float = statistics.median(
            [time_difference.total_seconds()
             for time_difference in time_differences]
        )
    else:
        result_in_seconds: float = statistics.mean(
            [time_difference.total_seconds()
             for time_difference in time_differences]
        )
    return datetime.timedelta(seconds=result_in_seconds)


@caching.cached(
    cache=caching.LFUFilesystemCache(max_total_size_mib=128),
    key_func=_cache_key_gen_dora,
)
def dora_changes_monthly(
    component_dependency_changes_with_commits: list[
        ComponentDependencyChangeWithCommits
    ],
    time_span_days: int,
) -> list[DoraMonthlyResponse]:

    code_changes_by_month: dict[
        tuple[int, int],
        list[tuple[datetime.datetime, CodeChange]],
    ] = (
        collections.defaultdict(list[tuple[datetime.datetime, CodeChange]])
    )

    for component_dependency_change_with_commits in component_dependency_changes_with_commits:
        for commit in component_dependency_change_with_commits.commits:
            if (
                    (
                            commit_date := dateutil.parser.isoparse(commit.commit.author['date'])
                    ) > (
                    datetime.datetime.now(datetime.timezone.utc) -
                    datetime.timedelta(days=time_span_days)
            )
            ):
                commit_sha: str = commit.sha
                key = (commit_date.year, commit_date.month)
                code_changes_by_month[key].append(
                    (
                        util.get_creation_date(
                            component_dependency_change_with_commits.component
                        ),
                        CodeChange(
                            commit_date=commit_date,
                            commit_sha=commit_sha,
                            deployment_date=util.get_creation_date(
                                component_dependency_change_with_commits.component
                            ),
                        ),
                    ),
                )

    by_month_list: list[DoraMonthlyResponse] = []

    for (year, month), code_changes in code_changes_by_month.items():

        median_change_lead_time = datetime.timedelta(seconds=statistics.median(
            [
                (deploy_date - commits_and_date.commit_date).total_seconds()
                for deploy_date, commits_and_date in code_changes
            ]
        ))

        by_month_list.append(DoraMonthlyResponse(
            changes=[commits_and_date for _, commits_and_date in code_changes],
            month=month,
            year=year,
            median_change_lead_time=median_change_lead_time.days,
        ))

    # create "empty" months which lie within the time_span_days
    entry_date = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=time_span_days)
    )

    while entry_date < datetime.datetime.now(datetime.timezone.utc):
        if (entry_date.year, entry_date.month) not in code_changes_by_month:
            by_month_list.append(DoraMonthlyResponse(
                changes=[],
                month=entry_date.month,
                year=entry_date.year,
                median_change_lead_time=-1,
            ))
        entry_date += datetime.timedelta(days=30)

    return by_month_list


@caching.cached(
    cache=caching.LFUFilesystemCache(max_total_size_mib=128),
    key_func=_cache_key_gen_dora,
)
def dora_deployments(
        component_dependency_changes_with_commits: list[
            ComponentDependencyChangeWithCommits
        ],
) -> list[DoraDeploymentsResponse]:
    deployments: list[DoraDeploymentsResponse] = []

    for component_dependency_change_with_commits in component_dependency_changes_with_commits:

        median_change_lead_time = datetime.timedelta(
            seconds=statistics.median([
                (util.get_creation_date(
                    component_dependency_change_with_commits.component
                ) - dateutil.parser.isoparse(
                    commit.commit.author['date']
                )).total_seconds()
                for commit in component_dependency_change_with_commits.commits
            ]) if component_dependency_change_with_commits.commits else 0,
        )

        deployment_date = util.get_creation_date(
            component_dependency_change_with_commits.component
        )

        deployments.append(
            DoraDeploymentsResponse(
                deployment_date=deployment_date,
                component_version=(
                    component_dependency_change_with_commits.dependency_component_vector.end.version
                ),
                target_deployment_version=component_dependency_change_with_commits.component.version,
                changes=[
                    CodeChange(
                        commit_date=dateutil.parser.isoparse(commit.commit.author['date']),
                        commit_sha=commit.sha,
                        deployment_date=deployment_date,
                    )
                    for commit in component_dependency_change_with_commits.commits
                ],
                median_change_lead_time=median_change_lead_time.days,
            )
        )

    return deployments


def all_change_lead_time_durations(
    component_dependency_changes_with_commits: list[
        ComponentDependencyChangeWithCommits
    ],
    time_span_days: int,
) -> list[int]:
    commit_durations = []
    for component_dependency_change_with_commits in component_dependency_changes_with_commits:
        commit_durations.extend(
            [
                (
                        util.get_creation_date(
                            component_dependency_change_with_commits.component
                        )
                        - dateutil.parser.isoparse(commit.commit.author['date'])
                ).total_seconds()
                for commit in component_dependency_change_with_commits.commits
                if (
                    dateutil.parser.isoparse(commit.commit.author['date']) >
                    (
                            datetime.datetime.now(datetime.timezone.utc)
                            - datetime.timedelta(days=time_span_days)
                    )
            )
            ]
        )

    return commit_durations


def all_changes(
    component_dependency_changes_with_commits: list[
        ComponentDependencyChangeWithCommits
    ],
    time_span_days: int,
) -> list[CodeChange]:

    all_changes = []
    for component_dependency_change_with_commits in component_dependency_changes_with_commits:
        all_changes.extend(
            [
                CodeChange(
                    commit_sha=commit.sha,
                    commit_date=dateutil.parser.isoparse(commit.commit.author['date']),
                    deployment_date=util.get_creation_date(
                        component_dependency_change_with_commits.component,
                    ),
                ) for commit in component_dependency_change_with_commits.commits
                if dateutil.parser.isoparse(commit.commit.author['date']) >
                   datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=time_span_days)
            ]
        )

    return all_changes


def create_response_object(
    target_updates_by_dependency: dict[
        str,
        list[ComponentDependencyChangeWithCommits],
    ],
    time_span_days: int,
):
    dependencies_response: dict[
        str,
        DoraDependencyResponse,
    ] = {}

    all_change_lead_time_durations_seconds = []

    for dependency_name, component_dependency_changes_with_commits \
            in target_updates_by_dependency.items():

        median = calculate_change_lead_time(
            component_dependency_changes_with_commits,
            time_span_days,
            CalculationType.MEDIAN,
        )
        average = calculate_change_lead_time(
            component_dependency_changes_with_commits,
            time_span_days,
            CalculationType.AVERAGE,
        )
        changes_monthly = dora_changes_monthly(
            component_dependency_changes_with_commits,
            time_span_days,
        )
        deployments = dora_deployments(
            component_dependency_changes_with_commits,
        )
        changes = all_changes(
            component_dependency_changes_with_commits,
            time_span_days,
        )
        repo_url = cnudie.util.main_source(
            component_dependency_changes_with_commits[0].dependency_component_vector.start
        ).access.repoUrl

        dependencies_response[dependency_name] = DoraDependencyResponse(
            change_lead_time_median=median.days,
            change_lead_time_average=average.days,
            deployment_frequency=round(time_span_days / len(deployments), 2),
            changes_monthly=changes_monthly,
            deployments=deployments,
            all_changes=changes,
            repo_url=repo_url,
        )

        all_change_lead_time_durations_seconds.extend(
            all_change_lead_time_durations(
                component_dependency_changes_with_commits,
                time_span_days,
            )
        )

    if all_change_lead_time_durations_seconds != []:
        change_lead_time_median = datetime.timedelta(
            seconds=statistics.median(
                all_change_lead_time_durations_seconds
            )
        ).days
        change_lead_time_average = datetime.timedelta(
            seconds=statistics.mean(
                all_change_lead_time_durations_seconds
            )
        ).days
    else:
        change_lead_time_median = -1
        change_lead_time_average = -1

    return DoraResponse(
        change_lead_time_median=change_lead_time_median,
        change_lead_time_average=change_lead_time_average,
        dependencies=dependencies_response,
    )


class DoraMetrics(aiohttp.web.View):
    async def get(self):
        '''
        ---
        tags:
        - Dora
        produces:
        - application/json
        parameters:
        - in: query
          name: target_component_name
          type: string
          required: true
        - in: query
          name: time_span_days
          type: integer
          required: false
          default: 90
        - in: query
          name: filter_component_names
          schema:
            type: array
            items:
              type: string
          required: false
        responses:
          "200":
            description: Successful operation.
            schema:
              type: object
              required:
              - change_lead_time_median
              - change_lead_time_average
              - dependencies
              properties:
                change_lead_time_median:
                  type: number
                change_lead_time_average:
                  type: number
                dependencies:
                  type: object
          "202":
            description: Dora metric calculation pending, client should retry.
        '''
        params = self.request.rel_url.query

        target_component_name = util.param(params, 'target_component_name', required=True)
        time_span_days = int(util.param(params, 'time_span_days', default=90))
        filter_component_names = params.getall('filter_component_names', default=[])

        component_descriptor_lookup = self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP]
        db_session = self.request.get(consts.REQUEST_DB_SESSION)

        await components.check_if_component_exists(
            component_name=target_component_name,
            db_session=db_session,
        )

        for filter_component_name in filter_component_names:
            await components.check_if_component_exists(
                component_name=filter_component_name,
                db_session=db_session,
            )

        # get all component descriptors of component versions of target component within time span
        target_descriptors_in_time_span = await versions_descriptors_newer_than(
            component_name=target_component_name,
            date=datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=time_span_days),
            component_descriptor_lookup=component_descriptor_lookup,
            sorting_direction='asc',
            db_session=db_session,
        )

        # Add the next older version, which is not within the time span anymore (if one exists)
        # at the beginning of the descriptor list to be able to detect changes which were
        # first introduced within the time span of the target component version.

        if (next_older_descriptor := await get_next_older_descriptor(
            component_id=ocm.ComponentIdentity(
                target_component_name,
                target_descriptors_in_time_span[0].component.version,
            ),
            component_descriptor_lookup=component_descriptor_lookup,
            db_session=db_session,
        )):
            target_descriptors_in_time_span.insert(0, next_older_descriptor)

        # calculate the changes which where introduced for every component version
        target_descriptors_with_updates: list[ComponentWithDependencyChanges] = []
        for index in range(1, len(target_descriptors_in_time_span)):
            component_diff = await _diff_components(
                component_vector=components.ComponentVector(
                    start=target_descriptors_in_time_span[index-1].component,
                    end=target_descriptors_in_time_span[index].component,
                ),
                component_descriptor_lookup=component_descriptor_lookup,
            )

            if component_diff:
                dependency_changes = dependency_changes_between_versions(
                    component_diff=component_diff,
                    dependency_name_filter=filter_component_names,
                    only_rising_changes=True,
                )
            else:
                dependency_changes = []

            target_descriptors_with_updates.append(
                ComponentWithDependencyChanges(
                    component_descriptor=target_descriptors_in_time_span[index],
                    dependency_changes=dependency_changes,
                )
            )

        target_descriptors_with_updates = tuple(target_descriptors_with_updates)

        key = _cache_key_changes_by_dependencies(target_descriptors_with_updates)

        # categorize changes by changed dependency
        # and add commits to the dependency changes
        if (updates_by_dependency := changes_by_dependencies_cache.get(key)) is None:
            if key not in changes_by_dependencies_cache:
                changes_by_dependencies_cache[key] = None
                tpe = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                tpe.submit(
                    categorize_by_changed_component,
                    target_descriptors_with_updates,
                    self.request.app[consts.APP_GITHUB_API_LOOKUP],
                )

            return aiohttp.web.Response(
                status=http.HTTPStatus.ACCEPTED,
            )

        return aiohttp.web.json_response(
            data=create_response_object(
                target_updates_by_dependency=updates_by_dependency,
                time_span_days=time_span_days,
            ),
            dumps=util.dict_to_json_factory,
        )


def _cache_key_diff_components(
    component_vector: components.ComponentVector,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
):
    return cachetools.keys.hashkey(
        component_vector.start.name,
        component_vector.end.name,
        component_vector.start.version,
        component_vector.end.version,
    )


@caching.async_cached(
    cache=caching.LFUFilesystemCache(max_total_size_mib=256),
    key_func=_cache_key_diff_components,
)
async def _diff_components(
    component_vector: components.ComponentVector,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
) -> cnudie.util.ComponentDiff | None:
    '''
    calculates component-diff between components from passed-in component-vector

    this function is mostly identical to cnudie.util.diff_components. It differs, however,
    in that it will merge multiple component-versions (of the same component) into just one
    component-version, choosing greatest/smallest versions.
    '''
    old_components = [
        c.component async for c in ocm.iter_async.iter(
            component=component_vector.start,
            lookup=component_descriptor_lookup,
            node_filter=ocm.iter.Filter.components,
        )
    ]

    new_components = [
        c.component async for c in ocm.iter_async.iter(
            component=component_vector.end,
            lookup=component_descriptor_lookup,
            node_filter=ocm.iter.Filter.components,
        )
    ]

    def only_greatest_versions(components: list[ocm.Component]):
        components_by_name: collections.defaultdict[
            str, list[ocm.Component]
        ] = collections.defaultdict(list[ocm.Component])

        for c in components:
            components_by_name[c.name].append(c)

        greatest_component_versions = []
        for component_name, component_list in components_by_name.items():
            if len(component_list) == 1:
                greatest_component_versions.append(component_list[0])
                continue
            current_biggest_version = component_list[0]
            for c in component_list[1:]:
                if(
                    versionutil.parse_to_semver(c.version) >
                    versionutil.parse_to_semver(current_biggest_version.version)
                ):
                    current_biggest_version = c
            greatest_component_versions.append(current_biggest_version)

        return greatest_component_versions

    old_greatest_component_versions = only_greatest_versions(old_components)
    new_greatest_component_versions = only_greatest_versions(new_components)

    old_greatest_component_identities = {
        c.identity() for c in old_greatest_component_versions
    }
    new_greatest_component_identities = {
        c.identity() for c in new_greatest_component_versions
    }

    old_only_greatest_component_identities = (
        old_greatest_component_identities - new_greatest_component_identities
    )
    new_only_greatest_component_identities = (
        new_greatest_component_identities - old_greatest_component_identities
    )

    old_only_greatest_component_versions = [
        c for c in old_greatest_component_versions
        if c.identity() in old_only_greatest_component_identities
    ]
    new_only_greatest_component_versions = [
        c for c in new_greatest_component_versions
        if c.identity() in new_only_greatest_component_identities
    ]

    if old_only_greatest_component_identities == new_only_greatest_component_identities:
        return None # no diff

    def find_changed_component(
        old_only_component_version: ocm.Component,
        new_only_component_versions: list[ocm.Component],
    ):
        for new_only_component_version in new_only_component_versions:
            if new_only_component_version.name == old_only_component_version.name:
                return (old_only_component_version, new_only_component_version)
        return (old_only_component_version, None) # no pair component found

    components_with_changed_versions = []
    for old_only_greatest_component_version in old_only_greatest_component_versions:
        changed_component = find_changed_component(
            old_only_greatest_component_version,
            new_only_greatest_component_versions,
        )
        if changed_component[1] is not None:
            components_with_changed_versions.append(changed_component)

    old_component_names = {i.name for i in old_greatest_component_identities}
    new_component_names = {i.name for i in new_greatest_component_identities}
    names_version_changed = {c[0].name for c in components_with_changed_versions}

    both_names = old_component_names & new_component_names
    old_component_names -= both_names
    new_component_names -= both_names

    return cnudie.util.ComponentDiff(
        cidentities_only_left=set(),
        cidentities_only_right=set(),
        cpairs_version_changed=components_with_changed_versions,
        names_only_left=old_component_names,
        names_only_right=new_component_names,
        names_version_changed=names_version_changed,
    )


def dependency_changes_between_versions(
    component_diff: cnudie.util.ComponentDiff,
    dependency_name_filter: collections.abc.Iterable[str] | None = None,
    only_rising_changes: bool = False,
) -> list[components.ComponentVector]:
    '''
    This function retrieves the changes which where made between two versions of a Component.
    There is the possibilitie to filter for the changes of just one component.

    @param dependency_name_filter: If given a dependency_name_filter (Component Names),
        only the changes of these specific components are returned.
    @param only_rising_changes: If True, only the changes are returned, where the version
        of the new component is higher than the version of the old component.

    @returns: List of the changes between the two versions
    '''
    if not component_diff:
        raise ValueError(component_diff)

    changes: list[components.ComponentVector] = []

    for left_component, right_component in component_diff.cpairs_version_changed:
        if (
            dependency_name_filter
            and left_component.name not in dependency_name_filter
        ):
            continue

        left_version = versionutil.parse_to_semver(left_component.version)
        right_version = versionutil.parse_to_semver(right_component.version)

        if only_rising_changes:
            if left_version >= right_version:
                continue
        elif left_version == right_version:
            continue

        changes.append(
            components.ComponentVector(
                left_component,
                right_component,
            )
        )

    return changes
