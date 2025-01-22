import collections.abc
import dataclasses
import enum
import logging
import time
import urllib.parse

import cachetools
import github3
import github3.exceptions
import github3.orgs
import github3.repos
import github3.repos.commit
import github3.repos.repo
import github3.repos.stats
import github3.users

import ccc.github
import ci.util

import ctx_util
import paths
import responsibles.user_model
import responsibles
import util


logger = logging.getLogger(__name__)


class ResponsibleDeterminationConfidence(enum.Enum):
    POOR = 'poor'
    MEDIOCRE = 'mediocre'
    GOOD = 'good'
    UNKNOWN = 'unknown'


@dataclasses.dataclass
class RepoStats:
    authors: int

    commit_total: float
    commit_n: int
    commit_n_percentile: float
    authors_in_commit_n_percentile: list[str]

    # loc == lines of changes
    loc_total: float
    loc_n: int
    loc_n_percentile: float
    authors_in_loc_n_percentile: list[str]


@dataclasses.dataclass(frozen=True)
class ResponsiblesDetectionHeuristicsParameters:
    weight_function_identifier: str
    max_responsibles: int
    percentile_min: int


def sigmoid(x, x0, k):
    import numpy

    y = 1 / (1 + numpy.exp(-k*(x-x0)))
    return y


def fit_sigmoid_for_repo_days(
    repo_age_in_days: int,
):
    '''
    fits a sigmoid function for given upper limit on x axis, considering inital data points.
    '''
    import numpy
    import scipy.optimize

    # describe expected function
    xdata = numpy.array([
        0,
        repo_age_in_days/4,
        repo_age_in_days/5*2,
        repo_age_in_days/2,
        repo_age_in_days/5*3,
        repo_age_in_days/4*3,
        repo_age_in_days,
    ])
    ydata = numpy.array([
        0.01,
        0.05,
        0.30,
        0.50,
        0.70,
        0.95,
        0.99,
    ])

    # fit sigmoid
    popt, _ = scipy.optimize.curve_fit(sigmoid, xdata, ydata, p0=[repo_age_in_days/4, 0.001])

    return popt


def weight(
    method: str,
    days_delta: int,
    repo_age_days: int,
    # bias used to cap loss of very old commits
    # current value based on testing
    bias: float = 0.17,
) -> float:
    '''
    Returns biased weight based on age in range ]0;1[
    `method` can either be "linear" or "sigmoid".
    `bias` is added to each returned weight.
    '''

    if method == 'linear':
        # greater x -> greater y (higher age == more value), thus 1 - value
        return 1-(days_delta/repo_age_days) + bias
    elif method == 'sigmoid':
        popt = fit_sigmoid_for_repo_days(
            repo_age_in_days=repo_age_days,
        )
        # greater x -> greater y (higher age == more value), thus 1 - value
        return (1-sigmoid(days_delta, *popt)) + bias

    raise NotImplementedError(f'weight {method=} not supported, choose from "linear" and "sigmoid"')


def n_percentile_with_member_count(
    member_count: int,
    usernames_values: dict,
    percentile_minimum: int,
):
    '''
    Recursively calculates the greatest n-th percentile with a certain member count.
    - accepts a sequence of (identifier, number), and a maximum amount of "members", and a minimum
      n for the n-th percentile
    - iteratively increases n, until the members-count is equal to or smaller than specfied allowed
      maximum
    - if members-count is smaller or reached, the greatest n without changes to this count is
      determined

    usernames_values: {
        <identifier e.g. username>: <value (considered by percentile)>
    }

    Returns tuple of: (
        <n>,
        <the n-th percentile>,
        <[identifiers in that percentile]>
    )
    '''
    import numpy

    first_match = True
    first_count = None

    for n in range(50, 100, 1):
        n_percentile = numpy.percentile([value for value in usernames_values.values()], n)
        in_percentile = [u for u, v in usernames_values.items() if v >= n_percentile]
        contributor_count = len(in_percentile)
        if contributor_count > member_count:
            continue
        # get greatest n-th percentile with same member count
        if first_match:
            first_match = False
            first_count = contributor_count

        if first_count == contributor_count:
            last_n = n
            last_n_percentile = n_percentile
            last_in_percentile = in_percentile

        else:
            if last_n >= percentile_minimum:
                return last_n, last_n_percentile, last_in_percentile

            # count would become smaller than target, but percentile minimun not reached
            # reduce count to have a smaller, more accurate determination
            return n_percentile_with_member_count(
                member_count=member_count-1,
                usernames_values=usernames_values,
                percentile_minimum=percentile_minimum,
            )
    else:
        return last_n, last_n_percentile, last_in_percentile


def global_stats(
    # retrieved from 'api.github.com/repos/<org>/<repo>/stats/contributors'
    repo_stats: list[dict],
    weight_function_identifier: str,
    max_responsibles: int,
    percentile_min: int,
) -> RepoStats:
    '''
    calculates global stats for given repo statistics and stat parameters.
    - determine n-th percentile considering max_responsibles and minimum n
    - apply weight_function for both metrics, commits, and locs

    weight_function_identifier: <str>
        defines which weight function to take, either sigmoid or linear

    percentile_min: <int>
        minimum n for n-th percentile required to acknowledge a percentile meaningful

    max_responsibles: <int>
        upper limit for amount of responsibles, algo will reduce responsibles until reached

    '''
    if not repo_stats:
        raise ValueError('not enough commits')

    # fit age weighting function
    now = int(time.time())
    first_week = repo_stats[0]['weeks'][0]
    then = int(first_week['w'])
    repo_age_in_days = int((now - then) / 60 / 60 / 24)

    # commits
    total_weighted_commits = []
    for r in repo_stats:
        weighted_commit_count = 0
        for week in r['weeks']:
            if week['c'] != 0:
                then = int(week['w'])
                # epoch (s) to days
                delta = int((now - then) / 60 / 60 / 24)
                weighted_commit_count += weight(
                    method=weight_function_identifier,
                    days_delta=delta,
                    repo_age_days=repo_age_in_days,
                ) * week['c']
        total_weighted_commits.append({
            'username': r['author']['login'],
            'commits': weighted_commit_count,
        })

    commit_n, commit_n_percentile, authors_in_commit_n_percentile = n_percentile_with_member_count(
        member_count=max_responsibles,
        usernames_values={
            e['username']: e['commits']
            for e in total_weighted_commits
        },
        percentile_minimum=percentile_min,
    )

    # loc
    total_weighted_loc = []
    for r in repo_stats:
        weighted_loc_count = 0
        for week in r['weeks']:
            if week['c'] != 0:
                then = int(week['w'])
                # epoch (s) to days
                delta = int((now - then) / 60 / 60 / 24)
                loc = week['a'] + week['d']
                weighted_loc_count += weight(
                    method=weight_function_identifier,
                    days_delta=delta,
                    repo_age_days=repo_age_in_days,
                ) * loc
        total_weighted_loc.append({
            'username': r['author']['login'],
            'loc': weighted_loc_count,
        })

    usernames_values = {
        e['username']: e['loc']
        for e in total_weighted_loc
    }

    if not sum(usernames_values.values()):
        # github does not provide LoC statistics for all repositories (e.g. cc-utils)
        raise ValueError('sum of contributors LoC must not be 0')

    loc_n, loc_n_percentile, authors_in_loc_n_percentile = n_percentile_with_member_count(
        member_count=max_responsibles,
        usernames_values=usernames_values,
        percentile_minimum=percentile_min,
    )

    return RepoStats(
        authors=repo_stats,
        commit_total=sum(w['commits'] for w in total_weighted_commits),
        commit_n=commit_n,
        commit_n_percentile=commit_n_percentile,
        authors_in_commit_n_percentile=authors_in_commit_n_percentile,
        loc_total=sum(w['loc'] for w in total_weighted_loc),
        loc_n=loc_n,
        loc_n_percentile=loc_n_percentile,
        authors_in_loc_n_percentile=authors_in_loc_n_percentile,
    )


def heuristically_determine_responsibles(
    stats: RepoStats,
    max_responsibles: int,
) -> tuple[tuple[str], ResponsibleDeterminationConfidence]:
    '''
    Return determined responsibles and determination confidence.
    '''
    candidates_from_commits_stats = set(stats.authors_in_commit_n_percentile)
    candidates_from_loc_stats = set(stats.authors_in_loc_n_percentile)

    candidates_in_both_stats = candidates_from_commits_stats & candidates_from_loc_stats
    candidate_diff_count = len(candidates_from_commits_stats - candidates_from_loc_stats)
    candidates_from_both_stats = list(candidates_from_commits_stats | candidates_from_loc_stats)

    # edge-case: locs and committers no intersection
    # check for length to reduce false-positives and only use this fallback
    # if resulting responsibles count is acceptable
    if not candidates_in_both_stats:
        if len(candidates_from_both_stats) <= max_responsibles:
            return candidates_from_both_stats, ResponsibleDeterminationConfidence.MEDIOCRE

    if candidate_diff_count == 0:
        return tuple(candidates_in_both_stats), ResponsibleDeterminationConfidence.GOOD
    if candidate_diff_count == 1:
        return tuple(candidates_in_both_stats), ResponsibleDeterminationConfidence.MEDIOCRE
    if candidate_diff_count == 2:
        return tuple(candidates_in_both_stats), ResponsibleDeterminationConfidence.POOR

    # locs and committers differ too much
    return (), ResponsibleDeterminationConfidence.UNKNOWN


@cachetools.cached(cachetools.TTLCache(maxsize=200, ttl=60 * 60 * 24))
def _org_members_from_repo_url(
    gh_api: github3.GitHub,
    repo_url: str,
) -> github3.orgs.Organization:
    '''
    convenience method to build Organization from url.
    '''

    if '://' not in repo_url:
        repo_url = 'x://' + repo_url

    parsed_url = urllib.parse.urlparse(repo_url)
    org_name, _ = parsed_url.path.strip('/').split('/')

    org = gh_api.organization(org_name)

    return [
        member.login
        for member in org.members()
    ]


def _repo_from_repo_url(
    gh_api: github3.GitHub,
    repo_url: str,
) -> github3.repos.repo.ShortRepository:
    '''
    convenience method to build ShortRepository from url.
    '''
    if '://' not in repo_url:
        repo_url = 'x://' + repo_url

    parsed_url = urllib.parse.urlparse(repo_url)
    org, repo = parsed_url.path.strip('/').split('/')
    return gh_api.repository(
        repository=repo,
        owner=org,
    )


def is_candidate_stat(
    stat: dict,
    positive_list: list[str],
    negative_list: list[str],
) -> bool:
    '''
    checks given username from stat against positive and negative list.
    '''
    username = stat['author']['login']
    if username in negative_list:
        return False

    if username not in positive_list:
        return False

    return True


def user_identifiers_for_responsible(
    username: str,
    repo_url: str,
    gh_api: github3.GitHub,
) -> collections.abc.Generator[responsibles.user_model.UserIdentifierBase, None, None]:

    github_hostname = util.normalise_url_to_second_and_tld(repo_url)

    yield responsibles.user_model.GithubUser(
        source=repo_url,
        username=username,
        github_hostname=github_hostname,
    )

    gh_user = gh_api.user(username)
    if gh_user:
        yield from responsibles.iter_additional_gh_user_identifier(gh_user)


@cachetools.cached(cachetools.TTLCache(maxsize=200, ttl=60 * 60 * 24))
def _negative_list() -> list[str]:
    '''
    cached wrapper to load negative list from disk
    '''
    return ci.util.parse_yaml_file(
        paths.responsibles_username_negative_list_path
    )['usernames']


@cachetools.cached(cachetools.TTLCache(maxsize=200, ttl=60 * 60 * 24)) # 24h
def repo_contributor_statistics(
    repo_url: str,
) -> list | None:
    gh_api = ccc.github.github_api(
        repo_url=repo_url,
        cfg_factory=ctx_util.cfg_factory(),
    )
    repo = _repo_from_repo_url(
        gh_api=gh_api,
        repo_url=repo_url,
    )
    repo_api_url = repo.url + '/stats/contributors'

    res = gh_api._get(repo_api_url)
    if res.status_code == 200:
        return res.json()


# (60 * 60s * 24) == 24h
@cachetools.cached(cachetools.TTLCache(maxsize=200, ttl=60 * 60 * 24))
def user_identities(
    repo_url: str,
    heuristic_parameters: ResponsiblesDetectionHeuristicsParameters,
) -> tuple[responsibles.user_model.UserIdentity]:
    gh_api = ccc.github.github_api(repo_url=repo_url, cfg_factory=ctx_util.cfg_factory())
    repo = _repo_from_repo_url(
        gh_api=gh_api,
        repo_url=repo_url,
    )

    meta_origin = responsibles.user_model.MetaOrigin(
        source=repo.html_url,
        originType='github-statistics-heuristic',
    )

    negative_list = _negative_list()

    positive_list = _org_members_from_repo_url(
        gh_api=gh_api,
        repo_url=repo_url,
    )

    repo_stats = repo_contributor_statistics(repo_url=repo_url)

    repo_stats = list(filter(
        lambda stat: is_candidate_stat(
            stat=stat,
            positive_list=positive_list,
            negative_list=negative_list,
        ),
        repo_stats,
    ))

    # e.g. not enough commits
    if not repo_stats:
        return ()

    processed_stats = global_stats(
        repo_stats=repo_stats,
        weight_function_identifier=heuristic_parameters.weight_function_identifier,
        max_responsibles=heuristic_parameters.max_responsibles,
        percentile_min=heuristic_parameters.percentile_min,
    )

    determined_responsibles, _ = heuristically_determine_responsibles(
        stats=processed_stats,
        max_responsibles=heuristic_parameters.max_responsibles,
    )

    def is_suspended(username: str) -> bool:
        user = gh_api.user(username)
        if user.as_dict().get('suspended_at'):
            return True
        return False

    # suspension status for user(name) requires dedicated github-api call
    # therefore, only consider for responsibles yielded by heuristic
    determined_responsibles = tuple(
        responsible
        for responsible in determined_responsibles
        if not is_suspended(responsible)
    )

    return tuple((
        responsibles.user_model.UserIdentity(
            identifiers=tuple(
                identifier
                for identifier in user_identifiers_for_responsible(
                    username=responsible,
                    repo_url=repo_url,
                    gh_api=gh_api,
                )
            ) + (meta_origin,)
        )
        for responsible in determined_responsibles
    ))
