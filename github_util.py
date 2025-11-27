import collections.abc
import datetime
import functools
import logging
import time

import github3
import github3.issues
import github3.repos

import github.retry


logger = logging.getLogger(__name__)


def is_remaining_quota_too_low(
    gh_api: github3.GitHub,
    relative_gh_quota_minimum: float=0.2,
) -> bool:
    rate_limit = gh_api.rate_limit().get('resources', dict()).get('core', dict()).get('limit', -1)
    rate_limit_remaining = gh_api.ratelimit_remaining

    logger.info(f'{rate_limit_remaining=} {rate_limit=}')

    return rate_limit_remaining < relative_gh_quota_minimum * rate_limit


def wait_for_quota_if_required(
    gh_api: github3.GitHub,
    relative_gh_quota_minimum: float=0.2,
):
    if not is_remaining_quota_too_low(
        gh_api=gh_api,
        relative_gh_quota_minimum=relative_gh_quota_minimum,
    ):
        return

    reset_timestamp = gh_api.rate_limit().get('resources', dict()).get('core', dict()).get('reset')
    if not reset_timestamp:
        return

    reset_datetime = datetime.datetime.fromtimestamp(
        timestamp=reset_timestamp,
        tz=datetime.timezone.utc,
    )
    time_until_reset = reset_datetime - datetime.datetime.now(tz=datetime.timezone.utc)

    logger.warning(f'github quota too low, will sleep {time_until_reset} until {reset_datetime}')
    time.sleep(time_until_reset.total_seconds())


@functools.cache
@github.retry.retry_and_throttle
def all_issues(
    repository: github3.repos.Repository,
    state: str='all',
    number: int=-1, # -1 means all issues
):
    return set(repository.issues(
        state=state,
        number=number,
    ))


def filter_issues_for_labels(
    issues: collections.abc.Iterable[github3.issues.ShortIssue],
    labels: collections.abc.Iterable[str],
) -> tuple[github3.issues.ShortIssue, ...]:
    labels = set(labels)

    def filter_issue(
        issue: github3.issues.ShortIssue,
    ) -> bool:
        issue_labels = {
            label.name
            for label in issue.original_labels
        }

        return labels.issubset(issue_labels)

    return tuple(
        issue for issue in issues
        if filter_issue(issue)
    )
