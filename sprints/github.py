import collections.abc
import datetime
import functools
import logging

import dacite
import github3.repos

import odg_client
import sprints.model as sm


logger = logging.getLogger(__name__)


@functools.cache
def sprints_cached(
    delivery_service_client: odg_client.DeliveryServiceClient,
) -> list[sm.Sprint]:
    return [
        dacite.from_dict(
            data_class=sm.Sprint,
            data=sprint,
            config=dacite.Config(
                type_hooks={
                    datetime.date: lambda date: datetime.datetime.fromisoformat(date).date(),
                },
                strict=True,
            ),
        )
        for sprint in delivery_service_client.sprints()
    ]


@functools.cache
def milestones_cached(
    repo: github3.repos.Repository,
    state: str = 'all',
) -> set[github3.repos.repo.milestone.Milestone]:
    return set(repo.milestones(state=state))  # resolve github3 iterator


def milestone_title(
    sprint: sm.Sprint,
    milestone_cfg: sm.MilestoneConfiguration | None = None,
) -> str:
    if not milestone_cfg:
        milestone_cfg = sm.MilestoneConfiguration()

    title = milestone_cfg.title_callback(sprint)
    title_prefix = milestone_cfg.title_prefix or ''
    title_suffix = milestone_cfg.title_suffix or ''

    return f'{title_prefix}{title}{title_suffix}'


def find_milestone_for_title(
    milestones: collections.abc.Iterable[github3.repos.repo.milestone.Milestone],
    title: str,
    absent_ok: bool = True,
) -> github3.repos.repo.milestone.Milestone | None:
    for milestone in milestones:
        if milestone.title == title:
            return milestone

    if not absent_ok:
        raise ValueError(f'Did not find GitHub milestone {title}')

    return None


def iter_and_create_github_milestones(
    sprints: collections.abc.Iterable[sm.Sprint],
    repo: github3.repos.Repository,
    milestone_cfg: sm.MilestoneConfiguration | None = None,
    state: str = 'open',
) -> collections.abc.Iterable[github3.repos.repo.milestone.Milestone]:
    """
    Yields the respective GitHub milestones for the specified `sprints`. Comparison is done via the
    title. Only milestones matching the provided `state` are yielded, others are skipped. If a
    milestone is not existing yet, it will be created ad-hoc.
    """
    if not milestone_cfg:
        milestone_cfg = sm.MilestoneConfiguration()

    all_milestones = milestones_cached(
        repo=repo,
    )

    for sprint in sprints:
        title = milestone_title(
            sprint=sprint,
            milestone_cfg=milestone_cfg,
        )

        if milestone := find_milestone_for_title(
            milestones=all_milestones,
            title=title,
        ):
            logger.debug(f'GitHub milestone {title} is already existing - skipping creation')

        else:
            due_date = milestone_cfg.due_date_callback(sprint)
            due_on = datetime.datetime(
                year=due_date.year,
                month=due_date.month,
                day=due_date.day,
                tzinfo=datetime.UTC,
            ).isoformat()

            milestone = repo.create_milestone(
                title=title,
                state='open',
                description=f'used to track issues for upcoming sprint {title}',
                due_on=due_on,
            )
            milestones_cached.cache_clear()

            logger.info(f'created GitHub milestone {title} with {due_date=}')

        if state == 'all' or milestone.state == state:
            yield milestone
