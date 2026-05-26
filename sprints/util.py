import collections.abc
import datetime

import github3.repos.repo

import sprints.model as sm


def find_sprint_for_ref_date(
    ref_date: datetime.date | None,
    sprints: collections.abc.Sequence[sm.Sprint] | None = None,
    milestones: collections.abc.Sequence[github3.repos.repo.milestone.Milestone] | None = None,
    sprint_assignment_offset: int = 0,
) -> sm.Sprint | github3.repos.repo.milestone.Milestone | None:
    """
    Returns the first sprint/milestone from the given list of `sprints`/`milestones` whose end date
    is after the passed in `ref_date`. Therefore, the sprints are sorted in ascending order based on
    their end date. If the end date of a sprint is identical to `ref_date`, it is still considered as
    the relevant sprint.

    If `sprint_assignment_offset` is set, the sprint returned is calculated relative to the sprint
    determined via the above rule. For example, an offset of +1 will return the next sprint, whereas
    -1 will return the previous one.

    Note that the date operations are not time-aware, which is believed to be "good enough".
    """
    if not ref_date or (not sprints and not milestones):
        return None

    if sprints and milestones:
        raise ValueError('Only one of `sprints` and `milestones` must be specified')

    if sprints:
        sorted_items = sorted(sprints, key=lambda sprint: sprint.due_date)
    else:
        sorted_items = sorted(milestones, key=lambda milestone: milestone.due_on.date())

    for idx, item in enumerate(sorted_items):
        date = item.due_date if sprints else item.due_on.date()
        if date >= ref_date:
            tgt_idx = idx + sprint_assignment_offset
            tgt_idx = max(tgt_idx, 0)  # fallback to first sprint
            tgt_idx = min(tgt_idx, len(sorted_items) - 1)  # fallback to last sprint

            return sorted_items[tgt_idx]

    # if this is reached, there is no sprint after the due date -> fallback to last sprint
    return sorted_items[-1]
