#!/usr/bin/env python3
import collections.abc
import dataclasses
import datetime
import os

import yaml


own_dir = os.path.abspath(os.path.dirname(__file__))


@dataclasses.dataclass(frozen=True)
class Sprint:
    name: str
    end_date: str


def sprint_name(
    initial_sprint_name: str, # expected format: \d\d\d\d(a|b)
    offset: int,
) -> str:
    if not len(initial_sprint_name) == 5:
        raise ValueError(initial_sprint_name)

    number = int(initial_sprint_name[:-1])
    a_or_b = initial_sprint_name[-1]

    new_number = number + int(offset / 2)

    if offset % 2 == 1: # toggle suffix
        if a_or_b == 'a':
            a_or_b = 'b'
        else:
            a_or_b = 'a'
            new_number += 1

    return f'{new_number}{a_or_b}'


def sprint_date(
    start_date: datetime.datetime,
    days_per_sprint: int,
    offset: int,
) -> datetime.datetime:
    diff = datetime.timedelta(days=days_per_sprint * offset)

    return start_date + diff


def iter_sprints(
    initial_sprint_name: str, # YYYY(a|b)
    days_per_sprint: int,
    start_date: datetime.datetime,
    end_date: datetime.datetime,
) -> collections.abc.Generator[Sprint, None, None]:
    current_date = start_date
    offset = 1

    while current_date < end_date:
        name = sprint_name(
            initial_sprint_name=initial_sprint_name,
            offset=offset,
        )

        current_date = sprint_date(
            start_date=start_date,
            days_per_sprint=days_per_sprint,
            offset=offset,
        )

        offset += 1

        yield Sprint(
            name=name,
            end_date=current_date.isoformat(),
        )


def main():
    initial_sprint_name = '1000a'
    days_per_sprint = int(os.environ.get('DAYS_PER_SPRINT', 14))

    # keep constant start date to ensure sprints don't change between different startups
    # since we also persist the data and it has to be in sync with the sprints
    start_date = datetime.datetime.fromisoformat('2024-01-01T00:00:00+00:00')

    # generate sprints for the next half year in the future (assuming there is no SLA > 180 days)
    end_date = datetime.date.today() + datetime.timedelta(days=180)
    end_date = datetime.datetime(
        year=end_date.year,
        month=end_date.month,
        day=end_date.day,
        tzinfo=datetime.timezone.utc,
    )

    # generate sprints from newest to oldest
    sprints = reversed(list(iter_sprints(
        initial_sprint_name=initial_sprint_name,
        days_per_sprint=days_per_sprint,
        start_date=start_date,
        end_date=end_date,
    )))

    sprints_base_file = os.path.join(own_dir, 'sprints_base.yaml')
    sprints_out_file = os.path.join(own_dir, 'sprints.yaml')

    sprints_file = yaml.safe_load(open(sprints_base_file))
    sprints_file['data']['sprints']['sprints'] = [
        dataclasses.asdict(sprint)
        for sprint in sprints
    ]

    sprints_file['data']['sprints'] = yaml.safe_dump(sprints_file['data']['sprints'])

    with open(sprints_out_file, 'w') as file:
        file.write(yaml.safe_dump(sprints_file))


if __name__ == '__main__':
    main()
