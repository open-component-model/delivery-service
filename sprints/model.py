import collections.abc
import dataclasses
import datetime
import enum


class SprintNames(enum.StrEnum):
    END_DATE = 'end_date'


@dataclasses.dataclass
class SprintOffsets:
    name: str
    display_name: str | None
    offset_days: int


@dataclasses.dataclass
class SprintMetadata:
    offsets: list[SprintOffsets] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class SprintDate:
    name: str
    display_name: str | None
    value: datetime.date


@dataclasses.dataclass
class Sprint:
    name: str
    dates: list[SprintDate]

    def __post_init__(self):
        seen_names = set()

        for sprint_date in self.dates:
            if sprint_date.name in seen_names:
                raise ValueError(f'Found duplicate date with name {sprint_date.name} in {self}')
            seen_names.add(sprint_date.name)

    def __eq__(self, other) -> bool:
        if not isinstance(other, type(self)):
            return False
        return self.name == other.name

    def __hash__(self) -> int:
        return hash(self.name)

    @property
    def due_date(self) -> datetime.date:
        return self.find_sprint_date(SprintNames.END_DATE).value

    def find_sprint_date(
        self,
        name: str,
        absent_ok: bool = False,
    ) -> SprintDate | None:
        for sprint_date in self.dates:
            if sprint_date.name == name:
                return sprint_date

        if absent_ok:
            return None

        raise ValueError(f'Did not find sprint with {name=} in {self=}')


@dataclasses.dataclass
class SprintsConfiguration:
    meta: SprintMetadata | None
    sprints: list[Sprint | dict]

    def __post_init__(self):
        offsets = self.meta.offsets if self.meta else []

        sprints = []
        for sprint in self.sprints:
            if isinstance(sprint, Sprint):
                sprints.append(sprint)
                continue
            elif not isinstance(sprint, dict):
                raise TypeError(sprint)

            end_date = datetime.datetime.fromisoformat(str(sprint['end_date'])).date()

            sprint_dates = [
                SprintDate(
                    name=SprintNames.END_DATE,
                    display_name='End Date',
                    value=end_date,
                ),
            ]

            for offset in offsets:
                sprint_dates.append(
                    SprintDate(
                        name=offset.name,
                        display_name=offset.display_name,
                        value=end_date + datetime.timedelta(days=offset.offset_days),
                    ),
                )

            sprints.append(
                Sprint(
                    name=sprint['name'],
                    dates=sprint_dates,
                ),
            )

        self.sprints = sprints


@dataclasses.dataclass
class MilestoneConfiguration:
    title_callback: collections.abc.Callable[[Sprint], str] = lambda sprint: sprint.name
    title_prefix: str | None = 'sprint-'
    title_suffix: str | None = None
    due_date_callback: collections.abc.Callable[[Sprint], datetime.date] = lambda sprint: (
        sprint.due_date
    )
