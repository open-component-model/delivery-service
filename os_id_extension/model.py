import dataclasses
import datetime

import awesomeversion
import dacite
import dateutil.parser


def _parse_date_if_present(date: str | bool) -> datetime.date | bool | None:
    if isinstance(date, bool):
        return date
    if not date:
        return None
    return dateutil.parser.isoparse(date).date()


@dataclasses.dataclass(frozen=True)
class OsReleaseInfo:
    name: str
    reached_eol: bool
    greatest_version: str | None = None
    eol_date: datetime.date | bool | None = None

    @property
    def parsed_version(self) -> awesomeversion.AwesomeVersion:
        return awesomeversion.AwesomeVersion(self.name)

    @staticmethod
    def from_dict(raw: dict):
        return dacite.from_dict(
            data_class=OsReleaseInfo,
            data=raw,
            config=dacite.Config(
                type_hooks={datetime.date | bool | None: _parse_date_if_present},
            ),
        )
