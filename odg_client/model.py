import dataclasses
import enum


class StatusType(enum.StrEnum):
    ERROR = enum.auto()
    INFO = enum.auto()


@dataclasses.dataclass(frozen=True)  # TODO: deduplicate with model-class delivery-service
class Status:
    type: StatusType
    msg: str


@dataclasses.dataclass(frozen=True)
class GitHubAuthCredentials:
    api_url: str
    auth_token: str
