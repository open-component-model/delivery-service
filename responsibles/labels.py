import dataclasses
import enum
import typing

import dacite
import ocm


class ResponsibleType(enum.Enum):
    GITHUB_USER = 'githubUser'
    GITHUB_TEAM = 'githubTeam'
    CODEOWNERS = 'codeowners'
    EMAIL = 'emailAddress'
    PERSONAL_NAME = 'personalName'


@dataclasses.dataclass(frozen=True, kw_only=True)
class Responsible:
    # Not intended to be instantiated
    type: ResponsibleType


@dataclasses.dataclass(frozen=True, kw_only=True)
class GitHubUserResponsible(Responsible):
    username: str
    github_hostname: str = None
    type: ResponsibleType = ResponsibleType.GITHUB_USER


@dataclasses.dataclass(frozen=True, kw_only=True)
class GitHubTeamResponsible(Responsible):
    teamname: str
    github_hostname: str = None
    type: ResponsibleType = ResponsibleType.GITHUB_TEAM


@dataclasses.dataclass(frozen=True, kw_only=True)
class CodeownersResponsible(Responsible):
    type: ResponsibleType = ResponsibleType.CODEOWNERS


@dataclasses.dataclass(frozen=True, kw_only=True)
class EmailResponsible(Responsible):
    email: str
    type: ResponsibleType = ResponsibleType.EMAIL


@dataclasses.dataclass(frozen=True, kw_only=True)
class PersonalNameResponsible(Responsible):
    firstName: str
    lastName: str
    type: ResponsibleType = ResponsibleType.PERSONAL_NAME


@dataclasses.dataclass(frozen=True, kw_only=True)
class ResponsiblesLabel(ocm.Label):
    value: typing.List[
        CodeownersResponsible
        | EmailResponsible
        | GitHubTeamResponsible
        | GitHubUserResponsible
        | PersonalNameResponsible
    ]
    name: str = 'cloud.gardener.cnudie/responsibles'

    @staticmethod
    def from_dict(data_dict: dict):
        return dacite.from_dict(
            data_class=ResponsiblesLabel,
            data=data_dict,
            config=dacite.Config(
                cast=[
                    ResponsibleType,
                ],
                strict=True,
            ),
        )
