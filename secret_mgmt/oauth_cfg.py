import dataclasses
import enum


class OAuthCfgTypes(enum.StrEnum):
   GITHUB = 'github'


class SubjectType(enum.StrEnum):
    GITHUB_USER = 'github-user'
    GITHUB_ORG = 'github-org'
    GITHUB_TEAM = 'github-team'


@dataclasses.dataclass
class Subject:
    type: SubjectType
    name: str


@dataclasses.dataclass
class RoleBinding:
    subjects: list[Subject]
    roles: list[str]


@dataclasses.dataclass
class OAuthCfg:
    name: str
    type: OAuthCfgTypes
    github_secret_name: str
    oauth_url: str
    token_url: str
    client_id: str
    client_secret: str
    scope: str | None
    role_bindings: list[RoleBinding] = dataclasses.field(default_factory=list)
