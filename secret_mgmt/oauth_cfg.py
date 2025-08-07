import dataclasses
import enum

import util


RoleName = str


class OAuthCfgTypes(enum.StrEnum):
   GITHUB = 'github'


class SubjectType(enum.StrEnum):
    GITHUB_APP = 'github-app'
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
    roles: list[RoleName]


@dataclasses.dataclass
class OAuthCfg:
    name: str
    type: OAuthCfgTypes
    api_url: str
    client_id: str
    client_secret: str
    role_bindings: list[RoleBinding] = dataclasses.field(default_factory=list)

    @property
    def normalised_domain(self) -> str:
        return util.normalise_url_to_second_and_tld(self.api_url)

    @property
    def oauth_url(self) -> str:
        return f'https://{self.normalised_domain}/login/oauth/authorize'

    @property
    def token_url(self) -> str:
        return f'https://{self.normalised_domain}/login/oauth/access_token'
