import collections.abc
import dataclasses
import enum
import time
import typing

import delivery.client
import github.codeowners

import odg.model
import secret_mgmt
import secret_mgmt.github
import util


class StrategyTypes(enum.StrEnum):
    COMPONENT_RESPONSIBLES = 'component-responsibles'
    STATIC_RESPONSIBLES = 'static-responsibles'


class ResponsibleTypes(enum.StrEnum):
    GITHUB_TEAM = 'githubTeam'
    GITHUB_USER = 'githubUser'


@dataclasses.dataclass
class Responsible:
    type: ResponsibleTypes


@dataclasses.dataclass(kw_only=True)
class GitHubUserResponsible(Responsible):
    username: str
    github_hostname: str
    type: ResponsibleTypes = ResponsibleTypes.GITHUB_USER


@dataclasses.dataclass(kw_only=True)
class GitHubTeamResponsible(Responsible):
    teamname: str
    github_hostname: str
    type: ResponsibleTypes = ResponsibleTypes.GITHUB_TEAM


@dataclasses.dataclass
class StrategyBase:
    type: StrategyTypes

    def iter_responsibles(
        self,
        artefact: odg.model.ComponentArtefactId,
        datatype: odg.model.Datatype,
        secret_factory: secret_mgmt.SecretFactory,
        delivery_client: delivery.client.DeliveryServiceClient,
    ) -> collections.abc.Generator[odg.model.UserIdentity, None, None]:
        raise NotImplementedError('must be implemented by its subclasses')


@dataclasses.dataclass
class ComponentResponsibles(StrategyBase):
    type: typing.Literal[StrategyTypes.COMPONENT_RESPONSIBLES]

    def iter_responsibles(
        self,
        artefact: odg.model.ComponentArtefactId,
        datatype: odg.model.Datatype,
        secret_factory: secret_mgmt.SecretFactory,
        delivery_client: delivery.client.DeliveryServiceClient,
    ) -> collections.abc.Generator[odg.model.UserIdentity, None, None]:
        user_identities, _ = delivery_client.component_responsibles(
            name=artefact.component_name,
            version=artefact.component_version,
            artifact=artefact.artefact.artefact_name,
            absent_ok=True,
        )

        if not user_identities:
            return

        for user_identity in user_identities:
            for identifier in user_identity:
                if identifier['type'] != odg.model.UserTypes.GITHUB_USER:
                    continue

                yield odg.model.UserIdentity(
                    identifiers=[odg.model.GithubUser(
                        source=odg.model.Datasource.RESPONSIBLES,
                        username=identifier['username'],
                        github_hostname=identifier['github_hostname'],
                    )],
                )


@dataclasses.dataclass
class StaticResponsibles(StrategyBase):
    type: typing.Literal[StrategyTypes.STATIC_RESPONSIBLES]
    responsibles: list[
        GitHubUserResponsible
        | GitHubTeamResponsible
    ] = dataclasses.field(default_factory=list)

    def iter_responsibles(
        self,
        artefact: odg.model.ComponentArtefactId,
        datatype: odg.model.Datatype,
        secret_factory: secret_mgmt.SecretFactory,
        delivery_client: delivery.client.DeliveryServiceClient,
    ) -> collections.abc.Generator[odg.model.UserIdentity, None, None]:
        for responsible in self.responsibles:
            if responsible.type is ResponsibleTypes.GITHUB_USER:
                yield odg.model.UserIdentity(
                    identifiers=[odg.model.GithubUser(
                        source=odg.model.Datasource.RESPONSIBLES,
                        username=responsible.username,
                        github_hostname=responsible.github_hostname,
                    )],
                )

            elif responsible.type is ResponsibleTypes.GITHUB_TEAM:
                team = github.codeowners.Team(responsible.teamname)

                github_api = secret_mgmt.github.github_api(
                    secret_factory=secret_factory,
                    repo_url=util.urljoin(responsible.github_hostname, team.org_name),
                )

                for username in github.codeowners.resolve_team_members(
                    team=team,
                    github_api=github_api,
                    absent_ok=False,
                ):
                    yield odg.model.UserIdentity(
                        identifiers=[odg.model.GithubUser(
                            source=odg.model.Datasource.RESPONSIBLES,
                            username=username,
                            github_hostname=responsible.github_hostname,
                        )],
                    )
                time.sleep(3) # prevent GitHub secondary rate limits

            else:
                raise ValueError(f'unknown {responsible.type=}')
