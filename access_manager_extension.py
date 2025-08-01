#!/usr/bin/env python3
'''
The access manager is intended to be run as a regular cronjob which takes care of updating the user
role bindings in the database. This is required to reflect changes in the origin of the respective
role bindings, e.g. a change of the GitHub organisation and/or team membership.
'''
import asyncio
import atexit
import collections
import collections.abc
import enum
import logging
import urllib.parse

import dacite
import github3.github
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.orm

import ci.log

import ctx_util
import deliverydb
import deliverydb.model as dm
import k8s.logging
import lookups
import odg.extensions_cfg
import odg.util
import secret_mgmt.oauth_cfg
import util


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


github_host = str
github_org_name = str
github_team_name = str
github_members = set[str]


def resolve_github_orgs_and_teams(
    oauth_cfgs: collections.abc.Iterable[secret_mgmt.oauth_cfg.OAuthCfg],
    github_api_lookup: collections.abc.Callable[[str], github3.github.GitHub | None],
) -> tuple[
    dict[github_host, dict[github_org_name, github_members]],
    dict[github_host, dict[github_team_name, github_members]],
]:
    '''
    Resolves all members of the GitHub organisations and/or teams specified in the role bindings of
    the specified `oauth_cfgs`.
    '''
    github_orgs_by_hostname = collections.defaultdict(dict)
    github_teams_by_hostname = collections.defaultdict(dict)

    for oauth_cfg in oauth_cfgs:
        github_host = urllib.parse.urlparse(oauth_cfg.api_url).hostname.lower()

        for role_binding in oauth_cfg.role_bindings:
            for subject in role_binding.subjects:
                if subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_ORG:
                    github_org = util.urljoin(github_host, subject.name)
                    github_api = github_api_lookup(github_org)

                    organisation = github_api.organization(subject.name)

                    github_orgs_by_hostname[github_host][subject.name] = {
                        member.login for member in organisation.members()
                    }

                elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_TEAM:
                    org_name, team_name = subject.name.split('/')
                    github_org = util.urljoin(github_host, org_name)
                    github_api = github_api_lookup(github_org)

                    organisation = github_api.organization(org_name)
                    team = organisation.team_by_name(team_name)

                    github_teams_by_hostname[github_host][subject.name] = {
                        member.login for member in team.members()
                    }

    return github_orgs_by_hostname, github_teams_by_hostname


def iter_github_user_role_bindings(
    identifier: dm.GitHubUserIdentifier,
    oauth_cfgs: collections.abc.Iterable[secret_mgmt.oauth_cfg.OAuthCfg],
    github_orgs_by_hostname: dict[github_host, dict[github_org_name, github_members]],
    github_teams_by_hostname: dict[github_host, dict[github_team_name, github_members]],
) -> collections.abc.Iterable[dm.RoleBinding]:
    for oauth_cfg in oauth_cfgs:
        github_host = urllib.parse.urlparse(oauth_cfg.api_url).hostname.lower()

        if identifier.hostname != github_host:
            continue

        def find_github_subject(
            subjects: list[secret_mgmt.oauth_cfg.Subject],
        ) -> secret_mgmt.oauth_cfg.Subject | None:
            for subject in subjects:
                if subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_USER:
                    if subject.name == identifier.username:
                        return subject

                elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_ORG:
                    for member in github_orgs_by_hostname[github_host][subject.name]:
                        if member == identifier.username:
                            return subject

                elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_TEAM:
                    for member in github_teams_by_hostname[github_host][subject.name]:
                        if member == identifier.username:
                            return subject

        for role_binding in oauth_cfg.role_bindings:
            if not (subject := find_github_subject(subjects=role_binding.subjects)):
                continue

            github_username = None
            github_organisation = None
            github_team = None
            if subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_USER:
                github_username = subject.name
            elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_ORG:
                github_organisation = subject.name
            elif subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_TEAM:
                github_team = subject.name
            else:
                raise ValueError(subject.type)

            yield from (
                dm.RoleBinding(
                    name=role,
                    origin=dm.GitHubRoleBindingOrigin(
                        hostname=github_host,
                        organisation=github_organisation,
                        team=github_team,
                        username=github_username,
                    ),
                ) for role in role_binding.roles
            )


def iter_github_app_role_bindings(
    identifier: dm.GitHubAppIdentifier,
    oauth_cfgs: collections.abc.Iterable[secret_mgmt.oauth_cfg.OAuthCfg],
) -> collections.abc.Iterable[dm.RoleBinding]:
    for oauth_cfg in oauth_cfgs:
        github_host = urllib.parse.urlparse(oauth_cfg.api_url).hostname.lower()

        if identifier.hostname != github_host:
            continue

        def find_github_subject(
            subjects: list[secret_mgmt.oauth_cfg.Subject],
        ) -> secret_mgmt.oauth_cfg.Subject | None:
            for subject in subjects:
                if subject.type is secret_mgmt.oauth_cfg.SubjectType.GITHUB_APP:
                    if subject.name == identifier.app_name:
                        return subject

        for role_binding in oauth_cfg.role_bindings:
            if not (subject := find_github_subject(subjects=role_binding.subjects)):
                continue

            yield from (
                dm.RoleBinding(
                    name=role,
                    origin=dm.GitHubRoleBindingOrigin(
                        hostname=github_host,
                        app=subject.name,
                    ),
                ) for role in role_binding.roles
            )


def update_github_role_bindings(
    identifiers: collections.abc.Iterable[dm.UserIdentifiers],
    role_bindings: collections.abc.Sequence[dm.RoleBinding],
    oauth_cfgs: collections.abc.Iterable[secret_mgmt.oauth_cfg.OAuthCfg],
    github_orgs_by_hostname: dict[github_host, dict[github_org_name, github_members]],
    github_teams_by_hostname: dict[github_host, dict[github_team_name, github_members]],
) -> list[dm.RoleBinding]:
    '''
    Returns an updated list of `role_bindings` by removing existing role bindings which originate
    from GitHub and adding new role bindings based on currently active memberships in GitHub
    organisations and/or teams.
    '''
    role_bindings = [
        role_binding for role_binding in role_bindings
        if role_binding.origin.type != dm.RoleBindingOriginType.GITHUB
    ]

    github_oauth_cfgs = [
        oauth_cfg for oauth_cfg in oauth_cfgs
        if oauth_cfg.type is secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB
    ]

    github_role_bindings = set()

    for identifier in identifiers:
        if identifier.type != secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB:
            continue

        identifier = identifier.deserialised_identifier

        if isinstance(identifier, dm.GitHubUserIdentifier):
            github_role_bindings.update(iter_github_user_role_bindings(
                identifier=identifier,
                oauth_cfgs=github_oauth_cfgs,
                github_orgs_by_hostname=github_orgs_by_hostname,
                github_teams_by_hostname=github_teams_by_hostname,
            ))
        elif isinstance(identifier, dm.GitHubAppIdentifier):
            github_role_bindings.update(iter_github_app_role_bindings(
                identifier=identifier,
                oauth_cfgs=github_oauth_cfgs,
            ))

    role_bindings.extend(github_role_bindings)

    return role_bindings


async def update_user_role_bindings(
    oauth_cfgs: collections.abc.Iterable[secret_mgmt.oauth_cfg.OAuthCfg],
    db_session: sqlasync.session.AsyncSession,
    github_api_lookup: collections.abc.Callable[[str], github3.github.GitHub | None],
):
    db_statement = sa.select(dm.User).options(sqlalchemy.orm.selectinload(dm.User.identifiers))
    users = (await db_session.execute(db_statement)).all()

    github_orgs_by_hostname, github_teams_by_hostname = resolve_github_orgs_and_teams(
        oauth_cfgs=oauth_cfgs,
        github_api_lookup=github_api_lookup,
    )

    try:
        for user in users:
            user: dm.User = user[0]

            role_bindings = [
                dacite.from_dict(
                    data_class=dm.RoleBinding,
                    data=role_binding_raw,
                    config=dacite.Config(
                        cast=[enum.Enum],
                    ),
                ) for role_binding_raw in user.role_bindings
            ]
            len_role_bindings_before = len(role_bindings)

            role_bindings = update_github_role_bindings(
                identifiers=user.identifiers,
                role_bindings=role_bindings,
                oauth_cfgs=oauth_cfgs,
                github_orgs_by_hostname=github_orgs_by_hostname,
                github_teams_by_hostname=github_teams_by_hostname,
            )
            len_role_bindings_after = len(role_bindings)

            user.role_bindings = util.dict_serialisation(role_bindings)

            logger.info(
                f'updated user {user.id} ({len_role_bindings_before=}, {len_role_bindings_after=})'
            )

        await db_session.commit()
    except:
        await db_session.rollback()
        raise


async def main():
    parsed_arguments = odg.util.parse_args(
        arguments=(
            odg.util.Arguments.K8S_CFG_NAME,
            odg.util.Arguments.KUBECONFIG,
            odg.util.Arguments.K8S_NAMESPACE,
        ),
    )
    namespace = parsed_arguments.k8s_namespace

    secret_factory = ctx_util.secret_factory()
    kubernetes_api = odg.util.kubernetes_api(parsed_arguments, secret_factory=secret_factory)

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.ACCESS_MANAGER,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.ACCESS_MANAGER,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    delivery_db_secrets = secret_factory.delivery_db()
    if len(delivery_db_secrets) != 1:
        raise ValueError(
            f'There must be exactly one delivery-db secret, found {len(delivery_db_secrets)}'
        )
    db_url = delivery_db_secrets[0].connection_url(
        namespace=namespace,
    )

    oauth_cfgs = secret_factory.oauth_cfg()

    github_api_lookup = lookups.github_api_lookup()

    db_session = await deliverydb.sqlalchemy_session(db_url)
    try:
        await update_user_role_bindings(
            oauth_cfgs=oauth_cfgs,
            db_session=db_session,
            github_api_lookup=github_api_lookup,
        )
    finally:
        await db_session.close()


if __name__ == '__main__':
    asyncio.run(main())
