import collections.abc
import dataclasses
import functools
import logging

import aiohttp.web
import github3
import github3.exceptions
import github3.users

import github.codeowners
import ocm

import ctx_util
import lookups
import odg.model
import responsibles.github_statistics as rg
import responsibles.labels
import secret_mgmt.github
import util


logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Status:
    type: str
    msg: str


def flatten_codeowners(
    codeowner_entries: collections.abc.Iterable[
        github.codeowners.Username | github.codeowners.EmailAddress | github.codeowners.Team
    ],
    gh_api: github3.GitHub,
) -> collections.abc.Generator[
    github.codeowners.Username | github.codeowners.EmailAddress,
    None,
    None,
]:
    '''
    yield Username and Emails from codeowner_entries, teams are resolved to Usernames recursively
    '''
    for codeowner_entry in codeowner_entries:
        if isinstance(codeowner_entry, github.codeowners.EmailAddress):
            yield codeowner_entry
            continue

        if isinstance(codeowner_entry, github.codeowners.Username):
            yield codeowner_entry
            continue

        if isinstance(codeowner_entry, github.codeowners.Team):
            yield from flatten_codeowners(
                codeowner_entries=github.codeowners.resolve_team_members(
                    team=codeowner_entry,
                    github_api=gh_api,
                ),
                gh_api=gh_api,
            )
            continue


def iter_additional_gh_user_identifier(
    gh_user: github3.users.User,
) -> collections.abc.Generator[odg.model.UserIdentifierBase, None, None]:
    if gh_user.email:
        yield odg.model.EmailAddress(
            source=gh_user.html_url,
            email=gh_user.email,
        )
    if not gh_user.name:
        # providing a personal name is not mandatory for github
        return

    nameparts = gh_user.name.rsplit(' ', 1)
    if nameparts.__len__() != 2:
        logger.warning(f'unable to split {gh_user.name=}')
        return
    yield odg.model.PersonalName(
        source=gh_user.html_url,
        first_name=nameparts[0],
        last_name=nameparts[1],
    )


def user_identifiers_for_gh_user(
    gh_user: github3.users.User,
) -> collections.abc.Generator[odg.model.UserIdentifierBase, None, None]:
    yield odg.model.GithubUser(
        source=gh_user.html_url,
        github_hostname=util.normalise_url_to_second_and_tld(gh_user.html_url),
        username=gh_user.login,
    )

    yield from iter_additional_gh_user_identifier(gh_user)


def user_identity_from_github_username_or_email(
    gh_api: github3.GitHub | github3.GitHubEnterprise,
    username_or_email: github.codeowners.Username | github.codeowners.EmailAddress,
    repo: github3.github.repo.Repository,
) -> odg.model.UserIdentity | None:
    if isinstance(username_or_email, github.codeowners.EmailAddress):
        return odg.model.UserIdentity(
            identifiers=[odg.model.EmailAddress(
                source=repo.html_url,
                email=username_or_email,
            )],
        )
    try:
        gh_user = gh_api.user(username=username_or_email)
    except github3.exceptions.NotFoundError:
        return None

    return odg.model.UserIdentity(
        identifiers=list(user_identifiers_for_gh_user(gh_user)),
    )


def user_identities_from_codeowners(
    flattend_codeowners: collections.abc.Iterable[
        github.codeowners.Username | github.codeowners.EmailAddress
    ],
    gh_api: github3.GitHub,
    repo: github3.repos.repo.Repository,
) -> collections.abc.Generator[odg.model.UserIdentity, None, None]:
    '''
    Generator of `odg.model.UserIdentity` from username and email contexts,
    removing duplicate email addresses
    '''
    usernames: set[github.codeowners.Username] = set()
    emails: set[github.codeowners.EmailAddress] = set()

    for username_or_email in flattend_codeowners:
        if isinstance(username_or_email, github.codeowners.EmailAddress):
            emails.add(username_or_email)
        elif isinstance(username_or_email, github.codeowners.Username):
            usernames.add(username_or_email)
        else:
            # should never be reached
            raise RuntimeError(f'{username_or_email=} must be either of Username or Email')

    for username in usernames:
        user_identity = user_identity_from_github_username_or_email(
            gh_api=gh_api,
            repo=repo,
            username_or_email=username,
        )
        if not user_identity:
            continue

        meta_origin = odg.model.MetaOrigin(
            source=repo.html_url,
            origin_type='github-codeowners-file',
        )
        user_identity.identifiers.append(meta_origin)
        yield user_identity

        # rm email to avoid duplicates
        for user_identifier in user_identity.identifiers:
            if user_identifier.type is odg.model.UserTypes.EMAIL_ADDRESS:
                if user_identifier.email in emails:
                    emails.remove(user_identifier.email)

    for email in emails:
        user_identity = user_identity_from_github_username_or_email(
            gh_api=gh_api,
            repo=repo,
            username_or_email=email,
        )

        meta_origin = odg.model.MetaOrigin(
            source=repo.html_url,
            origin_type='github-codeowners-file',
        )
        user_identity.identifiers.append(meta_origin)
        yield user_identity


@functools.lru_cache
def user_identities_from_github_repo(
    github_api,
    github_repo,
) -> tuple[odg.model.UserIdentity, ...]:
    flattend_codeowners = flatten_codeowners(
        codeowner_entries=github.codeowners.enumerate_codeowners_from_remote_repo(github_repo),
        gh_api=github_api,
    )

    return tuple(user_identities_from_codeowners(
        flattend_codeowners=flattend_codeowners,
        gh_api=github_api,
        repo=github_repo,
    ))


def user_identities_from_source(
    source: ocm.Source | None,
    fallback_to_codeowners: bool=False,
    heuristic_parameters=rg.ResponsiblesDetectionHeuristicsParameters(
        weight_function_identifier='sigmoid',
        max_responsibles=3,
        percentile_min=85,
    ),
    github_api_lookup=None,
) -> tuple[odg.model.UserIdentity, ...] | None:
    '''
    Returns user identities retrieved via GitHub contributor statistics (or, optionally via
    codeowners). If the GitHub statistics are still pending, `None` is returned which means the
    caller should retry at a later point in time. Otherwise, if no user identities can be retrieved
    (e.g. because of missing credentials), an empty iterable is returned instead.
    '''
    if not source:
        return ()

    if not ocm.AccessType(source.access.type) is ocm.AccessType.GITHUB:
        return ()

    repo_url = source.access.repoUrl

    if rg.repo_contributor_statistics(repo_url=repo_url) is None:
        # do not cache empty responses
        cache_key = rg.repo_contributor_statistics.cache_key(repo_url=repo_url)
        rg.repo_contributor_statistics.cache.pop(cache_key, None)
        return None

    if user_identities := rg.user_identities(
        repo_url=repo_url,
        heuristic_parameters=heuristic_parameters,
    ):
        return user_identities

    repo_url = source.access.repoUrl
    github_api = github_api_lookup(repo_url, absent_ok=True)
    if not github_api:
        logger.warning(f'did not find a GitHub cfg for {repo_url=}, skipping responsibles...')
        return ()

    github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)
    github_repo = github_repo_lookup(repo_url)

    if fallback_to_codeowners:
        return user_identities_from_github_repo(
            github_api=github_api,
            github_repo=github_repo,
        )

    return ()


def user_identifiers_from_responsible(
    responsible: responsibles.labels.Responsible,
    source: ocm.Source,
) -> collections.abc.Generator[odg.model.UserIdentifierBase, None, None]:
    '''
    Returns a generator yielding one UserIdentifier per human user that is specified by the
    Responsible-object.

    Usually, the returned generator will have one Identifier. For GitHub-Teams it may contain more,
    however no more than one Identifier per User in the team.
    '''
    match responsible:
        # Note: For the first two cases, github_hostname seems to be optional. If it isn't
        # set we use the main repository of the passed source to set it.
        case responsibles.labels.GitHubUserResponsible():
            yield odg.model.GithubUser(
                source='ComponentDescriptor',
                username=responsible.username,
                github_hostname=responsible.github_hostname or source.access.hostname(),
            )

        case responsibles.labels.GitHubTeamResponsible():
            org_name, _ = responsible.teamname.split('/')
            gh_hostname = responsible.github_hostname or source.access.hostname()

            secret_factory = ctx_util.secret_factory()
            repo_url = util.urljoin(gh_hostname, org_name)

            github_api = secret_mgmt.github.github_api(
                secret_factory=secret_factory,
                repo_url=repo_url,
                absent_ok=True,
            )

            if not github_api:
                logger.warning(f'did not find GitHub cfg for {repo_url=}, skipping responsibles...')
                return

            team = github.codeowners.Team(responsible.teamname)

            try:
                for username in github.codeowners.resolve_team_members(
                    team=team,
                    github_api=github_api,
                    absent_ok=False,
                ):
                    yield odg.model.GithubUser(
                        source='ComponentDescriptor',
                        username=username,
                        github_hostname=gh_hostname,
                    )
            except github3.exceptions.NotFoundError:
                raise aiohttp.web.HTTPNotFound(
                    text=f'Did not find GitHub team {responsible.teamname}',
                )

        case responsibles.labels.CodeownersResponsible():
            # We (re)use existing function responsibles.codeowners.user_identities_from_github_repo
            # in the only caller, so this should not happen.
            raise NotImplementedError()

        case responsibles.labels.PersonalNameResponsible():
            yield odg.model.PersonalName(
                source='ComponentDescriptor',
                first_name=responsible.firstName,
                last_name=responsible.lastName,
            )

        case responsibles.labels.EmailResponsible():
            yield odg.model.EmailAddress(
                source='ComponentDescriptor',
                email=responsible.email,
            )

        case _:
            raise NotImplementedError(f'Unkown responsible type: {responsible}')


def user_identities_from_responsibles_label(
    responsibles_label: responsibles.labels.ResponsiblesLabel,
    source: ocm.Source,
    component_identity: ocm.ComponentIdentity,
    github_api_lookup,
) -> collections.abc.Generator[odg.model.UserIdentity, None, None]:
    github_api = None
    github_repo = None

    for responsible in responsibles_label.value:
        # delegate to existing method that returns UserIdentity from responsibles
        if isinstance(responsible, responsibles.labels.CodeownersResponsible):
            if not (github_api and github_repo):
                repo_url = source.access.repoUrl
                github_api = github_api_lookup(repo_url, absent_ok=True)

                if not github_api:
                    logger.warning(
                        f'did not find a GitHub cfg for {repo_url=}, skipping responsibles...'
                    )
                    continue

                github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)
                github_repo = github_repo_lookup(repo_url)

            yield from user_identities_from_github_repo(
                github_api=github_api,
                github_repo=github_repo,
            )
        else:
            # pylint complains about iterating ober something that isn't iterable. False positive,
            # disable for the next line.
            # pylint: disable-next=E1133
            for identifier in user_identifiers_from_responsible(
                responsible=responsible,
                source=source,
            ):
                yield odg.model.UserIdentity(
                    identifiers=[
                        identifier,
                        odg.model.MetaOrigin(
                            source=f'{component_identity.name}:{component_identity.version}',
                            origin_type='component_descriptor',
                        )
                    ],
                )
