import dataclasses
import logging
import re

import github3.github
import github3.session

import http_requests

import secret_mgmt
import util


logger = logging.getLogger(__name__)


@dataclasses.dataclass
class GitHubAppMapping:
    installation_id: int
    org: str


@dataclasses.dataclass
class GitHubApp:
    api_url: str
    app_id: int
    mappings: list[GitHubAppMapping]
    private_key: str
    tls_verify: bool = True

    @property
    def hostname(self) -> str:
        parsed_api_url = util.urlparse(self.api_url)

        return parsed_api_url.hostname.removeprefix('api.')

    @property
    def http_url(self) -> str:
        return f'https://{self.hostname}'

    def find_installation_id(
        self,
        repo_url: str,
        absent_ok: bool=True,
    ) -> int | None:
        parsed_repo_url = util.urlparse(repo_url)
        org = parsed_repo_url.path.strip('/').split('/')[0]

        if self.hostname.lower() == parsed_repo_url.hostname.lower():
            for mapping in self.mappings:
                if mapping.org == org:
                    return mapping.installation_id

            # special case: passed-in url is the api-url -> e.g. for delivery-svc-client auth
            if self.api_url == repo_url and len(self.mappings) > 0:
                return self.mappings[0].installation_id

        if absent_ok:
            return None

        raise ValueError(f'did not find a valid GitHub App installation for {org=}')


def find_app_cfg(
    secret_factory: secret_mgmt.SecretFactory,
    repo_url: str,
    absent_ok: bool=True,
) -> GitHubApp | None:
    try:
        github_app_cfgs = secret_factory.github_app()
    except secret_mgmt.SecretTypeNotFound:
        if absent_ok:
            return None
        raise

    for github_app_cfg in github_app_cfgs:
        if not github_app_cfg.find_installation_id(repo_url=repo_url):
            continue

        return github_app_cfg

    if absent_ok:
        return None

    raise ValueError(f'did not find a GitHub App cfg for {repo_url=}')


@dataclasses.dataclass
class GitHub:
    api_url: str
    http_url: str
    username: str
    auth_token: str
    repo_urls: list[str]
    tls_verify: bool = True

    @property
    def hostname(self) -> str | None:
        parsed_http_url = util.urlparse(self.http_url)

        if not (hostname := parsed_http_url.hostname):
            return None

        return hostname

    def hostname_matches(
        self,
        hostname: str,
    ) -> bool:
        return self.hostname and self.hostname.lower() == hostname.lower()

    def repo_url_matches(
        self,
        repo_url: str,
    ) -> bool:
        parsed_repo_url = util.urlparse(repo_url)

        if not self.repo_urls:
            return self.hostname_matches(hostname=parsed_repo_url.hostname)

        repo_url = util.urljoin(parsed_repo_url.hostname, parsed_repo_url.path)

        for repo_url_regex in self.repo_urls:
            if re.fullmatch(repo_url_regex, repo_url, re.RegexFlag.IGNORECASE):
                return True

        return False


def find_cfg(
    secret_factory: secret_mgmt.SecretFactory,
    repo_url: str,
    absent_ok: bool=False,
) -> GitHub | None:
    github_cfgs: list[GitHub] = secret_factory.github()

    matching_cfgs = (
        github_cfg
        for github_cfg in github_cfgs
        if github_cfg.repo_url_matches(repo_url)
    )

    sorted_matching_cfgs = sorted(
        matching_cfgs,
        key=lambda cfg: len(cfg.repo_urls), # prefer cfg with most configured repo urls
    )

    if not sorted_matching_cfgs:
        if absent_ok:
            return None

        raise ValueError(f'did not find a GitHub cfg for {repo_url=}')

    github_cfg = sorted_matching_cfgs[-1]
    logger.debug(f'using {github_cfg.username=} for {repo_url=}')

    return github_cfg


def legacy_github_api(
    secret_factory: secret_mgmt.SecretFactory,
    repo_url: str,
    session: github3.session.GitHubSession,
    absent_ok: bool=False,
) -> github3.github.GitHub | None:
    github_cfg = find_cfg(
        secret_factory=secret_factory,
        repo_url=repo_url,
        absent_ok=absent_ok,
    )

    if not github_cfg:
        if absent_ok:
            return None

        raise ValueError(f'did not find a GitHub cfg for {repo_url=}')

    if github_cfg.hostname_matches('github.com'):
        github_api = github3.github.GitHub(
            token=github_cfg.auth_token,
            session=session,
        )
    else:
        github_api = github3.github.GitHubEnterprise(
            url=github_cfg.http_url,
            token=github_cfg.auth_token,
            verify=github_cfg.tls_verify,
            session=session,
        )
        github_api._github_url = github_cfg.api_url

    return github_api


def github_api(
    secret_factory: secret_mgmt.SecretFactory,
    repo_url: str,
    absent_ok: bool=False,
) -> github3.github.GitHub | None:
    session = http_requests.mount_default_adapter(
        session=github3.session.GitHubSession(),
        flags=http_requests.AdapterFlag.RETRY,
        max_pool_size=16, # increase with care, might cause github api "secondary-rate-limit"
    )

    github_app_cfg = find_app_cfg(
        secret_factory=secret_factory,
        repo_url=repo_url,
        absent_ok=True,
    )

    if not github_app_cfg:
        # XXX remove this case eventually when removing support for GitHub service accounts
        return legacy_github_api(
            secret_factory=secret_factory,
            repo_url=repo_url,
            session=session,
            absent_ok=absent_ok,
        )

    if not github_app_cfg:
        # this conditional branch will become effectively once above legacy lookup is removed
        if absent_ok:
            return None

        raise ValueError(f'did not find a GitHub App cfg for {repo_url=}')

    if github_app_cfg.hostname.lower() == 'github.com':
        github_api = github3.github.GitHub(
            session=session,
        )
    else:
        github_api = github3.github.GitHubEnterprise(
            url=github_app_cfg.http_url,
            verify=github_app_cfg.tls_verify,
            session=session,
        )
        github_api._github_url = github_app_cfg.api_url

    private_key_pem = github_app_cfg.private_key.encode('utf-8')
    installation_id = github_app_cfg.find_installation_id(
        repo_url=repo_url,
        absent_ok=False,
    )

    github_api.login_as_app_installation(
        private_key_pem=private_key_pem,
        app_id=github_app_cfg.app_id,
        installation_id=installation_id,
    )

    parsed_repo_url = util.urlparse(repo_url)
    repo_path_parts = parsed_repo_url.path.strip('/').split('/')

    if len(repo_path_parts) <= 1:
        # there is no specific repository requested, so we don't have to check for specific access
        return github_api

    repo = repo_path_parts[1]
    accessible_repos = [
        repo.name
        for repo in github_api.app_installation_repos()
    ]

    if not repo in accessible_repos:
        msg = f'GitHub app with {installation_id=} has no access for {repo_url=}'

        if absent_ok:
            logger.warning(msg)
            return None

        raise ValueError(msg)

    return github_api
