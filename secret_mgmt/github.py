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
        return None

    github_cfg = sorted_matching_cfgs[-1]
    logger.debug(f'using {github_cfg.username=} for {repo_url=}')

    return github_cfg


def github_api(
    secret_factory: secret_mgmt.SecretFactory,
    github_cfg: GitHub | None=None,
    repo_url: str=None,
) -> github3.github.GitHub:
    if not (bool(github_cfg) ^ bool(repo_url)):
        raise ValueError('exactly one of `github_cfg` or `repo_url` must be passed')

    if repo_url:
        github_cfg = find_cfg(
            secret_factory=secret_factory,
            repo_url=repo_url,
        )

    session = http_requests.mount_default_adapter(
        session=github3.session.GitHubSession(),
        flags=http_requests.AdapterFlag.RETRY,
        max_pool_size=16, # increase with care, might cause github api "secondary-rate-limit"
    )

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
