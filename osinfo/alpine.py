import dataclasses
import datetime

import aiohttp
import dacite
import dateutil.parser
import yaml

import version

import osinfo.model
import util


@dataclasses.dataclass
class AlpineRelease:
    date: str
    version: str
    notes: str | None = None


@dataclasses.dataclass
class AlpineReleaseBranch:
    arches: list[str] # architectures (x86_64, aarch64, ..)
    git_branch: str
    rel_branch: str # either edge, latest-stable, or v<major>.<minor>

    # optional attrs are present only for release-branches (not for edge)
    repos: list[dict[str, str]] | None = None
    branch_date: str | None = None
    eol_date: str | None = None
    releases: list[AlpineRelease] | None = None

    def greatest_release(self) -> AlpineRelease | None:
        if not self.releases:
            return None

        greatest = sorted(
            self.releases,
            key=lambda r: version.parse_to_semver(r.version)
        )[-1]

        return greatest

    def release_info(self) -> osinfo.model.OsReleaseInfo:
        if greatest_release := self.greatest_release():
            greatest_version = greatest_release.version
        else:
            greatest_version = None

        return osinfo.model.OsReleaseInfo(
            name=self.rel_branch,
            greatest_version=greatest_version,
            eol_date=self.eol_date,
            reached_eol=self.eol_date < datetime.date.today(),
        )


@dataclasses.dataclass
class AlpineReleases:
    '''
    root document as returned from https://alpinelinux.org/releases.json
    found at: https://gitlab.alpinelinux.org/alpine/infra/docker/secdb/-/merge_requests/1/diffs
    '''
    latest_stable: str
    architectures: list[str]
    release_branches: list[AlpineReleaseBranch]

    def release_branch_names(self) -> tuple[str]:
        names = tuple(rb.rel_branch for rb in self.release_branches if rb.rel_branch)
        return names

    def release_branch(self, branch_name: str):
        for rb in self.release_branches:
            if rb.rel_branch == branch_name:
                return rb

        return None


class Routes:
    def __init__(self):
        self._base_url = 'https://dl-cdn.alpinelinux.org/alpine/'

    def releases_json(self):
        return 'https://alpinelinux.org/releases.json'

    def branches(self):
        return self._base_url

    def latest_releases(self, branch: str, architecture: str='x86_64'):
        '''
        returns URL pointing to 'latest-releases.yaml'

        branch: alpine release (version w/o patch-level, e.g. v3.14, v3.15, ..)
        architecture: aarch64, x86_64, ..
        '''

        return util.urljoin(
            self._base_url,
            branch,
            'releases',
            architecture,
            'latest-releases.yaml',
        )


class Client:
    def __init__(self, routes=Routes()):
        self.routes = routes
        self._cached_releases: AlpineReleases = None
        self._cached_releases_timestamp: datetime.datetime = None

    async def release_infos(self) -> list[osinfo.model.OsReleaseInfo]:
        return [r.release_info() for r in await self.releases().release_branches]

    async def releases(self) -> AlpineReleases:
        now = datetime.datetime.now(tz=datetime.timezone.utc)

        async with aiohttp.ClientSession() as session:
            if self._cached_releases:
                async with session.head(self.routes.releases_json()) as res:
                    last_modified = dateutil.parser.parse(res.headers['last-modified'])

                if last_modified < self._cached_releases_timestamp:
                    return self._cached_releases

            async with session.get(self.routes.releases_json()) as res:
                raw = await res.json()

        self._cached_releases = dacite.from_dict(
            data_class=AlpineReleases,
            data=raw,
        )
        self._cached_releases_timestamp = now

        return self._cached_releases

    async def latest_release(self, branch: str, architecture: str='x86_64'):
        url = self.routes.latest_releases(branch=branch, architecture=architecture)

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as res:
                res = await res.text()

        parsed = yaml.safe_load(res)

        # hardcode to use first element (timestamps will differ, versions likely not)
        info = parsed[0]

        return {
            'version': info['version'],
            'date': info['date'].isoformat(),
        }
