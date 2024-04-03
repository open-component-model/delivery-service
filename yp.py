import datetime
import dateutil.parser
import dataclasses
import functools
import typing

import cachetools
import dacite
import github3.repos
import yaml

import delivery.model

import responsibles.user_model
import util


'''
utils for reading user-data from Gardener's Yellow-Pages
pragmatically hardcoding a lot.
'''


def parse_yaml_file(
    relpath: str,
    repo: github3.repos.Repository,
) -> dict:
    contents = repo.file_contents(
        path=relpath,
        ref=repo.default_branch,
    ).decoded

    return yaml.safe_load(contents)


@dataclasses.dataclass
class SprintOffsets:
    name: str
    comment: typing.Optional[str]
    offset_days: int


@dataclasses.dataclass
class SprintMetadata:
    offsets: list[SprintOffsets]
    sprint_length_days: int


@dataclasses.dataclass
class Sprint:
    name: str
    end_date: datetime.datetime

    def iter_sprint_dates(
        self,
        sprint_date_display_name_callback,
        meta: SprintMetadata=None,
    ) -> typing.Generator[delivery.model.SprintDate, None, None]:

        yield delivery.model.SprintDate(
            value=self.end_date.isoformat(),
            name='end_date',
            display_name=sprint_date_display_name_callback('end_date'),
        )

        if not meta:
            return

        for offset in meta.offsets:
            date = self.end_date + datetime.timedelta(days=offset.offset_days)

            yield delivery.model.SprintDate(
                value=date.isoformat(),
                name=offset.name,
                display_name=sprint_date_display_name_callback(offset.name),
            )

    def asdict(
        self,
        sprint_date_display_name_callback,
        meta: SprintMetadata=None,
    ) -> dict:
        return {
            'name': self.name,
            'dates': list(self.iter_sprint_dates(
                sprint_date_display_name_callback=sprint_date_display_name_callback,
                meta=meta,
            ))
        }


@cachetools.cached(cachetools.TTLCache(ttl=12 * 60 * 60, maxsize=2)) # 12h
def _sprints_raw(
    repo: github3.repos.Repository,
    sprints_file_relpath: str,
) -> dict:
    sprints_raw = parse_yaml_file(
        relpath=sprints_file_relpath,
        repo=repo,
    )

    return sprints_raw


@cachetools.cached(cachetools.TTLCache(ttl=12 * 60 * 60, maxsize=2)) # 12h
def _sprints_metadata(
    repo: github3.repos.Repository,
    sprints_file_relpath: str,
) -> SprintMetadata:
    meta_raw = _sprints_raw(
        repo=repo,
        sprints_file_relpath=sprints_file_relpath,
    )['meta']

    return dacite.from_dict(
        data_class=SprintMetadata,
        data=meta_raw,
    )


@cachetools.cached(cachetools.TTLCache(ttl=12 * 60 * 60, maxsize=2)) # 12h
def _sprints(
    repo: github3.repos.Repository,
    sprints_file_relpath: str,
) -> list[Sprint]:
    sprints_raw = _sprints_raw(
        repo=repo,
        sprints_file_relpath=sprints_file_relpath,
    )['sprints']

    return [
        dacite.from_dict(
            data_class=Sprint,
            data=raw,
            config=dacite.Config(
                type_hooks={datetime.datetime: lambda d: dateutil.parser.isoparse(d)},
            )
        ) for raw in sprints_raw
    ]


@functools.cache
def _github_mappings(
    repo: github3.repos.Repository,
    mappingfile_relpath: str,
) -> list[dict]:
    gh_mappings = parse_yaml_file(
        relpath=mappingfile_relpath,
        repo=repo,
    )['github_instances']

    return gh_mappings


@functools.cache
def _github_url(
    github_name: str,
    repo: github3.repos.Repository,
    mappingfile_relpath: str,
):
    '''
    looks up the github-url maintained in `repo`'s github mapping file for the logical
    github instance name, as used in `repo`'s addressbook file

    If not such mapping is found, None is returned.
    '''
    for entry in _github_mappings(repo=repo, mappingfile_relpath=mappingfile_relpath):
        # expected attrs: name, api_url
        if entry['name'] == github_name:
            return entry['api_url']

    return None # no matching entry was found


@functools.cache
def _github_name(
    github_url: str,
    repo: github3.repos.Repository,
    mappingfile_relpath: str,
):
    normalised_gh_domain = util.normalise_url_to_second_and_tld(url=github_url)
    for entry in _github_mappings(repo=repo, mappingfile_relpath=mappingfile_relpath):
        normalised_entry_domain = util.normalise_url_to_second_and_tld(url=entry['api_url'])
        if normalised_entry_domain == normalised_gh_domain:
            return entry['name']

    return None


@dataclasses.dataclass
class AddressbookEntry:
    name: str # firstname lastname (space-separated)
    email: str # email-addr
    github: typing.Dict[str, typing.Optional[str]] # github-name: username


@cachetools.cached(cachetools.TTLCache(maxsize=2, ttl=60 * 60)) # cache for 1h (60 * 60s)
def addressbook_entries(
    repo: github3.repos.Repository,
    relpath: str,
) -> tuple[AddressbookEntry]:
    if not repo or not relpath:
        return tuple()

    raw_entries = parse_yaml_file(
        relpath=relpath,
        repo=repo,
    )
    return tuple((
        dacite.from_dict(data_class=AddressbookEntry, data=raw)
        for raw in raw_entries
        if raw.get('github')
    ))


def find_addressbook_entry(
    addressbook_entries: typing.Sequence[AddressbookEntry],
    user_id: responsibles.user_model.UserIdentity,
    repo: github3.repos.Repository,
    mappingfile_relpath: str,
) -> typing.Optional[AddressbookEntry]:
    '''
    looks up first matching entry from given addressbook-entries (assumption: there is at most
    one addressbook entry per actual user)

    returns AddressbookEntry if found (based on github-user or email-address), or None if no such
    entry is found.
    '''
    for addressbook_entry in addressbook_entries:
        for user_info in user_id.identifiers:
            if user_info.type == responsibles.user_model.EmailAddress.type:
                user_info: responsibles.user_model.EmailAddress
                if user_info.email.lower() == addressbook_entry.email:
                    return addressbook_entry
            elif user_info.type == responsibles.user_model.GithubUser.type:
                user_info: responsibles.user_model.GithubUser
                if not (github_name := _github_name(
                    github_url=user_info.github_hostname,
                    repo=repo,
                    mappingfile_relpath=mappingfile_relpath,
                )):
                    continue
                github_name_from_addressbook_entry = addressbook_entry.github.get(github_name)

                # both required
                if not (github_name_from_addressbook_entry and user_info.username):
                    continue

                if github_name_from_addressbook_entry.lower() == user_info.username.lower():
                    return addressbook_entry

    return None


def inject_personal_name(
    addressbook_entries: typing.Sequence[AddressbookEntry],
    user_id: responsibles.user_model.UserIdentity,
    repo: github3.repos.Repository,
    mappingfile_relpath: str,
) -> responsibles.user_model.UserIdentity:
    '''
    injects personalName looked-up in passed addressbook-entries into the
    given `UserIdentity`, if no personalName identifier is present already.
    '''
    addressbook_entry = find_addressbook_entry(
        addressbook_entries=addressbook_entries,
        user_id=user_id,
        repo=repo,
        mappingfile_relpath=mappingfile_relpath,
    )

    if not addressbook_entry:
        return user_id

    def iter_infos():
        has_name = False
        for info in user_id.identifiers:
            if info.type == responsibles.user_model.PersonalName.type:
                has_name = True
            yield info

        if not has_name:
            nameparts = addressbook_entry.name.rsplit(' ', 1)
            yield responsibles.user_model.PersonalName(
                source=repo.url,
                firstName=nameparts[0],
                lastName=nameparts[1],
            )

    return dataclasses.replace(
        user_id,
        identifiers=tuple(iter_infos())
    )


def inject_github_users(
    addressbook_entries: typing.Sequence[AddressbookEntry],
    user_id: responsibles.user_model.UserIdentity,
    repo: github3.repos.Repository,
    mappingfile_relpath: str,
) -> responsibles.user_model.UserIdentity:
    '''
    injects additional known github-user-IDs looked-up in passed addressbook-entries into the
    given `UserIdentity`. If no additional user-IDs are found, the passed-in object is returned
    unchanged.
    '''
    addressbook_entry = find_addressbook_entry(
        addressbook_entries=addressbook_entries,
        user_id=user_id,
        repo=repo,
        mappingfile_relpath=mappingfile_relpath,
    )

    if not addressbook_entry:
        return user_id

    def iter_infos():
        seen_github_hostnames = set() # keep first entry for each github-host
        for info in user_id.identifiers:
            # keep everything but github-user unchanged
            if not info.type == responsibles.user_model.GithubUser.type:
                yield info
                continue

            info: responsibles.user_model.GithubUser
            seen_github_hostnames.add(util.normalise_url_to_second_and_tld(info.github_hostname))
            yield info

        for gh_name, username in addressbook_entry.github.items():
            gh_hostname = util.normalise_url_to_second_and_tld(
                _github_url(
                    github_name=gh_name,
                    repo=repo,
                    mappingfile_relpath=mappingfile_relpath,
                )
            )
            if gh_hostname in seen_github_hostnames:
                # existing entries "win" over yellow-pages-entries
                continue

            seen_github_hostnames.add(gh_hostname)

            yield responsibles.user_model.GithubUser(
                source=repo.url,
                github_hostname=gh_hostname,
                username=username,
            )

    return dataclasses.replace(
        user_id,
        identifiers=tuple(iter_infos())
    )


def inject(
    addressbook_entries: typing.Sequence[AddressbookEntry],
    user_id: responsibles.user_model.UserIdentity,
    repo: github3.repos.Repository,
    mappingfile_relpath: str,
) -> responsibles.user_model.UserIdentity:
    user_id = inject_github_users(
        addressbook_entries=addressbook_entries,
        user_id=user_id,
        repo=repo,
        mappingfile_relpath=mappingfile_relpath,
    )
    user_id = inject_personal_name(
        addressbook_entries=addressbook_entries,
        user_id=user_id,
        repo=repo,
        mappingfile_relpath=mappingfile_relpath,
    )
    return user_id
