import collections.abc
import datetime
import dataclasses

import delivery.model

import responsibles.user_model
import util


'''
utils for reading user-data from Gardener's Yellow-Pages
pragmatically hardcoding a lot.
'''


@dataclasses.dataclass
class SprintOffsets:
    name: str
    comment: str | None
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
    ) -> collections.abc.Generator[delivery.model.SprintDate, None, None]:

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


def _github_url(
    github_name: str,
    addressbook_github_mappings: collections.abc.Iterable[dict],
):
    '''
    looks up the github-url maintained in `repo`'s github mapping file for the logical
    github instance name, as used in `repo`'s addressbook file

    If not such mapping is found, None is returned.
    '''
    for entry in addressbook_github_mappings:
        # expected attrs: name, api_url
        if entry['name'] == github_name:
            return entry['api_url']

    return None # no matching entry was found


def _github_name(
    github_url: str,
    addressbook_github_mappings: collections.abc.Iterable[dict],
):
    normalised_gh_domain = util.normalise_url_to_second_and_tld(url=github_url)
    for entry in addressbook_github_mappings:
        normalised_entry_domain = util.normalise_url_to_second_and_tld(url=entry['api_url'])
        if normalised_entry_domain == normalised_gh_domain:
            return entry['name']

    return None


@dataclasses.dataclass
class AddressbookEntry:
    name: str # firstname lastname (space-separated)
    email: str # email-addr
    github: dict[str, str | None] # github-name: username


def find_addressbook_entry(
    addressbook_entries: collections.abc.Iterable[AddressbookEntry],
    addressbook_github_mappings: collections.abc.Iterable[dict],
    user_id: responsibles.user_model.UserIdentity,
) -> AddressbookEntry | None:
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
                    addressbook_github_mappings=addressbook_github_mappings,
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
    addressbook_source: str | None,
    addressbook_entries: collections.abc.Iterable[AddressbookEntry],
    addressbook_github_mappings: collections.abc.Iterable[dict],
    user_id: responsibles.user_model.UserIdentity,
) -> responsibles.user_model.UserIdentity:
    '''
    injects personalName looked-up in passed addressbook-entries into the
    given `UserIdentity`, if no personalName identifier is present already.
    '''
    addressbook_entry = find_addressbook_entry(
        addressbook_entries=addressbook_entries,
        addressbook_github_mappings=addressbook_github_mappings,
        user_id=user_id,
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
                source=addressbook_source,
                firstName=nameparts[0],
                lastName=nameparts[1],
            )

    return dataclasses.replace(
        user_id,
        identifiers=tuple(iter_infos())
    )


def inject_github_users(
    addressbook_source: str | None,
    addressbook_entries: collections.abc.Iterable[AddressbookEntry],
    addressbook_github_mappings: collections.abc.Iterable[dict],
    user_id: responsibles.user_model.UserIdentity,
) -> responsibles.user_model.UserIdentity:
    '''
    injects additional known github-user-IDs looked-up in passed addressbook-entries into the
    given `UserIdentity`. If no additional user-IDs are found, the passed-in object is returned
    unchanged.
    '''
    addressbook_entry = find_addressbook_entry(
        addressbook_entries=addressbook_entries,
        addressbook_github_mappings=addressbook_github_mappings,
        user_id=user_id,
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
                    addressbook_github_mappings=addressbook_github_mappings,
                )
            )
            if gh_hostname in seen_github_hostnames:
                # existing entries "win" over yellow-pages-entries
                continue

            seen_github_hostnames.add(gh_hostname)

            yield responsibles.user_model.GithubUser(
                source=addressbook_source,
                github_hostname=gh_hostname,
                username=username,
            )

    return dataclasses.replace(
        user_id,
        identifiers=tuple(iter_infos())
    )


def inject(
    addressbook_source: str | None,
    addressbook_entries: collections.abc.Iterable[AddressbookEntry],
    addressbook_github_mappings: collections.abc.Iterable[dict],
    user_id: responsibles.user_model.UserIdentity,
) -> responsibles.user_model.UserIdentity:
    user_id = inject_github_users(
        addressbook_source=addressbook_source,
        addressbook_entries=addressbook_entries,
        addressbook_github_mappings=addressbook_github_mappings,
        user_id=user_id,
    )
    user_id = inject_personal_name(
        addressbook_source=addressbook_source,
        addressbook_entries=addressbook_entries,
        addressbook_github_mappings=addressbook_github_mappings,
        user_id=user_id,
    )
    return user_id
