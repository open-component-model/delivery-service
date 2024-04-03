import dataclasses
import typing


@dataclasses.dataclass
class UserIdentifierBase:
    '''
    all implementing subclasses MUST define a unique type
    '''
    source: str

    def __post_init__(self):
        if not hasattr(self, 'type'):
            self.type = 'base'


@dataclasses.dataclass
class GithubUser(UserIdentifierBase):
    username: str
    github_hostname: str
    type: str = 'githubUser'


@dataclasses.dataclass
class EmailAddress(UserIdentifierBase):
    email: str
    type: str = 'emailAddress'


@dataclasses.dataclass
class PersonalName(UserIdentifierBase):
    firstName: str
    lastName: str
    type: str = 'personalName'


@dataclasses.dataclass
class MetaOrigin(UserIdentifierBase):
    '''
    meta-origin objects declare the origin of the assignment of a user-identity
    to a component or resource
    '''
    originType: str
    type: str = 'metaOrigin'


@dataclasses.dataclass
class UserIdentity:
    '''
    collection of identities that refer to the same user
    '''
    identifiers: typing.Tuple[typing.Union[
        GithubUser, EmailAddress, PersonalName, MetaOrigin, UserIdentifierBase
    ], ...]
