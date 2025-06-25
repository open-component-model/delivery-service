import dataclasses
import enum
import hashlib

import dacite
import sqlalchemy as sa
import sqlalchemy.ext.declarative
import sqlalchemy.orm
import sqlalchemy.orm.decl_api

import secret_mgmt.oauth_cfg


Base: sqlalchemy.orm.decl_api.DeclarativeMeta = sqlalchemy.ext.declarative.declarative_base()

uuid = str
unix_epoch = int


class ArtefactMetaData(Base):
    '''
    a (meta-)data entry about an artefact described in an OCM-Component-Descriptor.

    Examples of such data are:

    - vulnerability scan results (as e.g. reported from BDBA)
    - malware scan results
    - file system paths
    - operating system identification
    '''
    __tablename__ = 'artefact_metadata'

    id = sa.Column(sa.CHAR(length=32), primary_key=True)
    creation_date = sa.Column(
        sa.DateTime(timezone=True),
        server_default=sa.sql.func.now(),
    )

    type = sa.Column(sa.String(length=64)) # e.g. finding/vulnerability, malware, ...

    # component-id
    component_name = sa.Column(sa.String(length=256))
    component_version = sa.Column(sa.String(length=64))

    # artefact-id
    artefact_kind = sa.Column(sa.String(length=32)) # resource | source | runtime

    artefact_name = sa.Column(sa.String(length=128))
    artefact_version = sa.Column(sa.String(length=64))
    artefact_type = sa.Column(sa.String(length=64))

    artefact_extra_id_normalised = sa.Column(sa.String(length=1024))
    artefact_extra_id = sa.Column(sa.JSON)

    meta = sa.Column(sa.JSON, default=dict)
    data = sa.Column(sa.JSON, default=dict)
    data_key = sa.Column(sa.CHAR(length=40))
    datasource = sa.Column(sa.String(length=64)) # bdba, clamav, ...

    referenced_type = sa.Column(sa.String(length=64)) # type of finding a rescoring applies to

    discovery_date = sa.Column(sa.Date)
    allowed_processing_time = sa.Column(sa.String(length=16))


sa.Index(
    None,
    ArtefactMetaData.component_name,
    ArtefactMetaData.component_version,
    ArtefactMetaData.type,
    ArtefactMetaData.artefact_type,
)


class DBCache(Base):
    __tablename__ = 'cache'

    id = sa.Column(sa.CHAR(length=32), primary_key=True)
    descriptor = sa.Column(sa.JSON)

    creation_date = sa.Column(sa.DateTime(timezone=True), server_default=sa.sql.func.now())
    last_update = sa.Column(sa.DateTime(timezone=True), server_default=sa.sql.func.now())
    delete_after = sa.Column(sa.DateTime(timezone=True))
    keep_until = sa.Column(sa.DateTime(timezone=True))

    last_read = sa.Column(sa.DateTime(timezone=True))
    read_count = sa.Column(sa.Integer, default=0)
    revision = sa.Column(sa.Integer, default=0)
    costs = sa.Column(sa.Integer)

    size = sa.Column(sa.Integer)
    value = sa.Column(sa.LargeBinary)


class RoleBindingOriginType(enum.StrEnum):
    GITHUB = 'github'
    MANUAL = 'manual'


@dataclasses.dataclass
class RoleBindingOrigin:
    '''
    It is required to store the origin of a role binding to be able to correctly remove a binding
    again if it is not valid anymore. For example, if a user is assigned to a role XYZ because the
    user is part of a certain GitHub organisation, and the user is also manually assigned to the
    role XYZ, only the role binding which has been created because of the GitHub membership must be
    removed in case the user is not a member of the GitHub organisation anymore. The manually added
    role binding must persist.
    '''
    type: RoleBindingOriginType

    @property
    def key(self) -> str:
        return self.type


@dataclasses.dataclass(kw_only=True)
class GitHubRoleBindingOrigin(RoleBindingOrigin):
    type: RoleBindingOriginType = RoleBindingOriginType.GITHUB
    hostname: str
    organisation: str | None = None
    team: str | None = None
    username: str | None = None

    @property
    def key(self) -> str:
        return f'{self.type}|{self.hostname}|{self.organisation}|{self.team}|{self.username}'


@dataclasses.dataclass
class RoleBinding:
    name: str
    origin: GitHubRoleBindingOrigin | RoleBindingOrigin

    @property
    def key(self) -> str:
        return f'{self.name}|{self.origin.key}'

    def __hash__(self) -> int:
        return hash(self.key)


@dataclasses.dataclass
class RefreshToken:
    identifier: uuid
    exp: unix_epoch


class User(Base):
    __tablename__ = 'users'

    id = sa.Column(sa.CHAR(length=36), primary_key=True) # uuid
    creation_date = sa.Column(sa.DateTime(timezone=True), server_default=sa.sql.func.now())

    role_bindings = sa.Column(sa.JSON) # list[RoleBinding]
    refresh_tokens = sa.Column(sa.JSON) # list[RefreshToken]

    identifiers = sqlalchemy.orm.relationship('UserIdentifiers', cascade='delete')


@dataclasses.dataclass
class UserIdentifier:
    username: str

    @property
    def normalised(self) -> str:
        return f'username:{self.username}'

    @property
    def normalised_digest(self) -> str:
        return hashlib.sha1(
            self.normalised.encode('utf-8'),
            usedforsecurity=False,
        ).hexdigest()


@dataclasses.dataclass
class GitHubUserIdentifier(UserIdentifier):
    email_address: str | None
    hostname: str

    @property
    def normalised(self) -> str:
        return (
            f'username:{self.username}_email_address:{self.email_address}_hostname:{self.hostname}'
        )


class UserIdentifiers(Base):
    __tablename__ = 'user_identifiers'

    user_id = sa.Column(sa.CHAR(length=36), sa.ForeignKey('users.id')) # uuid

    type = sa.Column(sa.String(length=32), primary_key=True) # secret_mgmt.oauth_cfg.OAuthCfgTypes
    identifier_normalised_digest = sa.Column(sa.CHAR(length=40), primary_key=True)
    identifier = sa.Column(sa.JSON) # UserIdentifier

    @property
    def deserialised_identifier(self) -> GitHubUserIdentifier | UserIdentifier:
        idp_type = secret_mgmt.oauth_cfg.OAuthCfgTypes(self.type)

        if idp_type is secret_mgmt.oauth_cfg.OAuthCfgTypes.GITHUB:
            return dacite.from_dict(
                data_class=GitHubUserIdentifier,
                data=self.identifier,
            )

        else:
            return dacite.from_dict(
                data_class=UserIdentifier,
                data=self.identifier,
            )
