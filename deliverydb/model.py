import sqlalchemy as sa
import sqlalchemy.ext.declarative
import sqlalchemy.orm.decl_api


Base: sqlalchemy.orm.decl_api.DeclarativeMeta = sqlalchemy.ext.declarative.declarative_base()


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
    datasource = sa.Column(sa.String(length=64)) # bdba, checkmarx

    cfg_name = sa.Column(sa.String(length=64)) # relevant for compliance snapshots
    referenced_type = sa.Column(sa.String(length=64)) # type of finding a rescoring applies to

    discovery_date = sa.Column(sa.Date)


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
