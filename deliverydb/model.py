import sqlalchemy as sa

from sqlalchemy import Column, Integer
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy.orm.decl_api


Base: sqlalchemy.orm.decl_api.DeclarativeMeta = declarative_base()


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

    id = Column(Integer, primary_key=True, autoincrement=True)
    creation_date = Column(
        sa.DateTime(timezone=True),
        server_default=sa.sql.func.now(),
    )

    type = Column(sa.String(length=64)) # e.g. finding/vulnerability, malware, ...

    # component-id
    component_name = Column(sa.String(length=256))
    component_version = Column(sa.String(length=64))

    # artefact-id
    artefact_kind = Column(sa.String(length=32)) # resource | source

    artefact_name = Column(sa.String(length=128))
    artefact_version = Column(sa.String(length=64))
    artefact_type = Column(sa.String(length=64))

    artefact_extra_id_normalised = Column(sa.String(length=1024))
    artefact_extra_id = Column(sa.JSON)

    meta = Column(sa.JSON, default=dict)
    data = Column(sa.JSON, default=dict)
    data_key = Column(sa.CHAR(length=40))
    datasource = Column(sa.String(length=64)) # bdba, checkmarx

    cfg_name = Column(sa.String(length=64)) # relevant for compliance snapshots
    referenced_type = Column(sa.String(length=64)) # type of finding a rescoring applies to

    discovery_date = Column(sa.Date)


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
