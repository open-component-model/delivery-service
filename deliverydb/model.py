import sqlalchemy as sa

from sqlalchemy import Column, Integer
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy.orm.decl_api


Base: sqlalchemy.orm.decl_api.DeclarativeMeta = declarative_base()


class ArtefactMetaData(Base):
    '''
    a (meta-)data entry about an artefact described in a CNUDIE-Component-Descriptor.

    Examples of such data are:

    - vulnerability scan results (as e.g. reported from Protecode or Whitesource)
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
    data_key = Column(sa.String(length=4096))
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


sa.Index(
    None,
    ArtefactMetaData.component_name,
    ArtefactMetaData.artefact_name,
    ArtefactMetaData.type,
    ArtefactMetaData.artefact_type,
    ArtefactMetaData.data_key,
    ArtefactMetaData.cfg_name,
    ArtefactMetaData.referenced_type,
)
