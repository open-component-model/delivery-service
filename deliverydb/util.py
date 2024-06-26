import collections.abc
import dataclasses
import hashlib

import sqlalchemy as sa
import sqlalchemy.sql.elements as sqle

import ci.util
import dso.model
import gci.componentmodel as cm

import deliverydb.model as dm


def normalise_object(
    object: dict,
) -> str:
    '''
    generate stable representation of `object`

    sorted by key in alphabetical order and concatinated following pattern:
    key1:value1_key2:value2_ ...
    '''
    s = sorted(object.items(), key=lambda items: items[0])
    return '_'.join([
        f'{key}:{normalise_object(value) if isinstance(value, dict) else value}'
        for key, value in s
    ])


def to_db_artefact_metadata(
    artefact_metadata: dso.model.ArtefactMetadata,
) -> dm.ArtefactMetaData:
    artefact_ref = artefact_metadata.artefact
    artefact = artefact_ref.artefact

    meta = artefact_metadata.meta
    data = artefact_metadata.data

    data_raw = data
    if dataclasses.is_dataclass(data):
        data_raw = dataclasses.asdict(
            obj=data,
            dict_factory=ci.util.dict_to_json_factory,
        )

    data_key = hashlib.sha1(data.key.encode('utf-8')).hexdigest() if hasattr(data, 'key') else None
    cfg_name = data.cfg_name if hasattr(data, 'cfg_name') else None
    referenced_type = data.referenced_type if hasattr(data, 'referenced_type') else None

    meta_raw = dataclasses.asdict(
        obj=meta,
        dict_factory=ci.util.dict_to_json_factory,
    )

    # following attributes are about to be removed from artefact-extra-id
    IMAGE_VECTOR_REPO = 'imagevector-gardener-cloud+repository'
    IMAGE_VECTOR_TAG = 'imagevector-gardener-cloud+tag'

    if artefact.artefact_extra_id.get(IMAGE_VECTOR_REPO):
        del artefact.artefact_extra_id[IMAGE_VECTOR_REPO]
    if artefact.artefact_extra_id.get(IMAGE_VECTOR_TAG):
        del artefact.artefact_extra_id[IMAGE_VECTOR_TAG]

    return dm.ArtefactMetaData(
        type=meta.type,
        component_name=artefact_ref.component_name,
        component_version=artefact_ref.component_version,
        artefact_kind=artefact_ref.artefact_kind,
        artefact_name=artefact.artefact_name,
        artefact_type=artefact.artefact_type,
        artefact_version=artefact.artefact_version,
        artefact_extra_id=artefact.artefact_extra_id,
        artefact_extra_id_normalised=artefact.normalised_artefact_extra_id(),
        data=data_raw,
        data_key=data_key,
        meta=meta_raw,
        datasource=meta.datasource,
        cfg_name=cfg_name,
        referenced_type=referenced_type,
        creation_date=meta.creation_date,
        discovery_date=artefact_metadata.discovery_date,
    )


def db_artefact_metadata_to_dict(
    artefact_metadata: dm.ArtefactMetaData,
) -> dict:
    return {
        'id': artefact_metadata.id,
        'artefact': {
            'component_name': artefact_metadata.component_name,
            'component_version': artefact_metadata.component_version,
            'artefact_kind': artefact_metadata.artefact_kind,
            'artefact': {
                'artefact_name': artefact_metadata.artefact_name,
                'artefact_version': artefact_metadata.artefact_version,
                'artefact_type': artefact_metadata.artefact_type,
                'artefact_extra_id': artefact_metadata.artefact_extra_id,
            },
        },
        'meta': artefact_metadata.meta,
        'data': artefact_metadata.data,
        'discovery_date': (
            artefact_metadata.discovery_date.isoformat()
            if artefact_metadata.discovery_date
            else None
        ),
    }


def db_artefact_metadata_to_dso(
    artefact_metadata: dm.ArtefactMetaData,
) -> dso.model.ArtefactMetadata:
    artefact_metadata_dict = db_artefact_metadata_to_dict(
        artefact_metadata=artefact_metadata,
    )

    return dso.model.ArtefactMetadata.from_dict(
        raw=artefact_metadata_dict,
    )


class ArtefactMetadataFilters:
    @staticmethod
    def by_name_and_type(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        return sa.and_(
            dm.ArtefactMetaData.component_name == artefact_metadata.component_name,
            dm.ArtefactMetaData.artefact_name == artefact_metadata.artefact_name,
            dm.ArtefactMetaData.type == artefact_metadata.type,
            dm.ArtefactMetaData.datasource == artefact_metadata.datasource,
        )

    @staticmethod
    def by_artefact_id_and_type(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        return sa.and_(
            ArtefactMetadataFilters.by_name_and_type(artefact_metadata=artefact_metadata),
            dm.ArtefactMetaData.component_version == artefact_metadata.component_version,
            dm.ArtefactMetaData.artefact_type == artefact_metadata.artefact_type,
            dm.ArtefactMetaData.artefact_version == artefact_metadata.artefact_version,
            dm.ArtefactMetaData.artefact_extra_id_normalised
                == artefact_metadata.artefact_extra_id_normalised,
        )

    @staticmethod
    def by_single_scan_result(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        return sa.and_(
            ArtefactMetadataFilters.by_artefact_id_and_type(artefact_metadata=artefact_metadata),
            dm.ArtefactMetaData.data_key == artefact_metadata.data_key,
        )

    @staticmethod
    def filter_for_rescoring_type(
        type_filter: list[str]=None,
    ):
        if not type_filter:
            return True

        return sa.and_(
            dm.ArtefactMetaData.type == dso.model.Datatype.RESCORING,
            dm.ArtefactMetaData.referenced_type.in_(type_filter),
        )


class ArtefactMetadataQueries:
    @staticmethod
    def component_queries(
        components: tuple[cm.ComponentIdentity],
        none_ok: bool=False,
    ) -> collections.abc.Generator[sqle.BooleanClauseList, None, None]:
        for component in components:
            yield sa.and_(
                # if name or version is missing and `none_ok` is set, set predicate to `True`
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.component_name == None,
                    ),
                    dm.ArtefactMetaData.component_name == component.name,
                ),
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.component_version == None,
                    ),
                    dm.ArtefactMetaData.component_version == component.version,
                ),
            )
