import collections.abc
import dataclasses
import hashlib

import sqlalchemy as sa
import sqlalchemy.sql.elements as sqle

import ci.util
import cnudie.iter
import cnudie.iter_async
import cnudie.retrieve_async
import dso.model
import ocm

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

    if hasattr(data, 'key'):
        data_key = hashlib.sha1(data.key.encode('utf-8'), usedforsecurity=False).hexdigest()
    else:
        data_key = None

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


def db_artefact_metadata_row_to_dso(
    artefact_metadata_row: sa.Row[dm.ArtefactMetaData],
) -> dso.model.ArtefactMetadata:
    artefact_metadata = artefact_metadata_row[0]

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
    async def artefact_queries(
        artefacts: collections.abc.Iterable[ocm.Resource | ocm.Source]=None,
        component: ocm.ComponentIdentity=None,
        component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById=None,
        none_ok: bool=False,
    ) -> collections.abc.AsyncGenerator[sqle.BooleanClauseList, None, None]:
        '''
        Generates single SQL expressions which check for equality with one artefact of `artefacts`.
        If `artefacts` is not specified, `component` and `component_descriptor_lookup` _must_ be
        both specified to retrieve all artefacts of the given `component`.

        Intended to be concatenated using an `OR` expression which semantically checks a database
        entry to be one of `artefacts`.

        If a property mismatches but the value stored in the database is `None` and `none_ok` is set
        to `True`, the predecate evaluates to `True` anyways.
        '''
        if not (artefacts or (component and component_descriptor_lookup)):
            raise ValueError(
                'either `artefacts` or `component` and `component_descriptor_lookup` '
                'must be specified'
            )

        if not artefacts:
            if component.version:
                component: ocm.Component = (await component_descriptor_lookup(component)).component

                artefacts = [
                    artefact_node.artefact async for artefact_node in cnudie.iter_async.iter(
                        component=component,
                        lookup=component_descriptor_lookup,
                        node_filter=cnudie.iter.Filter.artefacts,
                    )
                ]
            else:
                # if no component version is specified, artefact specific querying must be
                # taken care of by the caller
                yield True
                return

        for artefact in artefacts:
            yield sa.and_(
                # if name or version is missing and `none_ok` is set, set predicate to `True`
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_name == None,
                    ),
                    dm.ArtefactMetaData.artefact_name == artefact.name,
                ),
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_version == None,
                    ),
                    dm.ArtefactMetaData.artefact_version == artefact.version,
                ),
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_type == None,
                    ),
                    dm.ArtefactMetaData.artefact_type == artefact.type,
                ),
                sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_extra_id_normalised == None,
                    ),
                    dm.ArtefactMetaData.artefact_extra_id_normalised
                        == dso.model.normalise_artefact_extra_id(
                        artefact_extra_id=artefact.extraIdentity,
                    ),
                ),
            )

    @staticmethod
    async def component_queries(
        components: tuple[ocm.Component | ocm.ComponentIdentity],
        none_ok: bool=False,
        component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById=None,
    ) -> collections.abc.AsyncGenerator[sqle.BooleanClauseList, None, None]:
        '''
        Generates single SQL expressions which check for equality with one component of `components`
        by name and version.

        Intended to be concatenated using an `OR` expression which semantically checks a database
        entry to be one of `components`.

        If a property mismatches but the value stored in the database is `None` and `none_ok` is set
        to `True`, the predecate evaluates to `True` anyways.

        If the component version of a database entry is not specified and `none_ok` is not `True`,
        it is checked whether the component in question contains an artefact version which matches
        the database entry. This is especially useful for retrieving BDBA scan results which don't
        contain a component version (for deduplication), to only query scan results for artefact
        versions which are included in the specified component versions.
        '''
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
                    dm.ArtefactMetaData.component_version == component.version,
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.component_version == None,
                    ),
                    sa.and_(
                        dm.ArtefactMetaData.component_version == None,
                        sa.or_(*[
                            query async for query
                            in ArtefactMetadataQueries.artefact_queries(
                                component=component,
                                component_descriptor_lookup=component_descriptor_lookup,
                            )
                        ]),
                    ),
                ),
            )
