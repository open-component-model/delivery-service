import collections.abc
import dataclasses

import sqlalchemy as sa
import sqlalchemy.sql.elements as sqle

import ci.util
import delivery.model
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
        artefact_extra_id_normalised=delivery.model.ComponentArtefactId.normalise_artefact_extra_id(
            artefact_extra_id=artefact.artefact_extra_id,
        ),
        data=data_raw,
        meta=meta_raw,
        datasource=meta.datasource,
        discovery_date=artefact_metadata.discovery_date,
    )


def db_artefact_metadata_to_dict(
    artefact_metadata: dm.ArtefactMetaData,
) -> dict:
    am = artefact_metadata
    return {
        'id': am.id,
        'artefactId': {
            'componentName': am.component_name,
            'componentVersion': am.component_version,
            'artefactKind': am.artefact_kind,
            'artefactName': am.artefact_name,
            'artefactVersion': am.artefact_version,
            'artefactType': am.artefact_type,
            'artefactExtraId': am.artefact_extra_id,
        },
        'type': am.type,
        'data': am.data,
        'meta': am.meta,
        'discovery_date': str(am.discovery_date) if am.discovery_date else None,
    }


class ArtefactMetadataFilters:
    @staticmethod
    def by_name_and_type(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        return sa.and_(
            dm.ArtefactMetaData.component_name == artefact_metadata.component_name,
            dm.ArtefactMetaData.artefact_name == artefact_metadata.artefact_name,
            dm.ArtefactMetaData.type == artefact_metadata.type,
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
                == delivery.model.ComponentArtefactId.normalise_artefact_extra_id(
                    artefact_extra_id=artefact_metadata.artefact_extra_id,
                ),
        )

    @staticmethod
    def by_type_id(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        id = artefact_metadata.data.get('id', dict())

        return sa.and_(
            id.get('source') == dso.model.Datasource.BDBA,
            dm.ArtefactMetaData.data.op('->')('id').op('->>')('source')
                == id.get('source'),
            dm.ArtefactMetaData.data.op('->')('id').op('->>')('package_name')
                == id.get('package_name'),
            dm.ArtefactMetaData.data.op('->')('id').op('->>')('package_version')
                == id.get('package_version'),
        )

    @staticmethod
    def by_scan_id(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        scan_id = artefact_metadata.data.get('scan_id', dict())

        return sa.and_(
            scan_id.get('source') == dso.model.Datasource.BDBA,
            dm.ArtefactMetaData.data.op('->')('scan_id').op('->>')('source')
                == scan_id.get('source'),
            dm.ArtefactMetaData.data.op('->')('scan_id').op('->>')('report_url')
                == scan_id.get('report_url'),
            dm.ArtefactMetaData.data.op('->')('scan_id').op('->>')('group_id').cast(sa.Integer)
                == scan_id.get('group_id'),
        )

    @staticmethod
    def by_finding_id(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        finding_id = artefact_metadata.data.get('finding', dict()).get('id', dict())

        return sa.and_(
            finding_id.get('source') == dso.model.Datasource.BDBA,
            dm.ArtefactMetaData.data.op('->')('finding').op('->')('id').op('->>')('source')
                == finding_id.get('source'),
            dm.ArtefactMetaData.data.op('->')('finding').op('->')('id').op('->>')('package_name')
                == finding_id.get('package_name'),
        )

    @staticmethod
    def by_single_scan_result(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        return sa.and_(
            ArtefactMetadataFilters.by_artefact_id_and_type(artefact_metadata=artefact_metadata),
            sa.or_(
                sa.and_(
                    dm.ArtefactMetaData.type == dso.model.Datatype.STRUCTURE_INFO,
                    ArtefactMetadataFilters.by_type_id(artefact_metadata=artefact_metadata),
                    ArtefactMetadataFilters.by_scan_id(artefact_metadata=artefact_metadata),
                ),
                sa.and_(
                    dm.ArtefactMetaData.type == dso.model.Datatype.VULNERABILITY,
                    ArtefactMetadataFilters.by_type_id(artefact_metadata=artefact_metadata),
                    ArtefactMetadataFilters.by_scan_id(artefact_metadata=artefact_metadata),
                    dm.ArtefactMetaData.data.op('->>')('cve').cast(sa.String)
                        == artefact_metadata.data.get('cve'),
                ),
                sa.and_(
                    dm.ArtefactMetaData.type == dso.model.Datatype.LICENSE,
                    ArtefactMetadataFilters.by_type_id(artefact_metadata=artefact_metadata),
                    ArtefactMetadataFilters.by_scan_id(artefact_metadata=artefact_metadata),
                    dm.ArtefactMetaData.data.op('->')('license').op('->>')('name').cast(sa.String)
                        == artefact_metadata.data.get('license', dict()).get('name'),
                ),
                sa.and_(
                    dm.ArtefactMetaData.type == dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
                    dm.ArtefactMetaData.data.op('->>')('cfg_name').cast(sa.String)
                        == artefact_metadata.data.get('cfg_name'),
                    dm.ArtefactMetaData.data.op('->>')('correlation_id').cast(sa.String)
                        == artefact_metadata.data.get('correlation_id'),
                ),
                sa.and_(
                    dm.ArtefactMetaData.type == dso.model.Datatype.MALWARE,
                ),
            ),
        )

    @staticmethod
    def filter_for_rescoring(
        artefact_metadata: dm.ArtefactMetaData,
    ):
        type = artefact_metadata.meta.get('relation').get('refers_to')
        severity = artefact_metadata.data.get('severity')
        username = artefact_metadata.data.get('user').get('username')
        comment = artefact_metadata.data.get('comment')
        finding = artefact_metadata.data.get('finding')

        return sa.and_(
            dm.ArtefactMetaData.type == dso.model.Datatype.RESCORING,
            ArtefactMetadataFilters.by_artefact_id_and_type(artefact_metadata),
            dm.ArtefactMetaData.meta.op('->')('relation').op('->>')('refers_to') == type,
            dm.ArtefactMetaData.data.op('->>')('severity') == severity,
            dm.ArtefactMetaData.data.op('->')('user').op('->>')('username') == username,
            dm.ArtefactMetaData.data.op('->>')('comment') == comment,
            sa.or_(
                sa.and_(
                    type == dso.model.Datatype.VULNERABILITY,
                    ArtefactMetadataFilters.by_finding_id(artefact_metadata=artefact_metadata),
                    dm.ArtefactMetaData.data.op('->')('finding').op('->>')('cve')
                        == finding.get('cve'),
                ),
                sa.and_(
                    type == dso.model.Datatype.LICENSE,
                    ArtefactMetadataFilters.by_finding_id(artefact_metadata=artefact_metadata),
                    dm.ArtefactMetaData.data.op('->')('finding').op('->')('license').op('->>')('name') # noqa: E501
                        == finding.get('license', dict()).get('name'),
                ),
            ),
        )

    @staticmethod
    def filter_for_rescoring_type(
        type_filter: list[str]=None,
    ):
        if not type_filter:
            return True

        return sa.and_(
            dm.ArtefactMetaData.type == dso.model.Datatype.RESCORING,
            dm.ArtefactMetaData.meta.op('->')('relation').op('->>')('refers_to').in_(type_filter),
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
