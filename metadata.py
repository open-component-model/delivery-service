import collections.abc
import dataclasses
import datetime

import falcon
import falcon.media.validators.jsonschema
import sqlalchemy as sa
import sqlalchemy.orm.session as ss

import ci.util
import dso.model
import gci.componentmodel as cm

import compliance_summary as cs
import deliverydb.model as dm
import deliverydb.util as du
import eol
import features


class ArtefactMetadata:
    required_features = (features.FeatureDeliveryDB,)

    def __init__(
        self,
        eol_client: eol.EolClient,
        artefact_metadata_cfg_by_type: dict,
    ):
        self.eol_client = eol_client
        self.artefact_metadata_cfg_by_type = artefact_metadata_cfg_by_type

    def on_post_query(self, req: falcon.Request, resp: falcon.Response):
        '''
        query artefact-metadata from delivery-db and mix-in existing rescorings

        **expected query parameters:**

            - type (optional): The metadata types to retrieve. Can be given multiple times. If \n
              no type is given, all relevant metadata will be returned. Check \n
              https://github.com/gardener/cc-utils/blob/master/dso/model.py `Datatype` model \n
              class for a list of possible values. \n
            - referenced_type (optional): The referenced types to retrieve (only applicable for \n
              metadata of type `rescorings`). Can be given multiple times. If no referenced type \n
              is given, all relevant metadata will be returned. Check \n
              https://github.com/gardener/cc-utils/blob/master/dso/model.py `Datatype` model \n
              class for a list of possible values. \n

        **expected body:**

            - components: <array> of <object> \n
                - componentName: <str> \n
                - componentVersion: <str> \n
        '''
        body = req.context.media
        component_filter: list[dict] = body.get('components')
        component_ids = tuple(
            cm.ComponentIdentity(
                name=component.get('componentName'),
                version=component.get('componentVersion'),
            ) for component in component_filter
        )

        session: ss.Session = req.context.db_session

        type_filter = req.get_param_as_list('type', required=False)
        referenced_type_filter = req.get_param_as_list('referenced_type', required=False)

        findings_query = session.query(dm.ArtefactMetaData)

        if type_filter:
            findings_query = findings_query.filter(
                dm.ArtefactMetaData.type.in_(type_filter),
            )

        if referenced_type_filter:
            findings_query = findings_query.filter(
                sa.and_(
                    dm.ArtefactMetaData.referenced_type.in_(referenced_type_filter),
                ),
            )

        if component_filter:
            if type_filter and dso.model.Datatype.RESCORING not in type_filter:
                findings_query = findings_query.filter(
                    sa.or_(du.ArtefactMetadataQueries.component_queries(
                        components=component_ids,
                    )),
                )
            else:
                # when filtering for metadata of type `rescorings`, entries without a component
                # name or version should also be considered a "match" (caused by different rescoring
                # scopes)
                findings_query = findings_query.filter(
                    sa.or_(
                        sa.and_(
                            dm.ArtefactMetaData.type == dso.model.Datatype.RESCORING,
                            sa.or_(du.ArtefactMetadataQueries.component_queries(
                                components=component_ids,
                                none_ok=True,
                            )),
                        ),
                        sa.or_(du.ArtefactMetadataQueries.component_queries(
                            components=component_ids,
                        )),
                    ),
                )

        findings_raw = findings_query.all()
        findings = [
            du.db_artefact_metadata_to_dso(raw)
            for raw in findings_raw
        ]

        def iter_findings(
            findings: list[dso.model.ArtefactMetadata],
            artefact_metadata_cfg_by_type: dict[str, cs.ArtefactMetadataCfg],
        ) -> collections.abc.Generator[dict, None, None]:
            def result_dict(
                finding: dso.model.ArtefactMetadata,
                meta: dict=None,
            ) -> dict:
                finding_dict = dataclasses.asdict(
                    obj=finding,
                    dict_factory=ci.util.dict_to_json_factory,
                )

                if meta:
                    finding_dict['meta'] = meta

                return finding_dict

            for finding in findings:
                cfg = artefact_metadata_cfg_by_type.get(finding.meta.type)

                if not cfg:
                    yield result_dict(finding)
                    continue

                severity = cs.severity_for_finding(
                    finding=finding,
                    artefact_metadata_cfg=cfg,
                    eol_client=self.eol_client,
                )
                if not severity:
                    yield result_dict(finding)
                    continue

                yield result_dict(
                    finding=finding,
                    meta=dict(**dataclasses.asdict(finding.meta), severity=severity),
                )

        resp.media = list(iter_findings(
            findings=findings,
            artefact_metadata_cfg_by_type=self.artefact_metadata_cfg_by_type,
        ))

    def on_put(self, req: falcon.Request, resp: falcon.Response):
        '''
        update artefact-metadata in delivery-db

        Only the data from the supplied request body is kept (created/updated), other database
        tuples for the same artefact and meta.type are removed. Check
        https://github.com/gardener/cc-utils/blob/master/dso/model.py for allowed values of
        meta.type (-> dso.model/Datatype) and meta.datasource (-> dso.model.Datasource).

        **expected body:**

            - entries: <array> of <object> \n
                - artefact: <object> \n
                    - component_name: <str> \n
                    - component_version: <str> \n
                    - artefact_kind: <str> {`artefact`, `rescoure`, `source`} \n
                    - artefact: <object> \n
                        - artefact_name: <str> \n
                        - artefact_version: <str> \n
                        - artefact_type: <str> \n
                        - artefact_extra_id: <object> \n
                - meta: <object> \n
                    - type: <str> # one of dso.model/Datatype \n
                    - datasource: <str> # one of dso.model/Datasource \n
                - data: <object> # schema depends on meta.type \n
                - discovery_date: <str of format YYYY-MM-DD> \n
        '''
        body = req.context.media
        entries: list[dict] = body.get('entries')

        if not entries:
            resp.status = falcon.HTTP_OK
            return

        session: ss.Session = req.context.db_session

        artefact_metadata = [
            dso.model.ArtefactMetadata.from_dict(_fill_default_values(entry))
            for entry in entries
        ]

        # determine all artefact/type combinations to query them at once afterwards
        artefacts = dict()
        for artefact_metadatum in artefact_metadata:
            key = (artefact_metadatum.artefact, artefact_metadatum.meta.type)
            if key not in artefacts:
                artefacts[key] = artefact_metadatum

        artefacts = artefacts.values()

        def artefact_queries(artefacts: collections.abc.Iterable[dso.model.ArtefactMetadata]):
            for artefact in artefacts:
                yield du.ArtefactMetadataFilters.by_name_and_type(
                    artefact_metadata=dm.ArtefactMetaData(
                        component_name=artefact.artefact.component_name,
                        artefact_name=artefact.artefact.artefact.artefact_name,
                        type=artefact.meta.type,
                        datasource=artefact.meta.datasource,
                    ),
                )

        existing_entries = session.query(dm.ArtefactMetaData).filter(
            sa.or_(artefact_queries(artefacts=artefacts)),
        ).all()

        created_artefacts: list[dm.ArtefactMetaData] = []

        try:
            for artefact_metadatum in artefact_metadata:
                metadata_entry = du.to_db_artefact_metadata(
                    artefact_metadata=artefact_metadatum,
                )

                reusable_discovery_date = None
                for existing_entry in existing_entries + created_artefacts:
                    if (
                        existing_entry.type != metadata_entry.type
                        or existing_entry.component_name != metadata_entry.component_name
                        or existing_entry.artefact_kind != metadata_entry.artefact_kind
                        or existing_entry.artefact_name != metadata_entry.artefact_name
                        or existing_entry.artefact_type != metadata_entry.artefact_type
                    ):
                        continue

                    if not reusable_discovery_date:
                        reusable_discovery_date = reuse_discovery_date_if_possible(
                            old_metadata=existing_entry,
                            new_metadata=metadata_entry,
                        )

                    if (
                        existing_entry.component_version != metadata_entry.component_version
                        or existing_entry.artefact_version != metadata_entry.artefact_version
                        # do not include extra id (yet) because there is only one entry for
                        # all ocm resources with different extra ids at the moment
                        # TODO include extra id as soon as there is one entry for each extra id
                        # or existing_entry.artefact_extra_id_normalised
                        #     != metadata_entry.artefact_extra_id_normalised
                        or existing_entry.data_key != metadata_entry.data_key
                    ):
                        continue

                    # found database entry that matches the supplied metadata entry
                    break
                else:
                    # did not find existing database entry that matches the supplied metadata entry
                    # -> create new entry (and re-use discovery date if possible)
                    if reusable_discovery_date:
                        metadata_entry.discovery_date = reusable_discovery_date

                    session.add(metadata_entry)
                    created_artefacts.append(metadata_entry)
                    continue

                # update actual payload
                existing_entry.data = metadata_entry.data

                # create new dict instead of patching it, otherwise it won't be updated in the db
                del existing_entry.meta['last_update']
                existing_entry.meta = dict(
                    **existing_entry.meta,
                    last_update=metadata_entry.meta['last_update'],
                )

            session.commit()
        except:
            session.rollback()
            raise

        resp.status = falcon.HTTP_CREATED

    def on_delete(self, req: falcon.Request, resp: falcon.Response):
        '''
        delete artefact-metadata from delivery-db

        **expected body:**

            - entries: <array> \n
                - artefact: <object> \n
                    - component_name: <str> \n
                    - component_version: <str> \n
                    - artefact: <object> \n
                        - artefact_name: <str> \n
                        - artefact_version: <str> \n
                        - artefact_type: <str> \n
                        - artefact_extra_id: <object> \n
                - meta: <object> \n
                    - type: <str> \n
                    - datasource: <str> \n
                - data: <object> # schema depends on meta.type \n
                - discovery_date: <str of format YYYY-MM-DD> \n
        '''
        body = req.context.media
        entries: list[dict] = body.get('entries')

        session: ss.Session = req.context.db_session

        try:
            for entry in entries:
                entry = _fill_default_values(entry)

                artefact_metadata = du.to_db_artefact_metadata(
                    artefact_metadata=dso.model.ArtefactMetadata.from_dict(entry),
                )

                session.query(dm.ArtefactMetaData).filter(
                    du.ArtefactMetadataFilters.by_single_scan_result(artefact_metadata)
                ).delete()

                session.commit()
        except:
            session.rollback()
            raise

        resp.status = falcon.HTTP_NO_CONTENT


def reuse_discovery_date_if_possible(
    old_metadata: dm.ArtefactMetaData,
    new_metadata: dm.ArtefactMetaData,
) -> datetime.date | None:
    if new_metadata.type == dso.model.Datatype.VULNERABILITY:
        if (
            new_metadata.data.get('package_name') == old_metadata.data.get('package_name')
            and new_metadata.data.get('cve') == old_metadata.data.get('cve')
        ):
            # found the same cve in existing entry, independent of the component-/
            # resource-/package-version, so we must re-use its discovery date
            return old_metadata.discovery_date

    elif new_metadata.type == dso.model.Datatype.LICENSE:
        if (
            new_metadata.data.get('package_name') == old_metadata.data.get('package_name')
            and new_metadata.data.get('license').get('name')
                == old_metadata.data.get('license').get('name')
        ):
            # found the same license in existing entry, independent of the component-/
            # resource-/package-version, so we must re-use its discovery date
            return old_metadata.discovery_date

    return None


def _fill_default_values(
    raw: dict,
) -> dict:
    meta = raw['meta']
    if not meta.get('last_update'):
        meta['last_update'] = datetime.datetime.now().isoformat()

    if not meta.get('creation_date'):
        meta['creation_date'] = datetime.datetime.now().isoformat()

    return raw
