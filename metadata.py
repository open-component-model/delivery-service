import collections.abc
import dataclasses
import datetime
import http

import aiohttp.web
import dacite
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync

import ci.util
import dso.model
import ocm

import compliance_summary as cs
import consts
import deliverydb.model as dm
import deliverydb.util as du
import features
import util


types_with_reusable_discovery_dates = (
    dso.model.Datatype.VULNERABILITY,
    dso.model.Datatype.LICENSE,
    dso.model.Datatype.DIKI_FINDING,
)


class ArtefactMetadataQuery(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    async def options(self):
        return aiohttp.web.Response()

    async def post(self):
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

            - entries: <array> of <object> \n
                - component_name: <str> \n
                - component_version: <str> \n
                - artefact: <object> \n
                    - artefact_name: <str> \n
                    - artefact_version: <str> \n
                    - artefact_type: <str> \n
                    - artefact_extra_id: <object> \n
        '''
        artefact_metadata_cfg_by_type = self.request.app[consts.APP_ARTEFACT_METADATA_CFG]
        component_descriptor_lookup = self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP]
        eol_client = self.request.app[consts.APP_EOL_CLIENT]
        params = self.request.rel_url.query

        body = await self.request.json()
        entries: list[dict] = body.get('entries', [])

        type_filter = params.getall('type', [])
        referenced_type_filter = params.getall('referenced_type', [])

        artefact_refs = [
            dacite.from_dict(
                data_class=dso.model.ComponentArtefactId,
                data=entry,
                config=dacite.Config(
                    cast=[dso.model.ArtefactKind],
                ),
            ) for entry in entries
        ]

        async def artefact_queries(artefact_ref: dso.model.ComponentArtefactId):
            # when filtering for metadata of type `rescorings`, entries without a component
            # name or version should also be considered a "match" (caused by different rescoring
            # scopes)
            none_ok = not type_filter or dso.model.Datatype.RESCORING in type_filter

            async for query in du.ArtefactMetadataQueries.component_queries(
                components=[ocm.ComponentIdentity(
                    name=artefact_ref.component_name,
                    version=artefact_ref.component_version,
                )],
                none_ok=none_ok,
                component_descriptor_lookup=component_descriptor_lookup,
            ):
                yield query

            if not artefact_ref.artefact:
                return

            if artefact_name := artefact_ref.artefact.artefact_name:
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_name == None,
                    ),
                    dm.ArtefactMetaData.artefact_name == artefact_name,
                )

            if artefact_version := artefact_ref.artefact.artefact_version:
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_version == None,
                    ),
                    dm.ArtefactMetaData.artefact_version == artefact_version,
                )

            if artefact_type := artefact_ref.artefact.artefact_type:
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_type == None,
                    ),
                    dm.ArtefactMetaData.artefact_type == artefact_type,
                )

            if artefact_extra_id := artefact_ref.artefact.normalised_artefact_extra_id():
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_extra_id_normalised == None,
                    ),
                    dm.ArtefactMetaData.artefact_extra_id_normalised == artefact_extra_id,
                )

        async def artefact_refs_queries(artefact_refs: list[dso.model.ComponentArtefactId]):
            for artefact_ref in artefact_refs:
                yield sa.and_(*[
                    query async for query
                    in artefact_queries(artefact_ref=artefact_ref)
                ])

        db_statement = sa.select(dm.ArtefactMetaData)

        if type_filter:
            db_statement = db_statement.where(
                dm.ArtefactMetaData.type.in_(type_filter),
            )

        if referenced_type_filter:
            db_statement = db_statement.where(
                dm.ArtefactMetaData.referenced_type.in_(referenced_type_filter),
            )

        if artefact_refs:
            db_statement = db_statement.where(
                sa.or_(*[
                    query async for query
                    in artefact_refs_queries(artefact_refs=artefact_refs)
                ]),
            )

        async def serialise_and_enrich_finding(
            finding: dso.model.ArtefactMetadata,
        ) -> dict:
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

            cfg = artefact_metadata_cfg_by_type.get(finding.meta.type)

            if not cfg:
                return result_dict(finding)

            severity = await cs.severity_for_finding(
                finding=finding,
                artefact_metadata_cfg=cfg,
                eol_client=eol_client,
            )
            if not severity:
                return result_dict(finding)

            return result_dict(
                finding=finding,
                meta=dict(**dataclasses.asdict(finding.meta), severity=severity),
            )

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
        db_stream = await db_session.stream(db_statement)

        return aiohttp.web.json_response(
            data=[
                await serialise_and_enrich_finding(du.db_artefact_metadata_row_to_dso(row))
                async for partition in db_stream.partitions(size=50)
                for row in partition
            ],
            dumps=util.dict_to_json_factory,
        )


class ArtefactMetadata(aiohttp.web.View):
    async def put(self):
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
                    - artefact_kind: <str> {`artefact`, `rescoure`, `source`, `runtime`} \n
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
        body = await self.request.json()
        entries: list[dict] = body.get('entries')

        if not entries:
            return aiohttp.web.Response()

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

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
        db_statement = sa.select(dm.ArtefactMetaData).where(
            sa.or_(artefact_queries(artefacts=artefacts)),
        )
        db_stream = await db_session.stream(db_statement)

        # order entries to increase chances to find matching existing entry as soon as possible
        existing_entries = sorted(
            [
                entry[0]
                async for partition in db_stream.partitions(size=50)
                for entry in partition
            ],
            key=lambda entry: entry.meta.get(
                'last_update',
                datetime.datetime.fromtimestamp(0, datetime.UTC).isoformat(),
            ),
            reverse=True,
        )

        existing_artefact_versions = {
            existing_entry.artefact_version for existing_entry in existing_entries
        }

        created_artefacts: list[dm.ArtefactMetaData] = []

        def find_entry_and_discovery_date(
            existing_entry: dm.ArtefactMetaData,
            new_entry: dm.ArtefactMetaData,
        ) -> tuple[dm.ArtefactMetaData | None, datetime.date | None]:
            if (
                existing_entry.type != new_entry.type
                or existing_entry.component_name != new_entry.component_name
                or existing_entry.artefact_kind != new_entry.artefact_kind
                or existing_entry.artefact_name != new_entry.artefact_name
                or existing_entry.artefact_type != new_entry.artefact_type
            ):
                return None, None

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
                return None, reusable_discovery_date

            return existing_entry, reusable_discovery_date

        try:
            for artefact_metadatum in artefact_metadata:
                metadata_entry = du.to_db_artefact_metadata(
                    artefact_metadata=artefact_metadatum,
                )

                found = None
                discovery_date = None

                for existing_entry in created_artefacts:
                    found, reusable_discovery_date = find_entry_and_discovery_date(
                        existing_entry=existing_entry,
                        new_entry=metadata_entry,
                    )

                    if not discovery_date:
                        discovery_date = reusable_discovery_date

                    if found:
                        break

                if not found:
                    for existing_entry in existing_entries:
                        if (
                            (
                                metadata_entry.type not in types_with_reusable_discovery_dates
                                or discovery_date
                            ) and metadata_entry.artefact_version not in existing_artefact_versions
                        ):
                            # there is no need to search any further -> we won't find any existing
                            # entry with the same artefact version and we don't have to find any
                            # reusable discovery date (anymore)
                            break

                        found, reusable_discovery_date = find_entry_and_discovery_date(
                            existing_entry=existing_entry,
                            new_entry=metadata_entry,
                        )

                        if not discovery_date:
                            discovery_date = reusable_discovery_date

                        if found:
                            break

                if not found:
                    # did not find existing database entry that matches the supplied metadata entry
                    # -> create new entry (and re-use discovery date if possible)
                    if discovery_date:
                        metadata_entry.discovery_date = discovery_date

                    db_session.add(metadata_entry)
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

            await db_session.commit()
        except:
            await db_session.rollback()
            raise

        return aiohttp.web.Response(
            status=http.HTTPStatus.CREATED,
        )

    async def delete(self):
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
        body = await self.request.json()
        entries: list[dict] = body.get('entries')

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        try:
            for entry in entries:
                entry = _fill_default_values(entry)

                artefact_metadata = du.to_db_artefact_metadata(
                    artefact_metadata=dso.model.ArtefactMetadata.from_dict(entry),
                )

                await db_session.execute(sa.delete(dm.ArtefactMetaData).where(
                    du.ArtefactMetadataFilters.by_single_scan_result(artefact_metadata),
                ))

            await db_session.commit()
        except:
            await db_session.rollback()
            raise

        return aiohttp.web.Response(
            status=http.HTTPStatus.NO_CONTENT,
        )


def reuse_discovery_date_if_possible(
    old_metadata: dm.ArtefactMetaData,
    new_metadata: dm.ArtefactMetaData,
) -> datetime.date | None:
    if new_metadata.type not in types_with_reusable_discovery_dates:
        return None

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

    elif new_metadata.type == dso.model.Datatype.DIKI_FINDING:
        if (
            new_metadata.data.get('provider_id') == old_metadata.data.get('provider_id')
            and new_metadata.data.get('ruleset_id') == old_metadata.data.get('ruleset_id')
            and new_metadata.data.get('rule_id') == old_metadata.data.get('rule_id')
        ):
            # found the same finding in existing entry, independent of the component-/
            # resource-/ruleset-version, so we must re-use its discovery date
            return old_metadata.discovery_date

    else:
        raise ValueError(
            f're-usage of discovery dates is configured for "{new_metadata.type}" but there is no '
            'special handling implemented to check when to re-use existing dates'
        )


def _fill_default_values(
    raw: dict,
) -> dict:
    meta = raw['meta']
    if not meta.get('last_update'):
        meta['last_update'] = datetime.datetime.now().isoformat()

    if not meta.get('creation_date'):
        meta['creation_date'] = datetime.datetime.now().isoformat()

    return raw
