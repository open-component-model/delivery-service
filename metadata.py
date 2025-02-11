import collections.abc
import dataclasses
import datetime
import http

import aiohttp.web
import dacite
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync

import dso.model
import ocm

import compliance_summary as cs
import consts
import deliverydb.cache as dc
import deliverydb.model as dm
import deliverydb.util as du
import deliverydb_cache.model as dcm
import features
import middleware.cors
import odg.findings
import util


types_with_reusable_discovery_dates = (
    odg.findings.FindingType.VULNERABILITY,
    odg.findings.FindingType.LICENSE,
    odg.findings.FindingType.DIKI,
)


class ArtefactMetadataQuery(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    async def options(self):
        return aiohttp.web.Response()

    async def post(self):
        '''
        ---
        description: Query artefact-metadata from delivery-db.
        tags:
        - Artefact metadata
        produces:
        - application/json
        parameters:
        - in: query
          name: type
          schema:
            $ref: '#/definitions/Datatype'
          required: false
          description:
            The metadata types to retrieve. Can be given multiple times. If no type is
            given, all relevant metadata will be returned. Check
            https://github.com/gardener/cc-utils/blob/master/dso/model.py `Datatype` model class for
            a list of possible values.
        - in: query
          name: referenced_type
          schema:
            $ref: '#/definitions/Datatype'
          required: false
          description:
            The referenced types to retrieve (only applicable for metadata of type
            `rescorings`). Can be given multiple times. If no referenced type is given, all relevant
            metadata will be returned. Check
            https://github.com/gardener/cc-utils/blob/master/dso/model.py `Datatype` model class for
            a list of possible values.
        - in: body
          name: body
          required: false
          schema:
            type: object
            properties:
              entries:
                type: array
                items:
                  $ref: '#/definitions/ComponentArtefactId'
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                $ref: '#/definitions/ArtefactMetadata'
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

            if artefact_ref.artefact_kind:
                yield dm.ArtefactMetaData.artefact_kind == artefact_ref.artefact_kind

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

            if artefact_extra_id := artefact_ref.artefact.normalised_artefact_extra_id:
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_extra_id_normalised == '',
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
                finding_dict = util.dict_serialisation(finding)

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

        finding_cfgs = self.request.app[consts.APP_FINDING_CFGS]

        artefact_metadata = []
        async for partition in db_stream.partitions(size=50):
            for row in partition:
                artefact_metadatum = du.db_artefact_metadata_row_to_dso(row)

                # only yield findings which were not explicitly filtered-out by central finding-cfg
                for finding_cfg in finding_cfgs:
                    if (
                        finding_cfg.type == artefact_metadatum.meta.type
                        and not finding_cfg.matches(artefact_metadatum.artefact)
                    ):
                        # artefact metadatum is filtered-out, do not include it
                        break
                else:
                    # artefact metadatum was not explicitly filtered-out by central finding-cfg
                    artefact_metadata.append(await serialise_and_enrich_finding(artefact_metadatum))

        data = util.dict_to_json_factory(artefact_metadata)

        response = aiohttp.web.StreamResponse(
            headers={
                'Content-Type': 'application/json',
                # cors must be set here already because `response.prepare` already sends header
                **middleware.cors.cors_headers(self.request),
            },
        )
        response.enable_compression()
        await response.prepare(self.request)
        await response.write(data.encode('utf-8'))
        await response.write_eof()

        return response


class ArtefactMetadata(aiohttp.web.View):
    async def put(self):
        '''
        ---
        description: Update artefact-metadata in delivery-db.
        tags:
        - Artefact metadata
        parameters:
        - in: body
          name: body
          required: false
          schema:
            type: object
            properties:
              entries:
                type: array
                items:
                  $ref: '#/definitions/ArtefactMetadata'
        responses:
          "200":
            description: No entries were provided and no operation was performed.
          "201":
            description: Successful operation.
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

            if existing_entry.id != metadata_entry.id:
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

                await _mark_compliance_summary_cache_for_deletion(
                    db_session=db_session,
                    artefact_metadata=metadata_entry,
                )

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
        ---
        description: Delete artefact-metadata from delivery-db.
        tags:
        - Artefact metadata
        parameters:
        - in: body
          name: body
          required: true
          schema:
            type: object
            properties:
              entries:
                type: array
                items:
                  $ref: '#/definitions/ArtefactMetadata'
        responses:
          "204":
            description: Successful operation.
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
                    dm.ArtefactMetaData.id == artefact_metadata.id,
                ))

                await _mark_compliance_summary_cache_for_deletion(
                    db_session=db_session,
                    artefact_metadata=artefact_metadata,
                )

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

    if new_metadata.type == odg.findings.FindingType.VULNERABILITY:
        if (
            new_metadata.data.get('package_name') == old_metadata.data.get('package_name')
            and new_metadata.data.get('cve') == old_metadata.data.get('cve')
        ):
            # found the same cve in existing entry, independent of the component-/
            # resource-/package-version, so we must re-use its discovery date
            return old_metadata.discovery_date

    elif new_metadata.type == odg.findings.FindingType.LICENSE:
        if (
            new_metadata.data.get('package_name') == old_metadata.data.get('package_name')
            and new_metadata.data.get('license').get('name')
                == old_metadata.data.get('license').get('name')
        ):
            # found the same license in existing entry, independent of the component-/
            # resource-/package-version, so we must re-use its discovery date
            return old_metadata.discovery_date

    elif new_metadata.type == odg.findings.FindingType.DIKI:
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


async def _mark_compliance_summary_cache_for_deletion(
    db_session: sqlasync.session.AsyncSession,
    artefact_metadata: dm.ArtefactMetaData,
):
    if not (
        artefact_metadata.component_name and artefact_metadata.component_version
        and artefact_metadata.type and artefact_metadata.datasource
    ):
        # If one of these properties is not set, the cache id cannot be calculated properly.
        # Currently, this is only the case for BDBA findings where the component version is left
        # empty. In that case, the cache is invalidated upon successful finish of the scan.
        return

    component = ocm.ComponentIdentity(
        name=artefact_metadata.component_name,
        version=artefact_metadata.component_version,
    )

    if artefact_metadata.type == dso.model.Datatype.ARTEFACT_SCAN_INFO:
        # If the artefact scan info changes, the compliance summary for all datatypes related to
        # this datasource has to be updated, because it may has changed from
        # UNKNOWN -> CLEAN/FINDINGS
        datatypes = dso.model.Datasource.datasource_to_datatypes(artefact_metadata.datasource)
    else:
        datatypes = (artefact_metadata.type,)

    for datatype in datatypes:
        try:
            finding_type = odg.findings.FindingType(datatype)
        except ValueError:
            continue

        await dc.mark_function_cache_for_deletion(
            encoding_format=dcm.EncodingFormat.PICKLE,
            function='compliance_summary.component_datatype_summaries',
            db_session=db_session,
            defer_db_commit=True, # only commit at the end of the query
            component=component,
            finding_type=finding_type,
            datasource=artefact_metadata.datasource,
        )
