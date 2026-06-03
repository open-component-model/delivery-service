"""
The cache manager is intended to be run as a regular cronjobs which takes care of pruning the cache
according to a configurable maximum allowed caching size. The strategy according to which existing
cache entries should be deleted, can be configured by setting custom property weights.
Also, the cache manager can be used to prefill the cache for specific functions based on the
supplied configuration.
"""

import asyncio
import atexit
import collections.abc
import datetime
import logging

import requests
import sqlalchemy
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.sql.elements

import ci.log
import cnudie.retrieve_async
import oci.client_async
import ocm
import ocm.iter
import ocm.iter_async

import compliance_summary
import components as components_module
import ctx_util
import deliverydb
import deliverydb.model as dm
import deliverydb.util as du
import k8s.logging
import lookups
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import odg_client
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def bytes_to_str(
    bytes: int,
    ndigits: int = 2,
) -> str:
    return f'{round(bytes / 1000000, ndigits)}Mb'


async def db_size(
    db_session: sqlasync.session.AsyncSession,
) -> int:
    size_query = sqlalchemy.select(sqlalchemy.func.sum(dm.DBCache.size))
    size_result = await db_session.execute(size_query)

    # there is no size result if the delivery-db cache relation does not have any entries yet
    return size_result.one()[0] or 0


def is_pruning_required(
    cache_size_bytes: int,
    max_cache_size_bytes: int,
) -> bool:
    logger.info(f'Current cache size: {bytes_to_str(cache_size_bytes)}')
    logger.info(f'Max cache size: {bytes_to_str(max_cache_size_bytes)}')

    if cache_size_bytes < max_cache_size_bytes:
        current_utilisation = round(cache_size_bytes * 100 / max_cache_size_bytes, ndigits=2)
        logger.info(f'No cache pruning required ({current_utilisation=}%)')
        return False

    return True


async def prune_cache(
    cache_size_bytes: int,
    cfg: odg.extensions_cfg.CacheManagerConfig,
    db_session: sqlasync.session.AsyncSession,
    chunk_size: int = 50,
):
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    def interval_min(column: sqlalchemy.DateTime) -> sqlalchemy.sql.elements.BinaryExpression:
        return sqlalchemy.func.coalesce(sqlalchemy.extract('epoch', (now - column)) / 60, 0)

    # Multiply with the negative weight to order in descending order (i.e. entry with greatest
    # weight first). Note: Using sqlalchemy's `.desc()` function only works when ordering by columns
    # without any modifications of the same.
    db_statement = sqlalchemy.select(dm.DBCache).order_by(
        interval_min(dm.DBCache.creation_date) * cfg.cache_pruning_weights.creation_date_weight
        + interval_min(dm.DBCache.last_update) * cfg.cache_pruning_weights.last_update_weight
        + interval_min(dm.DBCache.delete_after) * cfg.cache_pruning_weights.delete_after_weight
        + interval_min(dm.DBCache.keep_until) * cfg.cache_pruning_weights.keep_until_weight
        + interval_min(dm.DBCache.last_read) * cfg.cache_pruning_weights.last_read_weight
        + dm.DBCache.read_count * cfg.cache_pruning_weights.read_count_weight
        + dm.DBCache.revision * cfg.cache_pruning_weights.revision_weight
        + dm.DBCache.costs * cfg.cache_pruning_weights.costs_weight
        + dm.DBCache.size * cfg.cache_pruning_weights.size_weight,
    )
    db_stream = await db_session.stream(db_statement)

    prunable_size = cache_size_bytes - cfg.min_pruning_bytes
    logger.info(
        f'Will prune cache (prunable size {bytes_to_str(prunable_size)}) until '
        f'{bytes_to_str(cfg.min_pruning_bytes)} are available again.',
    )

    try:
        async for partition in db_stream.partitions(size=chunk_size):
            for row in partition:
                if prunable_size <= 0:
                    break  # deleted enough cache entries
                entry = row[0]
                prunable_size -= entry.size
                await db_session.delete(entry)
            else:
                continue
            break  # deleted enough cache entries

        await db_session.commit()
        logger.info(
            f'Pruned {bytes_to_str(cache_size_bytes - cfg.min_pruning_bytes - prunable_size)}',
        )
    except Exception:
        await db_session.rollback()
        raise


async def prefill_compliance_summary_cache(
    component_id: ocm.ComponentIdentity,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    db_session: sqlasync.session.AsyncSession,
):
    logger.info(f'Updating compliance summary for {component_id.name}:{component_id.version}')

    for finding_cfg in finding_cfgs:
        await compliance_summary.component_datatype_summaries(
            component=component_id,
            finding_cfg=finding_cfg,
            finding_type=finding_cfg.type,
            datasource=finding_cfg.type.datasource(),
            db_session=db_session,
            component_descriptor_lookup=component_descriptor_lookup,
        )


async def prefill_compliance_summary_caches(
    components: collections.abc.Iterable[odg.extensions_cfg.Component],
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    oci_client: oci.client_async.Client,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    db_session: sqlasync.session.AsyncSession,
):
    seen_component_ids = set()

    for component in components:
        if resolved_version := component.resolved_version:
            # if an explicit version is specified, use it without any further implict lookup
            versions = [resolved_version]
        else:
            versions = await components_module.greatest_component_versions(
                component_name=component.component_name,
                component_descriptor_lookup=component_descriptor_lookup,
                ocm_repo=component.ocm_repo,
                max_versions=component.max_versions_limit,
                oci_client=oci_client,
                db_session=db_session,
            )

        for version in versions:
            component_descriptor = await component_descriptor_lookup(
                ocm.ComponentIdentity(
                    name=component.component_name,
                    version=version,
                ),
            )

            async for component_node in ocm.iter_async.iter(
                component=component_descriptor.component,
                lookup=component_descriptor_lookup,
                node_filter=ocm.iter.Filter.components,
            ):
                component_id = component_node.component_id

                if component_id in seen_component_ids:
                    continue
                seen_component_ids.add(component_id)

                await prefill_compliance_summary_cache(
                    component_id=component_id,
                    component_descriptor_lookup=component_descriptor_lookup,
                    finding_cfgs=finding_cfgs,
                    db_session=db_session,
                )


async def prefill_component_versions_caches(
    components: collections.abc.Iterable[odg.extensions_cfg.Component],
    db_session: sqlasync.session.AsyncSession,
):
    for component in components:
        await components_module.component_versions(
            component_name=component.component_name,
            ocm_repo=component.ocm_repo,
            db_session=db_session,
        )


async def prefill_function_caches(
    function_names: collections.abc.Iterable[odg.extensions_cfg.FunctionNames],
    components: collections.abc.Iterable[odg.extensions_cfg.Component],
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    oci_client: oci.client_async.Client,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    db_session: sqlasync.session.AsyncSession,
):
    for function_name in function_names:
        logger.info(f'Prefilling cache for {function_name=} and {components=}')

        match function_name:
            case odg.extensions_cfg.FunctionNames.COMPLIANCE_SUMMARY:
                await prefill_compliance_summary_caches(
                    components=components,
                    component_descriptor_lookup=component_descriptor_lookup,
                    oci_client=oci_client,
                    finding_cfgs=finding_cfgs,
                    db_session=db_session,
                )

            case odg.extensions_cfg.FunctionNames.COMPONENT_VERSIONS:
                await prefill_component_versions_caches(
                    components=components,
                    db_session=db_session,
                )


async def iter_sbom_artefacts(
    artefact_enumerator_cfg: odg.extensions_cfg.ArtefactEnumeratorConfig,
    sbom_generator_cfg: odg.extensions_cfg.SBOMGeneratorConfig,
    delivery_service_client: odg_client.DeliveryServiceClient,
    component_descriptor_lookup: ocm.ComponentDescriptorLookup,
) -> collections.abc.AsyncGenerator[odg.model.ComponentArtefactId, None]:
    for component in artefact_enumerator_cfg.components:
        if resolved_version := component.resolved_version:
            # if an explicit version is specified, use it without any further implict lookup
            versions = [resolved_version]
        else:
            versions = delivery_service_client.greatest_component_versions(
                component_name=component.component_name,
                max_versions=component.max_versions_limit,
                ocm_repo=component.ocm_repo,
            )

        ocm_repository_lookup = lookups.extended_ocm_repository_lookup(component.ocm_repo)

        for version in versions:
            component_id = ocm.ComponentIdentity(
                name=component.component_name,
                version=version,
            )

            component_descriptor = await component_descriptor_lookup(
                component_id,
                ocm_repository_lookup=ocm_repository_lookup,
            )

            async for artefact_node in ocm.iter_async.iter(
                component=component_descriptor,
                lookup=component_descriptor_lookup,
                node_filter=ocm.iter.Filter.artefacts,
                ocm_repo=ocm_repository_lookup,
            ):
                component_artefact_id = odg.model.component_artefact_id_from_ocm(
                    component=artefact_node.component,
                    artefact=artefact_node.artefact,
                )

                if sbom_generator_cfg.is_supported(
                    artefact_kind=component_artefact_id.artefact_kind,
                    access_type=artefact_node.artefact.access.type,
                    artefact_type=component_artefact_id.artefact.artefact_type,
                ):
                    yield component_artefact_id


async def cleanup_sboms(
    artefact_enumerator_cfg: odg.extensions_cfg.ArtefactEnumeratorConfig,
    sbom_generator_cfg: odg.extensions_cfg.SBOMGeneratorConfig,
    delivery_service_client: odg_client.DeliveryServiceClient,
    component_descriptor_lookup: ocm.ComponentDescriptorLookup,
    db_session: sqlasync.session.AsyncSession,
    retention_period_seconds: int,
):
    artefact_keys = set()

    async for artefact in iter_sbom_artefacts(
        artefact_enumerator_cfg=artefact_enumerator_cfg,
        sbom_generator_cfg=sbom_generator_cfg,
        delivery_service_client=delivery_service_client,
        component_descriptor_lookup=component_descriptor_lookup,
    ):
        artefact_keys.add(artefact.key)

    db_statement = sqlalchemy.select(dm.ArtefactMetaData).where(
        dm.ArtefactMetaData.type == odg.model.Datatype.ARTEFACT_SCAN_INFO,
        dm.ArtefactMetaData.datasource == odg.model.Datasource.SBOM_GENERATOR,
    )

    db_stream = await db_session.stream(db_statement)

    now = datetime.datetime.now(tz=datetime.UTC)
    retention_period = datetime.timedelta(seconds=float(retention_period_seconds))

    active_count = 0
    deletion_count = 0

    try:
        async for partition in db_stream.partitions(size=50):
            for row in partition:
                artefact_metadatum = du.db_artefact_metadata_row_to_dso(row)

                if artefact_metadatum.meta.creation_date > now - retention_period:
                    logger.debug(f'Keeping {artefact_metadatum.meta.creation_date=}')
                    active_count += 1
                    continue  # artefact is newer than the configured retention period

                if artefact_metadatum.artefact.key in artefact_keys:
                    logger.debug(f'Keeping {artefact_metadatum.artefact.key=}')
                    active_count += 1
                    continue  # artefact is still active -> no cleanup required

                if digest := artefact_metadatum.data.get('digest'):
                    try:
                        logger.debug(f'Deleting blob with {digest=}')
                        delivery_service_client.delete_blob(digest=digest)
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code != 404:
                            raise

                        # blob has already been deleted, so no need to follow-up
                        logger.info(f'Blob with {digest=} has already been deleted, skipping...')

                logger.debug(f'Deleting artefact metadatum with {artefact_metadatum.id=}')
                await db_session.execute(
                    sqlalchemy.delete(dm.ArtefactMetaData).where(
                        dm.ArtefactMetaData.id == artefact_metadatum.id,
                    ),
                )
                deletion_count += 1

        await db_session.commit()
    except Exception:
        await db_session.rollback()
        raise

    logger.info(f'Deleted {deletion_count} SBOM(s)')
    logger.info(f'Kept {active_count} SBOM(s)')


async def main():
    parsed_arguments = odg.util.parse_args()

    namespace = parsed_arguments.k8s_namespace

    secret_factory = ctx_util.secret_factory()
    kubernetes_api = odg.util.kubernetes_api(parsed_arguments, secret_factory=secret_factory)

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.CACHE_MANAGER,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.CACHE_MANAGER,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    cache_manager_cfg = extensions_cfg.cache_manager

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    finding_cfgs = odg.findings.Finding.from_file(findings_cfg_path)

    delivery_db_secrets = secret_factory.delivery_db()
    if len(delivery_db_secrets) != 1:
        raise ValueError(
            f'There must be exactly one delivery-db secret, found {len(delivery_db_secrets)}',
        )
    db_url = delivery_db_secrets[0].connection_url(
        namespace=namespace,
    )

    oci_client = lookups.semver_sanitising_oci_client_async(secret_factory)

    if not (delivery_service_url := parsed_arguments.delivery_service_url):
        delivery_service_url = cache_manager_cfg.delivery_service_url

    if delivery_service_url:
        delivery_service_client = odg_client.DeliveryServiceClient(
            routes=odg_client.DeliveryServiceRoutes(
                base_url=delivery_service_url,
            ),
            auth_token_lookup=lookups.github_auth_token_lookup,
        )
    else:
        logger.warning('No delivery-service URL provided, will not be able cleanup SBOMs')
        delivery_service_client = None

    component_descriptor_lookup = lookups.init_component_descriptor_lookup_async(
        cache_dir=parsed_arguments.cache_dir,
        db_url=db_url,
        oci_client=oci_client,
    )

    db_session = await deliverydb.sqlalchemy_session_async(db_url)
    try:
        cache_size_bytes = await db_size(db_session=db_session)

        if is_pruning_required(
            cache_size_bytes=cache_size_bytes,
            max_cache_size_bytes=cache_manager_cfg.max_cache_size_bytes,
        ):
            await prune_cache(
                cache_size_bytes=cache_size_bytes,
                cfg=cache_manager_cfg,
                db_session=db_session,
            )

        await prefill_function_caches(
            function_names=cache_manager_cfg.prefill_function_caches.functions,
            components=cache_manager_cfg.prefill_function_caches.components,
            component_descriptor_lookup=component_descriptor_lookup,
            oci_client=oci_client,
            finding_cfgs=finding_cfgs,
            db_session=db_session,
        )

        if (
            extensions_cfg.artefact_enumerator
            and extensions_cfg.sbom_generator
            and cache_manager_cfg.sbom_retention_period_seconds is not None
            and delivery_service_client
        ):
            await cleanup_sboms(
                artefact_enumerator_cfg=extensions_cfg.artefact_enumerator,
                sbom_generator_cfg=extensions_cfg.sbom_generator,
                delivery_service_client=delivery_service_client,
                component_descriptor_lookup=component_descriptor_lookup,
                db_session=db_session,
                retention_period_seconds=cache_manager_cfg.sbom_retention_period_seconds,
            )
    finally:
        await db_session.close()
        await oci_client.session.close()


if __name__ == '__main__':
    asyncio.run(main())
