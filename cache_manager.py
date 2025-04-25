'''
The cache manager is intended to be run as a regular cronjobs which takes care of pruning the cache
according to a configurable maximum allowed caching size. The strategy according to which existing
cache entries should be deleted, can be configured by setting custom property weights.
Also, the cache manager can be used to prefill the cache for specific functions based on the
supplied configuration.
'''
import asyncio
import argparse
import atexit
import collections.abc
import datetime
import logging
import os

import sqlalchemy
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.sql.elements

import ci.log
import cnudie.iter
import cnudie.iter_async
import cnudie.retrieve_async
import dso.model
import oci.client_async
import ocm

import compliance_summary
import components as components_module
import config
import ctx_util
import deliverydb
import deliverydb.model as dm
import k8s.logging
import k8s.util
import lookups
import odg.extensions_cfg
import odg.findings
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


def bytes_to_str(
    bytes: int,
    ndigits: int=2,
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
    chunk_size: int=50,
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
        + dm.DBCache.size * cfg.cache_pruning_weights.size_weight
    )
    db_stream = await db_session.stream(db_statement)

    prunable_size = cache_size_bytes - cfg.min_pruning_bytes
    logger.info(
        f'Will prune cache (prunable size {bytes_to_str(prunable_size)}) until '
        f'{bytes_to_str(cfg.min_pruning_bytes)} are available again.'
    )

    try:
        async for partition in db_stream.partitions(size=chunk_size):
            for row in partition:
                if prunable_size <= 0:
                    break # deleted enough cache entries
                entry = row[0]
                prunable_size -= entry.size
                await db_session.delete(entry)
            else:
                continue
            break # deleted enough cache entries

        await db_session.commit()
        logger.info(
            f'Pruned {bytes_to_str(cache_size_bytes - cfg.min_pruning_bytes - prunable_size)}'
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
            datasource=dso.model.Datatype.datatype_to_datasource(finding_cfg.type),
            db_session=db_session,
            component_descriptor_lookup=component_descriptor_lookup,
        )


async def prefill_compliance_summary_caches(
    components: collections.abc.Iterable[odg.extensions_cfg.Component],
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent,
    oci_client: oci.client_async.Client,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    invalid_semver_ok: bool,
    db_session: sqlasync.session.AsyncSession,
):
    seen_component_ids = set()

    for component in components:
        if component.version_filter:
            version_filter = config.VersionFilter(component.version_filter)
        else:
            version_filter = config.VersionFilter.RELEASES_ONLY

        versions = await components_module.greatest_component_versions(
            component_name=component.component_name,
            component_descriptor_lookup=component_descriptor_lookup,
            ocm_repo=component.ocm_repo,
            version_lookup=version_lookup,
            max_versions=component.max_versions_limit,
            greatest_version=component.version,
            oci_client=oci_client,
            version_filter=version_filter,
            invalid_semver_ok=invalid_semver_ok,
            db_session=db_session,
        )

        for version in versions:
            component_descriptor = await component_descriptor_lookup(ocm.ComponentIdentity(
                name=component.component_name,
                version=version,
            ))

            async for component_node in cnudie.iter_async.iter(
                component=component_descriptor.component,
                lookup=component_descriptor_lookup,
                node_filter=cnudie.iter.Filter.components,
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
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent,
    db_session: sqlasync.session.AsyncSession,
):
    for component in components:
        await components_module.component_versions(
            component_name=component.component_name,
            version_lookup=version_lookup,
            ocm_repo=component.ocm_repo,
            db_session=db_session,
        )


async def prefill_function_caches(
    function_names: collections.abc.Iterable[odg.extensions_cfg.FunctionNames],
    components: collections.abc.Iterable[odg.extensions_cfg.Component],
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent,
    oci_client: oci.client_async.Client,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    invalid_semver_ok: bool,
    db_session: sqlasync.session.AsyncSession,
):
    for function_name in function_names:
        logger.info(f'Prefilling cache for {function_name=} and {components=}')

        match function_name:
            case odg.extensions_cfg.FunctionNames.COMPLIANCE_SUMMARY:
                await prefill_compliance_summary_caches(
                    components=components,
                    component_descriptor_lookup=component_descriptor_lookup,
                    version_lookup=version_lookup,
                    oci_client=oci_client,
                    finding_cfgs=finding_cfgs,
                    invalid_semver_ok=invalid_semver_ok,
                    db_session=db_session,
                )

            case odg.extensions_cfg.FunctionNames.COMPONENT_VERSIONS:
                await prefill_component_versions_caches(
                    components=components,
                    version_lookup=version_lookup,
                    db_session=db_session,
                )


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='specify kubernetes cluster to interact with',
        default=os.environ.get('K8S_CFG_NAME'),
    )
    parser.add_argument(
        '--kubeconfig',
        help='''
            specify kubernetes cluster to interact with extensions (and logs); if both
            `k8s-cfg-name` and `kubeconfig` are set, `k8s-cfg-name` takes precedence
        ''',
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with',
        default=os.environ.get('K8S_TARGET_NAMESPACE'),
    )
    parser.add_argument(
        '--extensions-cfg-path',
        help='path to the `extensions_cfg.yaml` file that should be used',
    )
    parser.add_argument(
        '--findings-cfg-path',
        help='path to the `findings.yaml` file that should be used',
    )
    parser.add_argument(
        '--invalid-semver-ok',
        action='store_true',
        default=os.environ.get('INVALID_SEMVER_OK') or False,
        help='whether to raise on invalid (semver) version when resolving greatest version',
    )
    parser.add_argument('--cache-dir', default=default_cache_dir)

    parsed_arguments = parser.parse_args()

    if not parsed_arguments.k8s_namespace:
        raise ValueError(
            'k8s namespace must be set, either via argument "k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


async def main():
    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace

    secret_factory = ctx_util.secret_factory()

    if k8s_cfg_name := parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(kubeconfig_path=parsed_arguments.kubeconfig)

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
            f'There must be exactly one delivery-db secret, found {len(delivery_db_secrets)}'
        )
    db_url = delivery_db_secrets[0].connection_url(
        namespace=namespace,
    )

    oci_client = lookups.semver_sanitising_oci_client_async(secret_factory)

    component_descriptor_lookup = lookups.init_component_descriptor_lookup_async(
        cache_dir=parsed_arguments.cache_dir,
        db_url=db_url,
        oci_client=oci_client,
    )

    version_lookup = lookups.init_version_lookup_async(
        oci_client=oci_client,
        default_absent_ok=True,
    )

    db_session = await deliverydb.sqlalchemy_session(db_url)
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
            version_lookup=version_lookup,
            oci_client=oci_client,
            finding_cfgs=finding_cfgs,
            invalid_semver_ok=parsed_arguments.invalid_semver_ok,
            db_session=db_session,
        )
    finally:
        await db_session.close()
        await oci_client.session.close()


if __name__ == '__main__':
    asyncio.run(main())
