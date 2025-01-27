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
import sys

import sqlalchemy
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.sql.elements

import ci.log
import ci.util
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
import eol
import k8s.logging
import k8s.model
import k8s.util
import lookups
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


def deserialise_cache_manager_cfg(
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> config.CacheManagerConfig:
    scan_cfg_crd = kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
        group=k8s.model.ScanConfigurationCrd.DOMAIN,
        version=k8s.model.ScanConfigurationCrd.VERSION,
        plural=k8s.model.ScanConfigurationCrd.PLURAL_NAME,
        namespace=namespace,
        name=cfg_name,
    )
    spec = scan_cfg_crd.get('spec', dict())

    cache_manager_cfg = config.deserialise_cache_manager_config(spec_config=spec)

    if not cache_manager_cfg:
        logger.warning(
            f'no cache manager configuration for config elem {cfg_name} set, '
            'job is not able to process and will terminate'
        )
        sys.exit(1)

    return cache_manager_cfg


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
    cfg: config.CacheManagerConfig,
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
    eol_client: eol.EolClient,
    finding_types: collections.abc.Sequence[str],
    artefact_metadata_cfg_by_type: dict[str, compliance_summary.ArtefactMetadataCfg],
    db_session: sqlasync.session.AsyncSession,
):
    logger.info(f'Updating compliance summary for {component_id.name}:{component_id.version}')

    for finding_type in finding_types:
        await compliance_summary.component_datatype_summaries(
            component=component_id,
            finding_type=finding_type,
            datasource=dso.model.Datatype.datatype_to_datasource(finding_type),
            db_session=db_session,
            component_descriptor_lookup=component_descriptor_lookup,
            eol_client=eol_client,
            artefact_metadata_cfg=artefact_metadata_cfg_by_type.get(finding_type),
        )


async def prefill_compliance_summary_caches(
    components: collections.abc.Iterable[config.Component],
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent,
    oci_client: oci.client_async.Client,
    eol_client: eol.EolClient,
    finding_types: collections.abc.Sequence[str],
    artefact_metadata_cfg_by_type: dict[str, compliance_summary.ArtefactMetadataCfg],
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
                    eol_client=eol_client,
                    finding_types=finding_types,
                    artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
                    db_session=db_session,
                )


async def prefill_component_versions_caches(
    components: collections.abc.Iterable[config.Component],
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
    function_names: collections.abc.Iterable[config.FunctionNames],
    components: collections.abc.Iterable[config.Component],
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    version_lookup: cnudie.retrieve_async.VersionLookupByComponent,
    oci_client: oci.client_async.Client,
    eol_client: eol.EolClient,
    finding_types: collections.abc.Sequence[str],
    artefact_metadata_cfg_by_type: dict[str, compliance_summary.ArtefactMetadataCfg],
    invalid_semver_ok: bool,
    db_session: sqlasync.session.AsyncSession,
):
    for function_name in function_names:
        logger.info(f'Prefilling cache for {function_name=} and {components=}')

        match function_name:
            case config.FunctionNames.COMPLIANCE_SUMMARY:
                await prefill_compliance_summary_caches(
                    components=components,
                    component_descriptor_lookup=component_descriptor_lookup,
                    version_lookup=version_lookup,
                    oci_client=oci_client,
                    eol_client=eol_client,
                    finding_types=finding_types,
                    artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
                    invalid_semver_ok=invalid_semver_ok,
                    db_session=db_session,
                )

            case config.FunctionNames.COMPONENT_VERSIONS:
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
        '--cfg-name',
        help='specify the context the process should run in',
        default=os.environ.get('CFG_NAME'),
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

    if not parsed_arguments.cfg_name:
        raise ValueError(
            'name of the to-be-used scan configuration must be set, either via '
            'argument "--cfg-name" or via environment variable "CFG_NAME"'
        )

    return parsed_arguments


async def main():
    parsed_arguments = parse_args()
    cfg_name = parsed_arguments.cfg_name
    namespace = parsed_arguments.k8s_namespace

    secret_factory = ctx_util.secret_factory()

    if k8s_cfg_name := parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(kubeconfig_path=parsed_arguments.kubeconfig)

    k8s.logging.init_logging_thread(
        service=config.Services.CACHE_MANAGER,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=config.Services.CACHE_MANAGER,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    cache_manager_cfg = deserialise_cache_manager_cfg(
        cfg_name=cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    db_url = secret_factory.delivery_db(cache_manager_cfg.delivery_db_cfg_name).url

    oci_client = lookups.semver_sanitising_oci_client_async(secret_factory)
    eol_client = eol.EolClient()

    component_descriptor_lookup = lookups.init_component_descriptor_lookup_async(
        cache_dir=parsed_arguments.cache_dir,
        db_url=db_url,
        oci_client=oci_client,
    )

    version_lookup = lookups.init_version_lookup_async(
        oci_client=oci_client,
        default_absent_ok=True,
    )

    finding_types = (
        dso.model.Datatype.LICENSE,
        dso.model.Datatype.VULNERABILITY,
        dso.model.Datatype.OS_IDS,
        dso.model.Datatype.CODECHECKS_AGGREGATED,
        dso.model.Datatype.MALWARE_FINDING,
    )

    artefact_metadata_cfg_by_type = compliance_summary.artefact_metadata_cfg_by_type(
        artefact_metadata_cfg=ci.util.parse_yaml_file(paths.artefact_metadata_cfg),
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
            function_names=cache_manager_cfg.prefill_function_caches.function_names,
            components=cache_manager_cfg.prefill_function_caches.components,
            component_descriptor_lookup=component_descriptor_lookup,
            version_lookup=version_lookup,
            oci_client=oci_client,
            eol_client=eol_client,
            finding_types=finding_types,
            artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
            invalid_semver_ok=parsed_arguments.invalid_semver_ok,
            db_session=db_session,
        )
    finally:
        await db_session.close()
        await oci_client.session.close()
        await eol_client.session.close()


if __name__ == '__main__':
    asyncio.run(main())
