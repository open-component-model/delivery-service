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
import datetime
import logging
import os
import sys

import sqlalchemy
import sqlalchemy.ext.asyncio as sqlasync
import sqlalchemy.sql.elements

import ci.log

import config
import ctx_util
import deliverydb
import deliverydb.model as dm
import k8s.logging
import k8s.model
import k8s.util


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


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

    cfg_factory = ctx_util.cfg_factory()

    if k8s_cfg_name := parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = cfg_factory.kubernetes(k8s_cfg_name)
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

    db_url = cfg_factory.delivery_db(cache_manager_cfg.delivery_db_cfg_name).as_url()

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

    finally:
        await db_session.close()


if __name__ == '__main__':
    asyncio.run(main())
