import http
import json
import logging
import textwrap
import threading
import time
import traceback

import kubernetes.client.rest

import k8s.model
import k8s.util
import odg.extensions_cfg


logger = logging.getLogger(__name__)

supported_log_levels = {logging.INFO, logging.WARNING, logging.ERROR}


def log_filename_for_level(level: int) -> str:
    return f'logs-{logging._levelToName[level].lower()}.log'


def read_logs_and_remove(level: int) -> list[dict]:
    log_filename = log_filename_for_level(level=level)
    try:
        with open(log_filename, 'r+') as file:
            logs = json.loads(f'[{file.read().rstrip().removesuffix(",")}]')
            file.truncate(0)
    except json.decoder.JSONDecodeError as jde:
        logger.warning(f'caugt error while reading logs: {jde}')
        logs = []
    except FileNotFoundError:
        # no new logs for specified log level found
        logs = []
    return logs


def write_logs_to_file(
    logs: list[dict],
    level: int,
):
    log_filename = log_filename_for_level(level=level)
    with open(log_filename, 'r+') as file:
        content = file.read()
        file.seek(0, 0)
        file.write(',\n'.join([json.dumps(log) for log in logs]) + ',\n' + content)


def trim_logs_to_fit_max_storage_size(
    logs: list[dict],
    max_storage_size_bytes: int=750000,
) -> list[dict]:
    while len(json.dumps(logs).encode('utf-8')) > max_storage_size_bytes:
        logs = logs[1:]
    return logs


def handle_conflict(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    name: str,
    log_level: int,
    logs_to_keep: list[dict]=[],
    max_retries: int=3,
    retry_count: int=0,
):
    if log_level <= logging.DEBUG:
        # drop logs in case of a conflict
        logger.debug(f'dropped {len(logs_to_keep)} logs because of a conflict while writing to crd')
        return

    if retry_count >= max_retries:
        logger.info(
            f'failed to write {len(logs_to_keep)} logs to crd, write to local file again...'
        )
        write_logs_to_file(
            logs=logs_to_keep,
            level=log_level,
        )
        return

    retry_interval = (retry_count + 1) * 10
    logger.info(
        f'trying to write logs to log collection {name} resulted in a conflict, '
        f'will try to rewrite logs again in {retry_interval} sec...'
    )
    time.sleep(retry_interval)
    return log_to_crd_for_level(
        service=service,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        log_level=log_level,
        logs_to_keep=logs_to_keep,
        max_retries=max_retries,
        retry_count=retry_count + 1,
    )


def create_log_collection(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    name: str,
    log_level: int,
    logs: list[dict],
    max_retries: int=3,
    retry_count: int=0,
):
    body = {
        'apiVersion': k8s.model.LogCollectionCrd.api_version(),
        'kind': k8s.model.LogCollectionCrd.KIND,
        'metadata': {
            'name': name,
            'namespace': namespace,
        },
        'spec': {
            'service': service.value,
            'logLevel': logging._levelToName[log_level],
            'logs': logs,
        },
    }

    try:
        kubernetes_api.custom_kubernetes_api.create_namespaced_custom_object(
            group=k8s.model.LogCollectionCrd.DOMAIN,
            version=k8s.model.LogCollectionCrd.VERSION,
            plural=k8s.model.LogCollectionCrd.PLURAL_NAME,
            namespace=namespace,
            body=body,
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status != http.HTTPStatus.CONFLICT:
            raise e

        # if there is a conflict, crd was just created (by another thread), so
        # retry again but with replacing crd instead of creating it
        return handle_conflict(
            service=service,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            name=name,
            log_level=log_level,
            logs_to_keep=logs,
            max_retries=max_retries,
            retry_count=retry_count,
        )


def log_to_crd_for_level(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    log_level: int,
    logs_to_keep: list[dict]=[],
    max_retries: int=3,
    retry_count: int=0,
):
    name = k8s.util.generate_kubernetes_name(
        name_parts=('logs', service, logging._levelToName[log_level]),
        generate_num_suffix=False,
    )

    logs = logs_to_keep + read_logs_and_remove(level=log_level)
    logs = trim_logs_to_fit_max_storage_size(logs=logs)

    try:
        log_collection = kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
            group=k8s.model.LogCollectionCrd.DOMAIN,
            version=k8s.model.LogCollectionCrd.VERSION,
            plural=k8s.model.LogCollectionCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status == http.HTTPStatus.NOT_FOUND:
            return create_log_collection(
                service=service,
                namespace=namespace,
                kubernetes_api=kubernetes_api,
                name=name,
                logs=logs,
                log_level=log_level,
                max_retries=max_retries,
                retry_count=retry_count,
            )
        raise e

    if not logs:
        # no need to update logs for this log level
        return

    spec = log_collection.get('spec')
    old_logs = spec.get('logs')
    spec['logs'] = trim_logs_to_fit_max_storage_size(logs=old_logs + logs)

    body = {
        'apiVersion': k8s.model.LogCollectionCrd.api_version(),
        'kind': k8s.model.LogCollectionCrd.KIND,
        'metadata': log_collection.get('metadata'),
        'spec': spec,
    }

    try:
        # use "replace" instead of "patch" here to allow running in a conflict
        # -> "patch" silently ignores conflicts and overrides the resource anyways
        kubernetes_api.custom_kubernetes_api.replace_namespaced_custom_object(
            group=k8s.model.LogCollectionCrd.DOMAIN,
            version=k8s.model.LogCollectionCrd.VERSION,
            plural=k8s.model.LogCollectionCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
            body=body,
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status != http.HTTPStatus.CONFLICT:
            raise e

        return handle_conflict(
            service=service,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            name=name,
            log_level=log_level,
            logs_to_keep=spec['logs'],
            max_retries=max_retries,
            retry_count=retry_count,
        )


def log_to_crd(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
):
    for log_level in supported_log_levels:
        log_to_crd_for_level(
            service=service,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            log_level=log_level,
        )


def continuously_log_to_crd(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    loop_interval: int=120,
    retry_interval: int=60,
):
    while True:
        try:
            log_to_crd(
                service=service,
                namespace=namespace,
                kubernetes_api=kubernetes_api,
            )
            time.sleep(loop_interval)
        except Exception:
            logger.warning(traceback.format_exc())
            logger.warning(f'caught error while looping func, will retry after {retry_interval}s')
            time.sleep(retry_interval)


def init_logging_thread(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
):
    thread = threading.Thread(
        target=continuously_log_to_crd,
        args=(
            service,
            namespace,
            kubernetes_api,
        ),
        daemon=True,
    )
    thread.name = 'logging'
    thread.start()


class JSONFormatter(logging.Formatter):
    def formatMessage(self, record) -> str:
        record.message = json.dumps(record.message)
        if (size := len(record.message.encode('utf-8'))) > 10000:
            record.message = f'"Request entity body is too large: {size} bytes"'
        return super().formatMessage(record)


def configure_kubernetes_logging():
    def add_file_handler(
        level: int,
        formatter: logging.Formatter=None,
    ) -> logging.FileHandler:
        file_handler = logging.FileHandler(
            filename=log_filename_for_level(level),
            mode='a',
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        logging.root.addHandler(hdlr=file_handler)

    log_formatter = JSONFormatter(
        fmt=textwrap.dedent('''\
        {
            "timestamp": "%(asctime)s.%(msecs)dZ",
            "name": "%(name)s",
            "logLevel": "%(levelname)s",
            "thread": "%(threadName)s",
            "message": %(message)s
        },'''),
        datefmt='%Y-%m-%dT%H:%M:%S',
    )

    for h in logging.root.handlers:
        if isinstance(h, logging.FileHandler):
            logging.root.removeHandler(h)
            h.close()

    for log_level in supported_log_levels:
        add_file_handler(level=log_level, formatter=log_formatter)

    logging.root.setLevel(level=logging.DEBUG)
