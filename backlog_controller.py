import datetime
import http
import logging
import math

import dateutil.parser
import kubernetes.client.rest
import urllib3.exceptions

import ci.log

import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import odg.extensions_cfg
import odg.util
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def on_backlog_change(
    backlog_controller_cfg: odg.extensions_cfg.BacklogControllerConfig,
    metadata: dict,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
):
    service = metadata.get('labels').get(k8s.model.LABEL_SERVICE)

    labels = {
        k8s.model.LABEL_SERVICE: service,
    }
    label_selector = k8s.util.create_label_selector(labels=labels)

    backlog_crds = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.BacklogItemCrd.DOMAIN,
        version=k8s.model.BacklogItemCrd.VERSION,
        plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
        namespace=namespace,
        label_selector=label_selector,
    ).get('items')

    running_pod_names = []
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    for backlog_crd in backlog_crds:
        crd_name = backlog_crd.get('metadata').get('name')
        labels = backlog_crd.get('metadata').get('labels')
        annotations = backlog_crd.get('metadata').get('annotations')

        label_claimed = labels.get(k8s.backlog.LABEL_CLAIMED)
        if not (label_claimed and k8s.util.label_is_true(label=label_claimed)):
            continue

        claimed_by = annotations.get(k8s.backlog.ANNOTATION_CLAIMED_BY)
        claimed_at = dateutil.parser.parse(annotations.get(k8s.backlog.ANNOTATION_CLAIMED_AT))

        if not running_pod_names:
            running_pod_names = [
                pod.metadata.name
                for pod in kubernetes_api.core_kubernetes_api.list_namespaced_pod(
                    namespace=namespace,
                    label_selector=label_selector,
                ).items
            ]

        if claimed_by and claimed_by not in running_pod_names:
            logger.warning(
                f'the pod {claimed_by} which claimed the backlog item {crd_name} '
                'is not available anymore'
            )
            k8s.backlog.remove_claim(
                namespace=namespace,
                kubernetes_api=kubernetes_api,
                backlog_crd=backlog_crd,
            )
        elif claimed_at.tzinfo and now - claimed_at >= datetime.timedelta(
            minutes=backlog_controller_cfg.remove_claim_after_minutes,
        ):
            logger.warning(
                f'the backlog item {crd_name} was claimed for more than '
                f'{backlog_controller_cfg.remove_claim_after_minutes} minutes by pod {claimed_by}'
            )
            k8s.backlog.remove_claim(
                namespace=namespace,
                kubernetes_api=kubernetes_api,
                backlog_crd=backlog_crd,
            )

    if service == odg.extensions_cfg.Services.ISSUE_REPLICATOR:
        # only allow up-scaling to 1 for issue replicator because of github's secondary rate limits
        max_replicas = 1
    else:
        max_replicas = backlog_controller_cfg.max_replicas

    items_per_replica = backlog_controller_cfg.backlog_items_per_replica
    desired_replicas = min(math.ceil(len(backlog_crds) / items_per_replica), max_replicas)

    k8s.util.scale_replicas(
        service=service,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        desired_replicas=desired_replicas,
    )


def main():
    parsed_arguments = odg.util.parse_args(
        arguments=(
            odg.util.Arguments.K8S_CFG_NAME,
            odg.util.Arguments.KUBECONFIG,
            odg.util.Arguments.K8S_NAMESPACE,
            odg.util.Arguments.EXTENSIONS_CFG_PATH,
        ),
    )
    kubernetes_api = odg.util.kubernetes_api(parsed_arguments)
    namespace = parsed_arguments.k8s_namespace

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.BACKLOG_CONTROLLER,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    backlog_controller_cfg = extensions_cfg.backlog_controller

    resource_version = ''

    while True:
        try:
            for event in kubernetes.watch.Watch().stream(
                kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object,
                group=k8s.model.BacklogItemCrd.DOMAIN,
                version=k8s.model.BacklogItemCrd.VERSION,
                namespace=namespace,
                plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
                resource_version=resource_version,
                timeout_seconds=0,
            ):
                if (type := str(event['type'])) == 'MODIFIED':
                    continue

                metadata = event['object'].get('metadata')
                resource_version = metadata['resourceVersion']
                name = metadata['name']

                logger.debug(f'identified modification {type=} of backlog item {name}')

                on_backlog_change(
                    backlog_controller_cfg=backlog_controller_cfg,
                    metadata=metadata,
                    namespace=namespace,
                    kubernetes_api=kubernetes_api,
                )
        except kubernetes.client.rest.ApiException as e:
            if e.status == http.HTTPStatus.GONE:
                resource_version = ''
                logger.info('API resource watching expired, will start new watch')
            else:
                raise e
        except urllib3.exceptions.ProtocolError:
            # this is a known error which has no impact on the functionality, thus rather be
            # degregated to a warning or even info
            # [ref](https://github.com/kiwigrid/k8s-sidecar/issues/233#issuecomment-1332358459)
            resource_version = ''
            logger.info('API resource watching received protocol error, will start new watch')
        except urllib3.exceptions.MaxRetryError as e:
            if not isinstance(e.reason, urllib3.exceptions.ProtocolError):
                raise
            resource_version = ''
            logger.info('API resource watching received protocol error, will start new watch')


if __name__ == '__main__':
    main()
