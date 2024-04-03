import argparse
import datetime
import dateutil.parser
import logging
import math
import os
import pytz

import ci.log
import ci.util

import config
import ctx_util
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def on_backlog_change(
    name: str,
    type: str,
    metadata: dict,
    spec: dict,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
):
    if type == 'MODIFIED':
        return

    service = metadata.get('labels').get(k8s.model.LABEL_SERVICE)
    cfg_name = metadata.get('labels').get(k8s.model.LABEL_CFG_NAME)

    labels = {
        k8s.model.LABEL_SERVICE: service,
        k8s.model.LABEL_CFG_NAME: cfg_name,
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
    now = datetime.datetime.now(tz=pytz.UTC)
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
        elif claimed_at.tzinfo and now - claimed_at >= datetime.timedelta(minutes=30):
            logger.warning(
                f'the backlog item {crd_name} was claimed for more than 30 minutes by '
                f'pod {claimed_by}'
            )
            k8s.backlog.remove_claim(
                namespace=namespace,
                kubernetes_api=kubernetes_api,
                backlog_crd=backlog_crd,
            )

    if service == config.Services.ISSUE_REPLICATOR:
        # only allow up-scaling to 1 for issue replicator because of github's secondary rate limits
        max_replicas = 1
    else:
        max_replicas = int(os.environ.get('MAX_REPLICAS', 5))
    items_per_replica = int(os.environ.get('ITEMS_PER_REPLICA', 3))
    desired_replicas = min(math.ceil(len(backlog_crds) / items_per_replica), max_replicas)

    k8s.util.scale_replica_set(
        service=service,
        cfg_name=cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        desired_replicas=desired_replicas,
    )


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='specify kubernetes cluster to watch',
        default=os.environ.get('K8S_CFG_NAME'),
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to watch',
        default=os.environ.get('K8S_TARGET_NAMESPACE'),
    )

    parsed_arguments = parser.parse_args()

    if not parsed_arguments.k8s_namespace:
        raise ValueError(
            'k8s namespace must be set, either via argument "--k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


def main():
    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace

    cfg_factory = ctx_util.cfg_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = cfg_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api()

    k8s.logging.init_logging_thread(
        service=config.Services.BACKLOG_CONTROLLER,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    k8s.util.watch_crd_changes(
        crd=k8s.model.BacklogItemCrd,
        on_change=on_backlog_change,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )


if __name__ == '__main__':
    main()
