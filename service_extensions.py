import collections.abc
import logging

import dacite
import falcon

import dso.model

import features
import k8s.backlog
import k8s.model
import k8s.util


def iter_container_statuses(
    service_filter: list[str],
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> collections.abc.Generator[k8s.model.ContainerStatus]:
    pods = kubernetes_api.core_kubernetes_api.list_namespaced_pod(
        namespace=namespace,
    )

    for pod in pods.items:
        service_label = k8s.util.normalise_pod_label(pod_label=pod.metadata.labels.get('app', ''))

        if service_label not in service_filter:
            continue

        for status in pod.status.container_statuses:
            yield k8s.model.ContainerStatus.from_v1_container_status(status)


class ContainerStatuses:
    required_features = (features.FeatureServiceExtensions,)

    def __init__(
        self,
        service_extensions_callback,
        namespace_callback,
        kubernetes_api_callback,
    ):
        self.service_extensions_callback = service_extensions_callback
        self.namespace_callback = namespace_callback
        self.kubernetes_api_callback = kubernetes_api_callback

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        service_filter = req.get_param_as_list(
            'service',
            required=False,
            default=self.service_extensions_callback(),
        )

        resp.media = tuple(iter_container_statuses(
            service_filter=service_filter,
            namespace=self.namespace_callback(),
            kubernetes_api=self.kubernetes_api_callback(),
        ))


def iter_log_collections(
    service_filter: list[str],
    log_level: int,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> collections.abc.Generator[dict, None, None]:
    log_collections = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.LogCollectionCrd.DOMAIN,
        version=k8s.model.LogCollectionCrd.VERSION,
        plural=k8s.model.LogCollectionCrd.PLURAL_NAME,
        namespace=namespace,
    )

    for log_collection in log_collections.get('items'):
        spec = log_collection.get('spec')

        if not (
            spec.get('service') in service_filter and
            logging._nameToLevel[spec.get('logLevel').upper()] == log_level
        ):
            continue

        yield log_collection


class LogCollections:
    required_features = (features.FeatureServiceExtensions,)

    def __init__(
        self,
        service_extensions_callback,
        namespace_callback,
        kubernetes_api_callback,
    ):
        self.service_extensions_callback = service_extensions_callback
        self.namespace_callback = namespace_callback
        self.kubernetes_api_callback = kubernetes_api_callback

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        service_filter = req.get_param_as_list(
            'service',
            required=False,
            default=self.service_extensions_callback(),
        )

        log_level = req.get_param(
            'log_level',
            required=True,
        )
        log_level = logging._nameToLevel[log_level.upper()]

        resp.media = tuple(iter_log_collections(
            service_filter=service_filter,
            log_level=log_level,
            namespace=self.namespace_callback(),
            kubernetes_api=self.kubernetes_api_callback(),
        ))


class ServiceExtensions:
    required_features = (features.FeatureServiceExtensions,)

    def __init__(
        self,
        service_extensions_callback,
    ):
        self.service_extensions_callback = service_extensions_callback

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        resp.media = self.service_extensions_callback()


class ScanConfigurations:
    required_features = (features.FeatureServiceExtensions,)

    def __init__(
        self,
        namespace_callback,
        kubernetes_api_callback,
    ):
        self.namespace_callback = namespace_callback
        self.kubernetes_api_callback = kubernetes_api_callback

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        resp.media = k8s.util.iter_scan_configurations(
            namespace=self.namespace_callback(),
            kubernetes_api=self.kubernetes_api_callback(),
        )


def iter_backlog_items(
    service: str,
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> collections.abc.Generator[dict, None, None]:
    labels = {
        k8s.model.LABEL_SERVICE: service,
        k8s.model.LABEL_CFG_NAME: cfg_name,
    }
    label_selector = k8s.util.create_label_selector(labels=labels)

    backlog_items = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.BacklogItemCrd.DOMAIN,
        version=k8s.model.BacklogItemCrd.VERSION,
        plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
        namespace=namespace,
        label_selector=label_selector,
    ).get('items')

    for backlog_item in backlog_items:
        yield {
            'metadata': {
                'name': backlog_item.get('metadata').get('name'),
                'uid': backlog_item.get('metadata').get('uid'),
                'labels': backlog_item.get('metadata').get('labels'),
                'annotations': backlog_item.get('metadata').get('annotations'),
                'creationTimestamp': backlog_item.get('metadata').get('creationTimestamp'),
            },
            'spec': backlog_item.get('spec'),
        }


class BacklogItems:
    required_features = (features.FeatureServiceExtensions,)

    def __init__(
        self,
        namespace_callback,
        kubernetes_api_callback,
    ):
        self.namespace_callback = namespace_callback
        self.kubernetes_api_callback = kubernetes_api_callback

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        service = req.get_param('service', required=True)
        cfg_name = req.get_param('cfg_name', required=True)

        resp.media = tuple(iter_backlog_items(
            service=service,
            cfg_name=cfg_name,
            namespace=self.namespace_callback(),
            kubernetes_api=self.kubernetes_api_callback(),
        ))

    def on_put(self, req: falcon.Request, resp: falcon.Response):
        '''
        update spec of backlog item with the specified name. If the backlog item does not
        exist (anymore), ignore it

        **expected query parameters:**

            - name (required) \n

        **expected body:**

            spec: <object> \n
              artefact: <object> \n
                component_name: <str> \n
                component_version: <str> \n
                artefact_kind: <str> \n
                artefact: <object> \n
                  artefact_name: <str> \n
                  artefact_version: <str> \n
                  artefact_type: <str> \n
                  artefact_extra_id: <object> \n
              priority: <int> \n
              timestamp: <str> \n
        '''
        name = req.get_param('name', required=True)

        backlog_item_raw = req.media.get('spec')
        backlog_item = k8s.backlog.BacklogItem.from_dict(backlog_item_raw)

        k8s.backlog.update_backlog_crd(
            name=name,
            namespace=self.namespace_callback(),
            kubernetes_api=self.kubernetes_api_callback(),
            backlog_item=backlog_item,
        )

        resp.status = falcon.HTTP_NO_CONTENT

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        '''
        create backlog items for the specified service (e.g. bdba) and the supplied artefacts

        **expected query parameters:**

            - service (required) \n
            - cfg_name (required) \n
            - priority (optional): one of {NONE, LOW, MEDIUM, HIGH, CRITICAL}, default CRITICAL \n

        **expected body:**

            artefacts: <array> of <object> \n
            - component_name: <str> \n
              component_version: <str> \n
              artefact_kind: <str> \n
              artefact: <object> \n
                artefact_name: <str> \n
                artefact_version: <str> \n
                artefact_type: <str> \n
                artefact_extra_id: <object> \n
        '''
        service = req.get_param('service', required=True)
        cfg_name = req.get_param('cfg_name', required=True)
        priority_str = req.get_param(
            name='priority',
            default=k8s.backlog.BacklogPriorities.CRITICAL.name,
        )
        priority = k8s.backlog.BacklogPriorities[priority_str.upper()]

        for artefact_raw in req.media.get('artefacts'):
            artefact = dacite.from_dict(
                data_class=dso.model.ComponentArtefactId,
                data=artefact_raw,
                config=dacite.Config(
                    cast=[dso.model.ArtefactKind],
                ),
            )

            k8s.backlog.create_backlog_item(
                service=service,
                cfg_name=cfg_name,
                namespace=self.namespace_callback(),
                kubernetes_api=self.kubernetes_api_callback(),
                artefact=artefact,
                priority=priority,
            )

        resp.status = falcon.HTTP_CREATED

    def on_delete(self, req: falcon.Request, resp: falcon.Response):
        names = req.get_param_as_list('name', required=True)

        for name in names:
            k8s.backlog.delete_backlog_crd(
                name=name,
                namespace=self.namespace_callback(),
                kubernetes_api=self.kubernetes_api_callback(),
            )

        resp.status = falcon.HTTP_NO_CONTENT
