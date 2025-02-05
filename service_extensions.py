import collections.abc
import http
import logging

import aiohttp.web
import dacite

import dso.model

import consts
import features
import k8s.backlog
import k8s.model
import k8s.runtime_artefacts
import k8s.util
import util


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


class ContainerStatuses(aiohttp.web.View):
    required_features = (features.FeatureClusterAccess,)

    async def get(self):
        '''
        ---
        tags:
        - Service extensions
        produces:
        - application/json
        parameters:
        - in: query
          name: service
          type: string
          required: false
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                type: object
        '''
        params = self.request.rel_url.query

        scan_cfg = self.request.app[consts.APP_SCAN_CFG]

        service_filter = params.getall(
            key='service',
            default=list(scan_cfg.enabled_extensions(convert_to_camel_case=True)),
        )

        return aiohttp.web.json_response(
            data=tuple(iter_container_statuses(
                service_filter=service_filter,
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            )),
            dumps=util.dict_to_json_factory,
        )


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


class LogCollections(aiohttp.web.View):
    required_features = (features.FeatureClusterAccess,)

    async def get(self):
        '''
        ---
        tags:
        - Service extensions
        produces:
        - application/json
        parameters:
        - in: query
          name: service
          type: string
          required: false
        - in: query
          name: log_level
          type: string
          enum:
          - ERROR
          - WARNING
          - INFO
          - DEBUG
          required: true
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                type: object
        '''
        params = self.request.rel_url.query

        scan_cfg = self.request.app[consts.APP_SCAN_CFG]

        service_filter = params.getall(
            key='service',
            default=list(scan_cfg.enabled_extensions(convert_to_camel_case=True)),
        )

        log_level = util.param(params, 'log_level', required=True)
        log_level = logging._nameToLevel[log_level.upper()]

        return aiohttp.web.json_response(
            data=tuple(iter_log_collections(
                service_filter=service_filter,
                log_level=log_level,
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            )),
        )


class ServiceExtensions(aiohttp.web.View):
    required_features = (features.FeatureClusterAccess,)

    async def get(self):
        '''
        ---
        tags:
        - Service extensions
        produces:
        - application/json
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                type: string
        '''
        scan_cfg = self.request.app[consts.APP_SCAN_CFG]

        return aiohttp.web.json_response(
            data=list(scan_cfg.enabled_extensions(convert_to_camel_case=True)),
        )


class ScanConfigurations(aiohttp.web.View):
    required_features = (features.FeatureKubernetes,)

    async def get(self):
        '''
        ---
        tags:
        - Service extensions
        produces:
        - application/json
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                type: object
        '''
        return aiohttp.web.json_response(
            data=k8s.util.iter_scan_configurations(
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            ),
            dumps=util.dict_to_json_factory,
        )


def iter_backlog_items(
    service: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> collections.abc.Generator[dict, None, None]:
    labels = {
        k8s.model.LABEL_SERVICE: service,
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


class BacklogItems(aiohttp.web.View):
    required_features = (features.FeatureClusterAccess,)

    async def options(self):
        return aiohttp.web.Response()

    async def get(self):
        '''
        ---
        tags:
        - Service extensions
        produces:
        - application/json
        parameters:
        - in: query
          name: service
          type: string
          required: true
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                $ref: '#/definitions/BacklogItem'
        '''
        params = self.request.rel_url.query

        service = util.param(params, 'service', required=True)

        return aiohttp.web.json_response(
            data=tuple(iter_backlog_items(
                service=service,
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            )),
        )

    async def put(self):
        '''
        ---
        description:
          Update spec of backlog item with the specified name. If the backlog item does not exist
          (anymore), ignore it.
        tags:
        - Service extensions
        parameters:
        - in: query
          name: name
          type: string
          required: true
        - in: body
          name: body
          required: true
          schema:
            type: object
            required:
            - spec
            properties:
              spec:
                $ref: '#/definitions/BacklogItemSpec'
        responses:
          "204":
            description: Successful operation.
        '''
        params = self.request.rel_url.query

        name = util.param(params, 'name', required=True)

        backlog_item_raw = (await self.request.json()).get('spec')
        backlog_item = k8s.backlog.BacklogItem.from_dict(backlog_item_raw)

        k8s.backlog.update_backlog_crd(
            name=name,
            namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
            kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            backlog_item=backlog_item,
        )

        return aiohttp.web.Response(
            status=http.HTTPStatus.NO_CONTENT,
        )

    async def post(self):
        '''
        ---
        description:
          Create backlog items for the specified service (e.g. bdba) and the supplied artefacts.
        tags:
        - Service extensions
        parameters:
        - in: query
          name: service
          type: string
          required: true
        - in: query
          name: priority
          type: string
          enum:
          - NONE
          - LOW
          - MEDIUM
          - HIGH
          - CRITICAL
          required: false
          default: CRITICAL
        - in: body
          name: body
          required: true
          schema:
            type: object
            required:
            - artefacts
            properties:
              artefacts:
                type: array
                items:
                 $ref: '#/definitions/ComponentArtefactId'
        responses:
          "201":
            description: Successful operation.
        '''
        params = self.request.rel_url.query

        service = util.param(params, 'service', required=True)
        priority_str = util.param(
            params=params,
            name='priority',
            default=k8s.backlog.BacklogPriorities.CRITICAL.name,
        )
        priority = k8s.backlog.BacklogPriorities[priority_str.upper()]

        for artefact_raw in (await self.request.json()).get('artefacts'):
            artefact = dacite.from_dict(
                data_class=dso.model.ComponentArtefactId,
                data=artefact_raw,
                config=dacite.Config(
                    cast=[dso.model.ArtefactKind],
                ),
            )

            k8s.backlog.create_backlog_item(
                service=service,
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
                artefact=artefact,
                priority=priority,
            )

        return aiohttp.web.Response(
            status=http.HTTPStatus.CREATED,
        )

    async def delete(self):
        '''
        ---
        tags:
        - Service extensions
        parameters:
        - in: query
          name: name
          schema:
            type: array
            items:
              type: string
          required: true
        responses:
          "204":
            description: Successful operation.
        '''
        params = self.request.rel_url.query

        names = params.getall('name')

        for name in names:
            k8s.util.delete_custom_resource(
                crd=k8s.model.BacklogItemCrd,
                name=name,
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            )

        return aiohttp.web.Response(
            status=http.HTTPStatus.NO_CONTENT,
        )


def iter_runtime_artefacts(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    labels: dict[str, str]={},
) -> collections.abc.Generator[dict, None, None]:
    label_selector = k8s.util.create_label_selector(labels=labels)

    runtime_artefacts = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.RuntimeArtefactCrd.DOMAIN,
        version=k8s.model.RuntimeArtefactCrd.VERSION,
        plural=k8s.model.RuntimeArtefactCrd.PLURAL_NAME,
        namespace=namespace,
        label_selector=label_selector,
    ).get('items')

    for runtime_artefact in runtime_artefacts:
        yield {
            'metadata': {
                'name': runtime_artefact.get('metadata').get('name'),
                'uid': runtime_artefact.get('metadata').get('uid'),
                'labels': runtime_artefact.get('metadata').get('labels'),
                'annotations': runtime_artefact.get('metadata').get('annotations'),
                'creationTimestamp': runtime_artefact.get('metadata').get('creationTimestamp'),
            },
            'spec': runtime_artefact.get('spec'),
        }


class RuntimeArtefacts(aiohttp.web.View):
    required_features = (features.FeatureClusterAccess,)

    async def options(self):
        return aiohttp.web.Response()

    async def get(self):
        '''
        ---
        description:
          Retrieve existing runtime artefacts, optionally pre-filtered using the `label_selector`.
        tags:
        - Service extensions
        produces:
        - application/json
        parameters:
        - in: query
          name: label
          schema:
            type: array
            items:
              type: string
          required: false
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                $ref: '#/definitions/RuntimeArtefact'
        '''
        params = self.request.rel_url.query

        labels_raw = params.getall('label', default=[])
        labels = dict([
            label_raw.split(':') for label_raw in labels_raw
        ])

        return aiohttp.web.json_response(
            data=tuple(iter_runtime_artefacts(
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
                labels=labels,
            )),
        )

    async def put(self):
        '''
        ---
        description: Create a runtime artefact with the specified spec.
        tags:
        - Service extensions
        parameters:
        - in: query
          name: label
          schema:
            type: array
            items:
              type: string
          required: false
        - in: body
          name: body
          required: true
          schema:
            type: object
            required:
            - artefacts
            properties:
              artefacts:
                type: array
                items:
                  $ref: '#/definitions/ComponentArtefactId'
        responses:
          "201":
            description: Successful operation.
        '''
        params = self.request.rel_url.query

        labels_raw = params.getall('label', default=[])
        labels = dict([
            label_raw.split(':') for label_raw in labels_raw
        ])

        for runtime_artefact_raw in (await self.request.json()).get('artefacts'):
            runtime_artefact = dacite.from_dict(
                data_class=dso.model.ComponentArtefactId,
                data=runtime_artefact_raw,
                config=dacite.Config(
                    cast=[dso.model.ArtefactKind],
                ),
            )

            k8s.runtime_artefacts.create_unique_runtime_artefact(
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
                artefact=runtime_artefact,
                labels=labels,
            )

        return aiohttp.web.Response(
            status=http.HTTPStatus.CREATED,
        )

    async def delete(self):
        '''
        ---
        description: Delete one or more runtime artefacts by their kubernetes resource `name`.
        tags:
        - Service extensions
        parameters:
        - in: query
          name: name
          schema:
            type: array
            items:
              type: string
          required: true
        responses:
          "204":
            description: Successful operation.
        '''
        params = self.request.rel_url.query

        names = params.getall('name')

        for name in names:
            k8s.util.delete_custom_resource(
                crd=k8s.model.RuntimeArtefactCrd,
                name=name,
                namespace=self.request.app[consts.APP_NAMESPACE_CALLBACK](),
                kubernetes_api=self.request.app[consts.APP_KUBERNETES_API_CALLBACK](),
            )

        return aiohttp.web.Response(
            status=http.HTTPStatus.NO_CONTENT,
        )
