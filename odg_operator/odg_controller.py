import argparse
import base64
import collections.abc
import enum
import http
import logging
import os

import dacite
import kubernetes.client
import kubernetes.client.exceptions
import kubernetes.client.rest
import kubernetes.watch
import urllib3
import yaml

import ci.log
import cnudie.iter
import oci.client
import ocm

import k8s.util
import lookups
import odg_operator.odg_model as odgm


ci.log.configure_default_logging()
logger = logging.getLogger(__name__)
own_dir = os.path.abspath(os.path.dirname(__file__))
CUSTOMER_CLEANUP_FINALIZER = 'open-delivery-gear.ocm.software/customer-cluster-cleanup'
ODG_COMPONENT_NAME = 'ocm.software/ocm-gear'


def delivery_dashboard_url(
    base_url: str,
) -> str:
    return f'odg-dashboard.{base_url}'


def delivery_service_url(
    base_url: str,
) -> str:
    return f'odg-service.{base_url}'


def default_extensions(
    base_url: str,
    delivery_db_password: str,
) -> list[odgm.Extension]:
    return [
        odgm.DeliveryService(
            type=odgm.ExtensionTypes.DELIVERY_SERVICE,
            base_url=base_url,
            hostnames=[delivery_service_url(base_url)],
        ),
        odgm.DeliveryDB(
            type=odgm.ExtensionTypes.DELIVERY_DB,
            base_url=base_url,
            postgres_password=delivery_db_password,
            helm_values_path='postgresql',
            ocm_node_name='postgresql',
        ),
        odgm.Extension(
            type=odgm.ExtensionTypes.ARTEFACT_ENUMERATOR,
            base_url=base_url,
            helm_values_path='extensions',
            ocm_node_name='extensions',
        ),
        odgm.Extension(
            type=odgm.ExtensionTypes.BACKLOG_CONTROLLER,
            base_url=base_url,
            helm_values_path='extensions',
            ocm_node_name='extensions',
        ),
        odgm.NginxIngress(
            type=odgm.ExtensionTypes.INGRESS_NGINX,
            base_url=base_url,
        ),
    ]


def helm_chart_for_extension(
    odg_version: str,
    extension: odgm.Extension,
) -> str:
    if extension.type == odgm.ExtensionTypes.INGRESS_NGINX:
        # remove once ingress references are part of ocm
        return 'europe-docker.pkg.dev/gardener-project/releases/charts/ocm-gear/ingress-nginx/ingress-nginx@sha256:f8296fc031beb8023b51e62c982a6c1c2f15e8584e4e70c36daf0885da830d2f' # noqa: E501

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir='./cache/ocm',
        oci_client=oci.client.Client(
            credentials_lookup=lambda **kwargs: None, # consume public oci-images only
        ),
    )
    odg_component = component_descriptor_lookup(f'{ODG_COMPONENT_NAME}:{odg_version}').component

    for resource_node in cnudie.iter.iter(
        component=odg_component,
        lookup=component_descriptor_lookup,
        node_filter=cnudie.iter.Filter.resources,
    ):
        resource_node: cnudie.iter.ResourceNode
        if resource_node.resource.type != ocm.ArtefactType.HELM_CHART:
            continue

        if resource_node.resource.name != extension.ocm_node_name:
            continue

        break

    else:
        logger.error(f'no helm chart found for {extension.type}')

    return resource_node.resource.access.imageReference


def create_or_update_extension_manifest(
    odg: odgm.ODG,
    kubernetes_api: k8s.util.KubernetesApi,
    extension: odgm.Extension,
):
    extension_secret = {
        'apiVersion': odgm.ODGExtensionMeta.apiVersion(),
        'kind': odgm.ODGExtensionMeta.kind,
        'metadata': {
            'name': str(extension.type),
            'namespace': odg.origin_namespace,
        },
        'spec': {
            'type': str(extension.type),
            'namespace': odg.target_namespace,
            'base_url': extension.base_url,
            'helm_chart_ref': helm_chart_for_extension(
                odg_version=odg.component_version,
                extension=extension,
            ),
            'helm_values': extension.helm_values(odg.target_namespace),
            'helm_values_path': extension.helm_values_path,
        }
    }

    secret_data = {
        'data.yaml': base64.b64encode(
            yaml.dump(extension_secret).encode()
        ).decode(),
    }
    secret_metadata = kubernetes.client.V1ObjectMeta(
        name=extension.type,
        namespace=odg.origin_namespace,
        finalizers=[CUSTOMER_CLEANUP_FINALIZER]
    )
    secret_body = kubernetes.client.V1Secret(
        api_version='v1',
        kind='Secret',
        metadata=secret_metadata,
        data=secret_data,
    )

    try:
        kubernetes_api.core_kubernetes_api.create_namespaced_secret(
            namespace=odg.origin_namespace,
            body=secret_body,
        )
        logger.debug(f'{extension.type} manifest created')
    except kubernetes.client.rest.ApiException as e:
        if e.status == 409:
            # secret already exists, update instead
            kubernetes_api.core_kubernetes_api.patch_namespaced_secret(
                name=extension.type,
                namespace=odg.origin_namespace,
                body=secret_body,
            )
            logger.debug(f'{extension.type} manifest updated')
        else:
            raise


def iter_extensions(
    extension_cfgs: list[dict],
    base_url: str,
) -> collections.abc.Generator[odgm.Extension, None, None]:
    for extension_cfg in extension_cfgs:
        extension_type = extension_cfg['type']

        if extension_type in (
            odgm.ExtensionTypes.ARTEFACT_ENUMERATOR,
            odgm.ExtensionTypes.BACKLOG_CONTROLLER,
            odgm.ExtensionTypes.DELIVERY_DB,
            odgm.ExtensionTypes.DELIVERY_SERVICE,
            odgm.ExtensionTypes.INGRESS_NGINX,
        ):
            logger.warning(f'skipping {extension_type=} as it is deployed by default') # noqa: E501

        elif extension_type in (
            odgm.ExtensionTypes.BDBA,
            odgm.ExtensionTypes.CRYPTO,
            odgm.ExtensionTypes.SAST,
            odgm.ExtensionTypes.MALWARE_SCANNER,
        ):
            yield odgm.Extension(
                type=odgm.ExtensionTypes(extension_type),
                base_url=base_url,
                helm_values_path='extensions',
                ocm_node_name='extensions',
            )

        elif extension_type == odgm.ExtensionTypes.DELIVERY_DASHBOARD:
            yield odgm.DeliveryDashboard(
                type=odgm.ExtensionTypes.DELIVERY_DASHBOARD,
                base_url=base_url,
                hostnames=[delivery_dashboard_url(base_url)],
                delivery_service_url=delivery_service_url(base_url),
            )

        else:
            logger.error(f'{extension_type=} not supported')


def create_managed_resource_if_absent(
    kubernetes_api: k8s.util.KubernetesApi,
    extension: odgm.Extension,
    namespace: str,
    managed_resource_class: str,
):
    try:
        kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
            group=odgm.ManagedResourceMeta.group,
            version=odgm.ManagedResourceMeta.version,
            plural=odgm.ManagedResourceMeta.plural,
            namespace=namespace,
            name=extension.type,
        )
    except kubernetes.client.exceptions.ApiException as e:
        if e.status != http.HTTPStatus.NOT_FOUND:
            raise

        kubernetes_api.custom_kubernetes_api.create_namespaced_custom_object(
            group=odgm.ManagedResourceMeta.group,
            version=odgm.ManagedResourceMeta.version,
            plural=odgm.ManagedResourceMeta.plural,
            namespace=namespace,
            body={
                'apiVersion': odgm.ManagedResourceMeta.apiVersion(),
                'kind': odgm.ManagedResourceMeta.kind,
                'metadata': {
                    'name': extension.type,
                    'namespace': namespace,
                    'finalizers': [CUSTOMER_CLEANUP_FINALIZER],
                },
                'spec': {
                    'class': managed_resource_class,
                    'keepObjects': False,
                    'secretRefs': [
                        {
                            'name': extension.type,
                        }
                    ],
                }
            },
        )
        logger.debug(f'{extension.type} managed-resource created')


def reconcile(
    kubeconfig_path: str=None,
):
    kubernetes_api = k8s.util.kubernetes_api(kubeconfig_path=kubeconfig_path)
    resource_version = ''

    while True:
        group = odgm.ODGExtensionMeta.group
        plural = odgm.ODGMeta.plural
        logger.info(f'watching for events: {group=} {plural=}')
        try:
            for event in kubernetes.watch.Watch().stream(
                kubernetes_api.custom_kubernetes_api.list_cluster_custom_object,
                group=group,
                version='v1',
                plural=plural,
                resource_version=resource_version,
                timeout_seconds=0,
            ):
                metadata = event['object'].get('metadata')
                odg_name = metadata['name']
                logger.info(f'{event["type"]} "{odg_name}" in "{metadata["namespace"]}"')

                resource_version = metadata['resourceVersion']
                base_url = event['object']['spec']['base_url']

                # TODO: let postgres generate random password on deployment and update consumers
                # to read password from secret -> rm delivery-db password from ODG spec
                delivery_db_password = event['object']['spec']['delivery_db_password']

                odg = dacite.from_dict(
                    data_class=odgm.ODG,
                    data={
                        'name': odg_name,
                        'target_namespace': event['object']['spec']['namespace'],
                        'origin_namespace': metadata['namespace'],
                        'extensions': list(iter_extensions(
                            extension_cfgs=event['object']['spec']['extensions']),
                            base_url=base_url,
                        ) + default_extensions(
                            base_url=base_url,
                            delivery_db_password=delivery_db_password,
                        ),
                        'component_version': event['object']['spec']['version'],
                    },
                    config=dacite.Config(cast=[enum.Enum])
                )

                if event['type'] in ('ADDED', 'MODIFIED'):
                    if (
                        event['type'] == 'MODIFIED'
                        and metadata.get('deletionTimestamp')
                    ):
                        for extension in odg.extensions:
                            kubernetes_api.custom_kubernetes_api.delete_namespaced_custom_object(
                                group=odgm.ManagedResourceMeta.group,
                                version=odgm.ManagedResourceMeta.version,
                                plural=odgm.ManagedResourceMeta.plural,
                                namespace=odg.origin_namespace,
                                name=extension.type,
                            )
                            kubernetes_api.core_kubernetes_api.delete_namespaced_secret(
                                namespace=odg.origin_namespace,
                                name=extension.type,
                            )

                        kubernetes_api.custom_kubernetes_api.patch_namespaced_custom_object(
                            group=odgm.ODGMeta.group,
                            version=odgm.ODGMeta.version,
                            plural=odgm.ODGMeta.plural,
                            namespace=odg.origin_namespace,
                            name=odg.name,
                            body={
                                'metadata': {
                                    # remove our finalizer
                                    'finalizers': [
                                        finalizer
                                        for finalizer in metadata.get('finalizers', [])
                                        if finalizer != CUSTOMER_CLEANUP_FINALIZER
                                    ],
                                }
                            },
                        )

                    else:
                        for extension in odg.extensions:
                            create_or_update_extension_manifest(
                                kubernetes_api=kubernetes_api,
                                odg=odg,
                                extension=extension,
                            )
                            create_managed_resource_if_absent(
                                kubernetes_api=kubernetes_api,
                                extension=extension,
                                namespace=odg.origin_namespace,
                                managed_resource_class=odgm.ManagedResourceClasses.INTERNAL,
                            )

                elif event['type'] == 'DELETED':
                    logger.debug(f'{extension.type} deleted')

                else:
                    logger.warning(f'{event["type"]} not supported')

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--kubeconfig')
    parsed = parser.parse_args()

    reconcile(
        kubeconfig_path=parsed.kubeconfig,
    )
