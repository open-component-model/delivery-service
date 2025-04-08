import argparse
import base64
import collections
import collections.abc
import dataclasses
import http
import logging
import os
import requests
import subprocess
import tarfile
import tempfile

import dacite
import kubernetes.client
import kubernetes.client.rest
import kubernetes.watch
import urllib3
import yaml

import ci.log
import cnudie.iter
import oci.client
import oci.model
import ocm

import k8s.util
import lookups
import ocm_util
import odg_operator.odg_model as odgm
import odg_operator.odg_util as odgu
import util


ci.log.configure_default_logging()
logger = logging.getLogger(__name__)

ODG_CLEAN_UP_FINALISER = 'open-delivery-gear.ocm.software/odg-clean-up'
ODG_NAME_LABEL = 'open-delivery-gear.ocm.software/odg-name'
ODG_COMPONENT_NAME = 'ocm.software/ocm-gear'
HELM_CHART_MEDIA_TYPE = 'application/vnd.cncf.helm.chart.content.v1.tar+gzip'
ODG_EXTENSION_ARTEFACT_TYPE = 'odg-extension'


def find_extension_definition(
    extension_definitions: list[odgm.ExtensionDefinition],
    extension_name: str,
    absent_ok: bool=False,
) -> odgm.ExtensionDefinition | None:
    for extension_definition in extension_definitions:
        if extension_definition.name == extension_name:
            return extension_definition

    if absent_ok:
        return None

    raise ValueError(f'unknown extension-definition for {extension_name=}')


def iter_missing_dependencies(
    requested: collections.abc.Container[odgm.ExtensionDefinition],
    known: collections.abc.Container[odgm.ExtensionDefinition],
) -> collections.abc.Generator[odgm.ExtensionDefinition, None, None]:
    '''
    recursively add known extensions until all dependencies are included.
    assumes extension-definitions are consistent.
    '''
    seen_names = set([e.name for e in requested])

    def resolve(
        dependencies,
    ):
        for dependency in dependencies:
            if dependency in seen_names:
                continue

            missing_extension_definition = find_extension_definition(
                extension_definitions=known,
                extension_name=dependency,
            )

            yield missing_extension_definition
            seen_names.add(missing_extension_definition.name)
            yield from resolve(missing_extension_definition.dependencies)

    for extension_definition in requested:
        yield from resolve(extension_definition.dependencies)


def outputs_as_jsonpath(
    outputs_by_extension: dict,
) -> dict:
    '''
    converts templated outputs to a nested dictionary structure compatible with `jsonpaths_ng`.
    '''
    output_lookup = collections.defaultdict(lambda: collections.defaultdict(dict))
    for name, outputs in outputs_by_extension.items():
        current_outputs = {}
        for output in outputs:
            output: odgm.ExtensionOutput
            current_outputs[output.name] = output.value
        output_lookup['dependencies'][name]['outputs'] = current_outputs
    return dict(output_lookup)


def _helm_template(
    helm_path: str,
    values: dict,
) -> list[dict]:
    values_path = os.path.join(helm_path, 'values-merged.yaml')
    with open (values_path, 'w') as f:
        f.write(yaml.safe_dump(values))

    argv = [
        'helm',
        'template',
        '--include-crds',
        helm_path,
        '-f',
        values_path,
    ]

    completed_process = subprocess.run(
        args=argv,
        capture_output=True,
        text=True,
        check=True,
    )

    manifests_raw = completed_process.stdout
    return list(yaml.safe_load_all(manifests_raw))


def create_or_update_resource(
    create_namespaced_resource: collections.abc.Callable,
    patch_namespaced_resource: collections.abc.Callable,
    data: dict,
    name: str,
    namespace: str,
    group: str=None,
    version: str=None,
    plural: str=None,
) -> None:
    kwargs = {
        'namespace': namespace,
        'body': data,
    }
    if group:
        kwargs['group'] = group
    if version:
        kwargs['version'] = version
    if plural:
        kwargs['plural'] = plural

    try:
        create_namespaced_resource(**kwargs)
    except kubernetes.client.rest.ApiException as e:
        kwargs['name'] = name
        if e.status == 409:
            # secret already exists, update instead
            patch_namespaced_resource(**kwargs)
        else:
            raise


def create_or_update_odg(
    odg: odgm.ODG,
    extension_definitions: list[odgm.ExtensionDefinition],
    component_descriptor_lookup,
    oci_client: oci.client.Client,
):
    requested_extension_definitions = [
        find_extension_definition(
            extension_definitions=extension_definitions,
            extension_name=extension_name,
        )
        for extension_name in odg.extensions
    ]

    requested_extension_definitions.extend(list(
        iter_missing_dependencies(
            requested=requested_extension_definitions,
            known=extension_definitions,
        )
    ))

    outputs_for_extension = dict([
        (
            extension_definition.name,
            extension_definition.templated_outputs(odg.context),
        )
        for extension_definition in requested_extension_definitions
    ])
    outputs_jsonpath = outputs_as_jsonpath(outputs_for_extension)

    extension_instances = [
        odgm.ExtensionInstance.from_definition(
            extension_definition=extension_definition,
            component_descriptor_lookup=component_descriptor_lookup,
            oci_client=oci_client,
            templated_values=[
                dataclasses.replace(
                    value_ref,
                    value=odgu.replace_with_jsonpath(
                        value=value_ref.value,
                        outputs=outputs_jsonpath,
                        context=odg.context,
                    ),
                )
                for value_ref in extension_definition.installation.values
            ],
        )
        for extension_definition in requested_extension_definitions
    ]

    for extension_instance in extension_instances:
        for artefact in extension_instance.artefacts:
            # must be unique per odg installation
            extension_artefact_name = f'{odg.name}-{extension_instance.name}-{artefact.name}'

            if artefact.access.type is ocm.AccessType.LOCAL_BLOB:
                content_iterator = ocm_util.iter_local_blob_content(
                    access=artefact.access,
                    oci_client=oci_client,
                    image_reference=artefact.access.imageReference,
                )

            elif artefact.access.type is ocm.AccessType.OCI_REGISTRY:
                content_iterator = oci.image_layers_as_tarfile_generator(
                    image_reference=artefact.access.imageReference,
                    oci_client=oci_client,
                    include_config_blob=False,
                    fallback_to_first_subimage_if_index=True,
                )

            else:
                raise ValueError(f'unsupported artefact access type {artefact.access.type}')

            tmpfile = tempfile.NamedTemporaryFile()
            for chunk in content_iterator:
                tmpfile.write(chunk)
            tmpfile.seek(0)

            # skip artefact iff helm archive has more than one member (== the helm chart)
            helm_chart_path = None
            has_multiple_members = False
            tmpdir = tempfile.TemporaryDirectory()

            with tarfile.open(fileobj=tmpfile, mode='r:gz') as tf:
                for member in tf.getmembers():
                    if helm_chart_path:
                        has_multiple_members = True
                        break

                    tf.extract(
                        member=member,
                        path=tmpdir.name,
                        filter='tar',
                    )

                    helm_chart_path = os.path.join(tmpdir.name, member.name)

            tmpfile.close()

            if has_multiple_members:
                logger.error(f'unexpected number of members in helm chart archive for "{extension_artefact_name}"')
                continue

            default_values_path = os.path.join(helm_chart_path, 'values.yaml')
            default_values = yaml.safe_load(open(default_values_path))

            installation_values_for_artefact = [
                iv
                for iv in extension_instance.values
                if iv.helm_reference == artefact.name
            ]

            merged_installation_values = {}
            for installation_value in installation_values_for_artefact:
                odgu.patch_jsonpath_into_dict(
                    input_dict=merged_installation_values,
                    jsonpath=installation_value.helm_attribute,
                    value=installation_value.value
                )

            manifests = _helm_template(
                values=util.merge_dicts(
                    merged_installation_values,
                    default_values
                ),
                helm_path=helm_chart_path,
            )

            data = {
                'apiVersion': odgm.ManagedResourceMeta.apiVersion,
                'kind': odgm.ManagedResourceMeta.kind,
                'metadata': {
                    'name': extension_artefact_name,
                    'namespace': odg.namespace,
                    'labels': {
                        ODG_NAME_LABEL: odg.name, # we need to fine them again
                    },
                },
                'spec': {
                    'class': odgm.ManagedResourceClasses.EXTERNAL,
                    'keepObjects': False,
                    'secretRefs': [
                        {
                            'name': extension_artefact_name,
                        }
                    ],
                }
            }
            create_or_update_resource(
                create_namespaced_resource=kubernetes_api.custom_kubernetes_api.create_namespaced_custom_object,
                patch_namespaced_resource=kubernetes_api.custom_kubernetes_api.patch_namespaced_custom_object,
                data=data,
                name=extension_artefact_name,
                namespace=odg.namespace,
                group=odgm.ManagedResourceMeta.group,
                version=odgm.ManagedResourceMeta.version,
                plural=odgm.ManagedResourceMeta.plural,
            )

            secret_body = kubernetes.client.V1Secret(
                api_version='v1',
                kind='Secret',
                metadata=kubernetes.client.V1ObjectMeta(
                    name=extension_artefact_name,
                    namespace=odg.namespace,
                    labels={
                        ODG_NAME_LABEL: odg.name, # we need to fine them again
                    }
                ),
                data={
                    'data.yaml': base64.b64encode(
                        yaml.dump_all(manifests).encode()
                    ).decode(),
                },
            )
            create_or_update_resource(
                create_namespaced_resource=kubernetes_api.core_kubernetes_api.create_namespaced_secret,
                patch_namespaced_resource=kubernetes_api.core_kubernetes_api.patch_namespaced_secret,
                data=secret_body.to_dict(),
                name=extension_artefact_name,
                namespace=odg.namespace,
            )


def delete_managed_resources(
    kubernetes_api: k8s.util.KubernetesApi,
    odg_name: str,
    odg_namespace: str,
):
    managed_resources = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=odgm.ManagedResourceMeta.group,
        version=odgm.ManagedResourceMeta.version,
        plural=odgm.ManagedResourceMeta.plural,
        namespace=odg_namespace,
        label_selector=f'{ODG_NAME_LABEL}={odg_name}',
    ).get('items', [])

    for managed_resource in managed_resources:
        resource_name = managed_resource['metadata']['name']
        kubernetes_api.custom_kubernetes_api.delete_namespaced_custom_object(
            group=odgm.ManagedResourceMeta.group,
            version=odgm.ManagedResourceMeta.version,
            plural=odgm.ManagedResourceMeta.plural,
            namespace=odg_namespace,
            name=resource_name,
        )

    secrets: kubernetes.client.V1SecretList = kubernetes_api.core_kubernetes_api.list_namespaced_secret(
        namespace=odg_namespace,
        label_selector=f'{ODG_NAME_LABEL}={odg_name}',
    )

    for secret in secrets.items:
        secret: kubernetes.client.V1Secret
        kubernetes_api.core_kubernetes_api.delete_namespaced_secret(
            name=secret.metadata.name,
            namespace=odg_namespace,
        )


def reconcile(
    extension_definitions: list[odgm.ExtensionDefinition],
    component_descriptor_lookup,
    oci_client: oci.client.Client,
    group: str= odgm.ODGMeta.group,
    plural: str = odgm.ODGMeta.plural,
    resource_version: str='',
):
    '''
    watches for events of ODG custom-resource
    creates, updates and deletes ODG installations using managed-resources
    '''

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
            odg = odgm.ODG.from_kubernetes_event(event=event)

            resource_version = metadata['resourceVersion']
            logger.info(f'{event["type"]} "{odg.name}" in "{odg.namespace}"')

            if event['type'] == 'DELETED':
                # noop, as we cleaned up on `deletionTimestamp` modificiation already
                pass

            elif event['type'] == 'MODIFIED':
                if metadata.get('deletionTimestamp'):
                    delete_managed_resources(
                        kubernetes_api=kubernetes_api,
                        odg_name=odg.name,
                        odg_namespace=odg.namespace,
                    )

                    # remove our finaliser to finally delete
                    kubernetes_api.custom_kubernetes_api.patch_namespaced_custom_object(
                        group=odgm.ODGMeta.group,
                        version=odgm.ODGMeta.version,
                        plural=odgm.ODGMeta.plural,
                        namespace=odg.namespace,
                        name=odg.name,
                        body={
                            'metadata': {
                                'finalizers': [
                                    finaliser
                                    for finaliser in metadata.get('finalizers', [])
                                    if finaliser != ODG_CLEAN_UP_FINALISER
                                ],
                            }
                        },
                    )

                else:
                    create_or_update_odg(
                        odg=odg,
                        extension_definitions=extension_definitions,
                        component_descriptor_lookup=component_descriptor_lookup,
                        oci_client=oci_client,
                    )

            elif event['type'] == 'ADDED':
                create_or_update_odg(
                    odg=odg,
                    extension_definitions=extension_definitions,
                    component_descriptor_lookup=component_descriptor_lookup,
                    oci_client=oci_client,
                )

            else:
                raise NotImplementedError(f'event type {event["type"]} not implemented')


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
    parser.add_argument('--extension-definition-file')
    parser.add_argument('--ocm-cache-path', default='./cache/ocm')
    parser.add_argument(
        '--extension',
        dest='extensions',
        action='append',
        default=[],
        help='can be specified multiple times, \
            expected format: <component-name>:<component-version>:<artefact-name>'
    )
    parsed = parser.parse_args()

    oci_client = oci.client.Client()
    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed.ocm_cache_path,
        oci_client=oci_client,
    )

    extension_definitions = []

    if parsed.extension_definition_file:
        with open(parsed.extension_definition_file) as f:
            extensions_raw = yaml.safe_load_all(f)
            extension_definitions.extend([
                dacite.from_dict(
                    data=extension_raw,
                    data_class=odgm.ExtensionDefinition,
                )
                for extension_raw in extensions_raw
            ])

    for extension in parsed.extensions:
        extension: str
        component_id, artefact_name = extension.rsplit(':', 1)
        component = component_descriptor_lookup(component_id).component
        for resource_node in cnudie.iter.iter(
            component=component,
            recursion_depth=0,
            node_filter=cnudie.iter.Filter.resources,
        ):
            if (
                resource_node.resource.type == ODG_EXTENSION_ARTEFACT_TYPE
                and resource_node.resource.name == artefact_name
            ):
                break
        else:
            raise ValueError(f'no odg-extension found in {extension}')

        resource_node: cnudie.iter.ResourceNode
        odg_extension_raw = oci_client.blob(
            image_reference=resource_node.component.current_ocm_repo.component_version_oci_ref(
                name=resource_node.component.name,
                version=resource_node.component.version,
            ),
            digest=resource_node.resource.access.localReference,
            stream=False,
        ).json()
        extension_definitions.append(dacite.from_dict(
            data=odg_extension_raw,
            data_class=odgm.ExtensionDefinition,
        ))

    logger.info(f'known extension definitions: {[e.name for e in extension_definitions]}')

    kubernetes_api = k8s.util.kubernetes_api(kubeconfig_path=parsed.kubeconfig)

    while True:
        reconcile(
            extension_definitions=extension_definitions,
            component_descriptor_lookup=component_descriptor_lookup,
            oci_client=oci_client,
        )
