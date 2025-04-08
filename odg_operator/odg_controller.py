import argparse
import collections
import collections.abc
import http
import logging
import os

import dacite
import kubernetes.client
import kubernetes.client.rest
import kubernetes.watch
import urllib3
import yaml

import ci.log
import cnudie.iter
import oci.client

import k8s.util
import lookups
import odg_operator.odg_model as odgm


ci.log.configure_default_logging()
logger = logging.getLogger(__name__)
own_dir = os.path.abspath(os.path.dirname(__file__))
CUSTOMER_CLEANUP_FINALIZER = 'open-delivery-gear.ocm.software/customer-cluster-cleanup'
ODG_COMPONENT_NAME = 'ocm.software/ocm-gear'


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
    seen = set([e.name for e in requested])

    def resolve(
        dependencies,
    ):
        for dependency in dependencies:
            if dependency in seen:
                continue

            missing_extension_definition = find_extension_definition(
                extension_definitions=known,
                extension_name=dependency,
            )

            yield missing_extension_definition
            seen.add(missing_extension_definition.name)
            yield from resolve(missing_extension_definition.dependencies)

    for extension_definition in requested:
        yield from resolve(extension_definition.dependencies)


def outputs_as_jsonpath(
    outputs_by_extension: dict,
) -> dict:
    '''
    convert outputs as templated by extensions to lookup dict ready to use with `jsonpaths_ng`.
    '''
    output_lookup = collections.defaultdict(lambda: collections.defaultdict(dict))
    for name, outputs in outputs_by_extension.items():
        _outputs = {}
        for output in outputs:
            output: odgm.ExtensionOutput
            _outputs[output.name] = output.value
        output_lookup['dependencies'][name]['outputs'] = _outputs
    return dict(output_lookup)


def reconcile(
    extension_definitions: list[odgm.ExtensionDefinition],
    component_descriptor_lookup,
    group: str= odgm.ODGExtensionMeta.group,
    plural: str = odgm.ODGMeta.plural,
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
            odg_name = metadata['name']
            logger.info(f'{event["type"]} "{odg_name}" in "{metadata["namespace"]}"')

            requested_extension_definitions = [
                find_extension_definition(
                    extension_definitions=extension_definitions,
                    extension_name=extension_name,
                )
                for extension_name in event['object']['spec']['extensions']
            ]

            requested_extension_definitions.extend(list(
                iter_missing_dependencies(
                    requested=requested_extension_definitions,
                    known=extension_definitions,
                )
            ))

            context = event['object']['spec']['context']

            outputs_for_extension = dict([
                (
                    extension_definition.name,
                    extension_definition.templated_outputs(context),
                )
                for extension_definition in requested_extension_definitions
            ])
            outputs_jsonpath = outputs_as_jsonpath(outputs_for_extension)

            extension_instances = [
                odgm.ExtensionInstance.from_definition(
                    extension_definition=extension_definition,
                    outputs=outputs_jsonpath,
                    component_descriptor_lookup=component_descriptor_lookup,
                )
                for extension_definition in requested_extension_definitions
            ]

            import pprint
            for extension_instance in extension_instances:
                pprint.pprint(extension_instance)

            # TODO: create managed resources

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
    parser.add_argument(
        '--extension',
        dest='extensions',
        action='append',
        default=[],
        help='can be specified multiple times, \
            expected format: <component-name>:<component-version>:<artefact-name>'
    )
    parsed = parser.parse_args()

    oci_client = oci.client.Client(
        credentials_lookup=lambda **kwargs: None, # consume public oci-images only
    )
    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir='./cache/ocm',
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
                resource_node.resource.type == 'odg-extension'
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
    resource_version = ''

    while True:
        reconcile(
            extension_definitions=extension_definitions,
            component_descriptor_lookup=component_descriptor_lookup,
        )
