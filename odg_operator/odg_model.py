import dataclasses
import enum
import string

import jsonpath_ng
import cnudie.iter
import oci
import oci.client
import ocm

import odg_operator.odg_util as odgu
import ocm_util


class ManagedResourceClasses(enum.StrEnum):
    INTERNAL = 'internal'
    EXTERNAL = 'external'


@dataclasses.dataclass
class ManagedResourceMeta:
    # see: https://github.com/gardener/gardener/blob/master/docs/concepts/resource-manager.md
    group: str = 'resources.gardener.cloud'
    version: str = 'v1alpha1'
    plural: str = 'managedresources'
    kind: str = 'ManagedResource'
    apiVersion: str = 'resources.gardener.cloud/v1alpha1'


@dataclasses.dataclass
class ODGMeta:
    group: str = 'open-delivery-gear.ocm.software'
    version: str = 'v1'
    plural: str = 'odgs'
    kind: str = 'ODG'

    @staticmethod
    def apiVersion() -> str:
        return f'{ODGMeta.group}/{ODGMeta.version}'


@dataclasses.dataclass
class ODG:
    name: str
    namespace: str
    context: dict
    extensions: list[str]

    @staticmethod
    def from_kubernetes_event(event: dict) -> 'ODG':
        odg_raw = event['object']
        return ODG(
            name=odg_raw['metadata']['name'],
            namespace=odg_raw['metadata']['namespace'],
            context=odg_raw['spec']['context'],
            extensions=odg_raw['spec']['extensions'],
        )


@dataclasses.dataclass
class OcmArtefactReference:
    name: str
    version: str


@dataclasses.dataclass
class InstallationOcmReference:
    ref_name: str
    name: str
    version: str
    artefact: OcmArtefactReference
    mappings: list[OcmArtefactReference]


@dataclasses.dataclass
class InstallationValues:
    helm_reference: str
    helm_attribute: str
    value: str | list[str]


@dataclasses.dataclass
class ExtensionInstallation:
    ocm_references: list[InstallationOcmReference] = dataclasses.field(default_factory=list)
    values: list[InstallationValues] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ExtensionOutput:
    name: str
    value: str


@dataclasses.dataclass
class ExtensionDefinition:
    name: str
    installation: ExtensionInstallation
    outputs: list[ExtensionOutput] = dataclasses.field(default_factory=list)
    dependencies: list[str] = dataclasses.field(default_factory=list)

    def templated_outputs(self, context: dict) -> list[ExtensionOutput]:
        return [
            ExtensionOutput(
                name=output.name,
                value=string.Template(output.value).substitute(context),
            )
            for output in self.outputs
        ]

    def __hash__(self):
        return hash(self.name)


@dataclasses.dataclass
class ExtensionInstance:
    name: str
    artefacts: list[ocm.Resource]
    values: list[InstallationValues]

    @staticmethod
    def from_definition(
        extension_definition: ExtensionDefinition,
        templated_values: list[InstallationValues],
        component_descriptor_lookup,
        oci_client: oci.client.Client,
    ) -> 'ExtensionInstance':
        '''
        convenient factory for a single extension instance.
        will raise ValueError if ocm references cannot be resolved.
        '''
        extension_installation_resources = []
        installation_values = []

        for ocm_ref in extension_definition.installation.ocm_references:
            component_descriptor = component_descriptor_lookup(f'{ocm_ref.name}:{ocm_ref.version}')
            component: ocm.Component = component_descriptor.component
            resource_node = ocm_util.find_artefact_node(
                artefact_name=ocm_ref.artefact.name,
                artefact_version=ocm_ref.artefact.version,
                artefact_type=ocm.ArtefactType.HELM_CHART,
                artefact_node_sequence=cnudie.iter.iter(
                    component=component,
                    node_filter=cnudie.iter.Filter.resources,
                    recursion_depth=0,
                ),
            )

            extension_installation_resources.append(resource_node.resource)

            for mapping in ocm_ref.mappings:
                resource_node: cnudie.iter.ResourceNode = ocm_util.find_artefact_node(
                    artefact_name=ocm_ref.artefact.name,
                    artefact_version=ocm_ref.artefact.version,
                    artefact_type='helmchart-imagemap',
                    artefact_node_sequence=cnudie.iter.iter(
                        component=component,
                        node_filter=cnudie.iter.Filter.resources,
                        recursion_depth=0,
                    ),
                )

                image_mappings = oci_client.blob(
                    image_reference=resource_node.component.current_ocm_repo.component_version_oci_ref( # noqa: E501
                        name=resource_node.component.name,
                        version=resource_node.component.version,
                    ),
                    digest=resource_node.resource.access.localReference,
                    # imagemaps are typically small, so it should be okay to read into memory
                    stream=False,
                ).json()['imageMapping']

                image_mappings = odgu.resolved_image_mappings(
                    image_mappings=image_mappings,
                    component=component,
                )

                for path, value in image_mappings.items():
                    installation_values.append(InstallationValues(
                        helm_reference=mapping.name,
                        helm_attribute=path,
                        value=value,
                    ))

        return ExtensionInstance(
            name=extension_definition.name,
            artefacts=extension_installation_resources,
            values=templated_values + installation_values,
        )
