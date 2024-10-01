import collections.abc

import yaml

import cnudie.retrieve
import cnudie.util
import ocm


def load_component_descriptors(file: str):
    component_descriptors: list[ocm.ComponentDescriptor] = []
    with open(file, 'r') as file:
        descriptors_dict = yaml.load(file, yaml.SafeLoader)
        for descriptor_dict in descriptors_dict["componentDescriptors"]:
            descriptor = ocm.ComponentDescriptor.from_dict(descriptor_dict)
            component_descriptors.append(descriptor)

    return component_descriptors


def component_descriptor_lookup_mockup_factory(
    mock_component_file_path: str,
) -> collections.abc.Callable[
    [ocm.ComponentIdentity | str, ocm.OcmRepository | None],
    ocm.ComponentDescriptor,
]:
    def component_descriptor_lookup_mockup(
        component_identity: ocm.ComponentIdentity | str,
        ocm_repo: ocm.OcmRepository | None=None,
    ) -> ocm.ComponentDescriptor:
        component_identity = cnudie.util.to_component_id(component_identity)
        component_descriptors: list[ocm.ComponentDescriptor] = load_component_descriptors(
            mock_component_file_path,
        )

        for component_descriptor in component_descriptors:
            if (
                component_descriptor.component.name == component_identity.name
                and component_descriptor.component.version == component_identity.version
            ):
                return component_descriptor

    return component_descriptor_lookup_mockup


def versions_lookup_mockup_factory(
    mock_component_file_path: str,
) -> collections.abc.Callable[
    [cnudie.retrieve.ComponentName, ocm.OcmRepository | None],
    collections.abc.Sequence[str],
]:
    def versions_lookup_mockup(
        component_name:cnudie.util.ComponentName,
        ocm: ocm.OcmRepository | None=None,
    ) -> collections.abc.Sequence[str]:
        component_descriptors = load_component_descriptors(
            mock_component_file_path
        )
        versions: list[str] = []
        for component_descriptor in component_descriptors:
            if component_descriptor.component.name == component_name:
                versions.append(component_descriptor.component.version)
        return versions

    return versions_lookup_mockup
