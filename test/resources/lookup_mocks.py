import typing

import yaml

import cnudie.retrieve
import cnudie.util
import gci.componentmodel as cm


def load_component_descriptors(file: str):
    component_descriptors: list[cm.ComponentDescriptor] = []
    with open(file, 'r') as file:
        descriptors_dict = yaml.load(file, yaml.SafeLoader)
        for descriptor_dict in descriptors_dict["componentDescriptors"]:
            descriptor = cm.ComponentDescriptor.from_dict(descriptor_dict)
            component_descriptors.append(descriptor)

    return component_descriptors


def component_descriptor_lookup_mockup_factory(
        mock_component_file_path: str,
) -> typing.Callable[
    [cm.ComponentIdentity | str, cm.OcmRepository | None],
    cm.ComponentDescriptor,
]:
    def component_descriptor_lookup_mockup(
            component_identity: cm.ComponentIdentity | str,
            ocm_repo: typing.Optional[cm.OcmRepository] = None,
    ) -> cm.ComponentDescriptor:
        component_identity = cnudie.util.to_component_id(component_identity)
        component_descriptors: list[cm.ComponentDescriptor] = load_component_descriptors(
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
) -> typing.Callable[
        [cnudie.retrieve.ComponentName, typing.Optional[cm.OcmRepository]],
        typing.Sequence[str],
]:
    def versions_lookup_mockup(
        component_name:cnudie.util.ComponentName,
        ocm: typing.Optional[cm.OcmRepository] = None,
    ) -> typing.Sequence[str]:
        component_descriptors = load_component_descriptors(
            mock_component_file_path
        )
        versions: list[str] = []
        for component_descriptor in component_descriptors:
            if component_descriptor.component.name == component_name:
                versions.append(component_descriptor.component.version)
        return versions

    return versions_lookup_mockup
