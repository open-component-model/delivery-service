import oci.model
import ocm

import ocm_util


def resolved_image_mappings(
    image_mappings: list[dict],
    component: ocm.Component,
) -> dict:
    for image_mapping in image_mappings:
        resource_name = image_mapping['resource']['name']
        for resource in component.resources:
            if resource.name != resource_name:
                continue
            if not resource.type is ocm.ArtefactType.OCI_IMAGE:
                continue
            break # found it
        else:
            raise ValueError(f'did not find oci-image w/ {resource_name=} in {component=}')

        resource.access = ocm_util.to_absolute_access(
            access=resource.access,
            ocm_repo=component.current_ocm_repo,
        )
        image_ref = oci.model.OciImageReference(resource.access.imageReference)

        if image_ref.has_mixed_tag:
            # special-handling, as OciImageReference will - for backwards-compatibility - always
            # return digest-tag for "mixed tags"
            symbolic_tag, digest_tag = image_ref.parsed_mixed_tag
            tag = f'{symbolic_tag}@{digest_tag}'
        else:
            tag = image_ref.tag

        return {
            image_mapping['repository']: image_ref.ref_without_tag,
            image_mapping['tag']: tag,
        }
