import string
import re

import jsonpath_ng

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

        resource.access = ocm_util.to_absolute_oci_access(
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


def patch_jsonpath_into_dict(
    jsonpath: str,
    value,
    input_dict: dict = None,
) -> dict:
    if input_dict is None:
        input_dict = {}

    # split by '.' but ignore dots inside double-quotes
    keys = re.findall(
        pattern=r'"[^"]*"|[^.]+',
        string=jsonpath,
    )
    keys = [key.strip('"') for key in keys]  # rm surrounding double-quotes
    current = input_dict

    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value
    return input_dict


def replace_with_jsonpath(
    value: str | list,
    context: dict,
    outputs: dict,
) -> str:
    processed_values = []

    for entry in value if isinstance(value, list) else [value]:
        templated = string.Template(entry).substitute(context)
        parsed = jsonpath_ng.parse(templated)
        replacements = parsed.find(outputs)

        if len(replacements) == 0:
            # fallback to raw value if no match in known jsonpaths
            processed_values.append(templated)
            continue

        processed_values.append(replacements[0].value)

    return processed_values if isinstance(value, list) else processed_values[0]
