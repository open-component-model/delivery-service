import collections.abc
import string
import re

import jsonpath_ng

import oci.model
import ocm

import odg_operator.odg_model as odgm
import ocm_util


def resolve_image_mappings(
    image_mappings: list[dict],
    component: ocm.Component,
) -> collections.abc.Generator[tuple[str, str], None, None]:
    '''
    A generator yielding key, value pairs for all image mappings.
    For each image mapping a key, value pair for both image repository and image tag
    is created.
    The key is taken from the image mapping itself, whereas the value is derived by
    looking up the referenced resource's oci-access in the provided component descriptor.
    '''
    def find_oci_resource(
        resource_name: str,
        resources: collections.abc.Iterable[ocm.Resource],
    ) -> ocm.Resource | None:
        for resource in resources:
            if resource.name != resource_name:
                continue
            if not resource.type is ocm.ArtefactType.OCI_IMAGE:
                continue
            return resource

    for image_mapping in image_mappings:
        resource_name = image_mapping['resource']['name']
        resource = find_oci_resource(
            resource_name=resource_name,
            resources=component.resources,
        )

        if not resource:
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

        yield image_mapping['repository'], image_ref.ref_without_tag
        yield image_mapping['tag'], tag


def patch_jsonpath_into_dict(
    jsonpath_expr: str,
    value,
    input_dict: dict = None,
) -> dict:
    '''
    Inserts or updates a value in a nested dictionary structure based on a JSONPath-like string.
    This function takes a JSONPath-like string (using dot notation, with support for quoted keys
    containing dots), a value to insert, and an optional input dictionary. It traverses or creates
    the nested dictionary structure according to the path, and sets the value at the specified
    location.
    Args:
        jsonpath (str): The JSONPath-like string specifying the nested keys, e.g., 'foo.bar."baz.x"'.
        value: The value to set at the specified path.
        input_dict (dict, optional): The dictionary to patch. If None, a new dictionary is created.
    Returns:
        dict: The updated dictionary with the value set at the specified path.
    Example:
        >>> patch_jsonpath_into_dict('foo.bar."baz.x"', 42)
        {'foo': {'bar': {'baz.x': 42}}}
    '''
    if input_dict is None:
        # avoid mutable object as default value
        input_dict = {}

    # split by '.' but ignore dots inside double-quotes
    # foo.bar."foobar" -> ['foo', 'bar', 'foobar']
    keys = re.findall(
        pattern=r'"[^"]*"|[^.]+',
        string=jsonpath_expr,
    )
    keys = [key.strip('"') for key in keys]  # rm surrounding double-quotes
    current = input_dict

    for key in keys[:-1]:
        if (
            key not in current
            or not isinstance(current[key], dict)
        ):
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value
    return input_dict


def template_and_resolve_jsonpath(
    value: str | bool | list | dict,
    value_type: odgm.ValueType,
    substitution_context: dict,
    jsonpaths: dict,
) -> str | bool | list | dict:
    '''
    Processes provided value according to its type.
    - `literal` is returned as-is
    - `template` is substituted via `substituion_context`
    - `jsonpath` is replaced using JSONPath semantics and provided `jsonpaths` dict

    list and dicts are recursively processed, for dicts both key and values are processed.

    Args:
        `value`: string value(s) containing placeholders and/or JSONPath expressions.
        `value_type`: defining how to process the value
        `substitution_context`: dictionary for placeholder substitution.
        `jsonpaths`: dictionary to replace using JSONPath semantics after substitution.
    '''

    if isinstance(value, str):
        templated = string.Template(value).substitute(substitution_context)

        if value_type is odgm.ValueType.LITERAL:
            return value

        elif value_type is odgm.ValueType.PYTHON_STRING_TEMPLATE:
            return templated

        elif value_type is odgm.ValueType.JSONPATH:
            parsed = jsonpath_ng.parse(templated)
            replacements = parsed.find(jsonpaths)

            if len(replacements) != 1:
                raise ValueError(f'do not know how to replace {value=}')

            # we know there is exactly one replacement
            return replacements[0].value

        else:
            raise ValueError(f'do not know how to handle {value_type=}')

    elif isinstance(value, bool):
        return value

    elif isinstance(value, dict):
        return dict([
            (
                template_and_resolve_jsonpath(
                    value=key,
                    substitution_context=substitution_context,
                    jsonpaths=jsonpaths,
                    value_type=value_type,
                ),
                template_and_resolve_jsonpath(
                    value=value,
                    substitution_context=substitution_context,
                    jsonpaths=jsonpaths,
                    value_type=value_type,
                )
            )
            for key, value in value.items()
        ])

    elif isinstance(value, list):
        return [
            template_and_resolve_jsonpath(
                value=entry,
                substitution_context=substitution_context,
                jsonpaths=jsonpaths,
                value_type=value_type,
            )
            for entry in value
        ]

    else:
        raise ValueError(f'do not know how to process {value=} of {type(value)=}')
