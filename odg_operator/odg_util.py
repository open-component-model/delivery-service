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
    value: str | list[str] | dict[str, str],
    substitution_context: dict,
    jsonpaths: dict,
) -> str:
    '''
    Substitute placeholders in the input value(s) using the provided context,
    then resolve JSONPath expressions against a dictionary.

    Args:
        `value`: string value(s) containing placeholders and/or JSONPath expressions.
        `substitution_context`: dictionary for placeholder substitution.
        `jsonpaths`: dictionary to replace using JSONPath semantics after substitution.

    Returns:
        Substituted value(s) with resolved JSONPath expressions.
        Returns a single string if `value` is a string, or a list if `value` is a list.

    Note:
        If no matches are found for a JSONPath expression, the substituted string is returned as-is.
    '''
    def process_single(entry: str) -> str:
        templated = string.Template(entry).substitute(substitution_context)
        parsed = jsonpath_ng.parse(templated)
        replacements = parsed.find(jsonpaths)

        if len(replacements) == 0:
            return templated

        return replacements[0].value

    def process(input: str | list[str] | dict[str, str]) -> str | list[str] | dict[str, str]:
        if isinstance(input, str):
            return process_single(input)

        elif isinstance(input, list):
            return [process_single(entry) for entry in input]

        elif isinstance(input, dict):
            res = {}
            pairs = input.items()
            for key, _value in pairs:
                res[process_single(key)] = process(_value)
            return res

    return process(value)
