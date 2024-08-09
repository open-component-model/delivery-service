'''
Create a JSON structure for a complex filter object used to apply multiple question-based filters with logical operators.
'''

from __future__ import annotations
import json
import typing

import pydantic

def generate_filter_json_structure(filter_options):
    # Initialize the JSON structure
    json_structure = {
        "filters": {
            "description": "A complex filter object used to apply multiple question-based filters with logical operators",
            "type": "object",
            "properties": {
                "AND": {
                    "description": "A list of conditions where all must be true (logical AND)",
                    "type": "array",
                    "items": {"$ref": "#/definitions/condition"},
                },
                "OR": {
                    "description": "A list of conditions where at least one must be true (logical OR)",
                    "type": "array",
                    "items": {"$ref": "#/definitions/condition"},
                },
                "XOR": {
                    "description": "A list of conditions where exactly one must be true (logical XOR)",
                    "type": "array",
                    "items": {"$ref": "#/definitions/condition"},
                },
                "NOT": {
                    "description": "A single condition that must not be true (logical NOT)",
                    "type": "array",
                    "items": {"$ref": "#/definitions/condition"},
                },
            },
            "definitions": {
                "condition": {
                    "description": "A filter condition which can be an question-based filter or another logical operator",
                    "type": "object",
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "filter_name": {
                                    "description": "The name of the filter.",
                                    "type": "string",
                                    "enum": [],
                                    "enumDescriptions": [],
                                },
                                "question": {
                                    "description": "A Question, this filter should answer. Question has to contain all important information for filter.",
                                    "type": "string",
                                },
                            },
                            "required": ["filter_name", "question"],
                        },
                        {
                            "type": "object",
                            "properties": {
                                "AND": {
                                    "description": "A list of conditions where all must be true (logical AND)",
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/condition"},
                                },
                                "OR": {
                                    "description": "A list of conditions where at least one must be true (logical OR)",
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/condition"},
                                },
                                "XOR": {
                                    "description": "A list of conditions where exactly one must be true (logical XOR)",
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/condition"},
                                },
                                "NOT": {
                                    "description": "A single condition that must not be true (logical NOT)",
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/condition"},
                                },
                            },
                        },
                    ],
                }
            },
            "additionalProperties": False,
        }
    }

    # Add filter options descriptions to the condition definition
    for filter_option in filter_options:
        name = filter_option["name"]
        description = filter_option["description"]
        json_structure["filters"]["definitions"]["condition"]["oneOf"][0]["properties"][
            "filter_name"
        ]["enum"].append(name)
        json_structure["filters"]["definitions"]["condition"]["oneOf"][0]["properties"][
            "filter_name"
        ]["enumDescriptions"].append(description)

    return json_structure


if __name__ == "__main__":
    # Example usage
    options = [
        {
            "name": "resource",
            "description": "Filter by the resource on which components depend",
        },
        {
            "name": "vulnerability",
            "description": "Filter by specific vulnerabilities in components",
        },
        {
            "name": "malware",
            "description": "Filter by the presence of malware in components",
        },
    ]
    print(json.dumps(generate_filter_json_structure(options), indent=2))


class Filter(pydantic.BaseModel):
    filter_name: str = pydantic.Field(..., description="The name of the attribute to filter on.")
    instruction: str = pydantic.Field(
        ...,
        description="The specific instruction related to this filter. Should be a sentence. Instrct only what the entity should have.",
    )


class OperatorNOT(pydantic.BaseModel):
    logical_operator: typing.Literal["NOT"] = "NOT"
    filterA: typing.Union[Filter, "OperatorNOT", "OperatorOR", "OperatorAND"] = pydantic.Field(
        ...,
        description="The Resulting list of this Filter or oprtation will be subtracted with the resulting list of filter B",
    )
    filterB: typing.Union[Filter, "OperatorNOT", "OperatorOR", "OperatorAND"] = pydantic.Field(
        ...,
        description="The Resulting list of this Filter or oprtation will be subtracted drom the result of filter A",
    )


class OperatorOR(pydantic.BaseModel):
    logical_operator: typing.Literal["OR"] = "OR"
    filter: typing.Union[
        list[Filter], list["OperatorNOT"], list["OperatorOR"], list["OperatorAND"]
    ] = pydantic.Field(
        ...,
        description="A list of conditions or Filters whose resulting lists will be meged together with the union operator.",
    )


class OperatorAND(pydantic.BaseModel):
    logical_operator: typing.Literal["AND"] = "AND"
    filter: typing.Union[
        list[Filter], list["OperatorNOT"], list["OperatorOR"], list["OperatorAND"]
    ] = pydantic.Field(
        ...,
        description="A list of conditions or Filters whose resulting lists will be meged together with the intersect operator.",
    )


class FilterJsonStruckture(pydantic.BaseModel):
    filter: OperatorNOT | OperatorOR | OperatorAND | None = pydantic.Field(
        None,
        description="A complex filter object used to apply multiple filters with logical operators",
    )


OperatorNOT.model_rebuild()
OperatorOR.model_rebuild()
OperatorAND.model_rebuild()
FilterJsonStruckture.model_rebuild()


class Conditions(pydantic.BaseModel):
    AND: typing.Optional[typing.List[typing.Union[Filter, Conditions]]] = pydantic.Field(
        None,
        description="A list of conditions or Filters where all must be true (logical AND)",
    )
    OR: typing.Optional[typing.List[typing.Union[Filter, Conditions]]] = pydantic.Field(
        None,
        description="A list of conditions or Filters where at least one must be true (logical OR)",
    )
    XOR: typing.Optional[typing.List[typing.Union[Filter, Conditions]]] = pydantic.Field(
        None,
        description="A list of conditions or Filters where exactly one must be true (logical XOR)",
    )
    NOT: typing.Optional[typing.List[typing.Union[Filter, Conditions]]] = pydantic.Field(
        None,
        description="A list condition or Filters that must not be true (logical NOT)",
    )
