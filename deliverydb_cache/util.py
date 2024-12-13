import collections.abc
import dataclasses
import datetime
import enum
import json
import pickle

import yaml

import deliverydb_cache.model as dcm


def normalise_and_serialise_object(
    object,
    *,
    recursion_depth: int=0,
    max_recursion_depth: int=100,
) -> str:
    '''
    Generate stable serialised representation of `object`. This is especially useful to calculate a
    stable descriptor as id for cache entries. If `object` contains one of the characters used for
    join operations (`|-`, `--|`, `|_`, `__|`, `|:`), a ValueError is raised to prevent collisions.

    If `object` contains a dictionary, the normalised keys are sorted in alphabetical order and
    concatenated using following pattern: `|--key1|:value1|-key2|:value2|-...--|`

    If `object` contains an iterable (note: generators are treated as ValueError), the normalised
    values are sorted in alphabetical order and concatenated using following pattern:
    `|__value1|_value2|_...__|`
    '''
    join_characters = ['|-', '--|', '|_', '__|', '|:']

    if recursion_depth > max_recursion_depth:
        raise RuntimeError(f'{max_recursion_depth=} exceeded for {object=}')

    if isinstance(object, collections.abc.Generator):
        raise ValueError(f'{object=} must not be a generator')

    if isinstance(object, enum.Enum):
        if any([join_char in object.value for join_char in join_characters]):
            raise ValueError(f'{object=} contains one of {join_characters=}')
        return object.value

    elif isinstance(object, str):
        if any([join_char in object for join_char in join_characters]):
            raise ValueError(f'{object=} contains one of {join_characters=}')
        return object

    elif isinstance(object, (datetime.date, datetime.datetime)):
        return object.isoformat()

    elif dataclasses.is_dataclass(object):
        return normalise_and_serialise_object(
            dataclasses.asdict(object),
            recursion_depth=recursion_depth + 1,
        )

    elif isinstance(object, collections.abc.Mapping):
        object_items_normalised = [
            (
                normalise_and_serialise_object(key, recursion_depth=recursion_depth + 1),
                normalise_and_serialise_object(
                    object.getall(key) if hasattr(object, 'getall') else object.get(key),
                    recursion_depth=recursion_depth + 1,
                ),
            )
            for key in set(object.keys())
        ]
        object_sorted = sorted(object_items_normalised, key=lambda items: items[0])
        return '|--' + '|-'.join([
            f'{key}|:{value}'
            for key, value in object_sorted
        ]) + '--|'

    elif isinstance(object, collections.abc.Iterable):
        object_items_normalised = [
            normalise_and_serialise_object(value, recursion_depth=recursion_depth + 1)
            for value in object
        ]
        object_sorted = sorted(object_items_normalised)
        return '|__' + '|_'.join([
            value
            for value in object_sorted
        ]) + '__|'

    return str(object)


def serialise_cache_value(
    value,
    encoding_format: dcm.EncodingFormat | str,
) -> bytes:
    if encoding_format.startswith('pickle'):
        protocol = dcm.EncodingFormat.pickle_protocol(pickle_encoding=encoding_format)
        return pickle.dumps(value, protocol)

    elif encoding_format is dcm.EncodingFormat.JSON:
        return json.dumps(value).encode('utf-8')

    elif encoding_format is dcm.EncodingFormat.YAML:
        return yaml.dump(value).encode('utf-8')

    else:
        raise ValueError(f'Unsupported encoding format {encoding_format}')


def deserialise_cache_value(
    value: bytes,
    encoding_format: dcm.EncodingFormat | str,
):
    if encoding_format.startswith('pickle'):
        # the pickle protocol is automatically detected, hence it is safe to ignore version here
        return pickle.loads(value)

    elif encoding_format is dcm.EncodingFormat.JSON:
        return json.loads(value)

    elif encoding_format is dcm.EncodingFormat.YAML:
        return yaml.safe_load(value)

    else:
        raise ValueError(f'Unsupported encoding format {encoding_format}')
