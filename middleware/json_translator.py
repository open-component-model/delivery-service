import enum
import dataclasses
import datetime
import json


def json_serializer(obj):
    if isinstance(obj, enum.Enum):
        return obj.value
    elif dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()

    return json.JSONEncoder().default(obj)
