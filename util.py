import collections.abc
import dataclasses
import datetime
import enum
import functools
import json
import logging
import re
import urllib.parse

import aiohttp.web
import dateutil.parser
import yaml

import cnudie.iter
import cnudie.retrieve
import cnudie.retrieve_async
import oci.model as om
import ocm


logger = logging.getLogger(__name__)


def parse_yaml_file(path: str) -> dict:
    with open(path) as file:
        return yaml.safe_load(file)


def urlparse(url: str) -> urllib.parse.ParseResult:
    if not '://' in url:
        url = f'x://{url}'

    return urllib.parse.urlparse(url)


def urljoin(*parts):
    if len(parts) == 1:
        return parts[0]

    first = parts[0]
    last = parts[-1]
    middle = parts[1:-1]

    first = first.rstrip('/')
    middle = list(map(lambda s: s.strip('/'), middle))
    last = last.lstrip('/')

    return '/'.join([first] + middle + [last])


@functools.cache
def normalise_url_to_second_and_tld(url: str):
    hostname = urlparse(url).hostname

    parts = hostname.strip('.').split('.')
    if parts[0] == 'api':
        parts = parts[1:]

    # hack: discard `api` subdomain (specific to github.com)
    return '.'.join(parts).lower()


def purge_callables_from_dict(data) -> dict:
    if isinstance(data, str):
        return data
    elif isinstance(data, dict):
        return dict(
            (k, purge_callables_from_dict(v))
            for k, v in data.items()
            if not isinstance(v, collections.abc.Callable)
        )
    elif isinstance(data, collections.abc.Iterable):
        return [
            purge_callables_from_dict(o)
            for o in data
            if not isinstance(o, collections.abc.Callable)
        ]
    return data


def dict_serialisation(data) -> dict:
    if isinstance(data, enum.Enum):
        return data.value
    elif isinstance(data, str):
        return data
    elif isinstance(data, (datetime.date, datetime.datetime)):
        return data.isoformat()
    elif isinstance(data, datetime.timedelta):
        return data.total_seconds()
    elif dataclasses.is_dataclass(data):
        return dict_serialisation(dataclasses.asdict(data))
    elif isinstance(data, dict):
        return dict((k, dict_serialisation(v)) for k, v in data.items())
    elif isinstance(data, collections.abc.Iterable):
        return [dict_serialisation(o) for o in data]
    return data


def dict_to_json_factory(data: dict) -> str:
    return json.dumps(dict_serialisation(data))


async def retrieve_component_descriptor(
    component_id: ocm.ComponentIdentity,
    /,
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    ocm_repo: ocm.OcmRepository=None,
) -> ocm.ComponentDescriptor:
    try:
        if ocm_repo:
            return await component_descriptor_lookup(
                component_id,
                ocm_repository_lookup=cnudie.retrieve.ocm_repository_lookup(ocm_repo),
            )
        return await component_descriptor_lookup(component_id)
    except om.OciImageNotFoundException:
        err_str = f'Component descriptor "{component_id.name}" in version "' \
        f'{component_id.version}" not found in {ocm_repo=}.'
        logger.debug(err_str)
        raise aiohttp.web.HTTPNotFound(
            reason='Component descriptor not found',
            text=err_str,
        )


def artefact_node_to_str(
    artefact_node: cnudie.iter.Node | cnudie.iter.ArtefactNode,
) -> str:
    component_id = artefact_node.component.identity()

    if isinstance(artefact_node, cnudie.iter.SourceNode):
        artefact_id = artefact_node.artefact.identity(peers=artefact_node.component.sources)
    else:
        artefact_id = artefact_node.artefact.identity(peers=artefact_node.component.resources)

    return f'{component_id.name}:{component_id.version}_{artefact_id}'


def get_enum_value_or_raise(
    value: object,
    enum_type: type,
):
    try:
        return enum_type(value)
    except ValueError:
        raise aiohttp.web.HTTPBadRequest(
            text=(
                f'Bad value for {enum_type=}: {value=}. '
                f'Allowed values: {[val.value for val in enum_type]}'
            ),
        )


def param(
    params: dict,
    name: str,
    *,
    required: bool=False,
    default=None,
):
    if required and default:
        raise ValueError('there must be no default value if `required` is set to `True`')

    if name not in params:
        if required:
            raise aiohttp.web.HTTPBadRequest(
                reason='Missing parameter',
                text=f'The {name} parameter is required.',
            )
        return default

    return params[name]


def param_as_bool(
    params: dict,
    name: str,
    *,
    required: bool=False,
    default: bool=False,
) -> bool:
    # taken from requests' `request.get_param_as_bool`
    true_strings = ('true', 'True', 't', 'yes', 'y', '1', 'on')
    false_strings = ('false', 'False', 'f', 'no', 'n', '0', 'off')

    val = str(param(
        params=params,
        name=name,
        required=required,
        default=default,
    ))

    if val in true_strings:
        return True
    elif val in false_strings:
        return False

    raise aiohttp.web.HTTPBadRequest(
        reason='Invalid parameter',
        text=f'The value of the paramter {name} must be a boolean value.',
    )


def error_description(
    error_id: str,
    **kwargs,
) -> str:
    '''
    Used to create a uniform error JSON response, containing a unique `error_id` as well as optional
    extra parameters to enrich the error description. Callers will still have to set the correct
    content type `application/json` for the error object.
    '''
    return dict_to_json_factory({
        'error_id': error_id,
        **kwargs,
    })


def get_creation_date(component: ocm.Component) -> datetime.datetime:
    '''
    Trys to extract creation date from creationTime attribute and if not set from label with name
    "cloud.gardener/ocm/creation-date".
    Raises KeyError, if both is not successful.
    '''

    if (creationTime := component.creationTime):
        return dateutil.parser.isoparse(creationTime)

    creation_label: ocm.Label | None = component.find_label('cloud.gardener/ocm/creation-date')

    if not creation_label:
        raise KeyError(
            'The attribute creation time, as well as the',
            'label named "cloud.gardener/ocm/creation-date", were not set.',
        )
    else:
        return dateutil.parser.isoparse(creation_label.value)


def convert_to_timedelta(
    time: str | int,
    default_unit: str='d',
) -> datetime.timedelta:
    seconds_per_unit = {
        's': 1,
        'sec': 1,
        'm': 60,
        'min': 60,
        'h': 60 * 60,
        'hr': 60 * 60,
        'd': 60 * 60 * 24,
        'w': 60 * 60 * 24 * 7,
        'y': 60 * 60 * 24 * 365,
        'yr': 60 * 60 * 24 * 365,
    }
    unit = None

    if match := re.match(r'([0-9]+)\s*([a-z]*)', str(time).strip(), re.IGNORECASE):
        time, unit = match.groups()
    seconds = int(time) * seconds_per_unit[unit or default_unit]

    return datetime.timedelta(seconds=seconds)


def pluralise(
    word: str,
    count: int,
) -> str:
    if count == 1:
        return word

    word = re.sub('y$', 'ie', word)
    word = re.sub('s$', 'se', word)

    return word + 's'
