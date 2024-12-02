import collections.abc
import dataclasses
import datetime
import enum
import functools
import json
import logging
import urllib.parse

import aiohttp.web

import cnudie.iter
import cnudie.retrieve_async
import oci.model as om
import ocm

import middleware.auth


logger = logging.getLogger(__name__)


@middleware.auth.noauth
class Ready(aiohttp.web.View):
    async def get(self):
        '''
        ---
        description: This endpoint allows to test that the service is up and running.
        tags:
        - Health check
        responses:
          "200":
            description: Service is up and running
        '''
        return aiohttp.web.Response()


@functools.cache
def normalise_url_to_second_and_tld(url: str):
    if '://' not in url:
        url = 'x://' + url
    hostname = urllib.parse.urlparse(url).hostname

    parts = hostname.strip('.').split('.')
    if parts[0] == 'api':
        parts = parts[1:]

    # hack: discard `api` subdomain (specific to github.com)
    return '.'.join(parts).lower()


def dict_factory_enum_name_serialisiation(data):
    def convert_value(obj):
        if isinstance(obj, enum.Enum):
            return obj.name
        return obj

    return dict((k, convert_value(v)) for k, v in data)


def dict_factory_date_serialisiation(data):

    def convert_value(obj):
        if isinstance(obj, datetime.date):
            return obj.isoformat()
        return obj

    return dict((k, convert_value(v)) for k, v in data)


def dict_serialisation(data) -> dict:
    if isinstance(data, enum.Enum):
        return data.value
    elif isinstance(data, str):
        return data
    elif isinstance(data, (datetime.date, datetime.datetime)):
        return data.isoformat()
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
        return await component_descriptor_lookup(
            component_id,
            ctx_repo=ocm_repo,
        )
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


def as_timezone(ts: datetime.datetime, target_tz: datetime.timezone = datetime.timezone.utc) -> datetime.datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=target_tz)
    if ts.tzinfo != target_tz:
        return ts.astimezone(target_tz)
    return ts
