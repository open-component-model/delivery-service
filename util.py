import datetime
import enum
import functools
import logging
import urllib.parse

import falcon

import cnudie.iter
import cnudie.retrieve
import oci.model as om
import ocm

import middleware.auth


logger = logging.getLogger(__name__)


@middleware.auth.noauth
class Ready:
    def on_get(self, req, resp: falcon.Response):
        resp.status = falcon.HTTP_200


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


def retrieve_component_descriptor(
    component_id: ocm.ComponentIdentity,
    /,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    ctx_repo: ocm.OcmRepository=None,
) -> ocm.ComponentDescriptor:
    try:
        return component_descriptor_lookup(
            component_id,
            ctx_repo=ctx_repo,
        )
    except om.OciImageNotFoundException as e:
        err_str = f'component descriptor "{component_id.name}" in version "' \
        f'{component_id.version}" not found in {ctx_repo=}'
        logger.debug(err_str)
        raise falcon.HTTPNotFound(
            title='component descriptor not found',
            description=err_str,
        ) from e


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
        raise falcon.HTTPBadRequest(title=(
            f'bad value for {enum_type=}: {value=}. '
            f'allowed values: {[val.value for val in enum_type]}'
        ))
