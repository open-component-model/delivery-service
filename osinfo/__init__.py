import functools
import logging

import aiohttp.web
import yaml

import consts
import eol
import os_id_extension.model as osidmodel
import osinfo.alpine
import osinfo.paths
import util


logger = logging.getLogger(__name__)


@functools.cache
def release_infos_from_cfg(
    os_id: str,
    absent_ok: bool = False,
) -> list[osidmodel.OsReleaseInfo] | None:
    '''
    reads os_release_info from filesystem,
    returns `None` if requested os is not supported
    '''

    path = osinfo.paths.for_os(os_id)

    try:
        with open(path) as f:
            release_infos_raw = yaml.safe_load(f)
    except FileNotFoundError as e:
        if not absent_ok:
            raise e

        return None

    return [
        eol.os_release_info_from_release_cycle({
            'eol': release_info_raw.get('eol_date'),
            'cycle': release_info_raw['name'],
            'latest': release_info_raw.get('greatest_version'),
        })
        for release_info_raw in release_infos_raw
    ]


@functools.cache
def osinfo_client(os_id: str):
    if os_id == 'alpine':
        return osinfo.alpine.Client()

    return None


def os_release_infos(
    os_id: str,
    eol_client: eol.EolClient,
) -> list[osidmodel.OsReleaseInfo] | None:
    '''
    returns release_info or `None` for given os_id
    lookup hierarchy:
      1. EOL API
      2. crawling via custom clients
      3. filesystem
    '''

    release_cycles = eol_client.cycles(
        product=os_id,
        absent_ok=True,
    )

    if release_cycles:
        return [
            eol.os_release_info_from_release_cycle(release_cycle)
            for release_cycle in release_cycles
        ]

    if (client := osinfo_client(os_id)):
        return client.release_infos()

    return release_infos_from_cfg(
        os_id=os_id,
        absent_ok=True,
    )


class OsInfoRoutes(aiohttp.web.View):
    async def options(self):
        return aiohttp.web.Response()

    async def get(self):
        '''
        ---
        tags:
        - OS info
        produces:
        - application/json
        parameters:
        - in: path
          name: os_id
          type: string
          required: true
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                type: object
                required:
                - name
                - reached_eol
                properties:
                  name:
                    type: string
                  reached_eol:
                    type: boolean
                  greatest_version:
                    type: string
                  eol_date:
                    type: string
        '''
        os_id = self.request.match_info.get('os_id')

        release_infos = await os_release_infos(
            os_id=eol.normalise_os_id(os_id),
            eol_client=self.request.app[consts.APP_EOL_CLIENT],
        )

        if not release_infos:
            # change to 404 eventually
            raise aiohttp.web.HTTPBadRequest(text=os_id)

        return aiohttp.web.json_response(
            data=release_infos,
            dumps=util.dict_to_json_factory,
        )
