import json
import zlib

import aiohttp.web

import oci.model
import ocm

import consts
import util


class ArtefactBlob(aiohttp.web.View):
    async def get(self):
        '''
        returns a requested artefact (from a OCM Component) as an octet-stream. This route is
        limited to artefacts with `localBlob` as access-type.

        required query-parameters:

        component: ocm-component-id (<name>:<version>)
        artefact:  has two forms:
                    1. str - interpreted as `name` attribute
                    2. json (object) - str-to-str mapping for attributes

        optional query-parameters:

        ocm_repository: ocm-repository-url
        unzip:          bool, defaults to true; if true, and artefact's access is gzipped, returned
                        content will be unzipped (for convenience)

        If artefact is not specified unambiguously, the first match will be used.
        '''
        params = self.request.rel_url.query

        component_id = util.param(params, 'component', required=True)
        if component_id.count(':') != 1:
            raise aiohttp.web.HTTPBadRequest(text='Malformed component-id')

        artefact = util.param(params, 'artefact', required=True).strip()
        if artefact.startswith('{'):
            artefact = json.loads(artefact)

            # special-handling for name/version (should refactor in ocm)
            artefact_name = artefact.pop('name', None)
            artefact_version = artefact.pop('version', None)
        elif artefact.startswith('['):
            raise aiohttp.web.HTTPBadRequest(
                text='Bad artefact: Either name or json-object is allowed',
            )
        else:
            artefact_name = artefact
            artefact = {}
            artefact_version = None

        ocm_repository = util.param(params, 'ocm_repository')
        unzip = util.param_as_bool(params, 'unzip', default=True)

        component_descriptor_lookup = self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP]

        try:
            component_descriptor = await component_descriptor_lookup(
                component_id,
                ocm_repository,
            )
            component = component_descriptor.component
        except oci.model.OciImageNotFoundException:
            raise aiohttp.web.HTTPBadRequest(text=f'Did not find {component_id=}')

        def matches(a: ocm.Artifact):
            if artefact_name and artefact_name != a.name:
                return False
            if artefact_version and artefact_version != a.version:
                return False

            for attr, value in artefact.items():
                if a.extraIdentity.get(attr) != value:
                    return False

            return True

        for a in component.iter_artefacts():
            if matches(a):
                break
        else:
            raise aiohttp.web.HTTPBadRequest(text='Did not find requested artefact')

        artefact = a
        access = artefact.access

        if not isinstance(access, ocm.LocalBlobAccess):
            raise aiohttp.web.HTTPBadRequest(
                text=f'{artefact.name=} has {access.type=}; only localBlobAccess is supported',
            )

        access: ocm.LocalBlobAccess
        digest = access.globalAccess.digest if access.globalAccess else access.localReference

        oci_client = self.request.app[consts.APP_OCI_CLIENT]
        blob = await oci_client.blob(
            image_reference=component.current_ocm_repo.component_oci_ref(component),
            digest=digest,
            absent_ok=True,
        )

        if access.mediaType == 'application/pdf':
            file_ending = '.pdf'
        elif access.mediaType == 'application/tar+gzip':
            file_ending = '.tar.gz'
        elif access.mediaType == 'application/tar':
            file_ending = '.tar'
        else:
            file_ending = ''

        fname = f'{component.name}_{component.version}_{artefact.name}{file_ending}'

        if unzip and access.mediaType == 'application/gzip':
            response = aiohttp.web.StreamResponse(
                headers={
                    'Content-Type': artefact.type,
                    'Content-Disposition': f'attachment; filename="{fname}"',
                },
            )
            await response.prepare(self.request)

            decompressor = zlib.decompressobj(wbits=31)
            async for chunk in blob.content.iter_chunked(4096):
                await response.write(decompressor.decompress(chunk))
            await response.write(decompressor.flush())
        else:
            response = aiohttp.web.StreamResponse(
                headers={
                    'Content-Type': access.mediaType,
                    'Content-Disposition': f'attachment; filename="{fname}"',
                },
            )
            await response.prepare(self.request)

            async for chunk in blob.content.iter_chunked(4096):
                await response.write(chunk)

        await response.write_eof()
        return response
