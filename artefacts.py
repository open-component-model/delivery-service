import json
import zlib

import falcon

import ocm
import oci.model


class ArtefactBlob:
    def __init__(
        self,
        component_descriptor_lookup,
        oci_client,
    ):
        self.component_descriptor_lookup = component_descriptor_lookup
        self.oci_client = oci_client

    def on_get(self, req: falcon.Request, resp: falcon.Response):
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
        component_id = req.get_param(
            'component',
            required=True,
        )
        if component_id.count(':') != 1:
            raise falcon.HTTPBadRequest(title='malformed component-id')

        artefact = req.get_param(
            'artefact',
            required=True,
        ).strip()
        if artefact.startswith('{'):
            artefact = json.loads(artefact)

            # special-handling for name/version (should refactor in gci/componentmodel)
            artefact_name = artefact.pop('name', None)
            artefact_version = artefact.pop('version', None)
        elif artefact.startswith('['):
            raise falcon.HTTPBadRequest(title='bad artefact: either name or json-object is allowed')
        else:
            artefact_name = artefact
            artefact = {}
            artefact_version = None

        ocm_repository = req.get_param('ocm_repository')
        unzip = req.get_param_as_bool('unzip', default=True)

        try:
            component = self.component_descriptor_lookup(
                component_id,
                ocm_repository,
            ).component
        except oci.model.OciImageNotFoundException:
            raise falcon.HTTPBadRequest(title=f'did not find {component_id=}')

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
            raise falcon.HTTPBadRequest('did not find requested artefact')

        artefact = a
        access = artefact.access

        if not isinstance(access, ocm.LocalBlobAccess):
            raise falcon.HTTPBadRequest(
                f'{artefact.name=} has {access.type=}; only localBlobAccess is supported',
            )

        access: ocm.LocalBlobAccess

        if access.globalAccess:
            digest = access.globalAccess.digest
            size = access.globalAccess.size
        else:
            digest = access.localReference
            size = access.size

        blob = self.oci_client.blob(
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

        # required to allow download from delivery-dashboard (CORS):
        # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#attributes
        resp.set_header('Content-Disposition', f'attachment; filename="{fname}"')

        if unzip and access.mediaType == 'application/gzip':
            def iter_uncompressed():
                decompressor = zlib.decompressobj(wbits=31)
                for chunk in blob.iter_content(chunk_size=4096):
                    yield decompressor.decompress(chunk)
                yield decompressor.flush()

            resp.content_type = artefact.type
            resp.stream = iter_uncompressed()
            return

        resp.content_type = access.mediaType
        resp.content_length = size
        resp.stream = blob.iter_content(chunk_size=4096)
