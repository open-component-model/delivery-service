import json
import zlib

import falcon

import http_requests


class DecompressorMiddleware:
    '''
    Used to decompress request body in case it is compressed. The decompressed payload is stored
    in `request.context.media`.
    '''

    def process_resource(self, req: falcon.Request, resp: falcon.Response, resource, params):
        if not (content_encoding := req.get_header('Content-Encoding')):
            req.context.media = req.get_media(default_when_empty=None)
            return

        if content_encoding == http_requests.EncodingMethod.GZIP:
            try:
                decompressor = zlib.decompressobj(wbits=31)
                data = decompressor.decompress(req.stream.read())
            except Exception as e:
                raise falcon.HTTPBadRequest(
                    title='Invalid gzip data',
                    description=e,
                )

        else:
            raise NotImplementedError(content_encoding)

        if req.content_type == 'application/json':
            try:
                data = json.loads(data)
            except Exception as e:
                raise falcon.HTTPBadRequest(
                    title=f'Invalid json data: {data}',
                    description=e,
                )

        req.context.media = data
