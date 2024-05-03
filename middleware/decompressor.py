import json
import logging
import zlib

import falcon

import http_requests


logger = logging.getLogger(__name__)


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
                import traceback
                logger.error(traceback.format_exc())
                raise falcon.HTTPBadRequest(
                    title='Invalid gzip data',
                    description=e,
                )

        else:
            raise NotImplementedError(content_encoding)

        if req.content_type == 'application/json':
            data = json.loads(data)

        req.context.media = data
