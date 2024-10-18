import collections.abc

import aiohttp.typedefs
import aiohttp.web


def cors_middleware(
    allow_origins: str | collections.abc.Iterable[str]='*',
    allow_credentials: str | collections.abc.Iterable[str]='*',
) -> aiohttp.typedefs.Middleware:

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        try:
            response = await handler(request)
        except Exception as e:
            response = e
            pass

        if not (origin := request.headers.get('Origin')):
            return response

        if allow_origins != '*' and origin not in allow_origins:
            return response

        if not request.headers.get('Access-Control-Allow-Origin'):
            set_origin = '*' if allow_origins == '*' else origin

            if allow_credentials == '*' or origin in allow_credentials:
                set_origin = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'

            response.headers['Access-Control-Allow-Origin'] = set_origin

        if (
            request.method == 'OPTIONS'
            and 'Access-Control-Request-Method' in request.headers
        ):
            allow_methods = request.headers.get('Access-Control-Request-Method')
            allow_headers = request.headers.get('Access-Control-Request-Headers', default='*')

            response.headers['Access-Control-Allow-Headers'] = allow_headers
            response.headers['Access-Control-Allow-Methods'] = allow_methods

            # this is a preflight request -> skip processing of this request in other middlewares
            raise aiohttp.web.HTTPOk(headers=response.headers)

        return response

    return middleware
