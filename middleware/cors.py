import collections.abc

import aiohttp.typedefs
import aiohttp.web


def cors_headers(
    request: aiohttp.web.Request,
    allow_origins: str | collections.abc.Iterable[str]='*',
    allow_credentials: str | collections.abc.Iterable[str]='*',
) -> dict:
    headers = {}

    if not (origin := request.headers.get('Origin')):
        return headers

    if allow_origins != '*' and origin not in allow_origins:
        return headers

    if not request.headers.get('Access-Control-Allow-Origin'):
        set_origin = '*' if allow_origins == '*' else origin

        if allow_credentials == '*' or origin in allow_credentials:
            set_origin = origin
            headers['Access-Control-Allow-Credentials'] = 'true'

        headers['Access-Control-Allow-Origin'] = set_origin

    if (
        request.method == 'OPTIONS'
        and 'Access-Control-Request-Method' in request.headers
    ):
        allow_methods = request.headers.get('Access-Control-Request-Method')
        allow_headers = request.headers.get('Access-Control-Request-Headers', default='*')

        headers['Access-Control-Allow-Headers'] = allow_headers
        headers['Access-Control-Allow-Methods'] = allow_methods

    return headers


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

        response.headers.extend(cors_headers(
            request=request,
            allow_origins=allow_origins,
            allow_credentials=allow_credentials,
        ))

        if request.method == 'OPTIONS':
            # this is a preflight request -> skip processing of this request in other middlewares
            raise aiohttp.web.HTTPOk(headers=response.headers)

        return response

    return middleware
