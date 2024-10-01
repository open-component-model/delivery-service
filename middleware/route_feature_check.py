import collections.abc

import aiohttp.typedefs
import aiohttp.web

import features
import util


def _feature_name_set(
    feature_list: collections.abc.Iterable[features.FeatureBase],
) -> set[str]:
    return set([f.name for f in feature_list])


def feature_check_middleware(
    unavailable_features: collections.abc.Iterable[features.FeatureBase],
) -> aiohttp.typedefs.Middleware:
    '''
    Used to catch requests that require features which are unavailable. Returns a
    response with status code 400 and a list of the missing features.
    '''

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        if not (required_features := getattr(handler, 'required_features', False)):
            # no features required
            return await handler(request)

        if request.method == 'OPTIONS':
            return await handler(request)

        if (
            missing_features := _feature_name_set(required_features)
            & _feature_name_set(unavailable_features)
        ):
            raise aiohttp.web.HTTPBadRequest(
                reason='Feature is inactive',
                text=util.dict_to_json_factory({
                    'error_id': 'feature-inactive',
                    'missing_features': list(missing_features)
                }),
                content_type='application/json',
            )

        return await handler(request)

    return middleware
