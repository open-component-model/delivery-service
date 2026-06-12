import logging
import traceback

import aiohttp.typedefs
import aiohttp.web
import aiohttp.web_exceptions


logger = logging.getLogger(__name__)


def errors_middleware() -> aiohttp.typedefs.Middleware:

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        try:
            return await handler(request)
        except aiohttp.web_exceptions.HTTPException as e:
            error = e
            stacktrace = traceback.format_exc()
        except Exception:
            # only raise internal server error in case error was not already handled properly
            error = aiohttp.web.HTTPInternalServerError
            stacktrace = traceback.format_exc()

        logger.error(stacktrace)
        raise error

    return middleware
