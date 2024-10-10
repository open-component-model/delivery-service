import logging
import traceback

import aiohttp.typedefs
import aiohttp.web
import aiohttp.web_exceptions

import ccc.elasticsearch

import metric


logger = logging.getLogger(__name__)


def errors_middleware(
    es_client: ccc.elasticsearch.ElasticSearchClient | None,
) -> aiohttp.typedefs.Middleware:

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        try:
            return await handler(request)
        except Exception as e:
            if getattr(e, '__module__', None) == aiohttp.web_exceptions.__name__:
                error = e
            else:
                # only raise internal server error in case error was not already handled properly
                error = aiohttp.web.HTTPInternalServerError

            stacktrace = traceback.format_exc()
            logger.error(stacktrace)

            if not es_client:
                raise error

            try:
                body = await request.json()
            except:
                body = None

            exception_metric = metric.ExceptionMetric.create(
                service='delivery-service',
                stacktrace=stacktrace,
                request=body,
                params=request.rel_url.query,
            )
            try:
                ccc.elasticsearch.metric_to_es(
                    es_client=es_client,
                    metric=exception_metric,
                    index_name=metric.index_name(exception_metric),
                )
            except:
                logger.warning(
                    'An exception occurred whilst trying to log to elasticsearch - will ignore'
                )
                traceback.print_exc()

            # raise HTTP error to not leak logs to client
            raise error

    return middleware
