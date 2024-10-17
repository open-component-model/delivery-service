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
        except aiohttp.web_exceptions.HTTPException as e:
            error = e
            stacktrace = traceback.format_exc()
        except Exception:
            # only raise internal server error in case error was not already handled properly
            error = aiohttp.web.HTTPInternalServerError
            stacktrace = traceback.format_exc()

        logger.error(stacktrace)

        if not es_client:
            raise error

        content_length_limit = 4096
        if not request.content_length or request.content_length <= content_length_limit:
            if request.content_type == 'application/json':
                try:
                    body = await request.json()
                except Exception:
                    body = (
                        'Error while trying to retrieve request\'s JSON body '
                        f'({await request.text()}); {traceback.format_exc()}'
                    )
            else:
                body = await request.text()
        else:
            body = (
                'Request\'s body was skipped because content length exceeds limit '
                f'({request.content_length=} > {content_length_limit})'
            )

        exception_metric = metric.ExceptionMetric.create(
            service='delivery-service',
            stacktrace=stacktrace,
            request=body,
            params=dict(request.rel_url.query),
        )

        ccc.elasticsearch.metric_to_es(
            es_client=es_client,
            metric=exception_metric,
            index_name=metric.index_name(exception_metric),
        )

        raise error

    return middleware
