import datetime

import aiohttp.typedefs
import aiohttp.web
import prometheus_client

import middleware.auth


APP_REQUEST_LATENCY_SECONDS = 'request_latency_seconds'
APP_REQUESTS_IN_PROGRESS_TOTAL = 'requests_in_progress_total'
APP_REQUESTS_TOTAL = 'requests_total'


@middleware.auth.noauth
class Metrics(aiohttp.web.View):
    async def get(self):
        '''
        ---
        tags:
        - Metrics
        produces:
        - text/plain
        responses:
          "200":
            description: Successful operation.
        '''
        return aiohttp.web.Response(
            body=prometheus_client.generate_latest(),
            content_type='text/plain',
        )


def add_prometheus_middleware(
    app: aiohttp.web.Application,
) -> aiohttp.typedefs.Middleware:

    @aiohttp.web.middleware
    async def middleware(
        request: aiohttp.web.Request,
        handler: aiohttp.typedefs.Handler,
    ) -> aiohttp.web.StreamResponse:
        start_time = datetime.datetime.now()
        request.app[APP_REQUESTS_IN_PROGRESS_TOTAL].labels(request.path, request.method).inc()

        response = await handler(request)

        latency = datetime.datetime.now() - start_time
        request.app[APP_REQUEST_LATENCY_SECONDS].labels(request.path, request.method).observe(latency.total_seconds()) # noqa: E501
        request.app[APP_REQUESTS_IN_PROGRESS_TOTAL].labels(request.path, request.method).dec()
        request.app[APP_REQUESTS_TOTAL].labels(request.path, request.method, response.status).inc()

        return response

    app[APP_REQUEST_LATENCY_SECONDS] = prometheus_client.Histogram(
        name=APP_REQUEST_LATENCY_SECONDS,
        documentation='Request latency (seconds)',
        labelnames=['endpoint', 'method'],
    )
    app[APP_REQUESTS_IN_PROGRESS_TOTAL] = prometheus_client.Gauge(
        name=APP_REQUESTS_IN_PROGRESS_TOTAL,
        documentation='Requests in progress total',
        labelnames=['endpoint', 'method'],
    )
    app[APP_REQUESTS_TOTAL] = prometheus_client.Counter(
        name=APP_REQUESTS_TOTAL,
        documentation='Requests total',
        labelnames=['endpoint', 'method', 'status'],
    )

    app.router.add_view(
        '/metrics',
        handler=Metrics,
    )
    app.middlewares.insert(0, middleware)

    return app
