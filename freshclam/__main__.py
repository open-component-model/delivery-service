#!/usr/bin/env python3

import os
import subprocess

import starlette.applications
import starlette.responses
import starlette.routing
import starlette.staticfiles
import uvicorn

import paths


status_file = os.path.join('/', 'freshclam', 'status')


async def readiness(request):
    if not os.path.isfile(status_file):
        return starlette.responses.HTMLResponse(status_code=425)

    with open(status_file, 'r') as f:
        status = f.read().strip()

    if status == 'outdated':
        return starlette.responses.HTMLResponse(status_code=400)
    elif status == 'up-to-date':
        return starlette.responses.HTMLResponse(status_code=200)
    else:
        return starlette.responses.HTMLResponse(status_code=501)


def start_server(path, directory, port, debug=False):
    app = starlette.applications.Starlette(
        routes=[
            starlette.routing.Route(path='/readiness', endpoint=readiness, methods=['GET']),
        ],
        debug=debug,
    )
    f = starlette.staticfiles.StaticFiles(directory=directory)
    app.mount(path, f)

    uvicorn.run(app, host='0.0.0.0', port=port)


def main():
    os.mkdir('/freshclam')

    subprocess.run(
        args=[
            'freshclam',
            '--daemon',
            '--config-file',
            paths.freshclam_config_path,
        ],
    )
    start_server('/', '/www', 8080)


if __name__ == '__main__':
    main()
