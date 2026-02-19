import functools
import logging
import os

import watchdog.events
import watchdog.observers.polling

import secret_mgmt


logger = logging.getLogger(__name__)
own_dir = os.path.abspath(os.path.dirname(__file__))


class FileChangeEventHandler(watchdog.events.FileSystemEventHandler):
    def dispatch(self, event):
        # Clear cache so that the next time the cfg factory is needed it is
        # created using the new cfg
        secret_factory.cache_clear()


@functools.cache
def watch_for_file_changes(
    path: str,
    event_handler: FileChangeEventHandler=None,
):
    if not event_handler:
        event_handler = FileChangeEventHandler()
    observer = watchdog.observers.polling.PollingObserver(timeout=60)
    observer.schedule(event_handler, path)
    observer.start()


@functools.cache
def secret_factory() -> secret_mgmt.SecretFactory:
    local_path = os.path.join(own_dir, 'secrets')

    # secret factory creation from k8s secrets
    if not (path := os.environ.get('SECRET_FACTORY_PATH')):
        path = local_path

    watch_for_file_changes(path)
    secret_factory = secret_mgmt.SecretFactory.from_dir(
        secrets_dir=path,
    )

    if not (secret_types := secret_factory.secret_types()):
        logger.warning(
            'Found no directory containing credentials, hence no secrets will be available. If '
            'secrets are required, consider either setting the `SECRET_FACTORY_PATH` env-var '
            'pointing to the directory containing the secrets, or use the templates provided at the '
            f'standard lookup location at "{local_path}".'
        )
    else:
        logger.info(f'Found secrets of the following types: {secret_types}')

    return secret_factory
