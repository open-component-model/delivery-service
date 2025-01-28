import functools
import os

import watchdog.events
import watchdog.observers.polling

import ci.util

import secret_mgmt


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
    # secret factory creation from k8s secrets
    if path := os.environ.get('SECRET_FACTORY_PATH'):
        watch_for_file_changes(path)
        return secret_mgmt.SecretFactory.from_dir(
            secrets_dir=path,
        )

    # fallback: use cfg factory and convert it to secret factory structure
    # this is handy for local development where the cfg-factory is available
    return secret_mgmt.SecretFactory.from_cfg_factory(
        cfg_factory=ci.util.ctx().cfg_factory(),
    )
