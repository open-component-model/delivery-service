import functools
import json
import os
import threading

import watchdog.events
import watchdog.observers.polling

import ccc.secrets_server
import ci.util
import model


def _cfg_factory_from_secret(path: str) -> model.ConfigFactory:
    path = ci.util.existing_file(path)

    with open(path, 'rb') as f:
        cipher_text = f.read()

    secret = ccc.secrets_server.get_secret_cfg_from_env_if_available()
    cfg = ccc.secrets_server._decrypt_cipher_text(
        encrypted_cipher_text=cipher_text,
        secret=secret,
    ).decode('utf-8')

    return model.ConfigFactory.from_dict(json.loads(cfg))


class FileChangeEventHandler(watchdog.events.FileSystemEventHandler):
    def dispatch(self, event):
        # Clear cache so that the next time the cfg factory is needed it is
        # created using the new cfg
        cfg_factory.cache_clear()


@functools.cache
def watch_for_file_changes(
    path: str,
    event_handler: FileChangeEventHandler=None,
):
    if not event_handler:
        event_handler = FileChangeEventHandler()
    observer = watchdog.observers.polling.PollingObserver(60)
    observer.schedule(event_handler, path)
    observer.start()


class RepeatTimer(threading.Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(
                *self.args,
                **self.kwargs,
            )


def refresh_periodically(
    refresh_interval_seconds: float,
):
    timer = RepeatTimer(
        refresh_interval_seconds,
        cfg_factory.cache_clear,
    )
    timer.daemon = True
    timer.start()


@functools.cache
def cfg_factory() -> model.ConfigFactory:
    # cfg factory creation from k8s secret
    if path := os.environ.get('CFG_FACTORY_SECRET_PATH'):
        watch_for_file_changes(path)
        return _cfg_factory_from_secret(path)

    # fallback to default cfg factory creation
    refresh_interval_seconds = 60 * 60 * 12 # 12h
    refresh_periodically(refresh_interval_seconds=refresh_interval_seconds)
    return ci.util.ctx().cfg_factory()
