import collections
import datetime
import hashlib
import os
import pickle
import threading

import cachetools.keys

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache', 'dora')


class FilesystemCache:
    '''
    Base class which implements a basic filesytem cache using pickle. This implementation does _not_
    take care of clearing the cache, e.g. if it reaches a certain size.
    '''
    def __get_item__(self, filepath: str):
        if os.path.exists(filepath):
            return pickle.load(open(filepath, 'rb'))
        raise self.__missing__(filepath)

    def __set_item__(self, filepath: str, value):
        cache_dir = os.path.dirname(filepath)
        if not os.path.isdir(cache_dir):
            os.makedirs(name=cache_dir, exist_ok=True)

        pickle.dump(value, open(filepath, 'wb'))

    def __missing__(self, filepath: str):
        raise KeyError(filepath)


class LFUFilesystemCache(FilesystemCache):
    '''
    Implements a Least-Frequently-Used filesystem cache. If `max_total_size_mib` is reached, the
    least frequently used items are removed from the cache accordingly until enough space is
    available again to store new items.

    @param max_total_size_mib:
        the maximum allowed total cache size in MiB, if `None`, LFU cache clearing is disabled
    '''
    def __init__(self, max_total_size_mib: int | None=None):
        # convert MiB -> bytes
        self._max_total_size = max_total_size_mib * 1024 * 1024 if max_total_size_mib else None
        self._item_sizes = {}
        self._total_size = 0
        self._ref_counters = collections.Counter()

        self._item_sizes_lock = threading.Lock()
        self._ref_counters_lock = threading.Lock()

    def __get_item__(self, filepath: str):
        item = super().__get_item__(filepath)

        if self._max_total_size:
            with self._ref_counters_lock:
                self._ref_counters[filepath] -= 1

        return item

    def __set_item__(self, filepath: str, value):
        if not self._max_total_size:
            return super().__set_item__(filepath, value)

        cache_dir = os.path.dirname(filepath)
        if not os.path.isdir(cache_dir):
            os.makedirs(name=cache_dir, exist_ok=True)

        pickled_value = pickle.dumps(value)

        item_size = len(pickled_value)
        if item_size > self._max_total_size:
            raise ValueError(f'value too large ({item_size=})')

        while self._total_size + item_size > self._max_total_size:
            self.pop_item()

        with self._item_sizes_lock:
            self._item_sizes[filepath] = item_size
        self._total_size += item_size
        with self._ref_counters_lock:
            self._ref_counters[filepath] -= 1

        with open(filepath, 'wb') as f:
            f.write(pickled_value)

    def pop_item(self):
        with self._ref_counters_lock:
            ((filepath, _),) = self._ref_counters.most_common(1)

        value = self.__get_item__(filepath)
        try:
            os.remove(filepath)
        except OSError:
            pass

        with self._item_sizes_lock:
            self._total_size -= self._item_sizes[filepath]
            del self._item_sizes[filepath]
        with self._ref_counters_lock:
            self._ref_counters.pop(filepath)

        return (filepath, value)


class TTLFilesystemCache(LFUFilesystemCache):
    '''
    Implements a Time-To-Live filesystem cache. If an item is older than `ttl`, it is removed from
    the cache. If `max_total_size_mib` is reached, the least frequently used items are removed from
    the cache accordingly until enough space is available again to store new items.

    @param ttl:
        the maximum allowed time a cache item is valid in seconds
    @param max_total_size_mib:
        the maximum allowed total cache size in MiB, if `None`, LFU cache clearing is disabled
    '''
    def __init__(self, ttl: int, max_total_size_mib: int):
        super().__init__(max_total_size_mib)
        self._ttl = ttl

    def __get_item__(self, filepath: str):
        if os.path.exists(filepath):
            modified_on = datetime.datetime.fromtimestamp(os.path.getmtime(filepath))
            age_seconds = datetime.datetime.now() - modified_on

            if age_seconds.total_seconds() < self._ttl:
                return super().__get_item__(filepath)

        return self.__missing__(filepath)

    def __set_item__(self, filepath: str, value):
        super().__set_item__(filepath, value)


def cached(
    cache: FilesystemCache,
    key_func: collections.abc.Callable=cachetools.keys.hashkey,
    cache_dir: str=default_cache_dir,
):
    '''
    Decorator to wrap a function with a callable that saves results to a defined `FilesystemCache`.
    '''
    def decorator(func):
        def wrapper(*args, **kwargs):
            key = hashlib.sha1()
            for key_part in key_func(*args, **kwargs):
                key.update(str(key_part).encode('utf-8'))

            filepath = os.path.join(cache_dir, key.hexdigest())

            try:
                return cache.__get_item__(filepath)
            except KeyError:
                pass

            result = func(*args, **kwargs)
            cache.__set_item__(filepath, result)

            return result

        return wrapper
    return decorator
