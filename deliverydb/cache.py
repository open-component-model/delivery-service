import collections.abc
import dataclasses
import datetime
import logging
import traceback

import sqlalchemy.exc
import sqlalchemy.orm.session

import deliverydb.model as dm
import deliverydb_cache.model as dcm
import deliverydb_cache.util as dcu
import util


logger = logging.getLogger(__name__)


def update_cache_entry(
    db_session: sqlalchemy.orm.session.Session,
    cache_entry: dm.DBCache,
) -> bool:
    if not (existing_cache_entry := db_session.get(dm.DBCache, cache_entry.id)):
        # cache entry does not exist yet, hence we cannot _update_ it
        return False

    try:
        existing_cache_entry.revision = existing_cache_entry.revision + 1
        existing_cache_entry.last_update = datetime.datetime.now(datetime.timezone.utc)
        existing_cache_entry.delete_after = cache_entry.delete_after
        existing_cache_entry.keep_until = cache_entry.keep_until
        existing_cache_entry.costs = cache_entry.costs
        existing_cache_entry.size = cache_entry.size
        existing_cache_entry.value = cache_entry.value

        db_session.commit()
        return True
    except Exception:
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

        db_session.rollback()

    return False


def add_or_update_cache_entry(
    db_session: sqlalchemy.orm.session.Session,
    cache_entry: dm.DBCache,
) -> bool:
    try:
        db_session.add(cache_entry)
        db_session.commit()
        return True

    except sqlalchemy.exc.IntegrityError:
        db_session.rollback()

        # try to update cache entry instead because it may have already existed and hence raised a
        # duplicated key error (this is the expected case if a cache entry got stale or it is
        # calculated multiple times concurrently)
        if update_cache_entry(
            db_session=db_session,
            cache_entry=cache_entry,
        ):
            return True

        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

    except Exception:
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

        db_session.rollback()

    return False


def find_cached_value(
    db_session: sqlalchemy.orm.session.Session,
    id: str,
) -> bytes | None:
    if not (cache_entry := db_session.get(dm.DBCache, id)):
        return None

    now = datetime.datetime.now(datetime.timezone.utc)

    # explicitly cast timezone to UTC to also support sqlite usage since it drops the timezone
    # information and always casts to UTC internally
    if cache_entry.delete_after and now > cache_entry.delete_after.astimezone(datetime.timezone.utc):
        # cache entry is already stale -> don't used it
        # TODO: return stale entry already to client and calculate new value in the background and
        # update client once new value is available
        return None

    value = cache_entry.value

    try:
        cache_entry.last_read = now
        cache_entry.read_count = cache_entry.read_count + 1
        db_session.commit()
    except Exception:
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

        db_session.rollback()

    return value


def dbcached_function(
    encoding_format: dcm.EncodingFormat | str = dcm.EncodingFormat.PICKLE,
    ttl_seconds: int = 0,
    keep_at_least_seconds: int = 0,
    max_size_octets: int = 0,
    exclude_args_at_idx: collections.abc.Sequence[int] = tuple(),
    exclude_kwargs: collections.abc.Sequence[str] = tuple(),
    skip_values: collections.abc.Sequence = tuple(),
):
    if ttl_seconds and ttl_seconds < keep_at_least_seconds:
        raise ValueError(
            'If time-to-live (`ttl_seconds`) and `keep_at_least_seconds` are both specified, '
            '`ttl_seconds` must be greater or equal than `keep_at_least_seconds`.',
        )

    def decorator(func):
        def wrapper(*args, **kwargs):
            function_name = f'{func.__module__}.{func.__qualname__}'

            cachable_args = tuple(
                arg for idx, arg in enumerate(args) if idx not in exclude_args_at_idx
            )
            cachable_kwargs = dict(
                [key, value] for key, value in kwargs.items() if key not in exclude_kwargs
            )

            # remove `db_session` from kwargs to allow proper serialisation
            if not (db_session := cachable_kwargs.pop('db_session', None)):
                logger.warning(f'Could not parse `db_session` parameter from {function_name=}')
                return func(*args, **kwargs)

            shortcut_cache = cachable_kwargs.pop('shortcut_cache', False)

            descriptor = dcm.CachedPythonFunction(
                encoding_format=encoding_format,
                function_name=function_name,
                args=dcu.normalise_and_serialise_object(cachable_args),
                kwargs=dcu.normalise_and_serialise_object(cachable_kwargs),
            )

            if not shortcut_cache and (
                value := find_cached_value(
                    db_session=db_session,
                    id=descriptor.id,
                )
            ):
                return dcu.deserialise_cache_value(
                    value=value,
                    encoding_format=encoding_format,
                )

            start = datetime.datetime.now()
            result = func(*args, **kwargs)
            duration = datetime.datetime.now() - start

            if result in skip_values:
                # don't store result in cache if it is explicitly excluded
                return result

            value = dcu.serialise_cache_value(
                value=result,
                encoding_format=encoding_format,
            )

            if max_size_octets > 0 and len(value) > max_size_octets:
                # don't store result in cache if it exceeds max size for an individual cache entry
                return result

            now = datetime.datetime.now(datetime.timezone.utc)
            cache_entry = dm.DBCache(
                id=descriptor.id,
                descriptor=util.dict_serialisation(dataclasses.asdict(descriptor)),
                delete_after=now + datetime.timedelta(seconds=ttl_seconds) if ttl_seconds else None,
                keep_until=now + datetime.timedelta(seconds=keep_at_least_seconds),
                costs=int(duration.total_seconds() * 1000),
                size=len(value),
                value=value,
            )

            add_or_update_cache_entry(
                db_session=db_session,
                cache_entry=cache_entry,
            )

            return result

        return wrapper

    return decorator


def mark_for_deletion(
    db_session: sqlalchemy.orm.session.Session,
    id: str,
    delete_after: datetime.datetime | None = None,
    defer_db_commit: bool = False,
) -> bool:
    if not (cache_entry := db_session.get(dm.DBCache, id)):
        return True

    if not delete_after:
        delete_after = datetime.datetime.now(tz=datetime.timezone.utc)

    try:
        cache_entry.delete_after = delete_after

        if not defer_db_commit:
            db_session.commit()
        return True
    except Exception:
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

        db_session.rollback()

    return False


def mark_function_cache_for_deletion(
    encoding_format: dcm.EncodingFormat | str,
    function: collections.abc.Callable | str,
    db_session: sqlalchemy.orm.session.Session,
    delete_after: datetime.datetime | None = None,
    defer_db_commit: bool = False,
    *args,
    **kwargs,
):
    if isinstance(function, str):
        function_name = function
    else:
        function_name = f'{function.__module__}.{function.__qualname__}'

    descriptor = dcm.CachedPythonFunction(
        encoding_format=encoding_format,
        function_name=function_name,
        args=dcu.normalise_and_serialise_object(args),
        kwargs=dcu.normalise_and_serialise_object(kwargs),
    )

    mark_for_deletion(
        db_session=db_session,
        id=descriptor.id,
        delete_after=delete_after,
        defer_db_commit=defer_db_commit,
    )
