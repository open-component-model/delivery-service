import collections.abc
import dataclasses
import datetime
import logging
import traceback

import aiohttp.web
import sqlalchemy.exc
import sqlalchemy.ext.asyncio as sqlasync

import consts
import deliverydb.model as dm
import deliverydb_cache.model as dcm
import deliverydb_cache.util as dcu
import util


logger = logging.getLogger(__name__)


async def update_cache_entry(
    db_session: sqlasync.session.AsyncSession,
    cache_entry: dm.DBCache,
) -> bool:
    if not (existing_cache_entry := await db_session.get(dm.DBCache, cache_entry.id)):
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

        await db_session.commit()
        return True
    except Exception:
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

        await db_session.rollback()

    return False


async def add_or_update_cache_entry(
    db_session: sqlasync.session.AsyncSession,
    cache_entry: dm.DBCache,
) -> bool:
    try:
        db_session.add(cache_entry)
        await db_session.commit()
        return True

    except sqlalchemy.exc.IntegrityError:
        await db_session.rollback()

        # try to update cache entry instead because it may have already existed and hence raised a
        # duplicated key error (this is the expected case if a cache entry got stale or it is
        # calculated multiple times concurrently)
        if await update_cache_entry(
            db_session=db_session,
            cache_entry=cache_entry,
        ):
            return True

        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

    except Exception:
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

        await db_session.rollback()

    return False


async def find_cached_value(
    db_session: sqlasync.session.AsyncSession,
    id: str,
) -> bytes | None:
    if not (cache_entry := await db_session.get(dm.DBCache, id)):
        return None

    now = datetime.datetime.now(datetime.timezone.utc)

    if cache_entry.delete_after and now > cache_entry.delete_after:
        # cache entry is already stale -> don't used it
        # TODO: return stale entry already to client and calculate new value in the background and
        # update client once new value is available
        return None

    value = cache_entry.value

    try:
        cache_entry.last_read = now
        cache_entry.read_count = cache_entry.read_count + 1
        await db_session.commit()
    except Exception:
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

        await db_session.rollback()

    return value


def dbcached_function(
    encoding_format: dcm.EncodingFormat | str=dcm.EncodingFormat.PICKLE,
    ttl_seconds: int=0,
    keep_at_least_seconds: int=0,
    max_size_octets: int=0,
    exclude_kwargs: collections.abc.Sequence[str]=tuple(),
):
    if ttl_seconds and ttl_seconds < keep_at_least_seconds:
        raise ValueError(
            'If time-to-live (`ttl_seconds`) and `keep_at_least_seconds` are both specified, '
            '`ttl_seconds` must be greater or equal than `keep_at_least_seconds`.'
        )

    def decorator(func):
        async def wrapper(*args, **kwargs):
            function_name = f'{func.__module__}.{func.__name__}'

            cachable_args = tuple(
                arg
                for arg in args
                if not isinstance(arg, collections.abc.Callable)
            )
            cachable_kwargs = dict(
                [key, value]
                for key, value in kwargs.items()
                if key not in exclude_kwargs and not isinstance(value, collections.abc.Callable)
            )

            # remove `db_session` from kwargs to allow proper serialisation
            if not (db_session := cachable_kwargs.pop('db_session', None)):
                logger.warning(f'Could not parse `db_session` parameter from {function_name=}')
                return await func(*args, **kwargs)

            descriptor = dcm.CachedPythonFunction(
                encoding_format=encoding_format,
                function_name=function_name,
                args=dcu.normalise_and_serialise_object(cachable_args),
                kwargs=dcu.normalise_and_serialise_object(cachable_kwargs),
            )

            if value := await find_cached_value(
                db_session=db_session,
                id=descriptor.id,
            ):
                return dcu.deserialise_cache_value(
                    value=value,
                    encoding_format=encoding_format,
                )

            start = datetime.datetime.now()
            result = await func(*args, **kwargs)
            duration = datetime.datetime.now() - start

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

            await add_or_update_cache_entry(
                db_session=db_session,
                cache_entry=cache_entry,
            )

            return result

        return wrapper

    return decorator


def dbcached_route(
    encoding_format: dcm.EncodingFormat | str=dcm.EncodingFormat.PICKLE,
    ttl_seconds: int=0,
    keep_at_least_seconds: int=0,
    max_size_octets: int=0,
):
    if not encoding_format.startswith('pickle'):
        raise ValueError(
            f'Unsupported encoding format for HTTP route cache (must be pickle): {encoding_format}'
        )

    if ttl_seconds and ttl_seconds < keep_at_least_seconds:
        raise ValueError(
            'If time-to-live (`ttl_seconds`) and `keep_at_least_seconds` are both specified, '
            '`ttl_seconds` must be greater or equal than `keep_at_least_seconds`.'
        )

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # first non-keyword arg of http route functions is always the request object
            request: aiohttp.web.Request = args[0].request
            db_session: sqlasync.session.AsyncSession = request[consts.REQUEST_DB_SESSION]

            body = await request.json() if request.has_body else None

            descriptor = dcm.CachedHTTPRoute(
                encoding_format=encoding_format,
                route=request.path,
                params=dcu.normalise_and_serialise_object(request.url.query),
                body=dcu.normalise_and_serialise_object(body) if body else None,
            )

            if value := await find_cached_value(
                db_session=db_session,
                id=descriptor.id,
            ):
                return dcu.deserialise_cache_value(
                    value=value,
                    encoding_format=encoding_format,
                )

            start = datetime.datetime.now()
            result: aiohttp.web.Response = await func(*args, **kwargs)
            duration = datetime.datetime.now() - start

            if result.status >= 400:
                # don't cache error responses -> those might only be temporarily
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

            await add_or_update_cache_entry(
                db_session=db_session,
                cache_entry=cache_entry,
            )

            return result

        return wrapper

    return decorator
