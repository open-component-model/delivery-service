import collections.abc
import dataclasses
import datetime
import http
import logging
import traceback

import aiohttp.web
import dacite
import sqlalchemy.exc
import sqlalchemy.ext.asyncio as sqlasync

import consts
import deliverydb.model as dm
import deliverydb_cache.model as dcm
import deliverydb_cache.util as dcu
import features
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
            function_name = f'{func.__module__}.{func.__qualname__}'

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

            shortcut_cache = cachable_kwargs.pop('shortcut_cache', False)

            descriptor = dcm.CachedPythonFunction(
                encoding_format=encoding_format,
                function_name=function_name,
                args=dcu.normalise_and_serialise_object(cachable_args),
                kwargs=dcu.normalise_and_serialise_object(cachable_kwargs),
            )

            if not shortcut_cache and (value := await find_cached_value(
                db_session=db_session,
                id=descriptor.id,
            )):
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


def parse_shortcut_cache(
    request: aiohttp.web.Request,
) -> bool:
    '''
    Parses the information, if existing cache entries should be ignored, from the given request
    object. If the optional query parameter `shortcutCache` is set to a truthy value, it evaluates
    to `True`. Otherwise, the value of the `Shortcut-Cache` http header is considered.
    '''
    if util.param_as_bool(request.rel_url.query, 'shortcutCache', default=False):
        return True

    if util.param_as_bool(request.headers, 'Shortcut-Cache', default=False):
        return True

    return False


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

            shortcut_cache = parse_shortcut_cache(request)

            if not shortcut_cache and (value := await find_cached_value(
                db_session=db_session,
                id=descriptor.id,
            )):
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


async def mark_for_deletion(
    db_session: sqlasync.session.AsyncSession,
    id: str,
    delete_after: datetime.datetime | None=None,
) -> bool:
    if not (cache_entry := await db_session.get(dm.DBCache, id)):
        return True

    if not delete_after:
        delete_after = datetime.datetime.now(tz=datetime.timezone.utc)

    try:
        cache_entry.delete_after = delete_after

        await db_session.commit()
        return True
    except Exception:
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)

        await db_session.rollback()

    return False


async def mark_function_cache_for_deletion(
    encoding_format: dcm.EncodingFormat | str,
    function: collections.abc.Callable | str,
    db_session: sqlasync.session.AsyncSession,
    delete_after: datetime.datetime | None=None,
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

    await mark_for_deletion(
        db_session=db_session,
        id=descriptor.id,
        delete_after=delete_after,
    )


class DeliveryDBCache(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    async def delete(self):
        '''
        ---
        description: Mark the delivery-db cache entry with the given id for deletion.
        tags:
        - Artefact metadata
        parameters:
        - in: query
          name: id
          schema:
            type: string
          required: false
          description:
            The descriptor id of the cache entry which should be marked for deletion. See
            `deliverydb_cache.model.CacheDescriptorBase` for available descriptor types and how
            their id is composed. If not specified, the full descriptor must be passed in the body.
        - in: query
          name: deleteAfter
          schema:
            type: string
          required: false
          description:
            Optional, timezone-aware iso-formated datetime to schedule the deletion of the
            referenced cache entry. If not set, the entry will be marked for immediate deletion.
        - in: body
          name: descriptor
          schema:
            type: object
          description:
            If the descriptor id is not passed as param, this descriptor is used to calculate the
            required id. The passed descriptor must be serialisable by one of the dataclasses which
            inherits `deliverydb_cache.model.CacheDescriptorBase` base class.
        responses:
          "204":
            description: Successful operation.
        '''
        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
        params = self.request.rel_url.query

        now = datetime.datetime.now(tz=datetime.timezone.utc)

        id = util.param(params, 'id', required=False)
        delete_after_str = util.param(params, 'deleteAfter', default=now.isoformat())
        delete_after = datetime.datetime.fromisoformat(delete_after_str)

        if not id:
            if not self.request.has_body:
                raise aiohttp.web.HTTPBadRequest(
                    text='Either `id` param or descriptor body must be specified.',
                )

            type_to_class = {
                dcm.CacheValueType.COMPONENT_DESCRIPTOR: dcm.CachedComponentDescriptor,
                dcm.CacheValueType.PYTHON_FUNCTION: dcm.CachedPythonFunction,
                dcm.CacheValueType.HTTP_ROUTE: dcm.CachedHTTPRoute,
            }

            body = await self.request.json()
            cache_value_type = util.get_enum_value_or_raise(body.get('type'), dcm.CacheValueType)

            descriptor = dacite.from_dict(
                data_class=type_to_class[cache_value_type],
                data=body,
                config=dacite.Config(
                    cast=[dcm.CacheValueType],
                ),
            )
            id = descriptor.id

        await mark_for_deletion(
            db_session=db_session,
            id=id,
            delete_after=delete_after,
        )

        return aiohttp.web.Response(
            status=http.HTTPStatus.NO_CONTENT,
        )
