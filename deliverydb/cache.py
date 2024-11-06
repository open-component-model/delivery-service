import collections.abc
import dataclasses
import datetime
import enum
import hashlib
import json
import logging
import pickle
import traceback

import aiohttp.web
import sqlalchemy.exc
import sqlalchemy.ext.asyncio as sqlasync
import yaml

import ocm

import consts
import deliverydb.model
import util


logger = logging.getLogger(__name__)


def normalise_and_serialise_object(
    object,
    *,
    recursion_depth: int=0,
    max_recursion_depth: int=100,
) -> str:
    '''
    Generate stable serialised representation of `object`. This is especially useful to calculate a
    stable descriptor as id for cache entries. If `object` contains one of the characters used for
    join operations (`|-`, `--|`, `|_`, `__|`, `|:`), a ValueError is raised to prevent collisions.

    If `object` contains a dictionary, the normalised keys are sorted in alphabetical order and
    concatenated using following pattern: `|--key1|:value1|-key2|:value2|-...--|`

    If `object` contains an iterable (note: generators are treated as ValueError), the normalised
    values are sorted in alphabetical order and concatenated using following pattern:
    `|__value1|_value2|_...__|`
    '''
    join_characters = ['|-', '--|', '|_', '__|', '|:']

    if recursion_depth > max_recursion_depth:
        raise RuntimeError(f'{max_recursion_depth=} exceeded for {object=}')

    if isinstance(object, collections.abc.Generator):
        raise ValueError(f'{object=} must not be a generator')

    if isinstance(object, enum.Enum):
        if any([join_char in object.value for join_char in join_characters]):
            raise ValueError(f'{object=} contains one of {join_characters=}')
        return object.value

    elif isinstance(object, str):
        if any([join_char in object for join_char in join_characters]):
            raise ValueError(f'{object=} contains one of {join_characters=}')
        return object

    elif isinstance(object, (datetime.date, datetime.datetime)):
        return object.isoformat()

    elif dataclasses.is_dataclass(object):
        return normalise_and_serialise_object(
            dataclasses.asdict(object),
            recursion_depth=recursion_depth + 1,
        )

    elif isinstance(object, collections.abc.Mapping):
        object_items_normalised = [
            (
                normalise_and_serialise_object(key, recursion_depth=recursion_depth + 1),
                normalise_and_serialise_object(
                    object.getall(key) if hasattr(object, 'getall') else object.get(key),
                    recursion_depth=recursion_depth + 1,
                ),
            )
            for key in set(object.keys())
        ]
        object_sorted = sorted(object_items_normalised, key=lambda items: items[0])
        return '|--' + '|-'.join([
            f'{key}|:{value}'
            for key, value in object_sorted
        ]) + '--|'

    elif isinstance(object, collections.abc.Iterable):
        object_items_normalised = [
            normalise_and_serialise_object(value, recursion_depth=recursion_depth + 1)
            for value in object
        ]
        object_sorted = sorted(object_items_normalised)
        return '|__' + '|_'.join([
            value
            for value in object_sorted
        ]) + '__|'

    return str(object)


class EncodingFormat(enum.StrEnum):
    JSON = 'json'
    PICKLE = 'pickle-4.0'
    YAML = 'yaml'

    @staticmethod
    def pickle_protocol(pickle_encoding: str) -> int:
        if not pickle_encoding.startswith('pickle'):
            raise ValueError(f'Unsupported encoding format string for pickle: {pickle_encoding}')

        pickle_version = pickle_encoding.split('-')[1]
        return int(float(pickle_version))


class CacheValueType(enum.StrEnum):
    COMPONENT_DESCRIPTOR = 'component-descriptor'
    PYTHON_FUNCTION = 'python-function'
    HTTP_ROUTE = 'http-route'


@dataclasses.dataclass
class CacheDescriptorBase:
    type: CacheValueType
    encoding_format: EncodingFormat | str # allow str to support pickle versions different to `pickle.format_version` # noqa: E501

    @property
    def key(self) -> str:
        raise NotImplementedError('subclasses must overwrite')

    @property
    def id(self) -> str:
        # not using byte digest here since sqlalchemy only supports `LargeBinary` datatype for
        # storing plain bytes on postgresql, hence using string with fixed length is more efficient
        return hashlib.blake2s(
            self.key.encode('utf-8'),
            digest_size=16,
            usedforsecurity=False,
        ).hexdigest()


@dataclasses.dataclass(kw_only=True)
class CachedComponentDescriptor(CacheDescriptorBase):
    type: CacheValueType = CacheValueType.COMPONENT_DESCRIPTOR
    component_name: str
    component_version: str
    ocm_repository: ocm.OciOcmRepository

    @property
    def key(self) -> str:
        return (
            f'{self.type}|{self.encoding_format}|'
            f'{self.component_name}|{self.component_version}|{self.ocm_repository.oci_ref}'
        )


@dataclasses.dataclass(kw_only=True)
class CachedPythonFunction(CacheDescriptorBase):
    type: CacheValueType = CacheValueType.PYTHON_FUNCTION
    function_name: str
    args: str
    kwargs: str

    @property
    def key(self) -> str:
        return f'{self.type}|{self.encoding_format}|{self.function_name}|{self.args}|{self.kwargs}'


@dataclasses.dataclass(kw_only=True)
class CachedHTTPRoute(CacheDescriptorBase):
    type: CacheValueType = CacheValueType.HTTP_ROUTE
    route: str
    params: str | None = None
    body: str | None = None

    @property
    def key(self) -> str:
        return f'{self.type}|{self.encoding_format}|{self.route}|{self.params}|{self.body}'


async def update_cache_entry(
    db_session: sqlasync.session.AsyncSession,
    cache_entry: deliverydb.model.DBCache,
) -> bool:
    if not (existing_cache_entry := await db_session.get(deliverydb.model.DBCache, cache_entry.id)):
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
    cache_entry: deliverydb.model.DBCache,
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
    if not (cache_entry := await db_session.get(deliverydb.model.DBCache, id)):
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


def serialise_cache_value(
    value,
    encoding_format: EncodingFormat | str,
) -> bytes:
    if encoding_format.startswith('pickle'):
        protocol = EncodingFormat.pickle_protocol(pickle_encoding=encoding_format)
        return pickle.dumps(value, protocol)

    elif encoding_format is EncodingFormat.JSON:
        return json.dumps(value).encode('utf-8')

    elif encoding_format is EncodingFormat.YAML:
        return yaml.dump(value).encode('utf-8')

    else:
        raise ValueError(f'Unsupported encoding format {encoding_format}')


def deserialise_cache_value(
    value: bytes,
    encoding_format: EncodingFormat | str,
):
    if encoding_format.startswith('pickle'):
        # the pickle protocol is automatically detected, hence it is safe to ignore version here
        return pickle.loads(value)

    elif encoding_format is EncodingFormat.JSON:
        return json.loads(value)

    elif encoding_format is EncodingFormat.YAML:
        return yaml.safe_load(value)

    else:
        raise ValueError(f'Unsupported encoding format {encoding_format}')


def dbcached_function(
    encoding_format: EncodingFormat | str=EncodingFormat.PICKLE,
    ttl_seconds: int=0,
    keep_at_least_seconds: int=0,
    max_size_octets: int=0,
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
                if not isinstance(value, collections.abc.Callable)
            )

            # remove `db_session` from kwargs to allow proper serialisation
            if not (db_session := cachable_kwargs.pop('db_session', None)):
                logger.warning(f'Could not parse `db_session` parameter from {function_name=}')
                return await func(*args, **kwargs)

            descriptor = CachedPythonFunction(
                encoding_format=encoding_format,
                function_name=function_name,
                args=normalise_and_serialise_object(cachable_args),
                kwargs=normalise_and_serialise_object(cachable_kwargs),
            )

            if value := await find_cached_value(
                db_session=db_session,
                id=descriptor.id,
            ):
                return deserialise_cache_value(
                    value=value,
                    encoding_format=encoding_format,
                )

            start = datetime.datetime.now()
            result = await func(*args, **kwargs)
            duration = datetime.datetime.now() - start

            value = serialise_cache_value(
                value=result,
                encoding_format=encoding_format,
            )

            if max_size_octets > 0 and len(value) > max_size_octets:
                # don't store result in cache if it exceeds max size for an individual cache entry
                return result

            now = datetime.datetime.now(datetime.timezone.utc)
            cache_entry = deliverydb.model.DBCache(
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
    encoding_format: EncodingFormat | str=EncodingFormat.PICKLE,
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

            descriptor = CachedHTTPRoute(
                encoding_format=encoding_format,
                route=request.path,
                params=normalise_and_serialise_object(request.url.query),
                body=normalise_and_serialise_object(body) if body else None,
            )

            if value := await find_cached_value(
                db_session=db_session,
                id=descriptor.id,
            ):
                return deserialise_cache_value(
                    value=value,
                    encoding_format=encoding_format,
                )

            start = datetime.datetime.now()
            result: aiohttp.web.Response = await func(*args, **kwargs)
            duration = datetime.datetime.now() - start

            if result.status >= 400:
                # don't cache error responses -> those might only be temporarily
                return result

            value = serialise_cache_value(
                value=result,
                encoding_format=encoding_format,
            )

            if max_size_octets > 0 and len(value) > max_size_octets:
                # don't store result in cache if it exceeds max size for an individual cache entry
                return result

            now = datetime.datetime.now(datetime.timezone.utc)
            cache_entry = deliverydb.model.DBCache(
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
