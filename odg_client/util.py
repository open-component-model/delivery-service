import collections.abc
import datetime
import enum
import io
import json as js
import typing
import urllib.parse
import zlib


class EncodingMethod(enum.StrEnum):
    GZIP = 'gzip'


def encode_request(
    data: str | bytes | dict | typing.IO = None,
    json: dict = None,
    headers: dict[str, str] = None,
    encoding_method: EncodingMethod = EncodingMethod.GZIP,
) -> tuple[bytes, dict[str, str]] | bytes:
    """
    Encodes the given `data` or `json` property based on the selected `encoding_method`. Only one of
    `data` or `json` must be set, otherwise a `ValueError` is raised.

    The corresponding `Content-Encoding` header is patched-in to the provided headers dictionary.

    If `headers` is provided and not `None`, the response is a tuple of the compression result and
    the patched headers, otherwise only the compression result is returned.
    """
    if not (data is not None ^ json is not None):
        raise ValueError('Exactly one of `data` or `json` must be set')

    if isinstance(data, dict) and encoding_method == EncodingMethod.GZIP:
        raise ValueError('`data` of type `dict` is not supported for gzip encoding')

    if json is not None:
        data = js.dumps(json)

    def _encode(obj, encoding: str = 'utf-8') -> bytes:
        if isinstance(obj, bytes):
            return obj
        elif isinstance(obj, str):
            return obj.encode(encoding=encoding)
        elif isinstance(obj, dict):
            return js.dumps(obj).encode(encoding=encoding)
        else:
            raise ValueError(f'Encoding of type {type(obj)} is not (yet) supported')

    def _compress(data, encoding_method) -> collections.abc.Generator[bytes, None, None]:
        if isinstance(data, io.BufferedIOBase):
            if encoding_method == EncodingMethod.GZIP:
                compressor = zlib.compressobj(wbits=31)
                data.seek(0)

                while chunk := data.read(4096):
                    yield compressor.compress(chunk)
                yield compressor.flush()

            else:
                raise ValueError(encoding_method)

        elif hasattr(data, '__iter__') and not isinstance(data, (str, bytes, dict)):
            raise ValueError(f'Encoding of iterable {type(data)} is not (yet) supported')

        else:
            data = _encode(data)

            if encoding_method == EncodingMethod.GZIP:
                compressor = zlib.compressobj(wbits=31)
                yield compressor.compress(data) + compressor.flush()

            else:
                raise ValueError(encoding_method)

    compressed_data = b''.join(_compress(data, encoding_method))
    content_length = len(compressed_data)

    if headers is not None:
        headers['Content-Encoding'] = encoding_method
        headers['Content-Length'] = str(content_length)
        return compressed_data, headers

    return compressed_data


def urljoin(*parts):
    if len(parts) == 1:
        return parts[0]
    first = parts[0]
    last = parts[-1]
    middle = parts[1:-1]

    first = first.rstrip('/')
    middle = list(map(lambda s: s.strip('/'), middle))
    last = last.lstrip('/')

    return '/'.join([first] + middle + [last])


def urlparse(url: str) -> urllib.parse.ParseResult:
    if '://' not in url:
        url = f'x://{url}'

    return urllib.parse.urlparse(url)


def dict_to_json_factory(data):
    def convert_value(obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        elif isinstance(obj, enum.Enum):
            return obj.value
        return obj

    return dict((k, convert_value(v)) for k, v in data)
