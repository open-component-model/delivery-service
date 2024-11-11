import dataclasses
import enum
import hashlib

import ocm


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
