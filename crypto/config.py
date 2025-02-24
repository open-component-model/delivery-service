import collections.abc
import dataclasses
import enum
import typing

import dacite
import yaml

import dso.model

import odg.extensions_cfg


@dataclasses.dataclass
class Base:
    name: str | None
    description: str | None
    references: list[str] | None
    category: str | None


@dataclasses.dataclass
class MinMaxEnumProperties:
    enum: list[int] | None = None
    min: int | None = None
    max: int | None = None

    def check_value(self, value: int | None) -> bool:
        # explicitly check for None as 0 is an allowed value
        if (self.enum or self.min is not None or self.max is not None) and value is None:
            return False

        if self.enum and value not in self.enum:
            return False
        if self.min and value < self.min:
            return False
        if self.max and value > self.max:
            return False

        return True

    def __str__(self) -> str:
        output_parts = []

        if self.enum:
            output_parts.append(f'values: {', '.join([str(val) for val in self.enum])}')
        if self.min:
            output_parts.append(f'minimum: {self.min}')
        if self.max:
            output_parts.append(f'maximum: {self.max}')

        return ', '.join(output_parts)


@dataclasses.dataclass
class CryptoLibrary:
    name: str
    versions: list[str]


@dataclasses.dataclass
class CryptoLibraries:
    validated_crypto_libraries: list[CryptoLibrary] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class SymmetricAlgorithmProperties:
    key_length: MinMaxEnumProperties


@dataclasses.dataclass
class SymmetricAlgorithm(Base):
    properties: list[SymmetricAlgorithmProperties] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class AsymmetricAlgorithmProperties:
    key_length: MinMaxEnumProperties | None
    curves: list[str] | None
    exponent: MinMaxEnumProperties | None # not being validated -> missing in cbom?


@dataclasses.dataclass
class AsymmetricAlgorithm(Base):
    properties: list[AsymmetricAlgorithmProperties] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class HashFunctionProperties:
    output_size: MinMaxEnumProperties


@dataclasses.dataclass
class HashFunction(Base):
    properties: list[HashFunctionProperties] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Primitives:
    symmetric_algorithms: list[SymmetricAlgorithm]
    asymmetric_algorithms: list[AsymmetricAlgorithm]
    hash_functions: list[HashFunction]


@dataclasses.dataclass
class SignatureProperties:
    name: str | None
    key_length: MinMaxEnumProperties | None # not being validated -> only hash algorithm in cbom?


@dataclasses.dataclass
class Signature(Base):
    properties: list[SignatureProperties] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Schemes:
    signatures: list[Signature]


@dataclasses.dataclass
class CertificateProperties:
    kind: dso.model.CertificateKind
    curves: list[str] | None
    key_length: MinMaxEnumProperties | None
    validity_years: MinMaxEnumProperties | None


@dataclasses.dataclass
class Certificate(Base):
    properties: list[CertificateProperties] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class PublicKeyInfrastructure:
    certificates: list[Certificate]


@dataclasses.dataclass
class Standard:
    name: str
    version: str
    description: str | None
    references: list[str] | None
    countries: list[str] | None
    categories: list[str]
    libraries: CryptoLibraries
    primitives: Primitives
    schemes: Schemes
    public_key_infrastructure: PublicKeyInfrastructure


@dataclasses.dataclass
class CryptoConfig:
    standards: list[Standard] = dataclasses.field(default_factory=list)
    libraries: list[str] = dataclasses.field(default_factory=list)

    @staticmethod
    def from_dict(crypto_cfg_raw: dict) -> typing.Self:
        return dacite.from_dict(
            data_class=CryptoConfig,
            data=crypto_cfg_raw,
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )

    @staticmethod
    def from_file(path: str) -> typing.Self:
        with open(path) as file:
            crypto_cfg_raw = yaml.safe_load(file)

        return CryptoConfig.from_dict(
            crypto_cfg_raw=crypto_cfg_raw,
        )

    def iter_filtered_standards(
        self,
        included_standards: odg.extensions_cfg.StandardRef,
    ) -> collections.abc.Generator[Standard, None, None]:
        for standard in self.standards:
            for included_standard in included_standards:
                if (
                    standard.name == included_standard.name
                    and standard.version == included_standard.version
                ):
                    yield standard
                    break
