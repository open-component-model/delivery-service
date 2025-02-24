import dataclasses

import dso.model


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
    '''
    Defines a standard which regulates usages of cryptographic assets within a software.
    '''
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
