import collections.abc
import dataclasses
import enum
import re
import textwrap
import typing

import dso.model

import crypto_extension.config as cc
import odg.findings


class FindingRatings(enum.StrEnum):
    COMPLIANT = 'compliant'
    MAYBE_COMPLIANT = 'maybe-compliant'
    NOT_COMPLIANT = 'not-compliant'


@dataclasses.dataclass
class Requirement:
    name: str
    required_value: enum.Enum | str | list[str] | cc.MinMaxEnumProperties | None
    actual_value: enum.Enum | str | int | None

    def __str__(self) -> str:
        return f'{self.name}: {self.required_value} (actual: {self.actual_value})'


def iter_unmet_requirements(
    requirements: collections.abc.Iterable[typing.Self],
) -> collections.abc.Generator[typing.Self, None, None]:
    '''
    Returns the requirements for which the actual value does not match the required one.
    '''
    for requirement in requirements:
        if isinstance(requirement.required_value, enum.Enum):
            if requirement.actual_value is requirement.required_value:
                continue
        elif isinstance(requirement.required_value, str):
            if requirement.actual_value == requirement.required_value:
                continue
        elif isinstance(requirement.required_value, list):
            if requirement.actual_value in requirement.required_value:
                continue
        elif isinstance(requirement.required_value, cc.MinMaxEnumProperties):
            if (
                isinstance(requirement.actual_value, int)
                and requirement.required_value.check_value(requirement.actual_value)
            ):
                continue
        else:
            raise TypeError(type(requirement.required_value))

        yield requirement


def find_crypto_asset_by_key(
    data_key: str,
    crypto_assets: collections.abc.Iterable[dso.model.CryptoAsset],
) -> dso.model.CryptoAsset:
    for crypto_asset in crypto_assets:
        if data_key == crypto_asset.key:
            return crypto_asset

    raise ValueError(f'{data_key=} could not be resolved')


def validate_symmetric_algorithm(
    algorithm_name: str,
    key_length: int | str,
    algorithm_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    '''
    Validates the provided symmetric algorithm (identified via its `algorithm_name` and `key_length`)
    against the allowed properties for symmetric algorithms defined in the `standard`. Therefore, it
    checks for a definition with a matching algorithm name, and in case it is found, checks if the
    given `key_length` is actually allowed for the detected algorithm. If either no matching
    algorithm is found, or it is found but the `key_length` is not sufficient, a finding with the
    rating `not-compliant` will be created.
    '''
    def check_unmet_requirements(
        algorithm_name: str,
        key_length: int | str,
        symmetric_algorithm_definitions: collections.abc.Iterable[cc.SymmetricAlgorithm],
    ) -> tuple[bool, list[Requirement] | None]:
        name_matches = False
        best_unmet_requirements: list[Requirement] | None = None

        for symmetric_algorithm_definition in symmetric_algorithm_definitions:
            if not re.fullmatch(symmetric_algorithm_definition.name, algorithm_name, re.IGNORECASE):
                continue

            name_matches = True

            for symmetric_algorithm_property in symmetric_algorithm_definition.properties:
                all_requirements = (
                    Requirement(
                        name='Required key length (bits)',
                        required_value=symmetric_algorithm_property.key_length,
                        actual_value=key_length,
                    ),
                )

                unmet_requirements = list(iter_unmet_requirements(all_requirements))

                if (
                    best_unmet_requirements is None
                    or len(unmet_requirements) < len(best_unmet_requirements)
                ):
                    # store those requirements which are the closest to be fulfilled for reporting
                    best_unmet_requirements = unmet_requirements

        return name_matches, best_unmet_requirements

    name_matches, best_unmet_requirements = check_unmet_requirements(
        algorithm_name=algorithm_name,
        key_length=key_length,
        symmetric_algorithm_definitions=standard.primitives.symmetric_algorithms,
    )

    if name_matches and not best_unmet_requirements:
        # all requirements are fulfilled, no need to create a finding
        return

    if name_matches:
        reason = '\n'.join(str(req) for req in best_unmet_requirements)
    else:
        reason = f'There is no supported algorithm matching the given name "{algorithm_name}".'

    if not (categorisation := odg.findings.categorise_finding(
        finding_cfg=crypto_finding_cfg,
        finding_property=FindingRatings.NOT_COMPLIANT,
    )):
        return

    return dso.model.CryptoFinding(
        severity=categorisation.id,
        standard=standard.name,
        asset=algorithm_asset,
        summary=textwrap.dedent(f'''\
            The symmetric algorithm "{algorithm_name}" is not allowed in {standard.name}. Reason:
            {reason}
        '''),
    )


def validate_asymmetric_algorithm(
    algorithm_name: str,
    key_length: int | str,
    curve: str | None,
    algorithm_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    '''
    Validates the provided asymmetric algorithm (identified via its `algorithm_name` and
    `key_length`/`curve`) against the allowed properties for asymmetric algorithms defined in the
    `standard`. Therefore, it checks for a definition with a matching algorithm name, and in case it
    is found, checks if the given `key_length` or `curve` is actually allowed for the detected
    algorithm. If either no matching algorithm is found, or it is found but the `key_length` or
    `curve` is not sufficient, a finding with the rating `not-compliant` will be created.
    '''
    def check_unmet_requirements(
        algorithm_name: str,
        key_length: int | str,
        curve: str | None,
        asymmetric_algorithm_definitions: collections.abc.Iterable[cc.AsymmetricAlgorithm],
    ) -> tuple[bool, list[Requirement] | None]:
        name_matches = False
        best_unmet_requirements: list[Requirement] | None = None

        for asymmetric_algorithm_definition in asymmetric_algorithm_definitions:
            if not re.fullmatch(asymmetric_algorithm_definition.name, algorithm_name, re.IGNORECASE):
                continue

            name_matches = True

            for asymmetric_algorithm_property in asymmetric_algorithm_definition.properties:
                def iter_requirements() -> collections.abc.Generator[Requirement, None, None]:
                    if asymmetric_algorithm_property.curves:
                        yield Requirement(
                            name='Allowed curves',
                            required_value=asymmetric_algorithm_property.curves,
                            actual_value=curve,
                        )
                    if asymmetric_algorithm_property.key_length:
                        yield Requirement(
                            name='Required key length (bits)',
                            required_value=asymmetric_algorithm_property.key_length,
                            actual_value=key_length,
                        )

                all_requirements = iter_requirements()
                unmet_requirements = list(iter_unmet_requirements(all_requirements))

                if (
                    best_unmet_requirements is None
                    or len(unmet_requirements) < len(best_unmet_requirements)
                ):
                    # store those requirements which are the closest to be fulfilled for reporting
                    best_unmet_requirements = unmet_requirements

        return name_matches, best_unmet_requirements

    name_matches, best_unmet_requirements = check_unmet_requirements(
        algorithm_name=algorithm_name,
        key_length=key_length,
        curve=curve,
        asymmetric_algorithm_definitions=standard.primitives.asymmetric_algorithms,
    )

    if name_matches and not best_unmet_requirements:
        # all requirements are fulfilled, no need to create a finding
        return

    if name_matches:
        reason = '\n'.join(str(req) for req in best_unmet_requirements)
    else:
        reason = f'There is no supported algorithm matching the given name "{algorithm_name}".'

    if not (categorisation := odg.findings.categorise_finding(
        finding_cfg=crypto_finding_cfg,
        finding_property=FindingRatings.NOT_COMPLIANT,
    )):
        return

    return dso.model.CryptoFinding(
        severity=categorisation.id,
        standard=standard.name,
        asset=algorithm_asset,
        summary=textwrap.dedent(f'''\
            The asymmetric algorithm "{algorithm_name}" is not allowed in {standard.name}. Reason:
            {reason}
        '''),
    )


def validate_hash_function(
    algorithm_name: str,
    output_size: int,
    algorithm_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    '''
    Validates the provided hash function (identified via its `algorithm_name` and `output_size`)
    against the allowed properties for hash functions defined in the `standard`. Therefore, it
    checks for a definition with a matching algorithm name, and in case it is found, checks if the
    given `output_size` is actually allowed for the detected function. If either no matching
    function is found, or it is found but the `output_size` is not sufficient, a finding with the
    rating `not-compliant` will be created.
    '''
    def check_unmet_requirements(
        algorithm_name: str,
        output_size: int,
        hash_function_definitions: collections.abc.Iterable[cc.HashFunction],
    ) -> tuple[bool, list[Requirement] | None]:
        name_matches = False
        best_unmet_requirements: list[Requirement] | None = None

        for hash_function_definition in hash_function_definitions:
            if not re.fullmatch(hash_function_definition.name, algorithm_name, re.IGNORECASE):
                continue

            name_matches = True

            for hash_function_property in hash_function_definition.properties:
                all_requirements = (
                    Requirement(
                        name='Required output size (bits)',
                        required_value=hash_function_property.output_size,
                        actual_value=output_size,
                    ),
                )

                unmet_requirements = list(iter_unmet_requirements(all_requirements))

                if (
                    best_unmet_requirements is None
                    or len(unmet_requirements) < len(best_unmet_requirements)
                ):
                    # store those requirements which are the closest to be fulfilled for reporting
                    best_unmet_requirements = unmet_requirements

        return name_matches, best_unmet_requirements

    name_matches, best_unmet_requirements = check_unmet_requirements(
        algorithm_name=algorithm_name,
        output_size=output_size,
        hash_function_definitions=standard.primitives.hash_functions,
    )

    if name_matches and not best_unmet_requirements:
        # all requirements are fulfilled, no need to create a finding
        return

    if name_matches:
        reason = '\n'.join(str(req) for req in best_unmet_requirements)
    else:
        reason = f'There is no supported algorithm matching the given name "{algorithm_name}".'

    if not (categorisation := odg.findings.categorise_finding(
        finding_cfg=crypto_finding_cfg,
        finding_property=FindingRatings.NOT_COMPLIANT,
    )):
        return

    return dso.model.CryptoFinding(
        severity=categorisation.id,
        standard=standard.name,
        asset=algorithm_asset,
        summary=textwrap.dedent(f'''\
            The hash algorithm "{algorithm_name}" is not allowed in {standard.name}. Reason:
            {reason}
        '''),
    )


def validate_signature_algorithm(
    algorithm_name: str,
    algorithm_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    '''
    Validates the provided signature algorithm (identified via its `algorithm_name`) against the
    allowed properties for asymmetric algorithms and hash functions defined in the `standard`.
    Therefore, it splits the provided `algorithm_name` at `-` and interprets the individual parts as
    either the asymmetric algorithm name or the name of the hash function. For both, it is checked
    whether they are allowed in the `standard` or not. Note, this only allows a comparison via their
    name, it is _not_ checked whether the algorithms fulfill the requirements of other properties,
    e.g. a sufficient key length and/or output size. If either no matching asymmetric algorithm or
    hash function (or both) is found, a finding with the rating `not-compliant` will be created.
    '''
    valid_asymmetric_algorithm = False
    valid_hash_algorithm = False

    for name in algorithm_name.split('-'):
        for asymmetric_algorithm in standard.primitives.asymmetric_algorithms:
            if re.fullmatch(asymmetric_algorithm.name, name, re.IGNORECASE):
                valid_asymmetric_algorithm = True
                break

        for hash_function in standard.primitives.hash_functions:
            if re.fullmatch(hash_function.name, name, re.IGNORECASE):
                valid_hash_algorithm = True
                break

    if valid_asymmetric_algorithm and valid_hash_algorithm:
        # all requirements are fulfilled, no need to create a finding
        return

    if valid_asymmetric_algorithm:
        summary = f'The used hash algorithm is not allowed in {standard.name}.'
    elif valid_hash_algorithm:
        summary = f'The used asymmetric algorithm is not allowed in {standard.name}.'
    else:
        summary = f'The signature algorithm "{algorithm_name}" is not allowed in {standard.name}.'

    if not (categorisation := odg.findings.categorise_finding(
        finding_cfg=crypto_finding_cfg,
        finding_property=FindingRatings.NOT_COMPLIANT,
    )):
        return

    return dso.model.CryptoFinding(
        severity=categorisation.id,
        standard=standard.name,
        asset=algorithm_asset,
        summary=summary,
    )


def validate_algorithm(
    algorithm_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    if algorithm_asset.asset_type is not dso.model.CryptoAssetTypes.ALGORITHM:
        raise ValueError(algorithm_asset.asset_type)

    algorithm_properties: dso.model.AlgorithmProperties = algorithm_asset.properties
    parameter_set_identifier = (
        int(algorithm_properties.parameter_set_identifier)
        if algorithm_properties.parameter_set_identifier
        else 'unknown'
    )

    if algorithm_properties.primitive is dso.model.Primitives.BLOCK_CIPHER:
        return validate_symmetric_algorithm(
            algorithm_name=algorithm_properties.name,
            key_length=parameter_set_identifier,
            algorithm_asset=algorithm_asset,
            standard=standard,
            crypto_finding_cfg=crypto_finding_cfg,
        )

    elif algorithm_properties.primitive is dso.model.Primitives.PKE:
        return validate_asymmetric_algorithm(
            algorithm_name=algorithm_properties.name,
            key_length=parameter_set_identifier,
            curve=algorithm_properties.curve,
            algorithm_asset=algorithm_asset,
            standard=standard,
            crypto_finding_cfg=crypto_finding_cfg,
        )

    elif algorithm_properties.primitive is dso.model.Primitives.HASH:
        return validate_hash_function(
            algorithm_name=algorithm_properties.name,
            output_size=parameter_set_identifier,
            algorithm_asset=algorithm_asset,
            standard=standard,
            crypto_finding_cfg=crypto_finding_cfg,
        )

    elif algorithm_properties.primitive is dso.model.Primitives.SIGNATURE:
        return validate_signature_algorithm(
            algorithm_name=algorithm_properties.name,
            algorithm_asset=algorithm_asset,
            standard=standard,
            crypto_finding_cfg=crypto_finding_cfg,
        )

    else:
        raise ValueError(algorithm_properties.primitive)


def validate_certificate(
    certificate_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_assets: collections.abc.Sequence[dso.model.CryptoAsset],
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    '''
    Validates the provided certificate (identified via the `certificate_properties`) against the
    allowed properties for certificates defined in the `standard`. Therefore, it resolves the
    `signature_algorithm_ref` and validates the signature algorithm according to
    `validate_signature_algorithm()`. Also, it resolves the `subject_public_key_ref` and validates
    the asymmetric algorithm, used to create the public key, accorging to
    `validate_asymmetric_algorithm()`. Last but not least, it checks for a definition with a
    matching certificate kind, and in case it is found, checks if the given `curve`, `key_length`
    and `validity_years` are actually allowed for the detected certificate kind. If either one of
    the used algorithms is not valid or the certificate properties are not sufficient for the
    detected certificate kind, a finding with the rating `not-compliant` will be created.
    '''
    if certificate_asset.asset_type is not dso.model.CryptoAssetTypes.CERTIFICATE:
        raise ValueError(certificate_asset.asset_type)

    certificate_properties: dso.model.CertificateProperties = certificate_asset.properties

    signature_algorithm = find_crypto_asset_by_key(
        data_key=certificate_properties.signature_algorithm_ref,
        crypto_assets=crypto_assets,
    )
    signature_algorithm_finding = validate_signature_algorithm(
        algorithm_name=signature_algorithm.properties.name,
        algorithm_asset=signature_algorithm,
        standard=standard,
        crypto_finding_cfg=crypto_finding_cfg,
    )

    public_key = find_crypto_asset_by_key(
        data_key=certificate_properties.subject_public_key_ref,
        crypto_assets=crypto_assets,
    )
    key_length = public_key.properties.size or 'unknown'
    asymmetric_algorithm = find_crypto_asset_by_key(
        data_key=public_key.properties.algorithm_ref,
        crypto_assets=crypto_assets,
    )
    asymmetric_algorithm_finding = validate_asymmetric_algorithm(
        algorithm_name=asymmetric_algorithm.properties.name,
        key_length=key_length,
        curve=public_key.properties.curve,
        algorithm_asset=asymmetric_algorithm,
        standard=standard,
        crypto_finding_cfg=crypto_finding_cfg,
    )

    def check_unmet_requirements(
        certificate_kind: dso.model.CertificateKind,
        key_length: int | str,
        curve: str | None,
        validity_years: int | None,
        certificate_definitions: collections.abc.Iterable[cc.Certificate],
    ) -> tuple[bool, list[Requirement] | None]:
        certificate_kind_matches = False
        best_unmet_requirements: list[Requirement] | None = None

        for certificate_definition in certificate_definitions:
            for certificate_property in certificate_definition.properties:
                if certificate_property.kind is not certificate_kind:
                    continue

                certificate_kind_matches = True

                def iter_requirements() -> collections.abc.Generator[Requirement, None, None]:
                    if certificate_property.curves:
                        yield Requirement(
                            name='Allowed curves',
                            required_value=certificate_property.curves,
                            actual_value=curve,
                        )
                    if certificate_property.key_length:
                        yield Requirement(
                            name='Required key length (bits)',
                            required_value=certificate_property.key_length,
                            actual_value=key_length,
                        )
                    if certificate_property.validity_years:
                        yield Requirement(
                            name='Required validity (years)',
                            required_value=certificate_property.validity_years,
                            actual_value=validity_years,
                        )

                all_requirements = iter_requirements()
                unmet_requirements = list(iter_unmet_requirements(all_requirements))

                if (
                    best_unmet_requirements is None
                    or len(unmet_requirements) < len(best_unmet_requirements)
                ):
                    # store those requirements which are the closest to be fulfilled for reporting
                    best_unmet_requirements = unmet_requirements

        return certificate_kind_matches, best_unmet_requirements

    certificate_kind_matches, best_unmet_requirements = check_unmet_requirements(
        certificate_kind=certificate_properties.kind,
        key_length=key_length,
        curve=public_key.properties.curve,
        validity_years=certificate_properties.validity_years,
        certificate_definitions=standard.public_key_infrastructure.certificates,
    )

    summary = ''

    if not certificate_kind_matches:
        summary += (
            f'Certificates of kind "{certificate_properties.kind}" '
            f'are not allowed in {standard.name}.'
        )

    if best_unmet_requirements:
        if summary:
            summary += '\n'
        summary += 'The certificate properties do not fulfill the given requirements:\n'
        summary += '\n'.join(str(req) for req in best_unmet_requirements)

    if signature_algorithm_finding:
        if summary:
            summary += '\n'
        summary += signature_algorithm_finding.summary

    if asymmetric_algorithm_finding:
        if summary:
            summary += '\n'
        summary += asymmetric_algorithm_finding.summary

    if not summary:
        # all requirements are fulfilled, no need to create a finding
        return

    if not (categorisation := odg.findings.categorise_finding(
        finding_cfg=crypto_finding_cfg,
        finding_property=FindingRatings.NOT_COMPLIANT,
    )):
        return

    return dso.model.CryptoFinding(
        severity=categorisation.id,
        standard=standard.name,
        asset=certificate_asset,
        summary=summary,
    )


def validate_library(
    library_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    '''
    Validates the provided library (identified via its `name` and `version`) against the known
    validated libraries defined in the `standard`. If the libary matches one of the validated
    libraries (`name` or `name` and `version` matches), a finding with the rating `maybe-compliant`
    will be created. Otherwise, a finding with the rating `not-compliant` will be created.
    '''
    if library_asset.asset_type is not dso.model.CryptoAssetTypes.LIBRARY:
        raise ValueError(library_asset.asset_type)

    library_properties: dso.model.LibraryProperties = library_asset.properties
    provides_validated_variant = False
    may_be_validated_variant = False

    for validated_crypto_library in standard.libraries.validated_crypto_libraries:
        if validated_crypto_library.name != library_properties.name:
            continue

        provides_validated_variant = True

        if library_properties.version not in validated_crypto_library.versions:
            continue

        may_be_validated_variant = True
        break

    if may_be_validated_variant:
        finding_rating = FindingRatings.MAYBE_COMPLIANT

        summary = textwrap.dedent(f'''\
            The library "{library_properties.name}:{library_properties.version}" is
            {standard.name} validated in the given version. However, it still has to be verified
            that the version is actually dominant, and not overwritten by any plugin or other
            mechanism.'
        ''')

    elif provides_validated_variant:
        finding_rating = FindingRatings.MAYBE_COMPLIANT

        summary = (
            f'The library "{library_properties.name}" generally provides a {standard.name} '
            'validated version. However, it could not be determined if the detected version '
            f'"{library_properties.version}" is actually {standard.name} validated.'
        )

    else:
        finding_rating = FindingRatings.NOT_COMPLIANT

        summary = (
            f'The library "{library_properties.name}:{library_properties.version}" does not provide '
            f'a {standard.name} validated version. If you consider this as a mistake, please assess '
            'this finding respectively.'
        )

    if not (categorisation := odg.findings.categorise_finding(
        finding_cfg=crypto_finding_cfg,
        finding_property=finding_rating,
    )):
        return

    return dso.model.CryptoFinding(
        severity=categorisation.id,
        standard=standard.name,
        asset=library_asset,
        summary=summary,
    )


def validate_protocol(
    protocol_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    if protocol_asset.asset_type is not dso.model.CryptoAssetTypes.LIBRARY:
        raise ValueError(protocol_asset.asset_type)

    # Currently, the generated CBOMs do not contain any detected protocols, hence skipping this
    # validation for now.
    return


def validate_related_crypto_material(
    related_crypto_material_asset: dso.model.CryptoAsset,
    standard: cc.Standard,
    crypto_assets: collections.abc.Sequence[dso.model.CryptoAsset],
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    if related_crypto_material_asset.asset_type is not dso.model.CryptoAssetTypes.RELATED_CRYPTO_MATERIAL: # noqa: E501
        raise ValueError(related_crypto_material_asset.asset_type)

    # Currently, the only detected related-crypto-material in the generated CBOMs are public keys,
    # which don't have to be valided against a standard by themselves but only in conjunction with
    # what they are used for (i.e. for a certificate).
    return


def validate_against_standard(
    crypto_assets: collections.abc.Sequence[dso.model.CryptoAsset],
    standard: cc.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> collections.abc.Generator[dso.model.CryptoFinding, None, None]:
    for crypto_asset in crypto_assets:
        if crypto_asset.asset_type is dso.model.CryptoAssetTypes.ALGORITHM:
            if finding := validate_algorithm(
                algorithm_asset=crypto_asset,
                standard=standard,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        elif crypto_asset.asset_type is dso.model.CryptoAssetTypes.CERTIFICATE:
            if finding := validate_certificate(
                certificate_asset=crypto_asset,
                standard=standard,
                crypto_assets=crypto_assets,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        elif crypto_asset.asset_type is dso.model.CryptoAssetTypes.LIBRARY:
            if finding := validate_library(
                library_asset=crypto_asset,
                standard=standard,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        elif crypto_asset.asset_type is dso.model.CryptoAssetTypes.PROTOCOL:
            if finding := validate_protocol(
                protocol_asset=crypto_asset,
                standard=standard,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        elif crypto_asset.asset_type is dso.model.CryptoAssetTypes.RELATED_CRYPTO_MATERIAL:
            if finding := validate_related_crypto_material(
                related_crypto_material_asset=crypto_asset,
                standard=standard,
                crypto_assets=crypto_assets,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        else:
            raise ValueError(crypto_asset.asset_type)


def iter_findings_for_standards(
    crypto_assets: collections.abc.Sequence[dso.model.CryptoAsset],
    standards: collections.abc.Iterable[cc.Standard],
    crypto_finding_cfg: odg.findings.Finding,
) -> collections.abc.Generator[dso.model.CryptoFinding, None, None]:
    for standard in standards:
        yield from validate_against_standard(
            crypto_assets=crypto_assets,
            standard=standard,
            crypto_finding_cfg=crypto_finding_cfg,
        )
