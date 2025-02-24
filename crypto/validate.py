import collections.abc
import dataclasses
import enum
import re
import typing

import dso.model

import crypto.config
import odg.findings


class FindingRatings(enum.StrEnum):
    COMPLIANT = 'compliant'
    MAYBE_COMPLIANT = 'maybe-compliant'
    NOT_COMPLIANT = 'not-compliant'


@dataclasses.dataclass
class Requirement:
    name: str
    required_value: enum.Enum | str | list[str] | crypto.config.MinMaxEnumProperties | None
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
        if requirement.required_value is None:
            continue

        if isinstance(requirement.required_value, enum.Enum):
            if requirement.actual_value is requirement.required_value:
                continue
        elif isinstance(requirement.required_value, str):
            if (
                not requirement.required_value
                or requirement.actual_value == requirement.required_value
            ):
                continue
        elif isinstance(requirement.required_value, list):
            if (
                not requirement.required_value or
                requirement.actual_value in requirement.required_value
            ):
                continue
        elif isinstance(requirement.required_value, crypto.config.MinMaxEnumProperties):
            if (
                not str(requirement.required_value)
                or (
                    isinstance(requirement.actual_value, int)
                    and requirement.required_value.validate(requirement.actual_value)
                )
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
    standard: crypto.config.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    name_matches = False
    best_unmet_requirements: list[Requirement] | None = None

    for symmetric_algorithm in standard.primitives.symmetric_algorithms:
        if not re.fullmatch(symmetric_algorithm.name, algorithm_name, re.IGNORECASE):
            continue

        name_matches = True

        for symmetric_algorithm_property in symmetric_algorithm.properties:
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

    if not best_unmet_requirements:
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
        summary=(
            f'The symmetric algorithm "{algorithm_name}" is not allowed in {standard.name}. '
            f'Reason:\n{reason}'
        ),
    )


def validate_asymmetric_algorithm(
    algorithm_name: str,
    key_length: int | str,
    curve: str | None,
    algorithm_asset: dso.model.CryptoAsset,
    standard: crypto.config.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    name_matches = False
    best_unmet_requirements: list[Requirement] | None = None

    for asymmetric_algorithm in standard.primitives.asymmetric_algorithms:
        if not re.fullmatch(asymmetric_algorithm.name, algorithm_name, re.IGNORECASE):
            continue

        name_matches = True

        for asymmetric_algorithm_property in asymmetric_algorithm.properties:
            all_requirements = (
                Requirement(
                    name='Allowed curves',
                    required_value=asymmetric_algorithm_property.curves,
                    actual_value=curve,
                ),
                Requirement(
                    name='Required key length (bits)',
                    required_value=asymmetric_algorithm_property.key_length,
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

    if not best_unmet_requirements:
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
        summary=(
            f'The asymmetric algorithm "{algorithm_name}" is not allowed in {standard.name}. '
            f'Reason:\n{reason}'
        ),
    )


def validate_hash_function(
    algorithm_name: str,
    output_size: int,
    algorithm_asset: dso.model.CryptoAsset,
    standard: crypto.config.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    name_matches = False
    best_unmet_requirements: list[Requirement] | None = None

    for hash_function in standard.primitives.hash_functions:
        if not re.fullmatch(hash_function.name, algorithm_name, re.IGNORECASE):
            continue

        name_matches = True

        for hash_function_property in hash_function.properties:
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

    if not best_unmet_requirements:
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
        summary=(
            f'The hash algorithm "{algorithm_name}" is not allowed in {standard.name}. '
            f'Reason:\n{reason}'
        ),
    )


def validate_signature_algorithm(
    algorithm_name: str,
    algorithm_asset: dso.model.CryptoAsset,
    standard: crypto.config.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
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
    standard: crypto.config.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    if algorithm_asset.asset_type is not dso.model.AssetTypes.ALGORITHM:
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
    standard: crypto.config.Standard,
    crypto_assets: collections.abc.Sequence[dso.model.CryptoAsset],
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    if certificate_asset.asset_type is not dso.model.AssetTypes.CERTIFICATE:
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

    best_unmet_requirements: list[Requirement] | None = None
    for certificate in standard.public_key_infrastructure.certificates:
        for certificate_property in certificate.properties:
            if certificate_property.kind is not certificate_properties.kind:
                continue

            all_requirements = (
                Requirement(
                    name='Allowed curves',
                    required_value=certificate_property.curves,
                    actual_value=public_key.properties.curve,
                ),
                Requirement(
                    name='Required key length (bits)',
                    required_value=certificate_property.key_length,
                    actual_value=key_length,
                ),
                Requirement(
                    name='Required validity (years)',
                    required_value=certificate_property.validity,
                    actual_value=certificate_properties.validity_years,
                ),
            )

            unmet_requirements = list(iter_unmet_requirements(all_requirements))

            if (
                best_unmet_requirements is None
                or len(unmet_requirements) < len(best_unmet_requirements)
            ):
                # store those requirements which are the closest to be fulfilled for reporting
                best_unmet_requirements = unmet_requirements

    summary = ''

    if best_unmet_requirements:
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
    standard: crypto.config.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    if library_asset.asset_type is not dso.model.AssetTypes.LIBRARY:
        raise ValueError(library_asset.asset_type)

    library_properties: dso.model.LibraryProperties = library_asset.properties
    provides_validated_variant = False
    may_be_validated_variant = False

    for validated_library in standard.libraries.validated:
        if validated_library.name != library_properties.name:
            continue

        provides_validated_variant = True

        if library_properties.version not in validated_library.versions:
            continue

        may_be_validated_variant = True
        break

    if may_be_validated_variant:
        finding_rating = FindingRatings.MAYBE_COMPLIANT

        summary = (
            f'The library "{library_properties.name}:{library_properties.version}" is '
            f'{standard.name} validated in the given version. However, it still has to be verified '
            'that the version is actually dominant, and not overwritten by any plugin or other '
            'mechanism.'
        )

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
    standard: crypto.config.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    if protocol_asset.asset_type is not dso.model.AssetTypes.LIBRARY:
        raise ValueError(protocol_asset.asset_type)

    # Currently, the generated CBOMs do not contain any detected protocols, hence skipping this
    # validation for now.
    return


def validate_related_crypto_material(
    related_crypto_material_asset: dso.model.CryptoAsset,
    standard: crypto.config.Standard,
    crypto_assets: collections.abc.Sequence[dso.model.CryptoAsset],
    crypto_finding_cfg: odg.findings.Finding,
) -> dso.model.CryptoFinding | None:
    if related_crypto_material_asset.asset_type is not dso.model.AssetTypes.RELATED_CRYPTO_MATERIAL:
        raise ValueError(related_crypto_material_asset.asset_type)

    # Currently, the only detected related-crypto-material in the generated CBOMs are public keys,
    # which don't have to be valided against a standard by themselves but only in conjunction with
    # what they are used for (i.e. for a certificate).
    return


def validate_against_standard(
    crypto_assets: collections.abc.Sequence[dso.model.CryptoAsset],
    standard: crypto.config.Standard,
    crypto_finding_cfg: odg.findings.Finding,
) -> collections.abc.Generator[dso.model.CryptoFinding, None, None]:
    for crypto_asset in crypto_assets:
        if crypto_asset.asset_type is dso.model.AssetTypes.ALGORITHM:
            if finding := validate_algorithm(
                algorithm_asset=crypto_asset,
                standard=standard,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        elif crypto_asset.asset_type is dso.model.AssetTypes.CERTIFICATE:
            if finding := validate_certificate(
                certificate_asset=crypto_asset,
                standard=standard,
                crypto_assets=crypto_assets,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        elif crypto_asset.asset_type is dso.model.AssetTypes.LIBRARY:
            if finding := validate_library(
                library_asset=crypto_asset,
                standard=standard,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        elif crypto_asset.asset_type is dso.model.AssetTypes.PROTOCOL:
            if finding := validate_protocol(
                protocol_asset=crypto_asset,
                standard=standard,
                crypto_finding_cfg=crypto_finding_cfg,
            ):
                yield finding

        elif crypto_asset.asset_type is dso.model.AssetTypes.RELATED_CRYPTO_MATERIAL:
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
    standards: collections.abc.Iterable[crypto.config.Standard],
    crypto_finding_cfg: odg.findings.Finding,
) -> collections.abc.Generator[dso.model.CryptoFinding, None, None]:
    for standard in standards:
        yield from validate_against_standard(
            crypto_assets=crypto_assets,
            standard=standard,
            crypto_finding_cfg=crypto_finding_cfg,
        )
