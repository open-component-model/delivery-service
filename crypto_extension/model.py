import collections.abc
import datetime
import enum
import math
import os
import re

import cyclonedx.schema

import dso.model


own_dir = os.path.dirname(__file__)


class SupportedSchemaVersions(enum.Enum):
    V1_6 = cyclonedx.schema.SchemaVersion.V1_6


class ComponentTypes(enum.StrEnum):
    CRYPTOGRAPHIC_ASSET = 'cryptographic-asset'
    LIBRARY = 'library'


def validate_supported_schema_version(schema_version_raw: str):
    try:
        schema_version = cyclonedx.schema.SchemaVersion.from_version(schema_version_raw)
        SupportedSchemaVersions(schema_version)
    except ValueError:
        raise ValueError(
            f'Schema version {schema_version_raw} is not supported, '
            f'supported versions: {[
                cyclonedx.schema.SchemaVersion.to_version(version.value)
                for version in SupportedSchemaVersions
            ]}'
        )


def filter_crypto_assets(
    components: collections.abc.Iterable[dict],
    known_crypto_libraries: collections.abc.Sequence[str],
    included_asset_types: list[dso.model.CryptoAssetTypes] | None,
) -> collections.abc.Generator[dict, None, None]:
    '''
    Filters the components of a CBOM document for those which are either of type
    `cryptographic-asset` or a library which matches one of the `known_crypto_libraries`.
    Also, if `included_asset_types` is specified, only components with a matching asset type
    will be considered.
    '''
    component_types = [component_type.value for component_type in ComponentTypes]

    for component in components:
        # the SBOM specification allows a couple of different component types in general, which are
        # not of interest for this extension (apart from the `library` type which is required to
        # identify cryptographic libraries). Hence, the other types can be safely skipped here
        if (component_type := component['type']) not in component_types:
            continue

        component_type = ComponentTypes(component_type)

        if (
            component_type is ComponentTypes.LIBRARY
            and component['name'] not in known_crypto_libraries
        ):
            continue

        if component_type is ComponentTypes.LIBRARY:
            asset_type = dso.model.CryptoAssetTypes.LIBRARY

        elif component_type is ComponentTypes.CRYPTOGRAPHIC_ASSET:
            crypto_properties = component.get('cryptoProperties', dict())
            asset_type = dso.model.CryptoAssetTypes(crypto_properties['assetType'])

        else:
            raise RuntimeError('this is a bug, we checked supported component types before')

        if included_asset_types is not None and asset_type not in included_asset_types:
            continue

        yield component


def iter_locations(
    crypto_asset_raw: dict,
) -> collections.abc.Generator[str, None, None]:
    '''
    The location(s) of a CBOM component may be stored at two different locations:
    1. as top-level `evidence` (this holds true for components added by "cbomkit-theia")
    2. as a property matching the below regex (this holds true for components added by "syft")
    '''
    if evidence := crypto_asset_raw.get('evidence'):
        if occurrences := evidence.get('occurrences'):
            for occurrence in occurrences:
                yield occurrence['location']

    for property in crypto_asset_raw.get('properties', []):
        if not (value := property.get('value')):
            continue

        # syft stores path information of a component in a label matching this regex
        if not re.fullmatch(r'^syft:location:\d+:path$', property['name']):
            continue

        yield value


def bom_ref_to_data_key(
    bom_ref: str | None,
    crypto_assets_raw: collections.abc.Sequence[dict],
) -> str | None:
    if not bom_ref:
        return None

    for crypto_asset_raw in crypto_assets_raw:
        if not crypto_asset_raw.get('bom-ref') == bom_ref:
            continue

        crypto_asset = deserialise_crypto_asset(
            crypto_asset_raw=crypto_asset_raw,
            crypto_assets_raw=crypto_assets_raw,
        )

        return crypto_asset.key

    raise ValueError(f'{bom_ref=} could not be resolved')


def guess_certificate_kind(
    subject_name: str | None,
) -> dso.model.CertificateKind:
    '''
    This function is intended to heuristically determine the "kind" of a certificate, like root-ca,
    intermediate-ca or end-user certificate. It checks the subject name for "well-known" phrases
    indicating one of the above certificate kinds. If no matching phrase is identified, it will be
    interpreted as end-user certificate, which will usually have the strictest rules regarding
    validity whereas the requirements for the used algorithm are usually less strict.
    '''
    root_ca_phrases = (
        'root',
    )
    intermediate_ca_phrases = (
        'intermediate',
        'ca',
        'certificationauthority',
    )

    if not subject_name:
        return dso.model.CertificateKind.END_USER

    subject_name = subject_name.lower().replace(' ', '')

    for root_ca_phrase in root_ca_phrases:
        if root_ca_phrase in subject_name:
            return dso.model.CertificateKind.ROOT_CA

    for intermediate_ca_phrase in intermediate_ca_phrases:
        if intermediate_ca_phrase in subject_name:
            return dso.model.CertificateKind.INTERMEDIATE_CA

    return dso.model.CertificateKind.END_USER


def determine_curve(
    description: str | None,
) -> str:
    '''
    This function is intended to heuristically determine the underlying ellipic curve by analysing
    the given description of a CBOM component description. It expects the description to adhere to
    the form: `Curve: <curve-name>`. In that case, it would return the respective `<curve-name>`.
    '''
    if not description or not 'Curve:' in description:
        return 'unknown'

    curve_parts = description.split('Curve:')

    return curve_parts[1].strip()


def deserialise_algorithm(
    name: str,
    algorithm_properties: dict,
) -> dso.model.AlgorithmProperties:
    if primitive := algorithm_properties.get('primitive'):
        primitive = dso.model.Primitives(primitive)

    return dso.model.AlgorithmProperties(
        name=name,
        primitive=primitive,
        parameter_set_identifier=algorithm_properties.get('parameterSetIdentifier'),
        curve=algorithm_properties.get('curve', 'unknown'),
        padding=algorithm_properties.get('padding'),
    )


def deserialise_certificate(
    certificate_properties: dict,
    crypto_assets_raw: collections.abc.Sequence[dict],
) -> dso.model.CertificateProperties:
    signature_algorithm_ref = bom_ref_to_data_key(
        bom_ref=certificate_properties.get('signatureAlgorithmRef'),
        crypto_assets_raw=crypto_assets_raw,
    )
    subject_public_key_ref = bom_ref_to_data_key(
        bom_ref=certificate_properties.get('subjectPublicKeyRef'),
        crypto_assets_raw=crypto_assets_raw,
    )

    kind = guess_certificate_kind(
        subject_name=certificate_properties.get('subjectName'),
    )

    if (
        (not_valid_before_raw := certificate_properties.get('notValidBefore'))
        and (not_valid_after_raw := certificate_properties.get('notValidAfter'))
    ):
        not_valid_before = datetime.datetime.fromisoformat(not_valid_before_raw)
        not_valid_after = datetime.datetime.fromisoformat(not_valid_after_raw)

        validity_seconds = (not_valid_after - not_valid_before).total_seconds()
        # use ceil here to better be too strict than too generous
        validity_years = math.ceil(validity_seconds / 60 / 60 / 24 / 365)
    else:
        validity_years = None

    return dso.model.CertificateProperties(
        kind=kind,
        validity_years=validity_years,
        signature_algorithm_ref=signature_algorithm_ref,
        subject_public_key_ref=subject_public_key_ref,
    )


def deserialise_related_crypto_material(
    related_crypto_material_properties: dict,
    crypto_assets_raw: collections.abc.Sequence[dict],
    description: str | None,
) -> dso.model.RelatedCryptoMaterialProperties:
    algorithm_ref = bom_ref_to_data_key(
        bom_ref=related_crypto_material_properties.get('algorithmRef'),
        crypto_assets_raw=crypto_assets_raw,
    )

    curve = determine_curve(
        description=description,
    )

    return dso.model.RelatedCryptoMaterialProperties(
        type=related_crypto_material_properties.get('type'),
        algorithm_ref=algorithm_ref,
        curve=curve,
        size=related_crypto_material_properties.get('size'),
    )


def deserialise_crypto_asset(
    crypto_asset_raw: dict,
    crypto_assets_raw: collections.abc.Sequence[dict],
) -> dso.model.CryptoAsset:
    name = crypto_asset_raw['name']
    type = ComponentTypes(crypto_asset_raw['type'])
    version = crypto_asset_raw.get('version')
    description = crypto_asset_raw.get('description')
    crypto_properties = crypto_asset_raw.get('cryptoProperties')

    if type is ComponentTypes.LIBRARY:
        asset_type = dso.model.CryptoAssetTypes.LIBRARY

    elif type is ComponentTypes.CRYPTOGRAPHIC_ASSET:
        if not crypto_properties:
            raise ValueError(
                f'The component property `cryptoProperties` must be set for components of {type=}'
            )
        asset_type = dso.model.CryptoAssetTypes(crypto_properties['assetType'])

    else:
        raise ValueError(
            f'{type=} is not a supported crypto asset type, '
            f'supported values: {[asset_type.value for asset_type in dso.model.CryptoAssetTypes]}'
        )

    if asset_type is dso.model.CryptoAssetTypes.ALGORITHM:
        properties = deserialise_algorithm(
            name=name,
            algorithm_properties=crypto_properties['algorithmProperties'],
        )

    elif asset_type is dso.model.CryptoAssetTypes.CERTIFICATE:
        properties = deserialise_certificate(
            certificate_properties=crypto_properties['certificateProperties'],
            crypto_assets_raw=crypto_assets_raw,
        )

    elif asset_type is dso.model.CryptoAssetTypes.LIBRARY:
        properties = dso.model.LibraryProperties(
            name=name,
            version=version,
        )

    elif asset_type is dso.model.CryptoAssetTypes.PROTOCOL:
        properties = dso.model.ProtocolProperties(
            type=crypto_properties['protocolProperties'].get('type'),
            version=crypto_properties['protocolProperties'].get('version'),
        )

    elif asset_type is dso.model.CryptoAssetTypes.RELATED_CRYPTO_MATERIAL:
        properties = deserialise_related_crypto_material(
            related_crypto_material_properties=crypto_properties.get('relatedCryptoMaterialProperties'), # noqa: E501
            crypto_assets_raw=crypto_assets_raw,
            description=description,
        )

    else:
        raise RuntimeError('this is a bug, we checked supported asset types before')

    locations = set(iter_locations(crypto_asset_raw=crypto_asset_raw))

    return dso.model.CryptoAsset(
        names=[name],
        locations=sorted(locations),
        asset_type=asset_type,
        properties=properties,
    )


def aggregate_crypto_assets(
    crypto_assets: collections.abc.Iterable[dso.model.CryptoAsset],
) -> list[dso.model.CryptoAsset]:
    '''
    Aggregates the provided `crypto_assets` based on their `key` property. If multiple assets have
    the same key, it means they are semantical identical but they may have a different name or were
    found at a different location. Therefore, all distinct names and locations are assigned to the
    aggregated asset as well.
    '''
    aggregated_crypto_assets: dict[str, dso.model.CryptoAsset] = dict()

    for crypto_asset in crypto_assets:
        key = crypto_asset.key

        if not key in aggregated_crypto_assets:
            aggregated_crypto_assets[key] = crypto_asset
            continue

        aggregated_crypto_asset = aggregated_crypto_assets[key]

        names = set(aggregated_crypto_asset.names) | set(crypto_asset.names)
        aggregated_crypto_asset.names = sorted(names)

        locations = set(aggregated_crypto_asset.locations) | set(crypto_asset.locations)
        aggregated_crypto_asset.locations = sorted(locations)

    return list(aggregated_crypto_assets.values())


def iter_crypto_assets(
    cbom: dict,
    crypto_libraries: list[str],
    included_asset_types: list[dso.model.CryptoAssetTypes] | None,
) -> list[dso.model.CryptoAsset]:
    validate_supported_schema_version(
        schema_version_raw=cbom['specVersion'],
    )

    crypto_assets_raw = list(filter_crypto_assets(
        components=cbom.get('components') or [],
        known_crypto_libraries=crypto_libraries,
        included_asset_types=included_asset_types,
    ))

    crypto_assets = list(
        deserialise_crypto_asset(
            crypto_asset_raw=crypto_asset_raw,
            crypto_assets_raw=crypto_assets_raw,
        ) for crypto_asset_raw in crypto_assets_raw
    )

    return aggregate_crypto_assets(
        crypto_assets=crypto_assets,
    )
