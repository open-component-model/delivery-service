import pytest

import crypto_extension.model
import crypto_extension.validate
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.shared_cfg
import paths


@pytest.fixture
def crypto_mapping() -> odg.extensions_cfg.CryptoMapping:
    return odg.extensions_cfg.CryptoMapping(
        prefix='',
        standards=[
            odg.extensions_cfg.StandardRef(
                name='FIPS',
                version='140-3',
                ref=odg.shared_cfg.SharedCfgLocalReference(path='odg/crypto_defaults.yaml'),
            ),
            odg.extensions_cfg.StandardRef(
                name='NCS',
                version='1.0',
                ref=odg.shared_cfg.SharedCfgLocalReference(path='odg/crypto_defaults.yaml'),
            ),
        ],
        libraries=[
            odg.extensions_cfg.LibrariesRef(
                ref=odg.shared_cfg.SharedCfgLocalReference(path='odg/crypto_defaults.yaml'),
            ),
        ],
        included_asset_types=None,
        aws_secret_name=None,
    )


@pytest.fixture
def crypto_finding_cfg() -> odg.findings.Finding:
    findings_cfg_path = paths.findings_cfg_path()

    return odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.CRYPTO_FINDING,
    )


@pytest.fixture
def cbom() -> dict:
    return {
        'specVersion': '1.6',
        'components': [{
            'type': 'library',
            'name': 'no-crypto-library',
            'version': '0.1.0',
        }, {
            'type': 'library',
            'name': 'golang.org/x/crypto',
            'version': 'v0.27.0',
            'properties': [{
                'name': 'syft:location:0:path',
                'value': '/opt/docker/dockerd',
            }],
        }, {
            'bom-ref': 'f8394d4343ecaefa',
            'type': 'cryptographic-asset',
            'name': 'ECDSA',
            'evidence': {
                'occurrences': [{
                    'location': '/etc/ssl/cert.pem',
                }],
            },
            'cryptoProperties': {
                'assetType': 'algorithm',
                'algorithmProperties': {
                    'primitive': 'pke',
                },
            },
        }, {
            'bom-ref': '01ae17be396c0524',
            'type': 'cryptographic-asset',
            'name': 'ECDSA-SHA384',
            'evidence': {
                'occurrences': [{
                    'location': '/etc/ssl/cert.pem',
                }],
            },
            'cryptoProperties': {
                'assetType': 'algorithm',
                'algorithmProperties': {
                    'primitive': 'signature',
                    'parameterSetIdentifier': '384',
                },
            },
        }, {
            'bom-ref': '6ca0151091803ee4',
            'type': 'cryptographic-asset',
            'name': 'ECDSA',
            'description': 'Curve: P-384',
            'evidence': {
                'occurrences': [{
                    'location': '/etc/ssl/cert.pem',
                }],
            },
            'cryptoProperties': {
                'assetType': 'related-crypto-material',
                'relatedCryptoMaterialProperties': {
                    'type': 'public-key',
                    'algorithmRef': 'f8394d4343ecaefa',
                },
            },
        }, {
            'type': 'cryptographic-asset',
            'name': 'arbitrary-certificate-name',
            'evidence': {
                'occurrences': [{
                    'location': '/etc/ssl/cert.pem',
                }],
            },
            'cryptoProperties': {
                'assetType': 'certificate',
                'certificateProperties': {
                    'subjectName': 'arbitrary-certificate-name',
                    'issuerName': 'arbitrary-certificate-name',
                    'notValidBefore': '2020-08-25T07:48:20Z',
                    'notValidAfter': '2045-08-25T23:59:59Z',
                    'signatureAlgorithmRef': '01ae17be396c0524',
                    'subjectPublicKeyRef': '6ca0151091803ee4',
                },
            },
        }],
    }


def test_crypto_validation(
    cbom: dict,
    crypto_mapping: odg.extensions_cfg.CryptoMapping,
    crypto_finding_cfg: odg.findings.Finding,
):
    crypto_assets = crypto_extension.model.iter_crypto_assets(
        cbom=cbom,
        crypto_libraries=crypto_mapping.libraries,
        included_asset_types=crypto_mapping.included_asset_types,
    )

    assert len([
        crypto_asset for crypto_asset in crypto_assets
        if crypto_asset.asset_type is odg.model.CryptoAssetTypes.LIBRARY
    ]) == 1

    assert len([
        crypto_asset for crypto_asset in crypto_assets
        if crypto_asset.asset_type is odg.model.CryptoAssetTypes.ALGORITHM
    ]) == 2

    assert len([
        crypto_asset for crypto_asset in crypto_assets
        if crypto_asset.asset_type is odg.model.CryptoAssetTypes.RELATED_CRYPTO_MATERIAL
    ]) == 1

    assert len([
        crypto_asset for crypto_asset in crypto_assets
        if crypto_asset.asset_type is odg.model.CryptoAssetTypes.CERTIFICATE
    ]) == 1

    assert len([
        crypto_asset for crypto_asset in crypto_assets
        if crypto_asset.asset_type is odg.model.CryptoAssetTypes.PROTOCOL
    ]) == 0

    findings = list(crypto_extension.validate.iter_findings_for_standards(
        crypto_assets=crypto_assets,
        standards=crypto_mapping.standards,
        crypto_finding_cfg=crypto_finding_cfg,
    ))

    assert len([
        finding for finding in findings
        if finding.standard == 'FIPS'
    ]) == 2

    assert len([
        finding for finding in findings
        if finding.standard == 'NCS'
    ]) == 3
