import pytest

import odg.scan_cfg


@pytest.fixture
def extension_cfg() -> odg.scan_cfg.ScanConfiguration:
    raw = {
        'defaults': {
            'delivery_service_url': 'foo',
        },
        'sast': {
            'enabled': True,
        },
        'bdba': {
            'enabled': False,
            'mappings': [],
        },
        'clamav': {
            'mappings': []
        },
    }
    return odg.scan_cfg.ScanConfiguration.from_dict(raw)


def test_enabled_defaults(extension_cfg: odg.scan_cfg.ScanConfiguration):
    assert extension_cfg.sast.enabled is True
    assert extension_cfg.bdba.enabled is False
    assert extension_cfg.clamav.enabled is True
