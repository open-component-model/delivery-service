import pytest

import odg.extensions_cfg


@pytest.fixture
def extensions_cfg() -> odg.extensions_cfg.ExtensionsConfiguration:
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
    return odg.extensions_cfg.ExtensionsConfiguration.from_dict(raw)


def test_enabled_defaults(extensions_cfg: odg.extensions_cfg.ExtensionsConfiguration):
    assert extensions_cfg.sast.enabled is True
    assert extensions_cfg.bdba.enabled is False
    assert extensions_cfg.clamav.enabled is True
