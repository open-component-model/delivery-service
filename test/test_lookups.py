import pytest

import lookups


@pytest.fixture
def ocm_repository_cfgs() -> list[lookups.VirtualOcmRepositoryCfg | lookups.OciOcmRepositoryCfg]:
    ocm_repository_cfgs_raw = [
        {
            'name': '<auto>',
            'type': 'virtual',
            'selectors': {
                'required_labels': 'releases',
            },
        },
        {
            'name': '<releases>',
            'type': 'virtual',
            'selectors': [{
                'required_labels': 'releases',
            }],
        },
        {
            'name': '<auto-all>',
            'type': 'virtual',
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/releases',
            'prefixes': [
                'ocm.software/ocm-gear',
                'github.com/gardener',
            ],
            'labels': 'releases',
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/releases/odg',
            'prefix': 'ocm.software/ocm-gear',
            'labels': 'releases',
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/snapshots',
            'prefixes': [
                'ocm.software/ocm-gear',
                'github.com/gardener',
            ],
            'labels': 'snapshots',
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/snapshots/odg',
            'prefixes': [
                'ocm.software/ocm-gear',
            ],
            'labels': [
                'snapshots',
            ],
        },
        {
            'repository': 'europe-docker.pkg.dev/gardener-project/fallback',
        },
    ]

    return [
        lookups.OcmRepositoryCfgBase.from_dict(ocm_repository_cfg_raw)
        for ocm_repository_cfg_raw in ocm_repository_cfgs_raw
    ]


def test_ocm_repository_cfgs(
    ocm_repository_cfgs: list[lookups.VirtualOcmRepositoryCfg | lookups.OciOcmRepositoryCfg],
):
    # test `<auto>` virtual repository
    ocm_repository_lookup = lookups.init_ocm_repository_lookup(
        ocm_repo=None,
        ocm_repository_cfgs=ocm_repository_cfgs,
    )

    assert len(list(ocm_repository_lookup('ocm.software/ocm-gear/delivery-service'))) == 2
    assert len(list(ocm_repository_lookup('github.com/gardener/gardener'))) == 1

    # test `<auto-all>` virtual repository
    ocm_repository_lookup = lookups.init_ocm_repository_lookup(
        ocm_repo='<auto-all>',
        ocm_repository_cfgs=ocm_repository_cfgs,
    )

    assert len(list(ocm_repository_lookup('ocm.software/ocm-gear/delivery-service'))) == 5
    assert len(list(ocm_repository_lookup('github.com/gardener/gardener'))) == 3

    # test existing standard repository
    ocm_repository_lookup = lookups.init_ocm_repository_lookup(
        ocm_repo='europe-docker.pkg.dev/gardener-project/releases/odg',
        ocm_repository_cfgs=ocm_repository_cfgs,
    )

    assert len(list(ocm_repository_lookup('ocm.software/ocm-gear/delivery-service'))) == 1
    assert len(list(ocm_repository_lookup('github.com/gardener/gardener'))) == 0

    # test not existing repository
    ocm_repository_lookup = lookups.init_ocm_repository_lookup(
        ocm_repo='foo',
        ocm_repository_cfgs=ocm_repository_cfgs,
    )

    assert len(list(ocm_repository_lookup('ocm.software/ocm-gear/delivery-service'))) == 1
    assert len(list(ocm_repository_lookup('github.com/gardener/gardener'))) == 1
