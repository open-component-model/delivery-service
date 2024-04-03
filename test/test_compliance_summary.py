import logging
import pytest
import unittest.mock

import ci.log

import compliance_summary as cs
import deliverydb.model as dm

# surpress warnings due to unknown os-id
ci.log.configure_default_logging(stdout_level=logging.ERROR)


@pytest.fixture()
def eol_client():
    def cycles(
        product: str,
        absent_ok: bool = False,
    ):
        return [
            {
                'cycle': '9.99',
                'latest': '9.99.9',
                'eol': '9999-12-30',
            },
            {
                'cycle': '3.11',
                'latest': '3.11.13',
                'eol': '2021-11-01',
            },
        ]

    api_mock = unittest.mock.Mock()
    api_mock.cycles = cycles

    return api_mock


@pytest.fixture()
def artefact_metadata_cfg_by_type():
    cfg_raw = {
        'artefactMetadataCfg': [
            {
                'type': 'malware',
                'categories': [
                    'compliance',
                ],
                'severityMappings': [
                    {
                        'severityName': 'BLOCKER',
                        'malwareNames': [
                            '.*',
                        ],
                    },
                ]
            },
            {
                'type': 'os_ids',
                'categories': [
                    'compliance',
                ],
                'severityMappings': [
                    {
                        'severityName': 'CRITICAL',
                        'status': [
                            'isEol',
                        ],
                    },
                    {
                        'severityName': 'MEDIUM',
                        'status': [
                            'updateAvailableForBranch',
                        ],
                    },
                    {
                        'severityName': 'UNKNOWN',
                        'status': [
                            'emptyOsId',
                            'noBranchInfo',
                            'unableToCompareVersion',
                        ],
                    },
                    {
                        'severityName': 'CLEAN',
                        'status': [
                            'greatestBranchVersion',
                        ],
                    },
                ]
            },
        ]
    }

    return cs.artefact_metadata_cfg_by_type(artefact_metadata_cfg=cfg_raw)


def test_vulnerability():
    type = 'finding/vulnerability'

    with pytest.raises(KeyError):
        cs.severity_for_finding(
            finding=dm.ArtefactMetaData(
                type=type,
                data=dict(),
            ),
        )

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={'severity': 'NONE'},
        ),
    ) == cs.ComplianceEntrySeverity.CLEAN.name

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={'severity': 'CRITICAL'},
        ),
    ) == cs.ComplianceEntrySeverity.CRITICAL.name


def test_malware(artefact_metadata_cfg_by_type):
    type = 'malware'

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={'findings': []},
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
    ) == cs.ComplianceEntrySeverity.CLEAN.name

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={
                'findings': [
                    {'name': 'bad_virus'},
                ],
            },
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
    ) == cs.ComplianceEntrySeverity.BLOCKER.name


def test_os_id(
    eol_client,
    artefact_metadata_cfg_by_type,
):
    type = 'os_ids'

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={'os_info': {}},
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.UNKNOWN.name

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={
                'os_info': {
                    'VERSION_ID': '9.99.1',
                    'ID': 'fooOs',
            },
        }),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.MEDIUM.name

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={
                'os_info': {
                    'VERSION_ID': '9.99.9',
                    'ID': 'fooOs',
            },
        }),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.CLEAN.name

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={
                'os_info': {
                    'VERSION_ID': '3.11.5',
                    'ID': 'fooOs',
                },
            },
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.CRITICAL.name

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={
                'os_info': {
                    'VERSION_ID': 'bar--foo',
                    'ID': 'fooOs',
                },
            },
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.UNKNOWN.name


def test_licenses():
    type = 'finding/license'

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={'severity': 'NONE'},
        ),
    ) == cs.ComplianceEntrySeverity.CLEAN.name

    assert cs.severity_for_finding(
        finding=dm.ArtefactMetaData(
            type=type,
            data={'severity': 'BLOCKER'},
        ),
    ) == cs.ComplianceEntrySeverity.BLOCKER.name
