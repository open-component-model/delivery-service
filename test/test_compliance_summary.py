import logging
import pytest
import unittest.mock

import ci.log
import dso.model
import unixutil.model

import compliance_summary as cs

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


@pytest.fixture
def component_artefact_id() -> dso.model.ComponentArtefactId:
    return dso.model.ComponentArtefactId(
        component_name=None,
        component_version=None,
        artefact=dso.model.LocalArtefactId(
            artefact_name=None,
            artefact_version=None,
            artefact_type=None,
            artefact_extra_id=dict(),
        ),
    )


def test_vulnerability(component_artefact_id):
    type = 'finding/vulnerability'
    meta = dso.model.Metadata(
        datasource=None,
        type=type,
    )

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.VulnerabilityFinding(
                package_name=None,
                package_version=None,
                base_url=None,
                report_url=None,
                product_id=-1,
                group_id=-1,
                severity='NONE',
                cve=None,
                cvss_v3_score=-1,
                cvss=dict(),
                summary=None,
            ),
        ),
    ) == cs.ComplianceEntrySeverity.CLEAN.name

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.VulnerabilityFinding(
                package_name=None,
                package_version=None,
                base_url=None,
                report_url=None,
                product_id=-1,
                group_id=-1,
                severity='CRITICAL',
                cve=None,
                cvss_v3_score=-1,
                cvss=dict(),
                summary=None,
            ),
        ),
    ) == cs.ComplianceEntrySeverity.CRITICAL.name


def test_malware(component_artefact_id):
    type = 'finding/malware'
    meta = dso.model.Metadata(
        datasource=None,
        type=type,
    )

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.ClamAVMalwareFinding(
                finding=dso.model.MalwareFindingDetails(
                    filename='sha256:xxx|foo/bar',
                    content_digest='sha256:foo',
                    malware='very-bad-virus',
                    context=None,
                ),
                octets_count=1024,
                scan_duration_seconds=1.0,
                severity='NONE',
                clamav_version=None,
                signature_version=None,
                freshclam_timestamp=None,
            ),
        ),
    ) == cs.ComplianceEntrySeverity.CLEAN.name

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.ClamAVMalwareFinding(
                finding=dso.model.MalwareFindingDetails(
                    filename='sha256:xxx|foo/bar',
                    content_digest='sha256:foo',
                    malware='very-bad-virus',
                    context=None,
                ),
                octets_count=1024,
                scan_duration_seconds=1.0,
                severity='BLOCKER',
                clamav_version=None,
                signature_version=None,
                freshclam_timestamp=None,
            ),
        ),
    ) == cs.ComplianceEntrySeverity.BLOCKER.name


def test_os_id(
    eol_client,
    artefact_metadata_cfg_by_type,
    component_artefact_id,
):
    type = 'os_ids'
    meta = dso.model.Metadata(
        datasource=None,
        type=type,
    )

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.OsID(
                os_info=unixutil.model.OperatingSystemId(),
            ),
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.UNKNOWN.name

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.OsID(
                os_info=unixutil.model.OperatingSystemId(
                    VERSION_ID='9.99.1',
                    ID='fooOs',
                ),
            ),
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.MEDIUM.name

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.OsID(
                os_info=unixutil.model.OperatingSystemId(
                    VERSION_ID='9.99.9',
                    ID='fooOs',
                ),
            ),
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.CLEAN.name

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.OsID(
                os_info=unixutil.model.OperatingSystemId(
                    VERSION_ID='3.11.5',
                    ID='fooOs',
                ),
            ),
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.CRITICAL.name

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.OsID(
                os_info=unixutil.model.OperatingSystemId(
                    VERSION_ID='bar--foo',
                    ID='fooOs',
                ),
            ),
        ),
        artefact_metadata_cfg=artefact_metadata_cfg_by_type[type],
        eol_client=eol_client,
    ) == cs.ComplianceEntrySeverity.UNKNOWN.name


def test_licenses(component_artefact_id):
    type = 'finding/license'
    meta = dso.model.Metadata(
        datasource=None,
        type=type,
    )

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.LicenseFinding(
                package_name=None,
                package_version=None,
                base_url=None,
                report_url=None,
                product_id=-1,
                group_id=-1,
                severity='NONE',
                license=None,
            ),
        ),
    ) == cs.ComplianceEntrySeverity.CLEAN.name

    assert cs.severity_for_finding(
        finding=dso.model.ArtefactMetadata(
            artefact=component_artefact_id,
            meta=meta,
            data=dso.model.LicenseFinding(
                package_name=None,
                package_version=None,
                base_url=None,
                report_url=None,
                product_id=-1,
                group_id=-1,
                severity='BLOCKER',
                license=None,
            ),
        ),
    ) == cs.ComplianceEntrySeverity.BLOCKER.name
