import logging
import pytest

import ci.log
import dso.model

import compliance_summary as cs
import odg.findings
import paths


# surpress warnings due to unknown os-id
ci.log.configure_default_logging(stdout_level=logging.ERROR)


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


@pytest.mark.asyncio
async def test_vulnerability(component_artefact_id):
    meta = dso.model.Metadata(
        datasource=None,
        type=odg.findings.FindingType.VULNERABILITY,
    )

    finding_cfg = odg.findings.Finding.from_file(
        path=paths.findings_cfg_path(),
        finding_type=odg.findings.FindingType.VULNERABILITY,
    )

    assert (await cs.calculate_summary_entry(
        finding_cfg=finding_cfg,
        findings=[dso.model.ArtefactMetadata(
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
        )],
        rescorings=[],
        eol_client=None,
    )).categorisation is cs.ComplianceEntryCategorisation.CLEAN

    assert (await cs.calculate_summary_entry(
        finding_cfg=finding_cfg,
        findings=[dso.model.ArtefactMetadata(
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
        )],
        rescorings=[],
        eol_client=None,
    )).categorisation == 'CRITICAL'


@pytest.mark.asyncio
async def test_malware(component_artefact_id):
    meta = dso.model.Metadata(
        datasource=None,
        type=odg.findings.FindingType.MALWARE,
    )

    finding_cfg = odg.findings.Finding.from_file(
        path=paths.findings_cfg_path(),
        finding_type=odg.findings.FindingType.MALWARE,
    )

    assert (await cs.calculate_summary_entry(
        finding_cfg=finding_cfg,
        findings=[dso.model.ArtefactMetadata(
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
        )],
        rescorings=[],
        eol_client=None,
    )).categorisation is cs.ComplianceEntryCategorisation.CLEAN

    assert (await cs.calculate_summary_entry(
        finding_cfg=finding_cfg,
        findings=[dso.model.ArtefactMetadata(
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
        )],
        rescorings=[],
        eol_client=None,
    )).categorisation == 'BLOCKER'


@pytest.mark.asyncio
async def test_licenses(component_artefact_id):
    meta = dso.model.Metadata(
        datasource=None,
        type=odg.findings.FindingType.LICENSE,
    )

    finding_cfg = odg.findings.Finding.from_file(
        path=paths.findings_cfg_path(),
        finding_type=odg.findings.FindingType.LICENSE,
    )

    assert (await cs.calculate_summary_entry(
        finding_cfg=finding_cfg,
        findings=[dso.model.ArtefactMetadata(
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
        )],
        rescorings=[],
        eol_client=None,
    )).categorisation is cs.ComplianceEntryCategorisation.CLEAN

    assert (await cs.calculate_summary_entry(
        finding_cfg=finding_cfg,
        findings=[dso.model.ArtefactMetadata(
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
        )],
        rescorings=[],
        eol_client=None,
    )).categorisation == 'BLOCKER'
