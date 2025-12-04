import logging

import ocm.iter

import bdba.client
import bdba.model as bm
import odg.cvss
import odg.findings
import odg.model
import rescore.utility as ru

logger = logging.getLogger(__name__)


def rescore(
    bdba_client: bdba.client.BDBAApi,
    scan_result: bm.AnalysisResult,
    scanned_element: ocm.iter.ResourceNode,
    vulnerability_cfg: odg.findings.Finding,
) -> bool:
    '''
    Rescores bdba-findings for the scanned element of the given components scan result.
    Rescoring is only possible if cve-categorisations are available from categoristion-label
    in either resource or component. Returns a boolean indicating whether a triage was applied
    or not (if yes, a refetching of the scan result may be required).
    '''
    if not vulnerability_cfg.rescoring_ruleset:
        return False

    if not (cve_categorisation := ru.find_cve_categorisation(scanned_element)):
        return False

    artefact = odg.model.component_artefact_id_from_ocm(
        component=scanned_element.component,
        artefact=scanned_element.resource,
    )

    if not vulnerability_cfg.matches(artefact):
        return False

    logger.info(f'rescoring {scan_result.display_name} - {scan_result.product_id=}')

    components_with_vulnerabilities = (
        component for component in scan_result.components
        if tuple(component.vulnerabilities)
    )

    components_with_vulnerabilities = sorted(
        components_with_vulnerabilities,
        key=lambda c: c.name,
    )

    triages_were_applied = False

    for c in components_with_vulnerabilities:
        if not c.version:
            continue # do not inject dummy-versions in fully automated mode, yet

        vulns_to_assess = []

        for v in c.vulnerabilities:
            if v.okay_to_skip or v.has_triage:
                # we don't need to add a triage if the vuln is skipped anyways or was already triaged
                continue

            categorisation = odg.findings.categorise_finding(
                finding_cfg=vulnerability_cfg,
                finding_property=v.cve_severity(),
            )

            if (
                not categorisation
                or not categorisation.automatic_rescoring
            ):
                continue

            matching_rules = ru.matching_rescore_rules(
                rescoring_rules=vulnerability_cfg.rescoring_ruleset.rules,
                categorisation=cve_categorisation,
                cvss=odg.cvss.CVSSV3.parse(v.cvss),
            )

            rescored_categorisation = ru.rescore_finding(
                finding_cfg=vulnerability_cfg,
                current_categorisation=categorisation,
                rescoring_rules=matching_rules,
                operations=vulnerability_cfg.rescoring_ruleset.operations,
            )

            if rescored_categorisation.value == 0: # BDBA only allows binary triages
                vulns_to_assess.append(v)

        if vulns_to_assess:
            logger.info(f'{len(vulns_to_assess)=}: {[v.cve for v in vulns_to_assess]}')
            bdba_client.add_triage_raw({
                'component': c.name,
                'version': c.version,
                'vulns': [v.cve for v in vulns_to_assess],
                'scope': bm.TriageScope.RESULT.value,
                'reason': 'OT',
                'description': 'auto-assessed as irrelevant based on cve-categorisation',
                'product_id': scan_result.product_id,
            })
            triages_were_applied = True

    return triages_were_applied
