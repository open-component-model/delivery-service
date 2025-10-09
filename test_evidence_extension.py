import collections.abc
import datetime
import functools
import logging

import ci.log
import cnudie.retrieve
import delivery.client
import ocm
import ocm.iter

import k8s.logging
import k8s.util
import odg.extensions_cfg
import odg.findings
import odg.labels
import odg.model
import odg.util
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()
PURPOSE_LABEL_VALUE = 'test'


def is_test_required(
    artefact_node: ocm.iter.ArtefactNode,
    extensions_cfg: odg.extensions_cfg.TestEvidenceConfig,
) -> bool:
    artefact = artefact_node.artefact

    # reuse artefact filter once it supports relation attribute
    if (
        not extensions_cfg.external_artefacts_require_tests
        and artefact_node.artefact.relation is ocm.ResourceRelation.EXTERNAL
    ):
        return False

    # TODO: use artefact filter once factored out

    test_policy_label = artefact.find_label(name=odg.labels.TestPolicyLabel.name)
    if not test_policy_label:
        return True # require all resources to provide test evidences by default

    test_policy_label: odg.labels.TestPolicyLabel = odg.labels.deserialise_label(
        label=test_policy_label,
    )
    return test_policy_label.value


def iter_test_evidence_resources(
    component: ocm.Component,
) -> collections.abc.Generator[ocm.Resource, None, None]:
    return (
        resource
        for resource in component.resources
        if (
            (label := resource.find_label(name=odg.labels.PurposeLabel.name))
            and PURPOSE_LABEL_VALUE in label.value
        )
    )


def has_artefact_test_coverage(
    artefact_name: str,
    test_evidences: collections.abc.Iterable[ocm.Resource],
) -> bool:
    artefact_names_with_test_evidence = []
    for test_evidence in test_evidences:
        if not (test_scope_label := test_evidence.find_label(name=odg.labels.TestScopeLabel.name)):
            # if label is absent, assume tests are scoping *all* resources within this component
            return True

        test_scope_label: ocm.Label
        test_scope_label: odg.labels.TestScopeLabel = odg.labels.deserialise_label(
            label=test_scope_label,
        )
        artefact_names_with_test_evidence.append(test_scope_label.value)

    return artefact_name in artefact_names_with_test_evidence


def missing_test_evidence_finding(
    artefact: odg.model.ComponentArtefactId,
    artefact_node: ocm.iter.ArtefactNode,
    sub_type: odg.model.TestStatus,
    findings_cfg: odg.findings.Finding,
    extensions_cfg: odg.extensions_cfg.TestEvidenceConfig,
) -> odg.model.ArtefactMetadata | None:
    categorisation: odg.findings.FindingCategorisation = odg.findings.categorise_finding(
        finding_cfg=findings_cfg,
        finding_property=sub_type
    )

    if not is_test_required(
        artefact_node=artefact_node,
        extensions_cfg=extensions_cfg,
    ):
        return None

    test_evidences: collections.abc.Iterable[ocm.Resource] = iter_test_evidence_resources(
        component=artefact_node.component,
    )

    if has_artefact_test_coverage(
        artefact_name=artefact_node.artefact.name,
        test_evidences=test_evidences,
    ):
        return None

    now = datetime.datetime.now()
    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.TEST_EVIDENCE,
            type=odg.model.Datatype.TEST_EVIDENCE_FINDING,
            creation_date=now,
            last_update=now,
        ),
        data=odg.model.TestEvidenceMissingFinding(
            test_status=odg.model.TestStatus.NO_TEST_EVIDENCE,
            severity=categorisation.id
        ),
        discovery_date=now.date(),
    )


def finding_artefact_metadata(
    artefact: odg.model.ComponentArtefactId,
    extensions_cfg: odg.extensions_cfg.TestEvidenceConfig,
    findings_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
) -> odg.model.ArtefactMetadata | None:
    if not findings_cfg.matches(artefact):
        logger.info(f'Findings are filtered out for {artefact=}, skipping...')
        return

    artefact_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )

    if not artefact_node:
        logger.info(f'did not find {artefact=}, skipping...')
        return

    if not extensions_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extensions_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(f'{artefact.artefact_kind} is not supported')
        return

    return missing_test_evidence_finding(
        component_resource_id=artefact,
        resource_node=artefact_node,
        sub_type=odg.model.TestStatus.NO_TEST_EVIDENCE,
        findings_cfg=findings_cfg,
        extensions_cfg=extensions_cfg,
    )


def scan(
    artefact: odg.model.ComponentArtefactId,
    extensions_cfg: odg.extensions_cfg.TestEvidenceConfig,
    findings_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    **kwargs, # odg wrapper passes more attributes than we need
):
    now = datetime.datetime.now()

    delivery_client.update_metadata(
        data=[
            odg.model.ArtefactMetadata(
                artefact=artefact,
                meta=odg.model.Metadata(
                    datasource=odg.model.Datasource.TEST_EVIDENCE,
                    type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
                    creation_date=now,
                    last_update=now,
                ),
                data={},
                discovery_date=now.date(),
            ),
            finding_artefact_metadata(
                artefact=artefact,
                extensions_cfg=extensions_cfg,
                findings_cfg=findings_cfg,
                component_descriptor_lookup=component_descriptor_lookup
            )
        ]
    )


def main():
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    findings_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.TEST_EVIDENCE_FINDING,
    )

    if not findings_cfg:
        logger.info('Test evidence findings are disabled, exiting...')
        return

    scan_callback = functools.partial(
        scan,
        findings_cfg=findings_cfg,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.TEST_EVIDENCE,
        callback=scan_callback,
    )


if __name__ == '__main__':
    main()
