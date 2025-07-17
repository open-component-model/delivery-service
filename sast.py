#!/usr/bin/env python3
import collections.abc
import datetime
import enum
import functools
import logging

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import ocm

import k8s.util
import k8s.logging
import odg.extensions_cfg
import odg.findings
import odg.labels
import odg.model
import odg.util
import paths
import rescore.utility


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


class AnalysisLabel(enum.StrEnum):
    SAST = 'sast'


def has_local_linter(
    resources: list[ocm.Resource],
) -> bool:
    for resource in resources:
        if not (label := resource.find_label(name=odg.labels.PurposeLabel.name)):
            continue

        label_content = odg.labels.deserialise_label(label)
        if AnalysisLabel.SAST.value in label_content.value:
            return True

    return False


def find_scan_policy(
    snode: cnudie.iter.SourceNode
) -> odg.labels.ScanPolicy | None:
    if label := snode.source.find_label(name=odg.labels.SourceScanLabel.name):
        label_content = odg.labels.deserialise_label(label)
        return label_content.value.policy

    # Fallback to component-level label
    if label := snode.component.find_label(name=odg.labels.SourceScanLabel.name):
        label_content = odg.labels.deserialise_label(label)
        return label_content.value.policy

    # No label found
    return None


def create_missing_linter_finding(
    artefact: odg.model.ComponentArtefactId,
    sub_type: odg.model.SastSubType,
    categorisation: odg.findings.FindingCategorisation,
    creation_timestamp: datetime.datetime=datetime.datetime.now(tz=datetime.timezone.utc),
) -> odg.model.ArtefactMetadata | None:
    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.SAST,
            type=odg.model.Datatype.SAST_FINDING,
            creation_date=creation_timestamp,
            last_update=creation_timestamp,
        ),
        data=odg.model.SastFinding(
            sast_status=odg.model.SastStatus.NO_LINTER,
            severity=categorisation.id,
            sub_type=sub_type,
        ),
        discovery_date=creation_timestamp.date(),
        allowed_processing_time=categorisation.allowed_processing_time_raw,
    )


def iter_sast_artefacts_for_sub_type(
    sast_finding_config: odg.findings.Finding,
    sub_type: odg.model.SastSubType,
    artefact: odg.model.ComponentArtefactId,
    creation_timestamp: datetime.datetime=datetime.datetime.now(datetime.timezone.utc),
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    categorisation = odg.findings.categorise_finding(
        finding_cfg=sast_finding_config,
        finding_property=sub_type,
    )

    if not categorisation:
        return

    missing_linter_finding = create_missing_linter_finding(
        artefact=artefact,
        sub_type=sub_type,
        categorisation=categorisation,
        creation_timestamp=creation_timestamp,
    )

    if not missing_linter_finding:
        return

    yield missing_linter_finding

    rescoring = rescore.utility.rescoring_for_sast_finding(
        finding=missing_linter_finding,
        sast_finding_cfg=sast_finding_config,
        categorisation=categorisation,
        user=odg.model.User(
            username='sast-extension-auto-rescoring',
            type='sast-extension-user',
        ),
        creation_timestamp=creation_timestamp,
    )

    if not rescoring:
        return

    yield rescoring


def iter_artefact_metadata(
    artefact: odg.model.ComponentArtefactId,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    sast_finding_config: odg.findings.Finding,
    sast_config: odg.extensions_cfg.SASTConfig,
    creation_timestamp: datetime.datetime = datetime.datetime.now(datetime.timezone.utc),
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    '''
    Processes source nodes for a given component descriptor, yielding SAST metadata.
    Handles resource filtering, local linter findings, and rescoring logic.
    '''
    if not sast_finding_config.matches(artefact):
        logger.info(f'SAST findings are filtered out for {artefact=}, skipping...')
        return

    if not sast_config.is_supported(artefact_kind=artefact.artefact_kind):
        if sast_config.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by the SAST extension, maybe the filter '
                'configurations have to be adjusted to filter out this artefact kind'
            )
        return

    source_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
        absent_ok=True,
    )

    if not source_node:
        logger.info(f'did not find source node for {artefact=}, skipping...')
        return

    if len(source_node.component.sources) == 1:
        resources = source_node.component.resources
    else:
        resources = [
            resource
            for resource in source_node.component.resources
            for src_ref in resource.srcRefs
            # only support identity selector for now
            if src_ref.identitySelector.get('name') == source_node.source.name
        ]

    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.SAST,
            type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
            creation_date=creation_timestamp,
            last_update=creation_timestamp,
        ),
        data={},
        discovery_date=creation_timestamp.date(),
    )

    if find_scan_policy(source_node) is odg.labels.ScanPolicy.SKIP:
        logger.info(f'Skip label found for source {source_node.source.name}. '
                    'No SAST Linting required ...')
        return

    if not has_local_linter(resources):
        yield from iter_sast_artefacts_for_sub_type(
            sast_finding_config=sast_finding_config,
            sub_type=odg.model.SastSubType.LOCAL_LINTING,
            artefact=artefact,
            creation_timestamp=creation_timestamp,
        )

    yield from iter_sast_artefacts_for_sub_type(
        sast_finding_config=sast_finding_config,
        sub_type=odg.model.SastSubType.CENTRAL_LINTING,
        artefact=artefact,
        creation_timestamp=creation_timestamp,
    )


def scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.OsId,
    sast_finding_config: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    **kwargs,
):
    all_metadata = list(
        iter_artefact_metadata(
            artefact=artefact,
            component_descriptor_lookup=component_descriptor_lookup,
            sast_finding_config=sast_finding_config,
            sast_config=extension_cfg,
        )
    )

    delivery_client.update_metadata(data=all_metadata)


def main():
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    sast_finding_config = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.SAST_FINDING,
    )

    if not sast_finding_config:
        logger.info('SAST findings are disabled, exiting...')
        return

    scan_callback = functools.partial(
        scan,
        sast_finding_config=sast_finding_config,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.SAST,
        callback=scan_callback,
    )


if __name__ == '__main__':
    main()
