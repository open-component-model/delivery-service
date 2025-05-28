#!/usr/bin/env python3

import logging

import ci.log
import cnudie.retrieve
import oci.client

import bdba.model
import bdba_utils.scan
import bdba_utils.util
import blackduck_extension.util
import lookups
import k8s.logging
import k8s.util
import odg.extensions_cfg
import odg.model
import odg.util
import secret_mgmt


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.BlackDuckExtensionConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    **kwargs,
):
    logger.info(f'processing {artefact}')

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(f'{artefact.artefact_kind} is not supported for BlackDuck scans')
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access = resource_node.resource.access

    if not extension_cfg.is_supported(access_type=access.type):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(f'{access.type} is not supported for BlackDuck scans')
        return

    mapping = extension_cfg.mapping(artefact.component_name)

    bdba_client = lookups.bdba_client_lookup(
        secret_factory=secret_factory,
        group_id=mapping.group_id_bdba
    )

    blackduck_client = lookups.blackduck_client_lookup(
        secret_factory=secret_factory,
        group_id=mapping.group_id_blackduck
    )

    known_scan_results = bdba_utils.scan.retrieve_existing_scan_results(
        bdba_client=bdba_client,
        group_id=mapping.group_id_bdba,
        resource_node=resource_node,
    )

    component_artefact_metadata = bdba_utils.util.component_artefact_metadata(resource_node)

    target_product_id = bdba_utils.util._matching_analysis_result_id(
        component_artefact_metadata=component_artefact_metadata,
        analysis_results=known_scan_results,
    )

    if not target_product_id:
        logger.info(f'No matching scan result found for {artefact=}, triggering scan')
        scan_result = bdba_utils.scan.run_scan(
            aws_secret_name=mapping.aws_secret_name,
            bdba_client=bdba_client,
            group_id=mapping.group_id_bdba,
            oci_client=oci_client,
            processing_mode=mapping.processing_mode,
            resource_node=resource_node,
            secret_factory=secret_factory,
        )
        target_product_id = next(scan_result).data.product_id

    bdio: bdba.model.BDIO = bdba_client.bdio_export(product_id=target_product_id)

    project_group_name = artefact.component_name

    project_group = blackduck_client.find_project_group_by_name(name=project_group_name)

    if not project_group:
        blackduck_client.create_project_group(
            name=project_group_name,
            description=f'Group for component {project_group_name}',
        )
        project_group = blackduck_extension.util.wait_for_project_group(
            blackduck_client=blackduck_client,
            project_group_name=project_group_name
        )

    project_group_id = blackduck_extension.util.extract_project_group_id(
        project_group=project_group
    )

    blackduck_client.assign_usergroup_to_project_group(
        project_group_id=project_group_id,
        usergroup_id=mapping.group_id_blackduck,
    )

    project = blackduck_client.find_project_by_name(
        name=bdio.name
    )

    if project:
        logger.info(f'Project already exists: {bdio.name} - skipping upload')
        return

    blackduck_client.create_project(
        project_name=bdio.name,
        project_group_id=project_group_id,
    )
    logger.info(f'Created project {bdio.name}')

    project = blackduck_extension.util.wait_for_project(
        blackduck_client=blackduck_client,
        project_name=bdio.name
    )

    if not project:
        logger.error(f'Failed to find project after creation: {bdio.name}')
        return

    blackduck_client.assign_usergroup_to_project(
        project_id=blackduck_extension.util.extract_project_id(project=project),
        usergroup_id=mapping.group_id_blackduck
    )
    logger.info(f'Assigned group id to {bdio.name}')

    blackduck_client.upload_bdio(bdio=bdio.as_blackduck_bytes())
    logger.info('Upload successful.')


def main():
    odg.util.process_backlog_items(
        parsed_arguments=odg.util.parse_args(),
        service=odg.extensions_cfg.Services.BLACKDUCK,
        callback=scan,
    )


if __name__ == '__main__':
    main()
