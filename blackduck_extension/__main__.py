#!/usr/bin/env python3

import functools
import logging

import blackduck.Client

import bdba_extension.scanning
import bdba.client
import bdba.model
import blackduck_extension.client
import k8s.logging
import k8s.util
import odg.extensions_cfg
import odg.model
import odg.util
import secret_mgmt

import cnudie.retrieve
import ci.log
import delivery.client
import oci.client

logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.BlackDuckExtensionConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
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

    bdba_secret = secret_factory.bdba(mapping.bdba_secret_name)
    bdba_client = bdba.client.BDBAApi(
        api_routes=bdba.client.BDBAApiRoutes(base_url=bdba_secret.api_url),
        token=bdba_secret.token,
        tls_verify=bdba_secret.tls_verify,
    )
    blackduck_secret = secret_factory.blackduck()[0]
    blackduck_client = blackduck.Client(
        base_url=blackduck_secret.api_url,
        token=blackduck_secret.credentials['token'],
    )

    known_scan_results = bdba_extension.scanning.retrieve_existing_scan_results(
        bdba_client=bdba_client,
        group_id=mapping.group_id_bdba,
        resource_node=resource_node,
    )

    for scan_result in known_scan_results:
        bdio: bdba.model.BDIO = bdba_client.bdio_export(scan_result.product_id)

        if project := blackduck_extension.client.find_project_by_name(
            blackduck_client,
            project_name=bdio.name
        ):
            logger.info(f'Project already exists {bdio.name} - skip')
            continue

        blackduck_extension.client.create_project(
            blackduck_client,
            project_name=bdio.name
        )

        blackduck_extension.client.assign_usergroup_to_project(
            blackduck_client,
            project,
            blackduck_secret.group_id
        )
        logger.info(f'Assigned group id to {bdio.name}')

        blackduck_extension.client.upload_bdio(
            blackduck_client=blackduck_client,
            bdio=bdio
        )


def main():
    parsed_arguments = odg.util.parse_args()

    scan_callback = functools.partial(
        scan,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.BlackDuck,
        callback=scan_callback,
    )


if __name__ == '__main__':
    main()
