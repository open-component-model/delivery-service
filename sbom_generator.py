#!/usr/bin/env python3
import json
import logging

import bdba.client
import bdba.model
import bdba_utils.scan
import bdba_utils.util
import ci.log
import cnudie.retrieve
import delivery.client
import oci.client
import k8s.util
import k8s.logging

import ocm
import odg.model
import odg.util
import odg.extensions_cfg
import secret_mgmt
import secret_mgmt.bdba

logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


SUPPORTED_SBOM_FORMATS = [
    bdba.model.SBomFormat.CYCLONEDX,
    bdba.model.SBomFormat.SPDX
    ]


def get_or_create_bdba_scan(
    resource_node: ocm.iter.ResourceNode,
    bdba_api: bdba.client.BDBAApi,
    group_id: int,
    aws_secret_name: str | None,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    processing_mode: bdba.model.ProcessingMode,
    create_new_scan_if_missing: bool=False,
) -> int:
    existing_scans = bdba_utils.scan.retrieve_existing_scan_results(
        bdba_client=bdba_api,
        group_id=group_id,
        resource_node=resource_node,
    )

    component_artefact_metadata = bdba_utils.util.component_artefact_metadata(resource_node)

    product_id = bdba_utils.util._matching_analysis_result_id(
        component_artefact_metadata=component_artefact_metadata,
        analysis_results=existing_scans,
    )

    if product_id:
        logger.info(f'Found existing BDBA scan: {product_id=}')
        return product_id

    if create_new_scan_if_missing:
        logger.info(
            f'No existing BDBA scan found, creating a new BDBA scan for: '
            f'{resource_node.resource.name}'
        )

        metadata_generator = bdba_utils.scan.run_scan(
            aws_secret_name=aws_secret_name,
            bdba_client=bdba_api,
            group_id=group_id,
            processing_mode=processing_mode,
            resource_node=resource_node,
            secret_factory=secret_factory,
            oci_client=oci_client,
            delivery_client=delivery_client,
        )

        if product_id := next(metadata_generator).data.get('product_id'):
            logger.info(f'Created new BDBA scan: {product_id=}')
            return product_id

        logger.error('BDBA scan created but no product_id was returned')
        raise RuntimeError('BDBA scan created but no product_id was returned')


def generate_sbom_for_resource_node(
    resource_node: ocm.iter.ResourceNode,
    aws_secret_name: str | None,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    group_id: int,
    processing_mode: bdba.model.ProcessingMode,
    output_format: str = bdba.model.SBomFormat.CYCLONEDX,
    create_new_scan_if_missing: bool=False,
) -> bdba.model.SBOM:
    if not (bdba_secret := secret_mgmt.bdba.find_cfg(
        secret_factory=secret_factory,
        group_id=group_id,
    )):
        raise ValueError(f'no BDBA secret found for group {group_id}')

    bdba_api = bdba.client.BDBAApi(
        api_routes=bdba.client.BDBAApiRoutes(base_url=bdba_secret.api_url),
        token=bdba_secret.token,
    )

    product_id = get_or_create_bdba_scan(
        resource_node=resource_node,
        bdba_api=bdba_api,
        group_id=group_id,
        aws_secret_name=aws_secret_name,
        delivery_client=delivery_client,
        oci_client=oci_client,
        secret_factory=secret_factory,
        create_new_scan_if_missing=create_new_scan_if_missing,
        processing_mode=processing_mode,
    )

    if not product_id:
        raise ValueError(f'No BDBA scan available '
                         f'for resource {resource_node.resource.name} '
                        f'in component {resource_node.component.name}:'
                        f'{resource_node.component.version}'
        )

    normalized_output_format = output_format.lower()
    if normalized_output_format not in SUPPORTED_SBOM_FORMATS:
        raise ValueError(f'Unsupported SBOM format: {output_format}. '
                        f'Supported formats: '
                        f'{', '.join(SUPPORTED_SBOM_FORMATS)}'
        )

    sbom_raw = bdba_api.export_sbom(product_id, normalized_output_format)

    sbom = bdba.model.SBOM(sbom_raw=sbom_raw, sbom_format=normalized_output_format)

    return sbom


def generate_sbom_for_artefact(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.SBOMGeneratorConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    **kwargs,
) -> bdba.model.SBOM:
    '''
    Generates Software Bill of Materials (SBOM) for a component artefact.
    Resolves the component descriptor from OCM repositories,
    retrieves BDBA security scans, and exports the SBOM
    in the requested format with OCM metadata.
    '''
    logger.info(f'Generating SBOM for artefact: {artefact}')

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported '
                'by the SBOM Generator extension,'
                'maybe the filter configurations have to be adjusted '
                'to filter out this artefact kind'
            )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact
    )

    if not resource_node:
        logger.info(f'did not find resource node for {artefact=}, skipping...')
        return

    mapping = extension_cfg.mapping(artefact.component_name)

    logger.info(f'Scanning {resource_node} resource nodes')

    sbom = generate_sbom_for_resource_node(
        resource_node=resource_node,
        aws_secret_name=mapping.aws_secret_name,
        delivery_client=delivery_client,
        oci_client=oci_client,
        secret_factory=secret_factory,
        output_format=extension_cfg.output_format,
        create_new_scan_if_missing=extension_cfg.create_new_scan_if_missing,
        group_id=mapping.group_id,
        processing_mode=extension_cfg.processing_mode,
    )

    safe_name = 'sbom_output.json'

    with open(safe_name, 'w', encoding='utf-8') as f:
        json.dump(sbom.sbom_raw, f, indent=2, ensure_ascii=False)

    logger.info(f'\nSBOM files saved to: {safe_name}')

    if not sbom:
        raise RuntimeError(f'Failed to generate SBOM for '
                           f'{resource_node.resource.name}'
        )
    return sbom


def main():
    parsed_arguments = odg.util.parse_args()

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.SBOM_GENERATOR,
        callback=generate_sbom_for_artefact,
    )


if __name__ == '__main__':
    main()
