#!/usr/bin/env python3
import dataclasses
import datetime
import hashlib
import json
import logging
import os
import tempfile

import ci.log
import cnudie.retrieve
import oci.client

import bdba.client
import bdba.model
import bdba_utils.scan
import bdba_utils.util
import dockerutil
import k8s.util
import k8s.logging
import ocm
import ocm.iter
import odg.model
import odg.util
import odg.extensions_cfg
import odg_client
import syft
import secret_mgmt
import secret_mgmt.bdba
import secret_mgmt.oci_registry

logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


@dataclasses.dataclass
class SBOM:
    sbom_raw: dict
    sbom_format: odg.extensions_cfg.SbomFormat


def generate_sbom_with_syft(
    resource_node: ocm.iter.ResourceNode,
    output_format: odg.extensions_cfg.SbomFormat,
    secret_factory: secret_mgmt.SecretFactory,
) -> SBOM:
    logger.info(f'Creating SBOM for resource node {resource_node} using syft')

    access = resource_node.resource.access

    if access.type is ocm.AccessType.OCI_REGISTRY:
        oci_secret = secret_mgmt.oci_registry.find_cfg(
            secret_factory=secret_factory,
            image_reference=access.imageReference,
        )

        if oci_secret:
            dockerutil.prepare_docker_cfg(
                image_reference=access.imageReference,
                username=oci_secret.username,
                password=oci_secret.password,
            )

    sbom_raw = syft.run_syft(
        source=access.imageReference,
        output_format=output_format,
    )

    return SBOM(sbom_raw=json.loads(sbom_raw), sbom_format=output_format)


def get_or_create_bdba_scan(
    resource_node: ocm.iter.ResourceNode,
    bdba_api: bdba.client.BDBAApi,
    group_id: int,
    aws_secret_name: str | None,
    delivery_service_client: odg_client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    processing_mode: bdba.model.ProcessingMode,
    create_new_scan_if_missing: bool,
) -> int:
    logger.info(f'Creating SBOM for resource node {resource_node} using BDBA')

    component_artefact_metadata = bdba_utils.util.component_artefact_metadata(resource_node)

    existing_scans = bdba_utils.scan.retrieve_existing_scan_results(
        bdba_client=bdba_api,
        group_id=group_id,
        resource_node=resource_node,
    )

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
            f'{resource_node.resource.name}',
        )

        metadata_generator = bdba_utils.scan.run_scan(
            aws_secret_name=aws_secret_name,
            bdba_client=bdba_api,
            group_id=group_id,
            processing_mode=processing_mode,
            resource_node=resource_node,
            secret_factory=secret_factory,
            oci_client=oci_client,
            delivery_service_client=delivery_service_client,
        )

        if product_id := next(metadata_generator).data.get('product_id'):
            logger.info(f'Created new BDBA scan: {product_id=}')
            return product_id

        logger.error('BDBA scan created but no product_id was returned')
        raise RuntimeError('BDBA scan created but no product_id was returned')

    raise RuntimeError(
        f'No existing BDBA scan found for {resource_node.resource.name} '
        f'and {create_new_scan_if_missing=}',
    )


def generate_sbom_with_bdba(
    resource_node: ocm.iter.ResourceNode,
    aws_secret_name: str | None,
    delivery_service_client: odg_client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    group_id: int,
    processing_mode: bdba.model.ProcessingMode,
    output_format: odg.extensions_cfg.SbomFormat,
    create_new_scan_if_missing: bool,
) -> SBOM:
    if not (
        bdba_secret := secret_mgmt.bdba.find_cfg(
            secret_factory=secret_factory,
            group_id=group_id,
        )
    ):
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
        delivery_service_client=delivery_service_client,
        oci_client=oci_client,
        secret_factory=secret_factory,
        create_new_scan_if_missing=create_new_scan_if_missing,
        processing_mode=processing_mode,
    )

    if not product_id:
        raise ValueError(
            f'No BDBA scan available '
            f'for resource {resource_node.resource.name} '
            f'in component {resource_node.component.name}:'
            f'{resource_node.component.version}',
        )

    sbom_raw = bdba_api.export_sbom(product_id, output_format)

    sbom_result = SBOM(sbom_raw=sbom_raw, sbom_format=output_format)

    return sbom_result


def generate_sbom_for_artefact(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.SBOMGeneratorConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_service_client: odg_client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    **kwargs,
) -> SBOM:
    """
    Generates Software Bill of Materials (SBOM) for a component artefact.
    Resolves the component descriptor from OCM repositories,
    retrieves BDBA security scans, and exports the SBOM
    in the requested format with OCM metadata.
    """
    logger.info(f'Generating SBOM for artefact: {artefact}')

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )

    if not resource_node:
        logger.info(f'did not find resource node for {artefact=}, skipping...')
        return

    if not extension_cfg.is_supported(
        artefact_kind=artefact.artefact_kind,
        access_type=resource_node.resource.access.type,
        artefact_type=resource_node.resource.type,
    ):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} / {resource_node.resource.access.type} / '
                f'{resource_node.resource.type} is not '
                'supported by the SBOM Generator extension, '
                'maybe the filter configurations have to be adjusted '
                'to filter out this artefact kind, access type, or artefact type',
            )
        return

    logger.info(f'Scanning using mode {extension_cfg.generation_mode}')

    match extension_cfg.generation_mode:
        case odg.model.SbomGenerationMode.SYFT:
            syft_output_format = {
                odg.extensions_cfg.SbomFormat.CYCLONEDX: syft.SyftSbomFormat.CYCLONEDX,
                odg.extensions_cfg.SbomFormat.SPDX: syft.SyftSbomFormat.SPDX,
            }.get(extension_cfg.output_format)

            if not syft_output_format:
                raise ValueError(
                    f'Unsupported SBOM format "{extension_cfg.output_format}" for generation mode '
                    f'"{extension_cfg.generation_mode}". Supported formats: '
                    f'{", ".join(f.value for f in syft.SyftSbomFormat)}',
                )

            sbom_result = generate_sbom_with_syft(
                resource_node=resource_node,
                output_format=syft_output_format,
                secret_factory=secret_factory,
            )

        case odg.model.SbomGenerationMode.BDBA:
            mapping = extension_cfg.mapping(artefact.component_name)
            bdba_output_format = {
                odg.extensions_cfg.SbomFormat.CYCLONEDX: bdba.model.BdbaSbomFormat.CYCLONEDX,
                odg.extensions_cfg.SbomFormat.SPDX: bdba.model.BdbaSbomFormat.SPDX,
                odg.extensions_cfg.SbomFormat.BDIO: bdba.model.BdbaSbomFormat.BDIO,
            }.get(extension_cfg.output_format)

            if not bdba_output_format:
                raise ValueError(
                    f'Unsupported SBOM format "{extension_cfg.output_format}" for generation mode '
                    f'"{extension_cfg.generation_mode}". Supported formats: '
                    f'{", ".join(f.value for f in bdba.model.BdbaSbomFormat)}',
                )

            sbom_result = generate_sbom_with_bdba(
                resource_node=resource_node,
                aws_secret_name=mapping.aws_secret_name,
                delivery_service_client=delivery_service_client,
                oci_client=oci_client,
                secret_factory=secret_factory,
                output_format=bdba_output_format,
                create_new_scan_if_missing=extension_cfg.create_new_scan_if_missing,
                group_id=mapping.group_id,
                processing_mode=extension_cfg.processing_mode,
            )

        case _:
            raise ValueError(
                f'Unsupported generation mode: {extension_cfg.generation_mode}. '
                f'Supported modes: {", ".join(m.value for m in odg.model.SbomGenerationMode)}',
            )

    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json',
        encoding='utf-8',
        delete=False,
    ) as tmp:
        tmp_path = tmp.name
        json.dump(sbom_result.sbom_raw, tmp, indent=2, ensure_ascii=False)

    try:
        sha256_hash = hashlib.sha256()
        size = 0
        with open(tmp_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                size += len(chunk)
        digest = 'sha256:' + sha256_hash.hexdigest()

        with open(tmp_path, 'rb') as f:
            delivery_service_client.upload_blob(
                data=f,
                digest=digest,
                size=size,
                mime_type='application/json',
            )
    finally:
        os.remove(tmp_path)

    logger.info(f'SBOM uploaded to blob storage with digest {digest}')

    delivery_service_client.update_metadata(
        data=[
            odg.model.ArtefactMetadata(
                artefact=artefact,
                meta=odg.model.Metadata(
                    datasource=odg.model.Datasource.SBOM_GENERATOR,
                    type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
                    creation_date=datetime.datetime.now(datetime.timezone.utc),
                    last_update=datetime.datetime.now(datetime.timezone.utc),
                ),
                data={
                    'digest': digest,
                    'size': size,
                    'sbom_format': sbom_result.sbom_format.value,
                },
            ),
        ],
    )

    return sbom_result


def main():
    parsed_arguments = odg.util.parse_args()

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.SBOM_GENERATOR,
        callback=generate_sbom_for_artefact,
    )


if __name__ == '__main__':
    main()
