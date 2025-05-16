import collections.abc
import datetime
import functools
import logging

import ci.log
import cnudie.retrieve
import delivery.client
import oci.client

import crypto_extension.cbom
import crypto_extension.model
import crypto_extension.validate
import k8s.logging
import k8s.util
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths
import secret_mgmt


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def as_artefact_metadata(
    artefact: odg.model.ComponentArtefactId,
    crypto_assets: collections.abc.Iterable[odg.model.CryptoAsset],
    findings: collections.abc.Iterable[odg.model.CryptoFinding],
    crypto_finding_cfg: odg.findings.Finding,
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    today = datetime.date.today()
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    meta = odg.model.Metadata(
        datasource=odg.model.Datasource.CRYPTO,
        type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
        creation_date=now,
        last_update=now,
    )

    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=meta,
        data={},
    )

    meta = odg.model.Metadata(
        datasource=odg.model.Datasource.CRYPTO,
        type=odg.model.Datatype.CRYPTO_ASSET,
        creation_date=now,
        last_update=now,
    )

    for crypto_asset in crypto_assets:
        yield odg.model.ArtefactMetadata(
            artefact=artefact,
            meta=meta,
            data=crypto_asset,
        )

    meta = odg.model.Metadata(
        datasource=odg.model.Datasource.CRYPTO,
        type=odg.model.Datatype.CRYPTO_FINDING,
        creation_date=now,
        last_update=now,
    )

    for finding in findings:
        categorisation = crypto_finding_cfg.categorisation_by_id(finding.severity)

        yield odg.model.ArtefactMetadata(
            artefact=artefact,
            meta=meta,
            data=finding,
            discovery_date=today,
            allowed_processing_time=categorisation.allowed_processing_time_raw,
        )


def scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.CryptoConfig,
    crypto_finding_cfg: odg.findings.Finding | None,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    **kwargs,
):
    logger.info(f'scanning {artefact}')

    retrieve_crypto_findings = crypto_finding_cfg and crypto_finding_cfg.matches(artefact)

    if not retrieve_crypto_findings:
        logger.info('crypto findings are filtered out for this artefact, skipping...')
        return

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by the crypto extension, maybe the '
                'filter configurations have to be adjusted to filter out this artefact kind'
            )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access_type = resource_node.resource.access.type
    resource_type = resource_node.resource.type

    if not extension_cfg.is_supported(
        access_type=access_type,
        artefact_type=resource_type,
    ):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{access_type=} with {resource_type=} is not supported by the crypto extension, '
                'maybe the filter configurations have to be adjusted to filter out these types'
            )
        return

    mapping = extension_cfg.mapping(artefact.component_name)

    cbom = crypto_extension.cbom.find_cbom_or_create(
        component=resource_node.component,
        access=resource_node.resource.access,
        mapping=mapping,
        oci_client=oci_client,
        secret_factory=secret_factory,
    )

    logger.info('successfully created CBOM document')

    crypto_assets = crypto_extension.model.iter_crypto_assets(
        cbom=cbom,
        crypto_libraries=mapping.libraries,
        included_asset_types=mapping.included_asset_types,
    )

    findings = list(crypto_extension.validate.iter_findings_for_standards(
        crypto_assets=crypto_assets,
        standards=mapping.standards,
        crypto_finding_cfg=crypto_finding_cfg,
    ))

    artefact_metadata = list(as_artefact_metadata(
        artefact=artefact,
        crypto_assets=crypto_assets,
        findings=findings,
        crypto_finding_cfg=crypto_finding_cfg,
    ))

    existing_artefact_metadata = (
        odg.model.ArtefactMetadata.from_dict(raw)
        for raw in delivery_client.query_metadata(
            artefacts=(artefact,),
            type=(
                odg.model.Datatype.CRYPTO_ASSET,
                odg.model.Datatype.CRYPTO_FINDING,
            ),
        ) if raw['meta']['datasource'] == odg.model.Datasource.CRYPTO
    )

    stale_artefact_metadata = []
    for existing_artefact_metadatum in existing_artefact_metadata:
        for asset in crypto_assets + findings:
            if existing_artefact_metadatum.data.key == asset.key:
                # finding still appeared in current scan result -> keep it
                break
        else:
            # finding did not appear in current scan result -> delete it
            stale_artefact_metadata.append(existing_artefact_metadatum)

    if stale_artefact_metadata:
        delivery_client.delete_metadata(data=stale_artefact_metadata)

    delivery_client.update_metadata(
        data=artefact_metadata,
    )

    logger.info(f'finished scan of artefact {artefact}')


def main():
    '''
    Note: Currently (as of 2024-12-05), CycloneDX Python lib's model class is not feature complete,
    hence deserialisation does not work. Instead, an own model class will be used which only supports
    properties which are required by this extension (see odg.model.CryptoAsset).
    '''
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    crypto_finding_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.CRYPTO_FINDING,
    )

    scan_callback = functools.partial(
        scan,
        crypto_finding_cfg=crypto_finding_cfg,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.CRYPTO,
        callback=scan_callback,
    )


if __name__ == '__main__':
    main()
