import functools
import logging

import ci.log
import cnudie.retrieve
import delivery.client
import oci.client
import ocm

import bdba.client
import bdba_utils.scan
import deliverydb_cache.model as dcm
import deliverydb_cache.util as dcu
import k8s.logging
import k8s.util
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths
import secret_mgmt
import secret_mgmt.aws
import secret_mgmt.bdba


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def _mark_compliance_summary_cache_for_deletion(
    delivery_client: delivery.client.DeliveryServiceClient,
    component: ocm.ComponentIdentity,
    finding_type: odg.model.Datatype,
):
    descriptor = dcm.CachedPythonFunction(
        encoding_format=dcm.EncodingFormat.PICKLE,
        function_name='compliance_summary.component_datatype_summaries',
        args=dcu.normalise_and_serialise_object(tuple()),
        kwargs=dcu.normalise_and_serialise_object({
            'component': component,
            'finding_type': finding_type,
            'datasource': odg.model.Datasource.BDBA,
        }),
    )

    delivery_client.mark_cache_for_deletion(
        id=descriptor.id,
    )


def scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.BDBAConfig,
    vulnerability_cfg: odg.findings.Finding | None,
    license_cfg: odg.findings.Finding | None,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    **kwargs,
):
    logger.info(f'scanning {artefact}')

    retrieve_vulnerability_findings = vulnerability_cfg and vulnerability_cfg.matches(artefact)
    retrieve_license_findings = license_cfg and license_cfg.matches(artefact)

    if (
        not retrieve_vulnerability_findings
        and not retrieve_license_findings
    ):
        logger.info(
            f'both the vulnerability and license finding configuration filter-out this {artefact=}, '
            'hence further processing will be skipped...'
        )
        return
    elif not retrieve_vulnerability_findings:
        logger.info(
            f'the vulnerabiltiy finding configuration filters-out this {artefact=}, hence only '
            'license findings will be considered'
        )
    elif not retrieve_license_findings:
        logger.info(
            f'the license finding configuration filters-out this {artefact=}, hence only '
            'vulnerability findings will be considered'
        )

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by the BDBA extension, maybe the filter '
                'configurations have to be adjusted to filter out this artefact kind'
            )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access = resource_node.resource.access

    if not extension_cfg.is_supported(access_type=access.type):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{access.type} is not supported by the BDBA extension, maybe the filter '
                'configurations have to be adjusted to filter out this access type'
            )
        return

    mapping = extension_cfg.mapping(artefact.component_name)

    if not (bdba_secret := secret_mgmt.bdba.find_cfg(
        secret_factory=secret_factory,
        group_id=mapping.group_id,
    )):
        raise ValueError(f'no BDBA secret found for group {mapping.group_id}')

    bdba_client = bdba.client.BDBAApi(
        api_routes=bdba.client.BDBAApiRoutes(base_url=bdba_secret.api_url),
        token=bdba_secret.token,
        tls_verify=bdba_secret.tls_verify,
    )

    scan_results = bdba_utils.scan.run_scan(
        aws_secret_name=mapping.aws_secret_name,
        bdba_client=bdba_client,
        group_id=mapping.group_id,
        processing_mode=mapping.processing_mode,
        resource_node=resource_node,
        secret_factory=secret_factory,
        oci_client=oci_client,
        delivery_client=delivery_client,
        vulnerability_cfg=vulnerability_cfg,
        license_cfg=license_cfg,
    )

    delivery_client.update_metadata(data=scan_results)

    component = ocm.ComponentIdentity(
        name=artefact.component_name,
        version=artefact.component_version,
    )

    if retrieve_vulnerability_findings:
        _mark_compliance_summary_cache_for_deletion(
            delivery_client=delivery_client,
            component=component,
            finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
        )
    if retrieve_license_findings:
        _mark_compliance_summary_cache_for_deletion(
            delivery_client=delivery_client,
            component=component,
            finding_type=odg.model.Datatype.LICENSE_FINDING,
        )

    logger.info(f'finished scan of artefact {artefact}')


def main():
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    vulnerability_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )
    license_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.LICENSE_FINDING,
    )

    scan_callback = functools.partial(
        scan,
        vulnerability_cfg=vulnerability_cfg,
        license_cfg=license_cfg,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.BDBA,
        callback=scan_callback,
    )


if __name__ == '__main__':
    main()
