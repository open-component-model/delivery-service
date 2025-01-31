import argparse
import atexit
import logging
import os
import signal
import sys
import time

import ci.log
import cnudie.access
import cnudie.retrieve
import delivery.client
import dso.model
import oci.client
import ocm
import tarutil

import bdba.client
import bdba.scanning
import consts
import ctx_util
import deliverydb_cache.model as dcm
import deliverydb_cache.util as dcu
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups
import ocm_util
import odg.findings
import odg.scan_cfg
import paths
import secret_mgmt


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')

ready_to_terminate = True
wants_to_terminate = False


def handle_termination_signal(*args):
    global ready_to_terminate, wants_to_terminate

    # also terminate if > 1 termination signals were received
    if ready_to_terminate or wants_to_terminate:
        sys.exit(0)

    # grace period to finish current scan is defined in the replica set
    # after this period, the scan will be terminated anyways by k8s means
    logger.info('termination signal received, will try to finish current scan and then exit')
    wants_to_terminate = True


def _mark_compliance_summary_cache_for_deletion(
    delivery_client: delivery.client.DeliveryServiceClient,
    component: ocm.ComponentIdentity,
    finding_type: odg.findings.FindingType,
):
    descriptor = dcm.CachedPythonFunction(
        encoding_format=dcm.EncodingFormat.PICKLE,
        function_name='compliance_summary.component_datatype_summaries',
        args=dcu.normalise_and_serialise_object(tuple()),
        kwargs=dcu.normalise_and_serialise_object({
            'component': component,
            'finding_type': finding_type,
            'datasource': dso.model.Datasource.BDBA,
        }),
    )

    delivery_client.mark_cache_for_deletion(
        id=descriptor.id,
    )


def scan(
    artefact: dso.model.ComponentArtefactId,
    bdba_cfg: odg.scan_cfg.BDBAConfig,
    vulnerability_cfg: odg.findings.Finding | None,
    license_cfg: odg.findings.Finding | None,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
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

    if not bdba_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access = resource_node.resource.access

    if not bdba_cfg.is_supported(access_type=access.type):
        return

    mapping = bdba_cfg.mapping(artefact.component_name)

    logger.info(f'using BDBA secret element "{mapping.bdba_secret_name}"')
    bdba_secret = secret_factory.bdba(mapping.bdba_secret_name)
    bdba_client = bdba.client.client(
        bdba_cfg=bdba_secret,
        group_id=mapping.group_id,
        secret_factory=secret_factory,
    )

    known_scan_results = bdba.scanning.retrieve_existing_scan_results(
        bdba_client=bdba_client,
        group_id=mapping.group_id,
        resource_node=resource_node,
    )

    processor = bdba.scanning.ResourceGroupProcessor(
        bdba_client=bdba_client,
        group_id=mapping.group_id,
    )

    access = resource_node.resource.access

    if access.type is ocm.AccessType.OCI_REGISTRY:
        content_iterator = oci.image_layers_as_tarfile_generator(
            image_reference=access.imageReference,
            oci_client=oci_client,
            include_config_blob=False,
            fallback_to_first_subimage_if_index=True,
        )

    elif access.type is ocm.AccessType.S3:
        if not mapping.aws_secret_name:
            raise ValueError('"aws_secret_name" must be configured for resources stored in S3')

        logger.info(f'using AWS secret element "{mapping.aws_secret_name}"')
        aws_secret = secret_factory.aws(mapping.aws_secret_name)
        s3_client = aws_secret.session.client('s3')

        content_iterator = tarutil.concat_blobs_as_tarstream(
            blobs=[
                cnudie.access.s3_access_as_blob_descriptor(
                    s3_client=s3_client,
                    s3_access=access,
                ),
            ]
        )

    elif access.type is ocm.AccessType.LOCAL_BLOB:
        ocm_repo = resource_node.component.current_ocm_repo
        image_reference = ocm_repo.component_version_oci_ref(
            name=resource_node.component.name,
            version=resource_node.component.version,
        )

        content_iterator = ocm_util.iter_local_blob_content(
            access=access,
            oci_client=oci_client,
            image_reference=image_reference,
        )

    else:
        # we filtered supported access types already earlier
        raise RuntimeError('this is a bug, this line should never be reached')

    scan_results = processor.process(
        resource_node=resource_node,
        content_iterator=content_iterator,
        known_scan_results=known_scan_results,
        processing_mode=mapping.processing_mode,
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
            finding_type=odg.findings.FindingType.VULNERABILITY,
        )
    if retrieve_license_findings:
        _mark_compliance_summary_cache_for_deletion(
            delivery_client=delivery_client,
            component=component,
            finding_type=odg.findings.FindingType.LICENSE,
        )

    logger.info(f'finished scan of artefact {artefact}')


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='specify kubernetes cluster to interact with',
        default=os.environ.get('K8S_CFG_NAME'),
    )
    parser.add_argument(
        '--kubeconfig',
        help='''
            specify kubernetes cluster to interact with extensions (and logs); if both
            `k8s-cfg-name` and `kubeconfig` are set, `k8s-cfg-name` takes precedence
        ''',
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with',
        default=os.environ.get('K8S_TARGET_NAMESPACE'),
    )
    parser.add_argument(
        '--scan-cfg-path',
        help='path to the `scan_cfg.yaml` file that should be used',
    )
    parser.add_argument(
        '--findings-cfg-path',
        help='path to the `findings.yaml` file that should be used',
    )
    parser.add_argument(
        '--delivery-service-url',
        help='''
            specify the url of the delivery service to use instead of the one configured in the
            respective scan configuration
        ''',
    )
    parser.add_argument('--cache-dir', default=default_cache_dir)

    parsed_arguments = parser.parse_args()

    if not parsed_arguments.k8s_namespace:
        raise ValueError(
            'k8s namespace must be set, either via argument "--k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


def main():
    signal.signal(signal.SIGTERM, handle_termination_signal)
    signal.signal(signal.SIGINT, handle_termination_signal)

    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace
    delivery_service_url = parsed_arguments.delivery_service_url

    secret_factory = ctx_util.secret_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(
            kubeconfig_path=parsed_arguments.kubeconfig,
        )

    k8s.logging.init_logging_thread(
        service=odg.scan_cfg.Services.BDBA,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.scan_cfg.Services.BDBA,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (scan_cfg_path := parsed_arguments.scan_cfg_path):
        scan_cfg_path = paths.scan_cfg_path()

    scan_cfg = odg.scan_cfg.ScanConfiguration.from_file(scan_cfg_path)
    bdba_cfg = scan_cfg.bdba

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    vulnerability_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.findings.FindingType.VULNERABILITY,
    )
    license_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.findings.FindingType.LICENSE,
    )

    if not delivery_service_url:
        delivery_service_url = bdba_cfg.delivery_service_url

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )

    oci_client = lookups.semver_sanitising_oci_client(
        secret_factory=secret_factory,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_client,
        oci_client=oci_client,
    )

    global ready_to_terminate, wants_to_terminate
    while not wants_to_terminate:
        ready_to_terminate = False

        backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
            service=odg.scan_cfg.Services.BDBA,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )

        if not backlog_crd:
            ready_to_terminate = True
            sleep_interval = consts.BACKLOG_ITEM_SLEEP_INTERVAL_SECONDS
            logger.info(f'no open backlog item found, will sleep for {sleep_interval} sec')
            time.sleep(sleep_interval)
            continue

        name = backlog_crd.get('metadata').get('name')
        logger.info(f'processing backlog item {name}')

        backlog_item = k8s.backlog.BacklogItem.from_dict(
            backlog_item=backlog_crd.get('spec'),
        )

        scan(
            artefact=backlog_item.artefact,
            bdba_cfg=bdba_cfg,
            vulnerability_cfg=vulnerability_cfg,
            license_cfg=license_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            oci_client=oci_client,
            secret_factory=secret_factory,
        )

        k8s.util.delete_custom_resource(
            crd=k8s.model.BacklogItemCrd,
            name=name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )
        logger.info(f'processed and deleted backlog item {name}')


if __name__ == '__main__':
    main()
