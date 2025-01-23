import argparse
import atexit
import logging
import os
import signal
import sys
import time

import botocore.client

import ci.log
import cnudie.access
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.model
import oci.client
import ocm
import tarutil

import bdba.client
import bdba.scanning
import bdba.util
import config
import ctx_util
import deliverydb_cache.model as dcm
import deliverydb_cache.util as dcu
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups
import ocm_util


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


def deserialise_bdba_configuration(
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> config.BDBAConfig:
    scan_cfg_crd = kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
        group=k8s.model.ScanConfigurationCrd.DOMAIN,
        version=k8s.model.ScanConfigurationCrd.VERSION,
        plural=k8s.model.ScanConfigurationCrd.PLURAL_NAME,
        namespace=namespace,
        name=cfg_name,
    )

    if scan_cfg_crd and (spec := scan_cfg_crd.get('spec')):
        bdba_config = config.deserialise_bdba_config(spec_config=spec)
    else:
        bdba_config = None

    if not bdba_config:
        logger.warning(
            f'no bdba configuration for config elem {cfg_name} set, '
            'job is not able to process current scan backlog and will terminate'
        )
        sys.exit(0)

    return bdba_config


def _mark_compliance_summary_cache_for_deletion(
    delivery_client: delivery.client.DeliveryServiceClient,
    component: ocm.ComponentIdentity,
    finding_type: str,
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
    backlog_item: k8s.backlog.BacklogItem,
    bdba_config: config.BDBAConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    bdba_client: bdba.client.BDBAApi,
    oci_client: oci.client.Client,
    s3_client: 'botocore.client.S3',
):
    if backlog_item.artefact.artefact_kind is not dso.model.ArtefactKind.RESOURCE:
        logger.warning(
            f'found unsupported artefact kind {backlog_item.artefact.artefact_kind}, skipping...'
        )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=backlog_item.artefact,
    )

    if not resource_node.resource.type in bdba_config.artefact_types:
        return

    if not bdba_config.node_filter(resource_node):
        return

    known_scan_results = bdba.scanning.retrieve_existing_scan_results(
        bdba_client=bdba_client,
        group_id=bdba_config.group_id,
        resource_node=resource_node,
    )

    processor = bdba.scanning.ResourceGroupProcessor(
        bdba_client=bdba_client,
        group_id=bdba_config.group_id,
    )

    access = resource_node.resource.access

    if access.type is ocm.AccessType.OCI_REGISTRY:
        content_iterator = oci.image_layers_as_tarfile_generator(
            image_reference=access.imageReference,
            oci_client=oci_client,
            include_config_blob=False,
            fallback_to_first_subimage_if_index=True
        )

    elif access.type is ocm.AccessType.S3:
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
        raise NotImplementedError(access)

    scan_results = processor.process(
        resource_node=resource_node,
        content_iterator=content_iterator,
        processing_mode=bdba_config.processing_mode,
        known_scan_results=known_scan_results,
        delivery_client=delivery_client,
        license_cfg=bdba_config.license_cfg,
        cve_rescoring_ruleset=bdba_config.cve_rescoring_ruleset,
        auto_assess_max_severity=bdba_config.auto_assess_max_severity,
    )

    if bdba_config.blacklist_finding_types:
        scan_results = tuple(
            scan_result for scan_result in scan_results
            if scan_result.meta.type not in bdba_config.blacklist_finding_types
        )

    delivery_client.update_metadata(data=scan_results)

    component = ocm.ComponentIdentity(
        name=backlog_item.artefact.component_name,
        version=backlog_item.artefact.component_version,
    )
    _mark_compliance_summary_cache_for_deletion(
        delivery_client=delivery_client,
        component=component,
        finding_type=dso.model.Datatype.VULNERABILITY,
    )
    _mark_compliance_summary_cache_for_deletion(
        delivery_client=delivery_client,
        component=component,
        finding_type=dso.model.Datatype.LICENSE,
    )

    logger.info(f'finished scan of artefact {backlog_item.artefact}')


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
        '--cfg-name',
        help='''
            specify the context the process should run in, not relevant for the artefact
            enumerator as well as backlog controller as these are context independent
        ''',
        default=os.environ.get('CFG_NAME'),
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

    if not parsed_arguments.cfg_name:
        raise ValueError(
            'name of the to-be-used scan configuration must be set, either via '
            'argument "--cfg-name" or via environment variable "CFG_NAME"'
        )

    return parsed_arguments


def main():
    signal.signal(signal.SIGTERM, handle_termination_signal)
    signal.signal(signal.SIGINT, handle_termination_signal)

    parsed_arguments = parse_args()
    cfg_name = parsed_arguments.cfg_name
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
        service=config.Services.BDBA,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=config.Services.BDBA,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    bdba_config = deserialise_bdba_configuration(
        cfg_name=cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    bdba_cfg = secret_factory.bdba(bdba_config.cfg_name)
    bdba_client = bdba.client.client(
        bdba_cfg=bdba_cfg,
        group_id=bdba_config.group_id,
        secret_factory=secret_factory,
    )

    if not delivery_service_url:
        delivery_service_url = bdba_config.delivery_service_url

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
    )

    if bdba_config.aws_cfg_name:
        aws_cfg = secret_factory.aws(bdba_config.aws_cfg_name)

        s3_client = aws_cfg.session.client('s3')
    else:
        s3_client = None

    global ready_to_terminate, wants_to_terminate
    while not wants_to_terminate:
        ready_to_terminate = False

        backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
            service=config.Services.BDBA,
            cfg_name=cfg_name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )

        if not backlog_crd:
            ready_to_terminate = True
            sleep_interval = bdba_config.lookup_new_backlog_item_interval
            logger.info(f'no open backlog item found, will sleep for {sleep_interval} sec')
            time.sleep(sleep_interval)
            continue

        name = backlog_crd.get('metadata').get('name')
        logger.info(f'processing backlog item {name}')

        backlog_item = k8s.backlog.BacklogItem.from_dict(
            backlog_item=backlog_crd.get('spec'),
        )

        scan(
            backlog_item=backlog_item,
            bdba_config=bdba_config,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            bdba_client=bdba_client,
            oci_client=oci_client,
            s3_client=s3_client,
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
