import argparse
import atexit
import logging
import os
import signal
import sys
import time

import botocore.client

import ccc.aws
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
        oci_client=oci_client,
    )

    processor = bdba.scanning.ResourceGroupProcessor(
        group_id=bdba_config.group_id,
        reference_group_ids=bdba_config.reference_group_ids,
        bdba_client=bdba_client,
        oci_client=oci_client,
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
        image_reference = ocm_repo.component_oci_ref(resource_node.component.name)

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
        cve_rescoring_rules=bdba_config.cve_rescoring_rules,
        auto_assess_max_severity=bdba_config.auto_assess_max_severity,
        use_product_cache=False,
        delete_inactive_products_after_seconds=bdba_config.delete_inactive_products_after_seconds,
    )

    filtered_scan_results = tuple(
        scan_result for scan_result in scan_results
        if scan_result.meta.type not in bdba_config.blacklist_finding_types
    )

    delivery_client.update_metadata(data=filtered_scan_results)

    logger.info(
        f'finished scan of artefact {backlog_item.artefact.artefact.artefact_name}:'
        f'{backlog_item.artefact.artefact.artefact_version} of component '
        f'{backlog_item.artefact.component_name}:{backlog_item.artefact.component_version}'
    )


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

    cfg_factory = ctx_util.cfg_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = cfg_factory.kubernetes(parsed_arguments.k8s_cfg_name)
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

    bdba_cfg = cfg_factory.bdba(bdba_config.cfg_name)
    bdba_client = bdba.client.client(
        bdba_cfg=bdba_cfg,
        group_id=bdba_config.group_id,
        base_url=bdba_cfg.base_url(),
        cfg_factory=cfg_factory,
    )

    if not delivery_service_url:
        delivery_service_url = bdba_config.delivery_service_url

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        cfg_factory=cfg_factory,
    )

    oci_client = lookups.semver_sanitised_oci_client(
        cfg_factory=cfg_factory,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_client,
    )

    try:
        cfg_set = cfg_factory.cfg_set(bdba_config.aws_cfg_set_name)
    except ValueError:
        logger.info(
            f'cfg set {bdba_config.aws_cfg_set_name} not found, '
            'trying to create default s3 client'
        )
        cfg_set = None

    s3_client = None
    try:
        s3_session = ccc.aws.default_session(
            cfg_factory=cfg_factory,
            cfg_set=cfg_set,
        )
        if s3_session:
            s3_client =  s3_session.client('s3')
    except RuntimeError:
        logger.warning('failed to create s3 client')

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
