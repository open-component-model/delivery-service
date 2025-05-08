import argparse
import atexit
import collections.abc
import dataclasses
import datetime
import logging
import os
import signal
import sys
import tarfile
import time

import awesomeversion.exceptions

import ci.log
import delivery.client
import dso.model
import oci.client
import oci.model
import ocm
import tarutil
import unixutil.model as um

import consts
import cnudie.retrieve
import ctx_util
import eol
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups
import odg.extensions_cfg
import odg.findings
import osinfo
import osid_extension.scan as osidscan
import osid_extension.util as osidutil
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')

ready_to_terminate = True
wants_to_terminate = False


def handle_termination_signal(*args):
    global wants_to_terminate

    # also terminate if > 1 termination signals were received
    if ready_to_terminate or wants_to_terminate:
        sys.exit(0)

    # grace period to finish current scan is defined in the replica set
    # after this period, the scan will be terminated anyways by k8s means
    logger.info('termination signal received, will try to finish current scan and then exit')
    wants_to_terminate = True


def determine_os_status(
    osid: um.OperatingSystemId,
    eol_client: eol.EolClient,
) -> tuple[dso.model.OsStatus, str | None, datetime.datetime | None]:
    '''
    determines the os status based on the given osid and release infos

    returns the os status, the greatest version and the eol date
    '''
    # checks if os id is empty
    if not any(dataclasses.asdict(osid).values()):
        return dso.model.OsStatus.EMPTY_OS_ID, None, None

    release_infos = osinfo.os_release_infos(
        os_id=eol.normalise_os_id(osid.ID),
        eol_client=eol_client,
    )
    if not release_infos:
        return dso.model.OsStatus.NO_RELEASE_INFO, None, None

    branch_info = osidutil.find_branch_info(
        osid=osid,
        os_infos=release_infos,
    )

    if not branch_info:
        return dso.model.OsStatus.NO_BRANCH_INFO, None, None

    greatest_version = branch_info.greatest_version
    eol_date = branch_info.eol_date

    if osid.is_distroless:
        return dso.model.OsStatus.DISTROLESS, greatest_version, eol_date

    if osidutil.branch_reached_eol(
        osid=osid,
        os_infos=release_infos,
    ):
        return dso.model.OsStatus.BRANCH_REACHED_EOL, greatest_version, eol_date

    try:
        update_available = osidutil.update_available(
            osid=osid,
            os_infos=release_infos,
        )
    except awesomeversion.exceptions.AwesomeVersionCompareException:
        return dso.model.OsStatus.UNABLE_TO_COMPARE_VERSION, greatest_version, eol_date

    if not update_available:
        return dso.model.OsStatus.UP_TO_DATE, greatest_version, eol_date

    more_than_one_patchlevel_behind = osidutil.update_available(
        osid=osid,
        os_infos=release_infos,
        ignore_if_patchlevel_is_next_to_greatest=True,
    )
    if more_than_one_patchlevel_behind:
        return dso.model.OsStatus.MORE_THAN_ONE_PATCHLEVEL_BEHIND, greatest_version, eol_date
    # otherwise, it's exaclty one patch behind
    return dso.model.OsStatus.AT_MOST_ONE_PATCHLEVEL_BEHIND, greatest_version, eol_date


def determine_osid(
    resource: ocm.Resource,
    oci_client: oci.client.Client,
) -> um.OperatingSystemId | None:

    if resource.type != ocm.ArtefactType.OCI_IMAGE:
        return

    if not resource.access:
        return

    if resource.access.type != ocm.AccessType.OCI_REGISTRY:
        return

    return base_image_osid(
        oci_client=oci_client,
        resource=resource,
    )


def base_image_osid(
    oci_client: oci.client.Client,
    resource: ocm.Resource,
) -> um.OperatingSystemId:
    image_reference = resource.access.imageReference

    manifest = oci_client.manifest(
        image_reference=image_reference,
        accept=oci.model.MimeTypes.prefer_multiarch,
    )

    # if multi-arch, randomly choose first entry (assumption: all variants have same os/version)
    if isinstance(manifest, oci.model.OciImageManifestList):
        manifest: oci.model.OciImageManifestList
        manifest: oci.model.OciImageManifestListEntry = manifest.manifests[0]
        image_reference = oci.model.OciImageReference(image_reference)
        manifest = oci_client.manifest(image_reference.with_tag(manifest.digest))

    last_os_info = None

    for layer in manifest.layers:
        layer_blob = oci_client.blob(
            image_reference=image_reference,
            digest=layer.digest,
        )
        fileproxy = tarutil.FilelikeProxy(
            layer_blob.iter_content(chunk_size=tarfile.BLOCKSIZE)
        )
        tf = tarfile.open(fileobj=fileproxy, mode='r|*')
        if (os_info := osidscan.determine_osinfo(tf)):
            last_os_info = os_info

    return last_os_info


def create_artefact_metadata(
    artefact: dso.model.ComponentArtefactId,
    osid_finding_config: odg.findings.Finding,
    osid: um.OperatingSystemId | None,
    eol_client: eol.EolClient,
    relation: ocm.ResourceRelation,
    time_now: datetime.datetime | None = None,
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    if not time_now:
        time_now = datetime.datetime.now()

    yield dso.model.ArtefactMetadata(
        artefact=artefact,
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.OSID,
            type=dso.model.Datatype.ARTEFACT_SCAN_INFO,
            creation_date=time_now,
            last_update=time_now,
        ),
        data={},
        discovery_date=time_now.date(),
    )

    if not osid:
        logger.info('No osid found, uploading artefact-scan-info only')
        return

    logger.info(f'Processing {osid=}')
    os_status, greatest_version, eol_date = determine_os_status(
        osid=osid,
        eol_client=eol_client,
    )
    logger.info(f'Determined {os_status=}')

    categorisation = odg.findings.categorise_finding(
        finding_cfg=osid_finding_config,
        finding_property=os_status,
    )
    severity = categorisation.id if categorisation else None
    logger.info(f'Determined {severity=}')

    yield dso.model.ArtefactMetadata(
        artefact=artefact,
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.OSID,
            type=dso.model.Datatype.OSID,
            creation_date=time_now,
            last_update=time_now,
        ),
        data=osid,
        discovery_date=time_now.date(),
    )

    if not severity:
        return

    if (
        relation is ocm.ResourceRelation.EXTERNAL
        and os_status is not dso.model.OsStatus.BRANCH_REACHED_EOL
    ):
        logger.info(
            f'skipping osid finding for external non-EOL artefact {artefact}'
        )
        return

    yield dso.model.ArtefactMetadata(
        artefact=artefact,
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.OSID,
            type=odg.findings.FindingType.OSID,
            creation_date=time_now,
            last_update=time_now,
        ),
        data=dso.model.OsIdFinding(
            severity=severity,
            osid=osid,
            os_status=os_status,
            greatest_version=greatest_version,
            eol_date=eol_date,
        ),
        discovery_date=time_now.date(),
        allowed_processing_time=categorisation.allowed_processing_time_raw,
    )


def process_artefact(
    artefact: dso.model.ComponentArtefactId,
    osid_finding_config: odg.findings.Finding,
    osid_config: odg.extensions_cfg.OsId,
    oci_client: oci.client.Client,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    eol_client: eol.EolClient,
    delivery_client: delivery.client.DeliveryServiceClient,
):
    if not osid_finding_config.matches(artefact):
        logger.info(f'OSID findings are filtered out for {artefact=}, skipping...')
        return

    if not osid_config.is_supported(artefact_kind=artefact.artefact_kind):
        if osid_config.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by the OSID extension, maybe the filter '
                'configurations have to be adjusted to filter out this artefact kind'
            )
        return

    resource = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    ).resource

    osid = determine_osid(
        resource=resource,
        oci_client=oci_client,
    )

    logger.info(f'uploading os-info for {artefact}')
    osid_metadata = create_artefact_metadata(
        artefact=artefact,
        osid=osid,
        osid_finding_config=osid_finding_config,
        eol_client=eol_client,
        relation=resource.relation,
    )

    delivery_client.update_metadata(data=osid_metadata)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='kubernetes cluster to use',
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
        '--extensions-cfg-path',
        help='path to the `extensions_cfg.yaml` file that should be used',
    )
    parser.add_argument(
        '--findings-cfg-path',
        help='path to the `findings.yaml` file that should be used',
    )
    parser.add_argument(
        '--delivery-service-url',
        help='''
            specify the url of the delivery service to use instead of the one configured in the
            respective extensions configuration
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
        service=odg.extensions_cfg.Services.OSID,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.OSID,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extension_cfg_path := parsed_arguments.extensions_cfg_path):
        extension_cfg_path = paths.extensions_cfg_path()

    extension_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extension_cfg_path)
    osid_config = extension_cfg.osid

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    osid_finding_config = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.findings.FindingType.OSID,
    )

    if not osid_finding_config:
        logger.info('OSID findings are disabled, exiting...')
        return

    if not delivery_service_url:
        delivery_service_url = osid_config.delivery_service_url

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )
    oci_client = lookups.semver_sanitising_oci_client(
        secret_factory=secret_factory,
    )

    eol_client = eol.EolClient()

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_client,
        oci_client=oci_client,
    )

    global ready_to_terminate
    while not wants_to_terminate:
        ready_to_terminate = False

        backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
            service=odg.extensions_cfg.Services.OSID,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )
        if not backlog_crd:
            ready_to_terminate = True
            sleep_interval_seconds = consts.BACKLOG_ITEM_SLEEP_INTERVAL_SECONDS
            logger.info(f'no open backlog item found, sleep for {sleep_interval_seconds=}')
            time.sleep(sleep_interval_seconds)
            continue
        name = backlog_crd.get('metadata').get('name')
        logger.info(f'processing backlog item {name}')

        backlog_item = k8s.backlog.BacklogItem.from_dict(
            backlog_item=backlog_crd.get('spec'),
        )

        process_artefact(
            artefact=backlog_item.artefact,
            osid_finding_config=osid_finding_config,
            osid_config=osid_config,
            oci_client=oci_client,
            component_descriptor_lookup=component_descriptor_lookup,
            eol_client=eol_client,
            delivery_client=delivery_client,
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
