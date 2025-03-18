#!/usr/bin/env python3
import argparse
import atexit
import collections.abc
import datetime
import enum
import logging
import os
import signal
import sys
import tarfile
import time

import awesomeversion.exceptions

import ci.log
import ci.util
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.model
import oci.client
import oci.model
import tarutil

import consts
import ctx_util
import eol
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups
import ocm
import odg.extensions_cfg
import odg.findings
import osinfo
import os_id_extension.model as osidmodel
import os_id_extension.scan as osidscan
import os_id_extension.util as osidutil
import paths


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


class OsStatus(enum.StrEnum):
    NO_BRANCH_INFO = 'noBranchInfo'
    NO_RELEASE_INFO = 'noReleaseInfo'
    UNABLE_TO_COMPARE_VERSION = 'unableToCompareVersion'
    IS_EOL = 'isEol'
    UPDATE_AVAILABLE_FOR_BRANCH = 'updateAvailableForBranch'
    GREATEST_BRANCH_VERSION = 'greatestBranchVersion'
    EMPTY_OS_ID = 'emptyOsId'


def empty_os_id(
    os_id: dso.model.OperatingSystemId,
) -> bool:
    if not any([
        field
        for field in os_id.__dict__.values()
    ]):
        return True
    return False


def determine_os_status(
    os_id: dso.model.OperatingSystemId,
    release_infos: list[osidmodel.OsReleaseInfo]
) -> OsStatus:
    branch_info = osidutil.find_branch_info(
        os_id=os_id,
        os_infos=release_infos,
    )

    if not branch_info:
        return OsStatus.NO_BRANCH_INFO

    is_eol = osidutil.branch_reached_eol(
        os_id=os_id,
        os_infos=release_infos,
    )

    try:
        update_avilable = osidutil.update_available(
            os_id=os_id,
            os_infos=release_infos,
        )
    except awesomeversion.exceptions.AwesomeVersionCompareException:
        return OsStatus.UNABLE_TO_COMPARE_VERSION

    if is_eol:
        return OsStatus.IS_EOL

    if update_avilable:
        return OsStatus.UPDATE_AVAILABLE_FOR_BRANCH

    return OsStatus.GREATEST_BRANCH_VERSION


def severity_for_os_status(
    os_status: OsStatus,
    os_id_finding_config: odg.findings.Finding
) -> str | None:
    categorisation = odg.findings.categorise_finding(os_id_finding_config, os_status.value)
    if categorisation:
        return categorisation.id
    return None


def determine_os_id(
    artefact: dso.model.ComponentArtefactId,
    oci_client: oci.client.Client,
    lookup: cnudie.retrieve.ComponentDescriptorLookupById,
) -> dso.model.OperatingSystemId:

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=lookup,
        artefact=artefact,
    )
    resource = resource_node.resource

    if resource.type != ocm.ArtefactType.OCI_IMAGE:
        return

    if not resource.access:
        return

    if resource.access.type != ocm.AccessType.OCI_REGISTRY:
        return

    return base_image_os_id(
        oci_client=oci_client,
        resource=resource,
    )


def base_image_os_id(
    oci_client: oci.client.Client,
    resource: ocm.Resource,
) -> dso.model.OperatingSystemId:
    image_reference = resource.access.imageReference

    manifest = oci_client.manifest(
        image_reference=image_reference,
        accept=oci.model.MimeTypes.prefer_multiarch,
    )

    # if multi-arch, randomly choose first entry (assumption: all variants have same os/version)
    if isinstance(manifest, oci.model.OciImageManifestList):
        manifest: oci.model.OciImageManifestList
        manifest: oci.model.OciBlobRef = manifest.manifests[0]
        image_reference = oci.model.OciImageReference(image_reference)
        manifest = oci_client.manifest(image_reference.ref_without_tag + '@' + manifest.digest)

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

    if not last_os_info:
        # if we could not determine os-info, upload a dummy os-info (with all entries set to None)
        # to keep track of the failed scan attempt
        last_os_info = dso.model.OperatingSystemId()

    return last_os_info


def create_artefact_metadata(
    artefact: dso.model.ComponentArtefactId,
    os_id_finding_config: odg.findings.Finding,
    os_id: dso.model.OperatingSystemId,
    time_now: datetime.datetime=datetime.datetime.now(),
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    logger.info(f'Processing os_id: {os_id}')
    if empty_os_id(os_id):
        os_status = OsStatus.EMPTY_OS_ID
        logger.info(f'determined os-status: {os_status}')
    else:
        eol_client = eol.EolClient()
        release_infos = osinfo.os_release_infos(
            os_id=eol.normalise_os_id(os_id.ID),
            eol_client=eol_client,
        )
        if not release_infos:
            os_status = OsStatus.NO_RELEASE_INFO
            logger.info(f'determined os-status: {os_status}')
        else:
            os_status = determine_os_status(
                os_id=os_id,
                release_infos=release_infos,
            )
            logger.info(f'determined os-status: {os_status}')

    severity = severity_for_os_status(
        os_status=os_status,
        os_id_finding_config=os_id_finding_config,
    )
    logger.info(f'determined severity: {severity}')

    if severity:
        data = dso.model.OsIDFinding(
            severity=severity,
            os_id=os_id,
        )
        type = dso.model.Datatype.OS_ID_FINDING
    else:
        data = os_id
        type = dso.model.Datatype.OS_ID

    yield dso.model.ArtefactMetadata(
        artefact=artefact,
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.OS_ID,
            type=type,
            creation_date=time_now,
            last_update=time_now,
        ),
        data=data,
        discovery_date=time_now.date(),
    )


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
        service=odg.extensions_cfg.Services.OS_ID,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.OS_ID,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extension_cfg_path := parsed_arguments.extensions_cfg_path):
        extension_cfg_path = paths.extensions_cfg_path()

    extension_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extension_cfg_path)
    os_id_config = extension_cfg.os_id

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    os_id_finding_config = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.findings.FindingType.OS_ID,
    )

    if not os_id_finding_config:
        logger.info('OS_ID findings are disabled, exiting...')
        return

    if not delivery_service_url:
        delivery_service_url = os_id_config.delivery_service_url

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

    global ready_to_terminate, wants_to_terminate
    while not wants_to_terminate:
        ready_to_terminate = False

        backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
            service=odg.extensions_cfg.Services.OS_ID,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            shortcut_claim=True,
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

        os_id = determine_os_id(
            artefact=backlog_item.artefact,
            oci_client=oci_client,
            lookup=component_descriptor_lookup,
        )

        time_now = datetime.datetime.now()
        all_metadata = []
        artefact_scan_info = dso.model.ArtefactMetadata(
            artefact=backlog_item.artefact,
            meta=dso.model.Metadata(
                datasource=dso.model.Datasource.OS_ID,
                type=dso.model.Datatype.ARTEFACT_SCAN_INFO,
                creation_date=time_now,
                last_update=time_now,
            ),
            data={},
            discovery_date=time_now.date(),
        )
        all_metadata.append(artefact_scan_info)

        if os_id:
            logger.info(f'uploading os-info for {backlog_item.artefact}')
            os_id_finding = list(
                create_artefact_metadata(
                    artefact=backlog_item.artefact,
                    os_id=os_id,
                    os_id_finding_config=os_id_finding_config,
                )
            )

            all_metadata.extend(os_id_finding)

        delivery_client.update_metadata(data=all_metadata)

        k8s.util.delete_custom_resource(
            crd=k8s.model.BacklogItemCrd,
            name=name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )
        logger.info(f'processed and deleted backlog item {name}')


if __name__ == '__main__':
    main()
