import collections.abc
import dataclasses
import datetime
import functools
import logging
import tarfile

import awesomeversion.exceptions

import ci.log
import delivery.client
import oci.client
import oci.model
import ocm
import tarutil

import cnudie.retrieve
import eol
import k8s.logging
import k8s.util
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import osinfo
import osid_extension.scan as osidscan
import osid_extension.util as osidutil
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def determine_os_status(
    osid: odg.model.OperatingSystemId,
    eol_client: eol.EolClient,
) -> tuple[odg.model.OsStatus, str | None, datetime.datetime | None]:
    '''
    determines the os status based on the given osid and release infos

    returns the os status, the greatest version and the eol date
    '''
    # checks if os id is empty
    if not any(dataclasses.asdict(osid).values()):
        return odg.model.OsStatus.EMPTY_OS_ID, None, None

    release_infos = osinfo.os_release_infos(
        os_id=eol.normalise_os_id(osid.ID),
        eol_client=eol_client,
    )
    if not release_infos:
        return odg.model.OsStatus.NO_RELEASE_INFO, None, None

    branch_info = osidutil.find_branch_info(
        osid=osid,
        os_infos=release_infos,
    )

    if not branch_info:
        return odg.model.OsStatus.NO_BRANCH_INFO, None, None

    greatest_version = branch_info.greatest_version
    eol_date = branch_info.eol_date

    if osid.is_distroless:
        return odg.model.OsStatus.DISTROLESS, greatest_version, eol_date

    if osidutil.branch_reached_eol(
        osid=osid,
        os_infos=release_infos,
    ):
        return odg.model.OsStatus.BRANCH_REACHED_EOL, greatest_version, eol_date

    try:
        update_available = osidutil.update_available(
            osid=osid,
            os_infos=release_infos,
        )
    except awesomeversion.exceptions.AwesomeVersionCompareException:
        return odg.model.OsStatus.UNABLE_TO_COMPARE_VERSION, greatest_version, eol_date

    if not update_available:
        return odg.model.OsStatus.UP_TO_DATE, greatest_version, eol_date

    more_than_one_patchlevel_behind = osidutil.update_available(
        osid=osid,
        os_infos=release_infos,
        ignore_if_patchlevel_is_next_to_greatest=True,
    )
    if more_than_one_patchlevel_behind:
        return odg.model.OsStatus.MORE_THAN_ONE_PATCHLEVEL_BEHIND, greatest_version, eol_date
    # otherwise, it's exaclty one patch behind
    return odg.model.OsStatus.AT_MOST_ONE_PATCHLEVEL_BEHIND, greatest_version, eol_date


def determine_osid(
    resource: ocm.Resource,
    oci_client: oci.client.Client,
) -> odg.model.OperatingSystemId | None:

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
) -> odg.model.OperatingSystemId:
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
    artefact: odg.model.ComponentArtefactId,
    osid_finding_config: odg.findings.Finding,
    osid: odg.model.OperatingSystemId | None,
    eol_client: eol.EolClient,
    relation: ocm.ResourceRelation,
    time_now: datetime.datetime | None = None,
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    if not time_now:
        time_now = datetime.datetime.now()

    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.OSID,
            type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
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

    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.OSID,
            type=odg.model.Datatype.OSID,
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
        and os_status is not odg.model.OsStatus.BRANCH_REACHED_EOL
    ):
        logger.info(
            f'skipping osid finding for external non-EOL artefact {artefact}'
        )
        return

    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.OSID,
            type=odg.model.Datatype.OSID_FINDING,
            creation_date=time_now,
            last_update=time_now,
        ),
        data=odg.model.OsIdFinding(
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
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.OsId,
    osid_finding_config: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    eol_client: eol.EolClient,
    **kwargs,
):
    if not osid_finding_config.matches(artefact):
        logger.info(f'OSID findings are filtered out for {artefact=}, skipping...')
        return

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
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


def main():
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    osid_finding_config = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.OSID_FINDING,
    )

    if not osid_finding_config:
        logger.info('OSID findings are disabled, exiting...')
        return

    eol_client = eol.EolClient()

    process_artefact_callback = functools.partial(
        process_artefact,
        osid_finding_config=osid_finding_config,
        eol_client=eol_client,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.OSID,
        callback=process_artefact_callback,
    )


if __name__ == '__main__':
    main()
