import collections.abc
import logging

import botocore.exceptions
import requests

import ci.log
import delivery.client
import oci
import oci.client
import ocm
import ocm.iter

import bdba.client
import bdba.model as bm
import bdba_utils.assessments
import bdba_utils.rescore
import bdba_utils.util
import bdba_utils.model
import odg.findings
import odg.labels
import odg.model
import ocm_util
import secret_mgmt


logger = logging.getLogger(__name__)
ci.log.configure_default_logging(print_thread_id=True)


class ResourceGroupProcessor:
    def __init__(
        self,
        bdba_client: bdba.client.BDBAApi,
        group_id: int=None,
    ):
        self.bdba_client = bdba_client
        self.group_id = group_id

    def scan_request(
        self,
        resource_node: ocm.iter.ResourceNode,
        content_iterator: collections.abc.Generator[bytes, None, None],
        known_artefact_scans: collections.abc.Iterable[bm.Product],
    ) -> bdba_utils.model.ScanRequest:
        component = resource_node.component
        resource = resource_node.resource
        display_name = f'{resource.name}_{resource.version}_{component.name}_{resource.type}'.replace('/', '_') # noqa: E501

        if resource.extraIdentity:
            # peers are not required here as version is considered anyways
            display_name += f'_{resource.identity(peers=())}'.replace('/', '_')

        component_artefact_metadata = bdba_utils.util.component_artefact_metadata(
            resource_node=resource_node,
        )

        target_product_id = bdba_utils.util._matching_analysis_result_id(
            component_artefact_metadata=component_artefact_metadata,
            analysis_results=known_artefact_scans,
        )

        if target_product_id:
            logger.info(f'{display_name=}: found {target_product_id=}')
        else:
            logger.info(f'{display_name=}: did not find old scan')

        return bdba_utils.model.ScanRequest(
            component=component,
            artefact=resource,
            scan_content=content_iterator,
            display_name=display_name,
            target_product_id=target_product_id,
            custom_metadata=component_artefact_metadata,
        )

    def process_scan_request(
        self,
        scan_request: bdba_utils.model.ScanRequest,
        processing_mode: bm.ProcessingMode,
    ) -> bm.Result:
        def raise_on_error(exception):
            raise bdba_utils.model.BdbaScanError(
                scan_request=scan_request,
                component=scan_request.component,
                artefact=scan_request.artefact,
                exception=exception,
            )

        if processing_mode is bm.ProcessingMode.FORCE_UPLOAD:
            if (product_id := scan_request.target_product_id):
                # reupload binary
                try:
                    return self.bdba_client.upload(
                        application_name=scan_request.display_name,
                        group_id=self.group_id,
                        data=scan_request.scan_content,
                        replace_id=product_id,
                        custom_attribs=scan_request.custom_metadata,
                    )
                except requests.exceptions.HTTPError as e:
                    raise_on_error(e)
                except botocore.exceptions.BotoCoreError as e:
                    raise_on_error(e)
            else:
                # upload new product
                try:
                    return self.bdba_client.upload(
                        application_name=scan_request.display_name,
                        group_id=self.group_id,
                        data=scan_request.scan_content,
                        custom_attribs=scan_request.custom_metadata,
                    )
                except requests.exceptions.HTTPError as e:
                    raise_on_error(e)
                except botocore.exceptions.BotoCoreError as e:
                    raise_on_error(e)
        elif processing_mode is bm.ProcessingMode.RESCAN:
            if (existing_id := scan_request.target_product_id):
                # check if result can be reused
                scan_result = self.bdba_client.scan_result(product_id=existing_id)
                if scan_result.stale and not scan_result.rescan_possible:
                    # no choice but to upload
                    try:
                        return self.bdba_client.upload(
                            application_name=scan_request.display_name,
                            group_id=self.group_id,
                            data=scan_request.scan_content,
                            replace_id=existing_id,
                            custom_attribs=scan_request.custom_metadata,
                        )
                    except requests.exceptions.HTTPError as e:
                        raise_on_error(e)
                    except botocore.exceptions.BotoCoreError as e:
                        raise_on_error(e)

                # update name unless identical
                if scan_result.name != scan_request.display_name:
                    self.bdba_client.set_product_name(
                        product_id=existing_id,
                        name=scan_request.display_name,
                    )
                # update metadata if new metadata is not completely included in current one
                if scan_result.custom_data.items() < scan_request.custom_metadata.items():
                    self.bdba_client.set_metadata(
                        product_id=existing_id,
                        custom_attribs=scan_request.custom_metadata,
                    )

                if scan_result.rescan_possible and scan_result.stale:
                    # binary is still available, and "result is stale" (there was an engine-
                    # update), trigger rescan
                    logger.info(
                        f'Triggering rescan for {existing_id} ({scan_request.display_name})'
                    )
                    self.bdba_client.rescan(product_id=existing_id)
                try:
                    return self.bdba_client.scan_result(product_id=existing_id)
                except requests.exceptions.HTTPError as e:
                    raise_on_error(e)
                except botocore.exceptions.BotoCoreError as e:
                    raise_on_error(e)
            else:
                try:
                    return self.bdba_client.upload(
                        application_name=scan_request.display_name,
                        group_id=self.group_id,
                        data=scan_request.scan_content,
                        custom_attribs=scan_request.custom_metadata,
                    )
                except requests.exceptions.HTTPError as e:
                    raise_on_error(e)
                except botocore.exceptions.BotoCoreError as e:
                    raise_on_error(e)
        else:
            raise NotImplementedError(processing_mode)

    def process(
        self,
        resource_node: ocm.iter.ResourceNode,
        content_iterator: collections.abc.Generator[bytes, None, None],
        known_scan_results: collections.abc.Iterable[bm.Product],
        processing_mode: bm.ProcessingMode,
        delivery_client: delivery.client.DeliveryServiceClient | None=None,
        vulnerability_cfg: odg.findings.Finding | None=None,
        license_cfg: odg.findings.Finding | None=None,
    ) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
        scan_request = self.scan_request(
            resource_node=resource_node,
            content_iterator=content_iterator,
            known_artefact_scans=known_scan_results,
        )
        try:
            result = self.process_scan_request(
                scan_request=scan_request,
                processing_mode=processing_mode,
            )
            scan_result = self.bdba_client.wait_for_scan_result(result.product_id)
            scan_failed = False
        except bdba_utils.model.BdbaScanError as bse:
            scan_result = bse
            scan_failed = True
            logger.warning(bse.print_stacktrace())

        scanned_element = ocm.iter.ResourceNode(
            path=(ocm.iter.NodePathEntry(resource_node.component),),
            resource=resource_node.resource,
        )

        if scan_failed:
            logger.error(f'scan of {scanned_element=} failed; {scan_result=}')
            return

        if not (scan_result.binary_bytes and scan_result.scanned_bytes):
            logger.error(
                f'scan of {scanned_element=} failed: uploaded or scanned file is empty '
                f'({scan_result.binary_bytes=}, {scan_result.scanned_bytes=})'
            )
            return

        logger.info(
            f'scan of {scan_result.display_name} succeeded, going to post-process results'
        )

        if version_hints := _package_version_hints(
            component=resource_node.component,
            resource=resource_node.resource,
        ):
            logger.info(f'uploading package-version-hints for {scan_result.display_name}')
            scan_result = bdba_utils.assessments.upload_version_hints(
                scan_result=scan_result,
                hints=version_hints,
                bdba_client=self.bdba_client,
            )

        if scan_request.skip_vulnerability_scan:
            logger.info('skipping vulnerabilities due to skip-scan label')
            vulnerability_cfg = None

        if vulnerability_cfg:
            refetching_required = bdba_utils.rescore.rescore(
                bdba_client=self.bdba_client,
                scan_result=scan_result,
                scanned_element=scanned_element,
                vulnerability_cfg=vulnerability_cfg,
            )

            if refetching_required:
                logger.info(f'retrieving result again from bdba for {scan_result.display_name}')
                scan_result = self.bdba_client.wait_for_scan_result(
                    product_id=scan_result.product_id,
                )

        logger.info(f'post-processing of {scan_result.display_name} done')

        yield from bdba_utils.util.iter_artefact_metadata(
            scanned_element=scanned_element,
            scan_result=scan_result,
            delivery_client=delivery_client,
            vulnerability_cfg=vulnerability_cfg,
            license_cfg=license_cfg,
        )


def _package_version_hints(
    component: ocm.Component,
    resource: ocm.Resource,
) -> list[odg.labels.PackageVersionHint] | None:
    package_hints_label = resource.find_label(name=odg.labels.PackageVersionHintLabel.name)

    if not package_hints_label:
        package_hints_label = component.find_label(name=odg.labels.PackageVersionHintLabel.name)

        if not package_hints_label:
            return None

    return [
        odg.labels.PackageVersionHint(
            name=hint.get('name'),
            version=hint.get('version'),
        ) for hint in package_hints_label.value
    ]


def retrieve_existing_scan_results(
    bdba_client: bdba.client.BDBAApi,
    group_id: int,
    resource_node: ocm.iter.ResourceNode,
) -> list[bm.Product]:
    query_data = bdba_utils.util.component_artefact_metadata(
        resource_node=resource_node,
        omit_resource_strict_id=True,
    )

    return list(bdba_client.list_apps(
        group_id=group_id,
        custom_attribs=query_data,
    ))


def run_scan(
    aws_secret_name: str,
    bdba_client: bdba.client.BDBAApi,
    group_id: int,
    oci_client: oci.client.Client,
    processing_mode: bm.ProcessingMode,
    resource_node: ocm.iter.ResourceNode,
    secret_factory: secret_mgmt.SecretFactory,
    vulnerability_cfg: odg.findings.Finding | None=None,
    license_cfg: odg.findings.Finding | None=None,
    delivery_client: delivery.client.DeliveryServiceClient | None=None,
) -> collections.abc.Iterator[odg.model.ArtefactMetadata]:

    content_iterator = ocm_util.iter_content_for_resource_node(
        resource_node=resource_node,
        oci_client=oci_client,
        secret_factory=secret_factory,
        aws_secret_name=aws_secret_name,
    )

    known_scan_results = retrieve_existing_scan_results(
        bdba_client=bdba_client,
        group_id=group_id,
        resource_node=resource_node,
    )

    processor = ResourceGroupProcessor(
        bdba_client=bdba_client,
        group_id=group_id,
    )

    return processor.process(
        resource_node=resource_node,
        content_iterator=content_iterator,
        known_scan_results=known_scan_results,
        processing_mode=bm.ProcessingMode(processing_mode),
        delivery_client=delivery_client,
        vulnerability_cfg=vulnerability_cfg,
        license_cfg=license_cfg
    )
