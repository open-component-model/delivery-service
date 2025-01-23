import collections
import collections.abc
import dataclasses
import logging

import botocore.exceptions
import requests

import ci.log
import cnudie.iter
import delivery.client
import dso.cvss
import dso.labels
import dso.model
import ocm

import bdba.assessments
import bdba.client
import bdba.model as bm
import bdba.rescore
import bdba.util
import config
import rescore.model

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
        resource_node: cnudie.iter.ResourceNode,
        content_iterator: collections.abc.Generator[bytes, None, None],
        known_artifact_scans: tuple[bm.Product],
    ) -> bm.ScanRequest:
        component = resource_node.component
        resource = resource_node.resource
        display_name = f'{resource.name}_{resource.version}_{component.name}_{resource.type}'.replace('/', '_') # noqa: E501

        if resource.extraIdentity:
            # peers are not required here as version is considered anyways
            display_name += f'_{resource.identity(peers=())}'.replace('/', '_')

        component_artifact_metadata = bdba.util.component_artifact_metadata(
            resource_node=resource_node,
        )

        target_product_id = bdba.util._matching_analysis_result_id(
            component_artifact_metadata=component_artifact_metadata,
            analysis_results=known_artifact_scans,
        )

        if target_product_id:
            logger.info(f'{display_name=}: found {target_product_id=}')
        else:
            logger.info(f'{display_name=}: did not find old scan')

        return bm.ScanRequest(
            component=component,
            artefact=resource,
            scan_content=content_iterator,
            display_name=display_name,
            target_product_id=target_product_id,
            custom_metadata=component_artifact_metadata,
        )

    def process_scan_request(
        self,
        scan_request: bm.ScanRequest,
        processing_mode: bm.ProcessingMode,
    ) -> bm.Result:
        def raise_on_error(exception):
            raise bm.BdbaScanError(
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
        resource_node: cnudie.iter.ResourceNode,
        content_iterator: collections.abc.Generator[bytes, None, None],
        known_scan_results: tuple[bm.Product],
        processing_mode: bm.ProcessingMode,
        delivery_client: delivery.client.DeliveryServiceClient=None,
        license_cfg: config.LicenseCfg=None,
        cve_rescoring_ruleset: rescore.model.CveRescoringRuleSet=None,
        auto_assess_max_severity: dso.cvss.CVESeverity=dso.cvss.CVESeverity.MEDIUM,
    ) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
        resource = resource_node.resource
        component = resource_node.component

        scan_request = self.scan_request(
            resource_node=resource_node,
            content_iterator=content_iterator,
            known_artifact_scans=known_scan_results,
        )
        try:
            result = self.process_scan_request(
                scan_request=scan_request,
                processing_mode=processing_mode,
            )
            scan_result = self.bdba_client.wait_for_scan_result(result.product_id)
            scan_failed = False
        except bm.BdbaScanError as bse:
            scan_result = bse
            scan_failed = True
            logger.warning(bse.print_stacktrace())

        # don't include component version here since it is also not considered in the BDBA scan
        # -> this will deduplicate findings of the same artefact version across different
        # component versions
        component = dataclasses.replace(scan_request.component, version=None)
        resource = scan_request.artefact
        scanned_element = cnudie.iter.ResourceNode(
            path=(cnudie.iter.NodePathEntry(component),),
            resource=resource,
        )

        if scan_failed:
            logger.error(f'scan of {scanned_element=} failed; {scan_result=}')
            return

        logger.info(
            f'scan of {scan_result.display_name} succeeded, going to post-process results'
        )

        if version_hints := _package_version_hints(resource=resource):
            logger.info(f'uploading package-version-hints for {scan_result.display_name}')
            scan_result = bdba.assessments.upload_version_hints(
                scan_result=scan_result,
                hints=version_hints,
                client=self.bdba_client,
            )

        assessed_vulns_by_component = collections.defaultdict(list)

        if scan_request.auto_triage_scan():
            assessed_vulns_by_component = bdba.assessments.auto_triage(
                analysis_result=scan_result,
                bdba_client=self.bdba_client,
                assessed_vulns_by_component=assessed_vulns_by_component,
            )

        if cve_rescoring_ruleset:
            assessed_vulns_by_component = bdba.rescore.rescore(
                bdba_client=self.bdba_client,
                scan_result=scan_result,
                scanned_element=scanned_element,
                cve_rescoring_ruleset=cve_rescoring_ruleset,
                max_rescore_severity=auto_assess_max_severity,
                assessed_vulns_by_component=assessed_vulns_by_component,
            )

        if assessed_vulns_by_component:
            logger.info(
                f'retrieving result again from bdba for {scan_result.display_name} ' +
                '(this may take a while)'
            )
            scan_result = self.bdba_client.wait_for_scan_result(
                product_id=scan_result.product_id,
            )

        logger.info(f'post-processing of {scan_result.display_name} done')

        yield from bdba.util.iter_artefact_metadata(
            scanned_element=scanned_element,
            scan_result=scan_result,
            license_cfg=license_cfg,
            delivery_client=delivery_client,
        )


def _package_version_hints(
    resource: ocm.Resource,
) -> list[dso.labels.PackageVersionHint] | None:
    package_hints_label = resource.find_label(name=dso.labels.PackageVersionHintLabel.name)

    if not package_hints_label:
        return None

    return [
        dso.labels.PackageVersionHint(
            name=hint.get('name'),
            version=hint.get('version'),
        ) for hint in package_hints_label.value
    ]


def retrieve_existing_scan_results(
    bdba_client: bdba.client.BDBAApi,
    group_id: int,
    resource_node: cnudie.iter.ResourceNode,
) -> list[bm.Product]:
    query_data = bdba.util.component_artifact_metadata(
        resource_node=resource_node,
        omit_resource_strict_id=True,
    )

    return list(bdba_client.list_apps(
        group_id=group_id,
        custom_attribs=query_data,
    ))
