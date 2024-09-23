import collections
import collections.abc
import dataclasses
import datetime
import functools
import logging

import botocore.exceptions
import dateutil.parser
import pytz
import requests

import ci.log
import cnudie.access
import cnudie.iter
import cnudie.retrieve
import concourse.model.traits.image_scan as image_scan
import delivery.client
import dso.cvss
import dso.labels
import dso.model
import oci.client
import ocm

import bdba.assessments
import bdba.client
import bdba.model as bm
import bdba.rescore
import bdba.util


logger = logging.getLogger(__name__)
ci.log.configure_default_logging(print_thread_id=True)


@functools.lru_cache(maxsize=200)
def _wait_for_scan_result(
    bdba_client: bdba.client.BDBAApi,
    product_id: int,
) -> bm.AnalysisResult:
    return bdba_client.wait_for_scan_result(product_id=product_id)


class ResourceGroupProcessor:
    def __init__(
        self,
        bdba_client: bdba.client.BDBAApi,
        oci_client: oci.client.Client,
        group_id: int=None,
        reference_group_ids: collections.abc.Sequence[int]=(),
        cvss_threshold: float=7.0,
    ):
        self.bdba_client = bdba_client
        self.oci_client = oci_client
        self.group_id = group_id
        self.reference_group_ids = reference_group_ids
        self.cvss_threshold = cvss_threshold

    def _products_with_relevant_triages(
        self,
        resource_node: cnudie.iter.ResourceNode,
    ) -> collections.abc.Generator[bm.Product, None, None]:
        relevant_group_ids = set(self.reference_group_ids)
        relevant_group_ids.add(self.group_id)

        metadata = bdba.util.component_artifact_metadata(
            resource_node=resource_node,
            # we want to find all possibly relevant scans, so omit all version data
            omit_resource_version=True,
            oci_client=self.oci_client,
        )

        for id in relevant_group_ids:
            products = list(self.bdba_client.list_apps(
                group_id=id,
                custom_attribs=metadata,
            ))
            yield from products

    def iter_products(
        self,
        products_to_import_from: list[bm.Product],
        use_product_cache: bool=True,
        delete_inactive_products_after_seconds: int=None,
    ) -> collections.abc.Generator[
        tuple[bm.Component, bm.Vulnerability, tuple[bm.Triage]],
        None,
        None,
    ]:
        '''
        Used to retrieve the triages of the supplied products grouped by components and
        their vulnerabilities. Also, if `delete_inactive_products_after` is set, old
        bdba products will be deleted according to it.
        Note: `delete_inactive_products_after` must be greater than the interval in which
        the resources are set or otherwise the products are going to be deleted immediately.
        Also, old products of resources which are not scanned anymore at all (meaning in no
        version) are _not_ going to be deleted.
        '''
        def _iter_vulnerabilities(
            result: bm.AnalysisResult,
        ) -> collections.abc.Generator[tuple[bm.Component, bm.Vulnerability], None, None]:
            for component in result.components():
                for vulnerability in component.vulnerabilities():
                    yield component, vulnerability

        def iter_vulnerabilities_with_assessments(
            result: bm.AnalysisResult,
        ):
            for component, vulnerability in _iter_vulnerabilities(result=result):
                if not vulnerability.has_triage():
                    continue
                yield component, vulnerability, tuple(vulnerability.triages())

        now = datetime.datetime.now(tz=pytz.UTC)
        delete_after = now + datetime.timedelta(
            seconds=delete_inactive_products_after_seconds or 0,
        )
        for product in products_to_import_from:
            if delete_inactive_products_after_seconds is not None:
                if not (delete_after_flag := product.custom_data().get('DELETE_AFTER')):
                    delete_after_flag = delete_after.isoformat()
                    self.bdba_client.set_metadata(
                        product_id=product.product_id(),
                        custom_attribs={
                            'DELETE_AFTER': delete_after_flag,
                        },
                    )

                if now >= dateutil.parser.isoparse(delete_after_flag):
                    self.bdba_client.delete_product(product_id=product.product_id())
                    logger.info(f'deleted old bdba product {product.product_id()}')
                    continue

            if use_product_cache:
                result = _wait_for_scan_result(
                    bdba_client=self.bdba_client,
                    product_id=product.product_id(),
                )
            else:
                result = self.bdba_client.wait_for_scan_result(
                    product_id=product.product_id(),
                )
            yield from iter_vulnerabilities_with_assessments(
                result=result,
            )

    def scan_request(
        self,
        resource_node: cnudie.iter.ResourceNode,
        content_iterator: collections.abc.Generator[bytes, None, None],
        known_artifact_scans: tuple[bm.Product],
    ) -> bm.ScanRequest:
        component = resource_node.component
        resource = resource_node.resource
        display_name = f'{resource.name}_{resource.version}_{component.name}'.replace('/', '_')

        component_artifact_metadata = bdba.util.component_artifact_metadata(
            resource_node=resource_node,
            omit_resource_version=False,
            oci_client=self.oci_client
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
    ) -> bm.AnalysisResult:
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
                if scan_result.is_stale() and not scan_result.has_binary():
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
                if scan_result.name() != scan_request.display_name:
                    self.bdba_client.set_product_name(
                        product_id=existing_id,
                        name=scan_request.display_name,
                    )
                # update metadata if new metadata is not completely included in current one
                if scan_result.custom_data().items() < scan_request.custom_metadata.items():
                    self.bdba_client.set_metadata(
                        product_id=existing_id,
                        custom_attribs=scan_request.custom_metadata,
                    )

                if scan_result.has_binary() and scan_result.is_stale():
                    # binary is still available, and "result is stale" (there was an engine-
                    # update), trigger rescan
                    logger.info(
                        f'Triggering rescan for {existing_id} ({scan_request.display_name()})'
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
        license_cfg: image_scan.LicenseCfg=None,
        cve_rescoring_rules: tuple[dso.cvss.RescoringRule]=tuple(),
        auto_assess_max_severity: dso.cvss.CVESeverity=dso.cvss.CVESeverity.MEDIUM,
        use_product_cache: bool=True,
        delete_inactive_products_after_seconds: int=None,
    ) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
        resource = resource_node.resource
        component = resource_node.component

        products_to_import_from = list(self._products_with_relevant_triages(
            resource_node=resource_node,
        ))

        assessments = self.iter_products(
            products_to_import_from=products_to_import_from,
            use_product_cache=use_product_cache,
            delete_inactive_products_after_seconds=delete_inactive_products_after_seconds,
        )

        scan_request = self.scan_request(
            resource_node=resource_node,
            content_iterator=content_iterator,
            known_artifact_scans=known_scan_results,
        )
        try:
            scan_result = self.process_scan_request(
                scan_request=scan_request,
                processing_mode=processing_mode,
            )
            scan_result = self.bdba_client.wait_for_scan_result(scan_result.product_id())
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
            f'scan of {scan_result.display_name()} succeeded, going to post-process results'
        )

        if version_hints := _package_version_hints(
            component=component,
            artefact=resource,
            result=scan_result,
        ):
            logger.info(f'uploading package-version-hints for {scan_result.display_name()}')
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

        assessed_vulns_by_component = bdba.assessments.add_assessments_if_none_exist(
            tgt=scan_result,
            tgt_group_id=self.group_id,
            assessments=assessments,
            bdba_client=self.bdba_client,
            assessed_vulns_by_component=assessed_vulns_by_component,
        )

        if cve_rescoring_rules:
            assessed_vulns_by_component = bdba.rescore.rescore(
                bdba_client=self.bdba_client,
                scan_result=scan_result,
                scanned_element=scanned_element,
                rescoring_rules=cve_rescoring_rules,
                max_rescore_severity=auto_assess_max_severity,
                assessed_vulns_by_component=assessed_vulns_by_component,
            )

        if assessed_vulns_by_component:
            logger.info(
                f'retrieving result again from bdba for {scan_result.display_name()} ' +
                '(this may take a while)'
            )
            scan_result = self.bdba_client.wait_for_scan_result(
                product_id=scan_result.product_id(),
            )

        if delete_inactive_products_after_seconds is not None:
            # remove deletion flag for current product as it is still in use
            self.bdba_client.set_metadata(
                product_id=scan_result.product_id(),
                custom_attribs={
                    'DELETE_AFTER': None,
                },
            )

        logger.info(f'post-processing of {scan_result.display_name()} done')

        yield from bdba.util.iter_artefact_metadata(
            scanned_element=scanned_element,
            scan_result=scan_result,
            license_cfg=license_cfg,
            delivery_client=delivery_client,
        )


def _package_version_hints(
    component: ocm.Component,
    artefact: ocm.Artifact,
    result: bm.AnalysisResult,
) -> list[dso.labels.PackageVersionHint] | None:
    def result_matches(resource: ocm.Resource, result: bm.AnalysisResult):
        '''
        find matching result for package-version-hint
        note: we require strict matching of resource-version
        '''
        cd = result.custom_data()
        if not cd.get('COMPONENT_NAME') == component.name:
            return False
        if not cd.get('IMAGE_REFERENCE_NAME') == artefact.name:
            return False
        if not cd.get('IMAGE_VERSION') == artefact.version:
            return False

        return True

    if not result_matches(resource=artefact, result=result):
        return None

    if not isinstance(artefact, ocm.Resource):
        raise NotImplementedError(artefact)

    artefact: ocm.Resource

    package_hints_label = artefact.find_label(name=dso.labels.PackageVersionHintLabel.name)
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
    oci_client: oci.client.Client,
) -> list[bm.Product]:
    query_data = bdba.util.component_artifact_metadata(
        resource_node=resource_node,
        omit_resource_version=True,
        oci_client=oci_client,
    )

    return list(bdba_client.list_apps(
        group_id=group_id,
        custom_attribs=query_data,
    ))
