import collections.abc
import dataclasses
import itertools
import logging
import pprint

import tabulate

import cnudie.access
import cnudie.iter
import oci
import ocm
import tarutil

import bdba.client
import bdba.model as bm
import bdba_utils.scan
import ctx_util
import lookups
import ocm_util
import odg.model
import util


__cmd_name__ = 'bdba'
logger = logging.getLogger(__name__)

# monkeypatch: disable html escaping
tabulate.htmlescape = lambda x: x


def retrieve(
    product_id: str,
    bdba_cfg_name='gardener',
):
    secret_factory = ctx_util.secret_factory()
    bdba_cfg = secret_factory.bdba(bdba_cfg_name)
    bdba_client = bdba.client.BDBAApi(
        api_routes=bdba.client.BDBAApiRoutes(base_url=bdba_cfg.api_url),
        token=bdba_cfg.token,
        tls_verify=bdba_cfg.tls_verify,
    )

    scan_result = bdba_client.wait_for_scan_result(
        product_id=product_id,
    )

    pprint.pprint(dataclasses.asdict(scan_result))


def ls_products(
    ocm_component: str,
    bdba_cfg_name: str,
    group_id: int,
):
    ocm_lookup = lookups.init_component_descriptor_lookup()

    secret_factory = ctx_util.secret_factory()
    bdba_cfg = secret_factory.bdba(bdba_cfg_name)
    bdba_client = bdba.client.BDBAApi(
        api_routes=bdba.client.BDBAApiRoutes(base_url=bdba_cfg.api_url),
        token=bdba_cfg.token,
        tls_verify=bdba_cfg.tls_verify,
    )

    if not ':' in ocm_component:
        raise ValueError('ocm_component must have form <name>:<version>')

    root_component_descriptor = ocm_lookup(ocm_component)

    for ocm_node in cnudie.iter.iter(
        component=root_component_descriptor,
        lookup=ocm_lookup,
        node_filter=cnudie.iter.Filter.components,
    ):
        component = ocm_node.component

        metadata = {
            'COMPONENT_NAME': component.name,
            'COMPONENT_VERSION': component.version,
        }

        for app in bdba_client.list_apps(group_id=group_id, custom_attribs=metadata):
            print(app.product_id)


def scan(
    bdba_cfg_name: str,
    bdba_group_id: str,
    component_id: str, # <name>:<version>
    cve_threshold: float=7.0,
    bdba_api_url=None,
    reference_bdba_group_ids: list[int]=[],
    aws_cfg_name: str=None,
):
    secret_factory = ctx_util.secret_factory()
    bdba_cfg = secret_factory.bdba(bdba_cfg_name)

    oci_client = lookups.semver_sanitising_oci_client(
        secret_factory=secret_factory,
    )
    if aws_cfg_name:
        aws_cfg = secret_factory.aws(aws_cfg_name)
        s3_client = aws_cfg.session.client('s3')
    else:
        s3_client = None
        logger.warning('failed to initialise s3-client')

    if not bdba_api_url:
        bdba_api_url = bdba_cfg.api_url
    bdba_group_url = util.urljoin(bdba_api_url, 'group', str(bdba_group_id))
    logger.info(f'Using BDBA at: {bdba_api_url} with group {bdba_group_id}')

    lookup = lookups.init_component_descriptor_lookup(
        oci_client=oci_client,
    )
    component_descriptor = lookup(component_id)

    cvss_version = bm.CVSSVersion.V3

    headers = ('BDBA Scan Configuration', '')
    entries = (
        ('BDBA target group id', str(bdba_group_id)),
        ('BDBA group URL', bdba_group_url),
        ('BDBA reference group IDs', reference_bdba_group_ids),
        ('Used CVSS version', cvss_version.value),
    )
    print(tabulate.tabulate(entries, headers=headers))

    logger.info('running BDBA scan for all components')

    secret_factory = ctx_util.secret_factory()
    bdba_cfg = secret_factory.bdba(bdba_cfg_name)
    bdba_client = bdba.client.BDBAApi(
        api_routes=bdba.client.BDBAApiRoutes(base_url=bdba_cfg.api_url),
        token=bdba_cfg.token,
        tls_verify=bdba_cfg.tls_verify,
    )

    def iter_resource_scans() -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
        for resource_node in cnudie.iter.iter(
            component=component_descriptor.component,
            lookup=lookup,
            node_filter=cnudie.iter.Filter.resources,
        ):
            known_scan_results = bdba_utils.scan.retrieve_existing_scan_results(
                bdba_client=bdba_client,
                group_id=bdba_group_id,
                resource_node=resource_node,
            )
            processor = bdba_utils.scan.ResourceGroupProcessor(
                bdba_client=bdba_client,
                group_id=bdba_group_id,
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

                content_iterator = tarutil.concat_blobs_as_tarstream(
                    blobs=[
                        ocm_util.local_blob_access_as_blob_descriptor(
                            access=access,
                            oci_client=oci_client,
                            image_reference=image_reference,
                        ),
                    ]
                )

            else:
                raise NotImplementedError(access)

            yield from processor.process(
                resource_node=resource_node,
                content_iterator=content_iterator,
                processing_mode=bm.ProcessingMode.RESCAN,
                known_scan_results=known_scan_results,
            )

    results = list(iter_resource_scans())

    results_above_threshold = [
        r for r in results
        if (
            isinstance(r.data, odg.model.VulnerabilityFinding) and
            r.data.cvss_v3_score >= cve_threshold
        )
    ]
    results_below_threshold = [
        r for r in results
        if (
            isinstance(r.data, odg.model.VulnerabilityFinding) and
            r.data.cvss_v3_score < cve_threshold
        )
    ]

    logger.info('Summary of found vulnerabilities:')
    logger.info(f'{len(results_above_threshold)=}')
    logger.info(f'{len(results_below_threshold)=}')

    def _grouped_results(results: list[odg.model.ArtefactMetadata]) -> dict:
        grouped_results = dict()

        for r in results:
            c_id = f'{r.artefact.component_name}:{r.artefact.component_version}'
            a_id = f'{r.artefact.artefact.artefact_name}:{r.artefact.artefact.artefact_version}'
            p_id = f'{r.data.package_name}:{r.data.package_version}'

            key = f'{c_id}:{a_id}:{p_id}'

            cve = r.data.cve
            cvss_v3_score = r.data.cvss_v3_score

            if key in grouped_results:
                grouped_results[key]['vulnerabilities'] += f'\n{cve} ({cvss_v3_score})'
            else:
                grouped_results[key] = {
                    'c_id': c_id,
                    'a_id': a_id,
                    'p_id': p_id,
                    'vulnerabilities': f'{cve} ({cvss_v3_score})',
                }

        return grouped_results

    grouped_results_above_threshold = _grouped_results(
        results=results_above_threshold,
    )
    grouped_results_below_threshold = _grouped_results(
        results=results_below_threshold,
    )

    def print_summary(grouped_results: dict):
        print(tabulate.tabulate(
            grouped_results.values(),
            headers={
                'c_id': 'Component ID',
                'a_id': 'Artefact ID',
                'p_id': 'Affected Package ID',
                'vulnerabilities': 'Vulnerabilities',
            },
            tablefmt='grid',
        ))

    print(f'Summary of found vulnerabilites above {cve_threshold=}')
    print_summary(grouped_results=grouped_results_above_threshold)
    print(f'Summary of found vulnerabilites below {cve_threshold=}')
    print_summary(grouped_results=grouped_results_below_threshold)


def transport_triages(
    bdba_cfg_name: str,
    from_product_id: int,
    to_group_id: int,
    to_product_ids: list[int],
):
    secret_factory = ctx_util.secret_factory()
    bdba_cfg = secret_factory.bdba(bdba_cfg_name)
    bdba_client = bdba.client.BDBAApi(
        api_routes=bdba.client.BDBAApiRoutes(base_url=bdba_cfg.api_url),
        token=bdba_cfg.token,
        tls_verify=bdba_cfg.tls_verify,
    )

    scan_result_from = bdba_client.scan_result(product_id=from_product_id)
    scan_results_to = {
        product_id: bdba_client.scan_result(product_id=product_id)
        for product_id in to_product_ids
    }

    def target_component_versions(product_id: int, component_name: str):
        scan_result = scan_results_to[product_id]
        component_versions = {
            c.version for c
            in scan_result.components
            if c.name == component_name
        }
        return component_versions

    def enum_triages():
        for component in scan_result_from.components:
            for vulnerability in component.vulnerabilities:
                for triage in vulnerability.triages:
                    yield component, triage

    triages = list(enum_triages())
    logger.info(f'found {len(triages)} triage(s) to import')

    for to_product_id, component_name_and_triage in itertools.product(to_product_ids, triages):
        component, triage = component_name_and_triage
        for target_component_version in target_component_versions(
            product_id=to_product_id,
            component_name=component.name,
        ):
            logger.info(f'adding triage for {triage.component}:{target_component_version}')
            bdba_client.add_triage(
                triage=triage,
                product_id=to_product_id,
                group_id=to_group_id,
                component_version=target_component_version,
            )
        logger.info(f'added triage for {triage.component} to {to_product_id}')
