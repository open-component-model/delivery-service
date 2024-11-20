import collections.abc
import itertools
import logging
import os
import pprint

import tabulate

import ccc.aws
import ccc.oci
import ci.util
import cnudie.access
import cnudie.iter
import cnudie.retrieve as cr
import ctx
import dso.cvss
import dso.model
import oci
import ocm
import tarutil

import bdba.assessments
import bdba.client
import bdba.model
import bdba.scanning
import ocm_util
import rescore.utility as ru
import rescore.model as rm


__cmd_name__ = 'bdba'
logger = logging.getLogger(__name__)

# monkeypatch: disable html escaping
tabulate.htmlescape = lambda x: x


def retrieve(
    product_id: str,
    bdba_cfg_name='gardener',
):
    client = bdba.client.client(bdba_cfg_name)

    scan_result = client.wait_for_scan_result(
        product_id=product_id,
    )

    pprint.pprint(scan_result.raw)


def ls_products(
    ocm_component: str,
    bdba_cfg_name='gardener',
    group_id=407,
    ocm_repo: str=None,
):
    if not ocm_repo:
        ocm_lookup = ctx.cfg.ctx.ocm_lookup
    else:
        ocm_lookup = cr.create_default_component_descriptor_lookup(
            ocm_repository_lookup=cr.ocm_repository_lookup(
                ocm_repo,
            )
        )

    client = bdba.client.client(bdba_cfg_name)

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

        for app in client.list_apps(group_id=group_id, custom_attribs=metadata):
            print(app.product_id())


def rescore(
    bdba_cfg_name: str,
    product_id: int,
    categorisation: str,
    rescoring_rules: str,
    assess: bool=False,
):
    client = bdba.client.client(bdba_cfg_name)

    if not os.path.isfile(categorisation):
        print(f'{categorisation} must point to an existing file w/ CveCategorisation')
        exit(1)

    if not os.path.isfile(rescoring_rules):
        print(f'{rescoring_rules} must point to an existing file w/ RescoringRules')
        exit(1)

    logger.info(f'retrieving bdba {product_id=}')
    result = client.scan_result(product_id=product_id)

    categorisation = dso.cvss.CveCategorisation.from_dict(
        ci.util.parse_yaml_file(categorisation),
    )

    rescoring_rules = tuple(
        rm.rescoring_rules_from_dicts(
            ci.util.parse_yaml_file(rescoring_rules)
        )
    )

    all_components = tuple(result.components())
    components_with_vulnerabilities = [c for c in all_components if tuple(c.vulnerabilities())]

    logger.info(f'{len(all_components)=}, {len(components_with_vulnerabilities)=}')

    components_with_vulnerabilities = sorted(
        components_with_vulnerabilities,
        key=lambda c: c.name()
    )

    total_vulns = 0
    total_rescored = 0

    for c in components_with_vulnerabilities:
        vulns_count = 0
        rescored_count = 0
        vulns_to_assess = []
        printed_cname = False

        for v in c.vulnerabilities():
            if v.historical():
                continue
            if v.has_triage():
                continue

            vulns_count += 1

            if not v.cvss:
                continue # happens if only cvss-v2 is available - ignore for now

            rules = tuple(ru.matching_rescore_rules(
                rescoring_rules=rescoring_rules,
                categorisation=categorisation,
                cvss=v.cvss,
            ))
            orig_severity = dso.cvss.CVESeverity.from_cve_score(v.cve_severity())
            rescored = ru.rescore_severity(
                rescoring_rules=rules,
                severity=orig_severity,
            )

            if orig_severity is not rescored:
                rescored_count += 1

                if not printed_cname:
                    print(f'{c.name()}:{c.version()}')
                    printed_cname = True

                print(f'  rescore {orig_severity.name} -> {rescored.name} - {v.cve()}')
                if assess and rescored is dso.cvss.CVESeverity.NONE:
                    if not c.version():
                        print(f'setting dummy-version for {c.name()}')
                        client.set_component_version(
                            component_name=c.name(),
                            component_version='does-not-matter',
                            objects=[eo.sha1() for eo in c.extended_objects()],
                            app_id=product_id,
                        )
                    else:
                        vulns_to_assess.append(v)

        if assess and vulns_to_assess:
            client.add_triage_raw({
                'component': c.name(),
                'version': c.version() or 'does-not-matter',
                'vulns': [v.cve() for v in vulns_to_assess],
                'scope': bdba.model.TriageScope.RESULT.value,
                'reason': 'OT',
                'description': 'assessed as irrelevant based on cve-categorisation',
                'product_id': product_id,
            })
            print(f'auto-assessed {len(vulns_to_assess)=}')

        total_vulns += vulns_count
        total_rescored += rescored_count

    print()
    print(f'{total_vulns=}, {total_rescored=}')


def assess(
    bdba_cfg_name: str,
    product_id: int,
    assessment: str,
):
    cfg_factory = ci.util.ctx().cfg_factory()
    bdba_cfg = cfg_factory.bdba(bdba_cfg_name)
    bdba_client = bdba.client.client(bdba_cfg=bdba_cfg)

    bdba.assessments.auto_triage(
        bdba_client=bdba_client,
        product_id=product_id,
        assessment_txt=assessment,
    )


def scan(
    bdba_cfg_name: str,
    bdba_group_id: str,
    component_id: str, # <name>:<version>
    cve_threshold: float=7.0,
    bdba_api_url=None,
    reference_bdba_group_ids: list[int]=[],
    aws_cfg: str=None,
):
    cfg_factory = ci.util.ctx().cfg_factory()
    bdba_cfg = cfg_factory.bdba(bdba_cfg_name)

    oci_client = ccc.oci.oci_client()
    if aws_cfg:
        aws_session = ccc.aws.session(aws_cfg=aws_cfg)
        s3_client = aws_session.client('s3')
    else:
        s3_client = None
        logger.warn('failed to initialise s3-client')

    if not bdba_api_url:
        bdba_api_url = bdba_cfg.api_url()
    bdba_group_url = ci.util.urljoin(bdba_api_url, 'group', str(bdba_group_id))
    logger.info(f'Using BDBA at: {bdba_api_url} with group {bdba_group_id}')

    lookup = cr.create_default_component_descriptor_lookup()
    component_descriptor = lookup(component_id)

    cvss_version = bdba.model.CVSSVersion.V3

    headers = ('BDBA Scan Configuration', '')
    entries = (
        ('BDBA target group id', str(bdba_group_id)),
        ('BDBA group URL', bdba_group_url),
        ('BDBA reference group IDs', reference_bdba_group_ids),
        ('Used CVSS version', cvss_version.value),
    )
    print(tabulate.tabulate(entries, headers=headers))

    logger.info('running BDBA scan for all components')

    bdba_client = bdba.client.client(
        bdba_cfg=bdba_cfg,
        group_id=bdba_group_id,
        base_url=bdba_api_url,
        cfg_factory=cfg_factory,
    )

    def iter_resource_scans() -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
        for resource_node in cnudie.iter.iter(
            component=component_descriptor.component,
            lookup=lookup,
            node_filter=cnudie.iter.Filter.resources,
        ):
            known_scan_results = bdba.scanning.retrieve_existing_scan_results(
                bdba_client=bdba_client,
                group_id=bdba_group_id,
                resource_node=resource_node,
            )
            processor = bdba.scanning.ResourceGroupProcessor(
                group_id=bdba_group_id,
                reference_group_ids=reference_bdba_group_ids,
                bdba_client=bdba_client,
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
                image_reference = ocm_repo.component_oci_ref(name=resource_node.component.name)

                content_iterator = ocm_util.iter_local_blob_content(
                    access=access,
                    oci_client=oci_client,
                    image_reference=image_reference,
                )

            else:
                raise NotImplementedError(access)

            yield from processor.process(
                resource_node=resource_node,
                content_iterator=content_iterator,
                processing_mode=bdba.model.ProcessingMode.RESCAN,
                known_scan_results=known_scan_results,
            )

    results = list(iter_resource_scans())

    results_above_threshold = [
        r for r in results
        if (
            isinstance(r.data, dso.model.VulnerabilityFinding) and
            r.data.cvss_v3_score >= cve_threshold
        )
    ]
    results_below_threshold = [
        r for r in results
        if (
            isinstance(r.data, dso.model.VulnerabilityFinding) and
            r.data.cvss_v3_score < cve_threshold
        )
    ]

    logger.info('Summary of found vulnerabilities:')
    logger.info(f'{len(results_above_threshold)=}')
    logger.info(f'{len(results_below_threshold)=}')

    def _grouped_results(results: list[dso.model.ArtefactMetadata]) -> dict:
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
    cfg_factory = ci.util.ctx().cfg_factory()
    bdba_cfg = cfg_factory.bdba(bdba_cfg_name)
    api = bdba.client.client(bdba_cfg=bdba_cfg)

    scan_result_from = api.scan_result(product_id=from_product_id)
    scan_results_to = {
        product_id: api.scan_result(product_id=product_id)
        for product_id in to_product_ids
    }

    def target_component_versions(product_id: int, component_name: str):
        scan_result = scan_results_to[product_id]
        component_versions = {
            c.version() for c
            in scan_result.components()
            if c.name() == component_name
        }
        return component_versions

    def enum_triages():
        for component in scan_result_from.components():
            for vulnerability in component.vulnerabilities():
                for triage in vulnerability.triages():
                    yield component, triage

    triages = list(enum_triages())
    logger.info(f'found {len(triages)} triage(s) to import')

    for to_product_id, component_name_and_triage in itertools.product(to_product_ids, triages):
        component, triage = component_name_and_triage
        for target_component_version in target_component_versions(
            product_id=to_product_id,
            component_name=component.name(),
        ):
            logger.info(f'adding triage for {triage.component_name()}:{target_component_version}')
            api.add_triage(
                triage=triage,
                product_id=to_product_id,
                group_id=to_group_id,
                component_version=target_component_version,
            )
        logger.info(f'added triage for {triage.component_name()} to {to_product_id}')
