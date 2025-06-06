#!/usr/bin/env python3

import logging

import ci.log
import bdba.client
import bdba.model
import blackduck
import k8s.logging
import odg.extensions_cfg
import odg.model
import odg.findings
import odg.util
import cnudie.retrieve
import delivery.client
import secret_mgmt.bdba
import secret_mgmt.bd
import secret_mgmt
import bdba_extension.scanning
import k8s.util
import paths
import functools


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def find_project_by_name(
    bd: blackduck.Client,
    project_name: str,
):
    params = {'q': [f"name:{project_name}"]}
    projects = [p for p in bd.get_resource('projects', params=params) if p['name'].casefold() == project_name.casefold()]
    return projects[0] if len(projects) == 1 else None


def assign_usergroup_to_project(
    bd: blackduck.Client,
    project,
    usergroup_id: str
):
    project_href = project['_meta']['href']
    target_url = f"{project_href}/usergroups"
    headers = {
        'Accept': 'application/vnd.blackducksoftware.project-detail-4+json',
        'Content-Type': 'application/vnd.blackducksoftware.project-detail-4+json'
    }
    response = bd.session.post(target_url, headers=headers, json={"group": f"{bd.base_url}/api/usergroups/{usergroup_id}"})
    response.raise_for_status()


def scan(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.BDConfig,
    vulnerability_cfg: odg.findings.Finding | None,
    license_cfg: odg.findings.Finding | None,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    secret_factory: secret_mgmt.SecretFactory,
    **kwargs: dict #do not crash on unexpected args
):
    logger.info(f'processing {artefact}')

    retrieve_vulnerability_findings = vulnerability_cfg and vulnerability_cfg.matches(artefact)
    retrieve_license_findings = license_cfg and license_cfg.matches(artefact)

    if not (retrieve_vulnerability_findings or retrieve_license_findings):
        logger.info(f'no findings to retrieve for {artefact=}, skipping...')
        return

    if not extension_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(f'{artefact.artefact_kind} is not supported for BD scans')
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access = resource_node.resource.access

    if not extension_cfg.is_supported(access_type=access.type):
        if extension_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(f'{access.type} is not supported for BD scans')
        return

    mapping = extension_cfg.mapping(artefact.component_name)

    # init BDBA
    logger.info(f'using BDBA secret element "{mapping.bdba_secret_name}"')
    bdba_secret = secret_factory.bdba(mapping.bdba_secret_name)
    bdba_client = bdba.client.BDBAApi(
        api_routes=bdba.client.BDBAApiRoutes(base_url=bdba_secret.api_url),
        token=bdba_secret.token,
        tls_verify=bdba_secret.tls_verify,
    )

    print(bdba_secret.api_url)

    # init Black Duck
    logger.info(f'using BD secret element "{mapping.bd_secret_name}"')
    bd_secret = secret_factory.bd(mapping.bd_secret_name)
    bd_client = blackduck.Client(
        base_url=bd_secret.api_url,
        token=bd_secret.token,
        verify=bd_secret.tls_verify,
    )

    # get existing BDBA results
    known_scan_results = bdba_extension.scanning.retrieve_existing_scan_results(
        bdba_client=bdba_client,
        group_id=mapping.group_id_bdba,
        resource_node=resource_node,
    )
    return
    for scan_result in known_scan_results:
        response = bdba_client.bdio_export(scan_result.product_id)
        bdio: bdba.model.BDIO = response.json()

        file_name = f'{bdio.name}.bdio.jsonld'
        files = {
            'file': (file_name, bdio.as_json(), 'application/ld+json')
        }

        upload_response = bd_client.session.post(
            '/api/scan/data',
            headers={'Accept': 'application/vnd.blackducksoftware.bdio+json'},
            params={'mode': 'replace'},
            files=files,
        )
        upload_response.raise_for_status()
        logger.info(f'Uploaded BDIO for {bdio.name}')

        project = find_project_by_name(bd_client, bdio.name)
        if project and bd_secret.usergroup_id:
            assign_usergroup_to_project(bd_client, project, bd_secret.usergroup_id)
            logger.info(f'Assigned user group to {bdio.name}')


def main():
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    vulnerability_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.VULNERABILITY_FINDING,
    )
    license_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.model.Datatype.LICENSE_FINDING,
    )

    scan_callback = functools.partial(
        scan,
        vulnerability_cfg=vulnerability_cfg,
        license_cfg=license_cfg,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.BD,
        callback=scan_callback,
    )


if __name__ == '__main__':
    main()
