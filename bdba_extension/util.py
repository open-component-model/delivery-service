# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


import collections.abc
import dataclasses
import datetime
import logging

import dacite

import ci.log
import cnudie.iter
import delivery.client
import dso.cvss
import dso.model

import bdba.model as bm
import odg.findings


logger = logging.getLogger(__name__)
ci.log.configure_default_logging(print_thread_id=True)


def iter_existing_findings(
    delivery_client: delivery.client.DeliveryServiceClient,
    resource_node: cnudie.iter.ResourceNode,
    finding_type: str | tuple[str],
    datasource: str=dso.model.Datasource.BDBA,
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    artefact = dso.model.component_artefact_id_from_ocm(
        component=resource_node.component_id,
        artefact=resource_node.resource,
    )

    findings = delivery_client.query_metadata(
        artefacts=(artefact,),
        type=finding_type,
    )

    return (
        finding for finding in findings
        if finding.meta.datasource == datasource
    )


def iter_artefact_metadata(
    scanned_element: cnudie.iter.ResourceNode,
    scan_result: bm.AnalysisResult,
    delivery_client: delivery.client.DeliveryServiceClient=None,
    vulnerability_cfg: odg.findings.Finding | None=None,
    license_cfg: odg.findings.Finding | None=None,
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    discovery_date = datetime.date.today()
    datasource = dso.model.Datasource.BDBA

    artefact_ref = dso.model.component_artefact_id_from_ocm(
        component=scanned_element.component,
        artefact=scanned_element.resource,
    )

    # don't include component version here since it is also not considered in the BDBA scan
    # -> this will deduplicate findings of the same artefact version across different
    # component versions
    finding_artefact_ref = dataclasses.replace(
        artefact_ref,
        component_version=None,
    )

    # rescoring should not reference artefact version so that the `ARTEFACT` rescoring scope will be
    # used -> rescoring will be used for future versions as well, so there is no need to replicate
    # BDBA triages to new BDBA scans
    rescoring_artefact_ref = dataclasses.replace(
        finding_artefact_ref,
        artefact=dataclasses.replace(
            finding_artefact_ref.artefact,
            artefact_version=None,
        ),
    )

    yield dso.model.artefact_scan_info(
        artefact_node=scanned_element,
        datasource=datasource,
        data={
            'report_url': scan_result.report_url,
        },
    )

    findings: list[dso.model.ArtefactMetadata] = []
    for package in scan_result.components:
        package_name = package.name
        package_version = package.version

        filesystem_paths = list(iter_filesystem_paths(component=package))

        licenses = list({
            dso.model.License(
                name=license.name,
            ) for license in package.iter_licenses
        })

        meta = dso.model.Metadata(
            datasource=datasource,
            type=dso.model.Datatype.STRUCTURE_INFO,
            creation_date=now,
        )

        structure_info = dso.model.StructureInfo(
            package_name=package_name,
            package_version=package_version,
            base_url=scan_result.base_url,
            report_url=scan_result.report_url,
            product_id=scan_result.product_id,
            group_id=scan_result.group_id,
            licenses=licenses,
            filesystem_paths=filesystem_paths,
        )

        yield dso.model.ArtefactMetadata(
            artefact=finding_artefact_ref,
            meta=meta,
            data=structure_info,
            discovery_date=discovery_date,
        )

        if license_cfg and license_cfg.matches(artefact_ref):
            meta = dso.model.Metadata(
                datasource=datasource,
                type=odg.findings.FindingType.LICENSE,
                creation_date=now,
            )

            for license in licenses:
                categorisation = odg.findings.categorise_finding(
                    finding_cfg=license_cfg,
                    finding_property=license.name,
                )

                if not categorisation:
                    continue

                license_finding = dso.model.LicenseFinding(
                    package_name=package_name,
                    package_version=package_version,
                    base_url=scan_result.base_url,
                    report_url=scan_result.report_url,
                    product_id=scan_result.product_id,
                    group_id=scan_result.group_id,
                    severity=categorisation.id,
                    license=license,
                )

                artefact_metadata = dso.model.ArtefactMetadata(
                    artefact=finding_artefact_ref,
                    meta=meta,
                    data=license_finding,
                    discovery_date=discovery_date,
                )

                findings.append(artefact_metadata)
                yield artefact_metadata

        if vulnerability_cfg and vulnerability_cfg.matches(artefact_ref):
            meta = dso.model.Metadata(
                datasource=datasource,
                type=odg.findings.FindingType.VULNERABILITY,
                creation_date=now,
            )

            for vulnerability in package.vulnerabilities:
                if vulnerability.okay_to_skip:
                    continue # we only support active vulnerabilities with a valid cvss v3 vector

                categorisation = odg.findings.categorise_finding(
                    finding_cfg=vulnerability_cfg,
                    finding_property=vulnerability.cve_severity(),
                )

                if not categorisation:
                    continue

                for triage in vulnerability.triages:
                    meta_rescoring = dso.model.Metadata(
                        datasource=datasource,
                        type=dso.model.Datatype.RESCORING,
                        creation_date=triage.modified.astimezone(datetime.UTC),
                    )

                    vulnerability_rescoring = dso.model.CustomRescoring(
                        finding=dso.model.RescoringVulnerabilityFinding(
                            package_name=package_name,
                            cve=vulnerability.cve,
                        ),
                        referenced_type=odg.findings.FindingType.VULNERABILITY,
                        severity=vulnerability_cfg.none_categorisation.id,
                        user=dacite.from_dict(
                            data_class=dso.model.BDBAUser,
                            data=triage.user,
                        ),
                        matching_rules=[dso.model.MetaRescoringRules.BDBA_TRIAGE],
                        comment=triage.description,
                    )

                    yield dso.model.ArtefactMetadata(
                        artefact=rescoring_artefact_ref,
                        meta=meta_rescoring,
                        data=vulnerability_rescoring,
                    )

                vulnerability_finding = dso.model.VulnerabilityFinding(
                    package_name=package_name,
                    package_version=package_version,
                    base_url=scan_result.base_url,
                    report_url=scan_result.report_url,
                    product_id=scan_result.product_id,
                    group_id=scan_result.group_id,
                    severity=categorisation.id,
                    cve=vulnerability.cve,
                    cvss_v3_score=vulnerability.cve_severity(),
                    cvss=dso.cvss.CVSSV3.parse(vulnerability.cvss),
                    summary=vulnerability.summary,
                )

                artefact_metadata = dso.model.ArtefactMetadata(
                    artefact=finding_artefact_ref,
                    meta=meta,
                    data=vulnerability_finding,
                    discovery_date=discovery_date,
                )

                findings.append(artefact_metadata)
                yield artefact_metadata

    if delivery_client:
        # delete those BDBA findings which were found before for this scan but which are not part
        # of the current scan anymore -> those are either solved license findings or (now)
        # historical vulnerability findings (e.g. because a custom version was entered)
        existing_findings = iter_existing_findings(
            delivery_client=delivery_client,
            resource_node=scanned_element,
            finding_type=(
                odg.findings.FindingType.VULNERABILITY,
                odg.findings.FindingType.LICENSE,
            ),
        )

        stale_findings = []
        for existing_finding in existing_findings:
            for finding in findings:
                if (
                    existing_finding.meta.type == finding.meta.type
                    and existing_finding.data.key == finding.data.key
                ):
                    # finding still appeared in current scan result -> keep it
                    break
            else:
                # finding did not appear in current scan result -> delete it
                stale_findings.append(existing_finding)

        if stale_findings:
            delivery_client.delete_metadata(data=stale_findings)


def iter_filesystem_paths(
    component: bm.Component,
    file_type: str | None=None,
) -> collections.abc.Generator[dso.model.FilesystemPath, None, None]:
    for ext_obj in component.extended_objects:
        path = [
            dso.model.FilesystemPathEntry(
                path=path,
                type=type,
            ) for path_infos in ext_obj.extended_fullpath
            if (
                (path := path_infos.get('path')) and (type := path_infos.get('type'))
                and (not file_type or file_type == type)
            )
        ]

        yield dso.model.FilesystemPath(
            path=path,
            digest=ext_obj.sha1,
        )


def enum_triages(
    result: bm.AnalysisResult,
) -> collections.abc.Generator[tuple[bm.Component, bm.Triage], None, None]:
    for component in result.components:
        for vulnerability in component.vulnerabilities:
            for triage in vulnerability.triages:
                yield component, triage


def component_artifact_metadata(
    resource_node: cnudie.iter.ResourceNode,
    omit_resource_strict_id: bool=False,
) -> dict:
    '''
    Returns a dict for querying bdba scan results (use for custom-data query). If
    `omit_resource_strict_id` is set, the resource version and extra id are not included in the
    result to allow querying of related (but not equal) scans.
    '''
    component = resource_node.component
    resource = resource_node.resource

    metadata = {
        'COMPONENT_NAME': component.name,
        'IMAGE_REFERENCE_NAME': resource.name, # deprecated, will be replaced with `RESOURCE_NAME`
        'RESOURCE_TYPE': resource.type,
    }

    if omit_resource_strict_id:
        return metadata

    metadata['RESOURCE_NAME'] = resource.name
    metadata['RESOURCE_VERSION'] = resource.version

    if resource.extraIdentity:
        # peers are not required here as version is considered anyways
        metadata['RESOURCE_EXTRA_ID'] = f'{resource.identity(peers=())}'

    return metadata


def _matching_analysis_result_id(
    component_artifact_metadata: dict[str, str],
    analysis_results: collections.abc.Iterable[bm.Product],
) -> int | None:
    # This is a helper function that is used when we create new ScanRequests for a given artifact
    # group. Since a given artifact group can trigger multiple scans in bdba, we want to be
    # able to find the correct one from a set of possible choices (if there is one).
    def filter_func(other_dict: dict[str, str]):
        # filter-function to find the correct match. We consider a given dict a match if
        # it contains all keys we have and the values associated with these keys are identical.
        # Note: That means that (manually) added bdba-metadata will not interfere.
        for key in component_artifact_metadata:
            if key not in other_dict.keys():
                return False
            if other_dict[key] != component_artifact_metadata[key]:
                return False
        return True

    filtered_results = tuple(r for r in analysis_results if filter_func(r.custom_data))

    if not filtered_results:
        return None

    # there may be multiple possible candidates since we switched from including the component
    # version in the component artefact metadata to excluding it
    if len(filtered_results) > 1:
        logger.warning(
            'more than one scan result found for component artefact with '
            f'{component_artifact_metadata=}, will use latest scan result...'
        )
        filtered_results = sorted(
            filtered_results,
            key=lambda result: result.product_id,
            reverse=True,
        )

    # there is at least one result and they are ordered (latest product id first)
    return filtered_results[0].product_id
