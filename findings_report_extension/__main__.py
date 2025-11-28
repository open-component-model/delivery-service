#!/usr/bin/env python

import argparse
import collections.abc
import datetime
import logging
import os
import pprint
import time
import traceback

import github3.issues.issue
import git.repo
import mako.template
import requests.exceptions
import semver

import ccc.delivery
import ccc.github
import ccc.oci
import ci.log
import ci.util
import cnudie.iter
import cnudie.retrieve
import delivery.client
import ocm

import odg.extensions_cfg
import odg.findings
import odg.model

import saf


ci.log.configure_default_logging()
logger = logging.getLogger(__name__)


# TODO: deduplicate with artefact-enumerator
def sprint_dates(
    delivery_client: delivery.client.DeliveryServiceClient,
    date_name: str='release_decision',
) -> tuple[datetime.date]:
    sprints = delivery_client.sprints()
    sprint_dates = tuple(
        sprint.find_sprint_date(name=date_name).value.date()
        for sprint in sprints
    )

    if not sprint_dates:
        raise ValueError('no sprints found')

    return sprint_dates


# TODO: deduplicate with issues-replicator
def calculate_due_date(
    finding: odg.model.ArtefactMetadata,
    sprints: collections.abc.Iterable[datetime.date],
    finding_cfg: odg.findings.Finding,
) -> datetime.date | None:
    categorisation = finding_cfg.categorisation_by_id(finding.data.severity)

    if not (due_date := categorisation.effective_due_date(
        finding=finding,
        rescoring=None,
    )):
        return None

    for sprint in sorted(sprints):
        if sprint >= due_date:
            return sprint

    logger.warning(
        f'could not determine target sprint for {finding=}, will use use unchanged '
        f'{due_date=}'
    )
    return due_date


def _known_issues(
    issue_repo_url: str,
) -> set[github3.issues.ShortIssue]:
    gh_api = ccc.github.github_api(repo_url=issue_repo_url)
    parsed_repo_url = ci.util.urlparse(issue_repo_url)
    repo_org, repo_name = parsed_repo_url.path.strip('/').split('/')
    repository = gh_api.repository(repo_org, repo_name)
    return set(repository.issues(state='all'))


# TODO: deduplicate with issues-replicator
def filter_issues_for_labels(
    issues: collections.abc.Iterable[github3.issues.issue.ShortIssue],
    labels: collections.abc.Iterable[str],
) -> tuple[github3.issues.ShortIssue]:
    labels = set(labels)

    def filter_issue(issue: github3.issues.issue.ShortIssue):
        issue_labels = set(label.name for label in issue.original_labels)

        return issue_labels & labels == labels

    return tuple(
        issue for issue in issues
        if filter_issue(issue)
    )


def find_issue(
    issues: collections.abc.Iterable[github3.issues.issue.ShortIssue],
    finding: odg.model.ArtefactMetadata,
    sprints: collections.abc.Iterable[datetime.date],
    finding_cfg: odg.findings.Finding,
) -> github3.issues.issue.ShortIssue | None:
    due_date = calculate_due_date(
        finding=finding,
        sprints=sprints,
        finding_cfg=finding_cfg,
    )

    issue_id = finding_cfg.issues.issue_id(
        artefact=finding.artefact,
        due_date=due_date,
    )

    for issue in filter_issues_for_labels(
        issues=issues,
        labels=(issue_id, finding_cfg.type),
    ):
        return issue

    return None


def find_finding_for_resource_node(
    resource_node: cnudie.iter.ResourceNode,
    artefact_metadata: collections.abc.Iterable[odg.model.ArtefactMetadata],
) -> odg.model.ArtefactMetadata | None:
    for am in artefact_metadata:
        # TODO: move these filter options to metadata/query route
        if (
            resource_node.artefact.name == am.artefact.artefact.artefact_name
            and resource_node.artefact.version == am.artefact.artefact.artefact_version
            and resource_node.component.name == am.artefact.component_name
            and resource_node.component.version == am.artefact.component_version
            and am.meta.datasource == odg.model.Datasource.CLAMAV
        ):
            return am

    return None


def resource_node_was_scanned(
    resource_node: cnudie.iter.ResourceNode,
    artefact_scan_infos: collections.abc.Iterable[odg.model.ArtefactMetadata],
) -> bool:
    for artefact_scan_info in artefact_scan_infos:
        artefact = artefact_scan_info.artefact
        # TODO: move these filter options to metadata/query route
        if (
            resource_node.artefact.name == artefact.artefact.artefact_name
            and resource_node.artefact.version == artefact.artefact.artefact_version
            and resource_node.component.name == artefact.component_name
            and resource_node.component.version == artefact.component_version
            and artefact_scan_info.meta.datasource == odg.model.Datasource.CLAMAV
        ):
            return True

    return False


def oci_resource_nodes(
    component_name: str,
    component_version: str,
    component_descriptor_lookup,
) -> collections.abc.Generator[cnudie.iter.ResourceNode, None, None]:
    component_descriptor = component_descriptor_lookup(ocm.ComponentIdentity(
        name=component_name,
        version=component_version,
    ))
    component = component_descriptor.component

    for rnode in cnudie.iter.iter_resources(
        component=component,
        lookup=component_descriptor_lookup,
    ):
        rnode: cnudie.iter.ResourceNode

        if rnode.resource.type != ocm.ArtefactType.OCI_IMAGE:
            continue

        yield rnode


def create_backlog_items(
    resource_nodes: collections.abc.Iterable[cnudie.iter.ResourceNode],
    delivery_client: delivery.client.DeliveryServiceClient,
):
    artefact_ids = [
        odg.model.component_artefact_id_from_ocm(
            component=node.component,
            artefact=node.artefact,
        )
        for node in resource_nodes
    ]

    delivery_client.create_backlog_item(
        service=odg.extensions_cfg.Services.CLAMAV,
        artefacts=artefact_ids,
    )


def parse_args():
    parser = argparse.ArgumentParser(
        prog='evidence',
        description='Work with evidence for different controls'
    )

    parser.add_argument(
        '--component-name',
        required=True,
    )
    parser.add_argument(
        '--component-version',
        required=False,
        action='append',
        dest='component_versions',
        help='if provided, do not lookup component-versions; instead use those provided via arg',
    )
    parser.add_argument(
        '--start-date',
        default=str(datetime.date.today()-datetime.timedelta(weeks=24)),
        help='Since when the data is relevant',
    )
    parser.add_argument(
        '--end-date',
        default=str(datetime.date.today()),
        help='Until when the data is relevant',
    )
    parser.add_argument(
        '--github-pages-out-path',
        default=None,
        help='if set, render report to (github pages) mako template',
    )
    parser.add_argument(
        '--issue-repo-url',
        default='REDACTED',
    )
    parser.add_argument(
        '--ocm-repo-url',
        default=['REDACTED'],
        action='append',
        dest='ocm_repo_urls',
        help='OCM Repository Context',
    )
    parser.add_argument(
        '--github-token',
        default=None,
        help='github-token for authenticating against SAF-API, if absent do not report towards SAF',
    )
    parser.add_argument(
        '--commit-markdown',
        default=False,
        action='store_true',
        help='Create commit in markdown folder (to publish github-pages)',
    )

    parser.add_argument(
        '--trigger-absent-scans',
        default=False,
        action='store_true',
        help='Create OCM-Gear backlog items for missing Malware scans',
    )

    parser.add_argument(
        '--cfg-set-name',
        default='odg-cluster-prod',
        help='The name of the cfg set to retrieve the findings-cfg from',
    )

    return parser.parse_args()


def _resource_node_identity(
    resource_node: cnudie.iter.ResourceNode,
) -> int:
    return hash((
        resource_node.component.name,
        resource_node.component.version,
        resource_node.resource.name,
        resource_node.resource.version,
    ))


def deduplicate_resource_nodes(
    resource_nodes: collections.abc.Iterable[cnudie.iter.ResourceNode],
    id_callback=_resource_node_identity,
) -> collections.abc.Generator[cnudie.iter.ResourceNode, None, None]:
    seen = set()

    for resource_node in resource_nodes:
        if (resource_node_id := id_callback(resource_node)) in seen:
            continue

        seen.add(resource_node_id)
        yield resource_node


def write_github_pages(
    start_date: datetime.date,
    end_date: datetime.date,
    outpath: str,
    component_name: str,
    component_versions: collections.abc.Iterable[str],
    resource_nodes: collections.abc.Iterable[cnudie.iter.ResourceNode],
    scanned: collections.abc.Iterable[cnudie.iter.ResourceNode],
    not_scanned: collections.abc.Iterable[cnudie.iter.ResourceNode],
    with_findings: collections.abc.Iterable[cnudie.iter.ResourceNode],
    issue_url_for_resource_node: dict[str, str],
):
    template = mako.template.Template(
        filename=f'{os.path.dirname(__file__)}/overview-report.mako',
        output_encoding='utf-8',
    )

    with open(outpath, 'wb') as f:
        f.write(template.render(
            component_name=component_name,
            component_versions=component_versions,
            start_date=start_date.isoformat(),
            end_date=end_date.isoformat(),
            resource_nodes=resource_nodes,
            scanned=scanned,
            not_scanned=not_scanned,
            with_findings=with_findings,
            issue_url_for_resource_node=issue_url_for_resource_node,
        ))


def filter_by_root_component(
    component_id: ocm.ComponentIdentity,
    resource_nodes: collections.abc.Iterable[cnudie.iter.ResourceNode],
) -> collections.abc.Generator[cnudie.iter.ResourceNode, None, None]:
    return (
        resource_node
        for resource_node in resource_nodes
        if resource_node.path[0].component.identity() == component_id
    )


def report_to_saf_api(
    component_name: str,
    component_versions: collections.abc.Iterable[str],
    resource_nodes: collections.abc.Iterable[cnudie.iter.ResourceNode],
    scanned_resource_nodes: collections.abc.Iterable[cnudie.iter.ResourceNode],
    github_token: str,
):
    evidences = []

    for component_version in component_versions:
        component_id = ocm.ComponentIdentity(
            name=component_name,
            version=component_version,
        )

        resource_nodes_count = len(tuple(filter_by_root_component(
            component_id=component_id,
            resource_nodes=resource_nodes,
        )))

        scanned_resource_nodes_count = len(tuple(filter_by_root_component(
            component_id=component_id,
            resource_nodes=scanned_resource_nodes,
        )))

        evidence_entry = saf.SafEvidenceEntry(
            ocm_component_name=component_name,
            ocm_component_version=component_version,
            creation_date=datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            artefacts_total_count=resource_nodes_count,
            artefacts_scanned_count=scanned_resource_nodes_count,
        )
        evidences.append(evidence_entry)

    pprint.pprint(evidences)

    access_token = saf.retrieve_auth_token(
        github_token=github_token,
    )

    logger.info('uploading evidences to SAF-API')
    saf.upload_evidences(
        evidences=evidences,
        access_token=access_token,
    )


def main():
    parsed = parse_args()
    outpath = os.path.join(parsed.github_pages_out_path)

    delivery_service_client = ccc.delivery.default_client_if_available()
    if not delivery_service_client:
        raise ValueError('`delivery_service_client` must not be empty')

    if parsed.component_versions:
        component_versions = parsed.component_versions
    else:
        component_versions = set()

        retries = 0
        max_retries = 3
        while retries < max_retries:
            try:
                versions_response = delivery_service_client.greatest_component_versions(
                    component_name=parsed.component_name,
                    start_date=datetime.date.fromisoformat(parsed.start_date),
                    end_date=datetime.date.fromisoformat(parsed.end_date),
                    timeout=(4.0, 301.0),
                )
                break
            except requests.exceptions.ReadTimeout:
                retries += 1
                if retries < max_retries:
                    delay = 2 ** retries
                    logger.warning(
                        f'Retrying greatest_component_versions after {delay} seconds '
                        f'(attempt {retries}/{max_retries - 1})...'
                    )
                    time.sleep(delay)
        else:
            raise RuntimeError('unable to retrieve greatest component versions due to timeout')

        component_versions.update(versions_response)

    logger.info(f'{parsed.start_date=}')
    logger.info(f'{parsed.end_date=}')
    logger.info(f'{component_versions=}')

    component_descriptor_lookup = cnudie.retrieve.create_default_component_descriptor_lookup(
        ocm_repository_lookup=cnudie.retrieve.ocm_repository_lookup(*parsed.ocm_repo_urls),
        oci_client=ccc.oci.oci_client(),
    )

    logger.info(f'{parsed.component_name=}')

    scanned: list[cnudie.iter.ResourceNode] = []
    not_scanned: list[cnudie.iter.ResourceNode] = []

    component_versions = sorted(component_versions, key=semver.VersionInfo.parse)

    count = 0
    for component_version in component_versions:
        count += 1
        logger.info(f'[{count}/{len(component_versions)}] - processing {component_version=}')

        resource_nodes = tuple(oci_resource_nodes(
            component_name=parsed.component_name,
            component_version=component_version,
            component_descriptor_lookup=component_descriptor_lookup,
        ))

        components = {
            str(resource_node.component.identity()): resource_node.component
            for resource_node in resource_nodes
        }.values()

        retries = 0
        max_retries = 3
        while retries < max_retries:
            try:
                artefact_scan_infos = tuple(
                    odg.model.ArtefactMetadata.from_dict(raw)
                    for raw in delivery_service_client.query_metadata(
                        components=components,
                        type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
                    )
                )
                break
            except:
                traceback.print_exc()
                retries += 1
                if retries < max_retries:
                    delay = 2 ** retries
                    logger.warning(
                        f'Retrying query metadata after {delay} seconds '
                        f'(attempt {retries}/{max_retries - 1})...'
                    )
                    time.sleep(delay)
        else:
            raise RuntimeError('unable to query metadata from delivery-service')

        for resource_node in resource_nodes:
            if resource_node_was_scanned(
                resource_node=resource_node,
                artefact_scan_infos=artefact_scan_infos,
            ):
                scanned.append(resource_node)
                continue

            not_scanned.append(resource_node)

    total_resource_nodes = scanned + not_scanned
    logger.info(f'{len(total_resource_nodes)=}')

    total_resource_nodes_deduplicated = tuple(deduplicate_resource_nodes(total_resource_nodes))
    logger.info(f'{len(total_resource_nodes_deduplicated)=}')

    scanned_deduplicated = tuple(deduplicate_resource_nodes(scanned))
    not_scanned_deduplicated = tuple(deduplicate_resource_nodes(not_scanned))
    logger.info(f'{len(scanned)=}')
    logger.info(f'{len(scanned_deduplicated)=}')
    logger.info(f'{len(not_scanned)=}')
    logger.info(f'{len(not_scanned_deduplicated)=}')

    with_findings: list[cnudie.iter.ResourceNode] = []
    without_findings: list[cnudie.iter.ResourceNode] = []

    components = list({
        str(resource_node.component.identity()): resource_node.component
        for resource_node in scanned_deduplicated
    }.values())

    artefact_metadata = tuple()
    chunk_size = 30

    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    for chunk in chunks(components, chunk_size):
        retries = 0
        max_retries = 3
        while retries < max_retries:
            try:
                artefact_metadata += tuple(
                    odg.model.ArtefactMetadata.from_dict(raw)
                    for raw in delivery_service_client.query_metadata(
                        components=chunk,
                        type=odg.model.Datatype.MALWARE_FINDING,
                    )
                )
            except:
                traceback.print_exc()
                retries += 1
                if retries < max_retries:
                    delay = 2 ** retries
                    logger.warning(
                        f'Retrying query metadata after {delay} seconds '
                        f'(attempt {retries}/{max_retries - 1})...'
                    )
                    time.sleep(delay)

            break

        else:
            raise RuntimeError('unable to query metadata from delivery-service')

    for resource_node in scanned_deduplicated:
        if find_finding_for_resource_node(
            resource_node=resource_node,
            artefact_metadata=artefact_metadata,
        ):
            with_findings.append(resource_node)
            continue

        without_findings.append(resource_node)

    logger.info(f'{len(with_findings)=}')
    logger.info(f'{len(without_findings)=}')

    if parsed.github_pages_out_path:
        known_issues = _known_issues(parsed.issue_repo_url)
        logger.info(f'{len(known_issues)=}')

        sprints = sprint_dates(delivery_client=delivery_service_client)
        logger.info(f'{len(sprints)=}')

        cfg_factory = ci.util.ctx().cfg_factory()
        cfg_set = cfg_factory.cfg_set(parsed.cfg_set_name)

        findings_raw = cfg_set.findings_cfg().raw['findings']
        finding_cfg = odg.findings.Finding.from_dict(
            findings_raw=findings_raw,
            finding_type=odg.model.Datatype.MALWARE_FINDING,
        )

        issue_url_for_resource_node = {}
        for resource_node in with_findings:
            finding = find_finding_for_resource_node(
                resource_node=resource_node,
                artefact_metadata=artefact_metadata,
            )
            issue = find_issue(
                issues=known_issues,
                finding=finding,
                sprints=sprints,
                finding_cfg=finding_cfg,
            )
            resource_id = resource_node.resource.identity(peers=resource_node.component.resources)

            if not issue:
                continue

            issue_url_for_resource_node[resource_id] = issue.html_url

        logger.info('rendering report to mako template (github pages) ...')

        write_github_pages(
            start_date=datetime.date.fromisoformat(parsed.start_date),
            end_date=datetime.date.fromisoformat(parsed.end_date),
            outpath=os.path.join(outpath, 'mm06-report.md'),
            component_name=parsed.component_name,
            component_versions=component_versions,
            resource_nodes=total_resource_nodes_deduplicated,
            scanned=scanned_deduplicated,
            not_scanned=not_scanned_deduplicated,
            with_findings=with_findings,
            issue_url_for_resource_node=issue_url_for_resource_node,
        )

    if parsed.trigger_absent_scans and not_scanned:
        create_backlog_items(
            resource_nodes=not_scanned,
            delivery_client=delivery_service_client,
        )

    def filter_resource_nodes_by_component_version(
        resource_nodes: collections.abc.Iterable[cnudie.iter.ResourceNode],
        component_version: str,
    ) -> collections.abc.Generator[cnudie.iter.ResourceNode, None, None]:
        for resource_node in resource_nodes:
            if resource_node.path[0].component.version == component_version:
                yield resource_node

    def resource_node_landscape_id_callback(rn):
        return hash((
            rn.path[0].component.name,
            rn.path[0].component.version,
            rn.component.name,
            rn.component.version,
            rn.resource.name,
            rn.resource.version,
        ))

    report_dir = os.path.join(outpath, 'mm06_reports')
    os.makedirs(report_dir, exist_ok=True)

    total_resource_nodes_deduplicated_per_landscape = tuple(deduplicate_resource_nodes(
        resource_nodes=total_resource_nodes,
        id_callback=resource_node_landscape_id_callback,
    ))
    scanned_deduplicated_per_landscape = tuple(deduplicate_resource_nodes(
        resource_nodes=scanned,
        id_callback=resource_node_landscape_id_callback,
    ))
    not_scanned_deduplicated_per_landscape = tuple(deduplicate_resource_nodes(
        resource_nodes=not_scanned,
        id_callback=resource_node_landscape_id_callback,
    ))

    with_findings_deduplicated_per_landscape = []
    for resource_node in scanned_deduplicated_per_landscape:
        if find_finding_for_resource_node(
            resource_node=resource_node,
            artefact_metadata=artefact_metadata,
        ):
            with_findings_deduplicated_per_landscape.append(resource_node)

    for component_version in component_versions:
        template = mako.template.Template(
            filename=f'{os.path.dirname(__file__)}/version-report.mako',
            output_encoding='utf-8',
        )

        with open(os.path.join(report_dir, f'{component_version}.md'), 'wb') as f:
            f.write(template.render(
                component_name=parsed.component_name,
                component_version=component_version,
                resource_nodes=list(filter_resource_nodes_by_component_version(
                    resource_nodes=total_resource_nodes_deduplicated_per_landscape,
                    component_version=component_version,
                )),
                scanned=list(filter_resource_nodes_by_component_version(
                    resource_nodes=scanned_deduplicated_per_landscape,
                    component_version=component_version,
                )),
                not_scanned=list(filter_resource_nodes_by_component_version(
                    resource_nodes=not_scanned_deduplicated_per_landscape,
                    component_version=component_version,
                )),
                with_findings=list(filter_resource_nodes_by_component_version(
                    resource_nodes=with_findings_deduplicated_per_landscape,
                    component_version=component_version,
                )),
                issue_url_for_resource_node=issue_url_for_resource_node,
            ))

    if parsed.commit_markdown:
        r = git.repo.Repo(outpath)
        r.git.add('--all')
        r.index.commit('Update mm06 information')

    if parsed.github_token:
        try:
            report_to_saf_api(
                resource_nodes=total_resource_nodes,
                scanned_resource_nodes=scanned,
                component_name=parsed.component_name,
                component_versions=list(component_versions)[-10:],
                github_token=parsed.github_token,
            )
        except Exception:
            traceback.print_exc()
            logger.error(
                'encountered error during upload of evidences to SAF-api, ignoring for now...'
            )


if __name__ == '__main__':
    main()
