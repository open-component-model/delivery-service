#!/usr/bin/env python3

import atexit
import collections.abc
import dataclasses
import datetime
import functools
import logging
import os
import tempfile
import typing

import cachetools.keys
import github3.issues
import mako.template
import semver

import ci.log
import delivery.client
import github.pullrequest
import gitutil
import ocm
import ocm.iter

import caching
import github_util
import k8s.logging
import lookups
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths
import rescore.utility
import util


ci.log.configure_default_logging()
logger = logging.getLogger(__name__)

own_dir = os.path.abspath(os.path.dirname(__file__))
templates_dir = os.path.join(own_dir, 'templates')
overview_report_path = os.path.join(templates_dir, 'overview-report.mako')
version_report_path = os.path.join(templates_dir, 'version-report.mako')


@dataclasses.dataclass
class EnrichedComponentArtefactId(odg.model.ComponentArtefactId):
    '''
    The purpose of this wrapper class is to be able to work on the granularity of
    `ComponentArtefactIds` (which is required for various use cases within the ODG context, e.g.
    filtering of findings), while still holding the information of the image reference (which is
    required for the rendered report).

    Note: This requires equality checks between instances of this wrapper class and the base class
    to compare the `key` property explicitly (instead of the `__eq__` function) because the type is
    different.
    '''
    image_reference: str | None = None

    @property
    def artefact_str(self) -> str:
        '''
        Representation of the "artefact-version" with a (markdown) reference to the image if
        available. Intended to be used within the generated report.
        '''
        artefact_id = f'`{self.artefact.artefact_name}:{self.artefact.artefact_version}`'

        if not self.image_reference:
            return artefact_id

        image_reference = self.image_reference.removeprefix('https://')

        return f'[{artefact_id}](https://{image_reference})'

    def __hash__(self) -> int:
        return super().__hash__()

    def __eq__(self, other: typing.Self) -> bool:
        if not type(self) == type(other):
            return False
        return self.key == other.key

    def __str__(self) -> str:
        return super().__str__()


@functools.cache
def sprint_dates(
    delivery_service_client: delivery.client.DeliveryServiceClient,
    date_name: str='release_decision',
) -> tuple[datetime.date]:
    sprints = delivery_service_client.sprints()
    return tuple(
        sprint.find_sprint_date(name=date_name).value.date()
        for sprint in sprints
    )


def iter_matching_component_artefact_ids(
    component: ocm.Component,
    finding_cfg: odg.findings.Finding,
    component_descriptor_lookup: ocm.ComponentDescriptorLookup,
) -> collections.abc.Iterable[EnrichedComponentArtefactId]:
    for artefact_node in ocm.iter.iter(
        component=component,
        lookup=component_descriptor_lookup,
        node_filter=ocm.iter.Filter.artefacts,
    ):
        component_artefact_id = odg.model.component_artefact_id_from_ocm(
            component=artefact_node.component,
            artefact=artefact_node.artefact,
        )
        component_artefact_id = EnrichedComponentArtefactId(
            component_name=component_artefact_id.component_name,
            component_version=component_artefact_id.component_version,
            artefact=component_artefact_id.artefact,
            artefact_kind=component_artefact_id.artefact_kind,
            references=component_artefact_id.references,
        )

        if not finding_cfg.matches(component_artefact_id):
            continue

        # XXX be backwards compatible (for now) and only allow OCI image resources
        if (
            component_artefact_id.artefact_kind is not odg.model.ArtefactKind.RESOURCE
            or component_artefact_id.artefact.artefact_type != ocm.ArtefactType.OCI_IMAGE
        ):
            continue

        if component_artefact_id.artefact.artefact_type == ocm.ArtefactType.OCI_IMAGE:
            component_artefact_id.image_reference = artefact_node.artefact.access.imageReference

        yield component_artefact_id


def component_artefact_id_was_scanned(
    component_artefact_id: odg.model.ComponentArtefactId,
    artefact_scan_infos: collections.abc.Iterable[odg.model.ArtefactMetadata],
    finding_cfg: odg.findings.Finding,
) -> bool:
    return any(
        (
            artefact_scan_info.artefact.key == component_artefact_id.key
            and artefact_scan_info.meta.datasource == finding_cfg.type.datasource()
        ) for artefact_scan_info in artefact_scan_infos
    )


def iter_findings_for_component_artefact_id(
    component_artefact_id: odg.model.ComponentArtefactId,
    findings: collections.abc.Iterable[odg.model.ArtefactMetadata],
) -> collections.abc.Iterable[odg.model.ArtefactMetadata]:
    '''
    Yields findings matching the given `component_artefact_id`. The `component_version` is ignored
    because the findings may not contain any component version for deduplication purposes (e.g. BDBA
    findings). Instead, the `artefact_version` is used for matching.
    '''
    general_component_artefact_id = dataclasses.replace(
        component_artefact_id,
        component_version=None,
    )

    for finding in findings:
        if (
            finding.artefact.component_version
            and finding.artefact.key == component_artefact_id.key
        ):
            yield finding

        elif finding.artefact.key == general_component_artefact_id.key:
            yield finding


def known_github_issues(
    component_name: str,
    issue_replicator_config: odg.extensions_cfg.IssueReplicatorConfig | None,
) -> set[github3.issues.ShortIssue] | None:
    if (
        not issue_replicator_config
        or not (mapping := issue_replicator_config.mapping(component_name))
    ):
        return None

    repository = odg.extensions_cfg.github_repository(mapping.github_repository)

    return github_util.all_issues(repository)


def _cache_key_calculate_due_date(
    finding: odg.model.ArtefactMetadata,
    sprints: collections.abc.Iterable[datetime.date],
    finding_cfg: odg.findings.Finding,
):
    # ignore the sprints for caching purposes -> they don't change during the run anyways
    return cachetools.keys.hashkey(
        finding,
        finding_cfg.type,
    )


@caching.cached(
    cache=caching.FilesystemCache(),
    key_func=_cache_key_calculate_due_date,
)
def calculate_due_date(
    finding: odg.model.ArtefactMetadata,
    sprints: collections.abc.Iterable[datetime.date],
    finding_cfg: odg.findings.Finding,
) -> datetime.date | None:
    categorisation = finding_cfg.categorisation_by_id(finding.data.severity)

    if not (due_date := categorisation.effective_due_date(finding)):
        return None

    for sprint in sorted(sprints):
        if sprint >= due_date:
            return sprint

    logger.warning(f'could not determine target sprint for {due_date=})')
    return None


def iter_matching_github_issue_urls(
    component_artefact_id: odg.model.ComponentArtefactId,
    findings: collections.abc.Iterable[odg.model.ArtefactMetadata],
    issues: collections.abc.Iterable[github3.issues.ShortIssue],
    sprints: collections.abc.Iterable[datetime.date],
    finding_cfg: odg.findings.Finding,
) -> collections.abc.Iterable[str]:
    issue_ids = set()

    for finding in findings:
        if not (due_date := calculate_due_date(
            finding=finding,
            sprints=sprints,
            finding_cfg=finding_cfg,
        )):
            continue

        issue_id = finding_cfg.issues.issue_id(
            artefact=component_artefact_id,
            due_date=due_date,
        )

        issue_ids.add(issue_id)

    for issue in github_util.filter_issues_for_labels(
        issues=issues,
        labels=(finding_cfg.type,),
    ):
        issue_labels = {
            label.name
            for label in issue.original_labels
        }

        for issue_id in issue_ids:
            if issue_id in issue_labels:
                yield issue.html_url


def write_github_pages(
    outpath: str,
    reports_dirname: str,
    component_name: str,
    component_versions: collections.abc.Iterable[str],
    start_date: datetime.date,
    end_date: datetime.date,
    finding_cfg: odg.findings.Finding,
    total: collections.abc.Iterable[EnrichedComponentArtefactId],
    scanned: collections.abc.Iterable[EnrichedComponentArtefactId],
    not_scanned: collections.abc.Iterable[EnrichedComponentArtefactId],
    with_findings: collections.abc.Iterable[EnrichedComponentArtefactId],
    issue_urls_by_component_artefact_id: dict[EnrichedComponentArtefactId, set[str]],
    dashboard_url_by_component_artefact_id: dict[EnrichedComponentArtefactId, str],
):
    template = mako.template.Template(
        filename=overview_report_path,
        output_encoding='utf-8',
    )

    with open(outpath, 'wb') as f:
        f.write(template.render(
            component_name=component_name,
            component_versions=component_versions,
            start_date=start_date,
            end_date=end_date,
            finding_name=finding_cfg.type.display_name(),
            total=total,
            scanned=scanned,
            not_scanned=not_scanned,
            with_findings=with_findings,
            issue_urls_by_component_artefact_id=issue_urls_by_component_artefact_id,
            dashboard_url_by_component_artefact_id=dashboard_url_by_component_artefact_id,
            reports_dirname=reports_dirname,
        ))


def generate_report_for_component_and_finding_type(
    component: odg.extensions_cfg.Component,
    report_filename: str,
    reports_dirname: str,
    trigger_absent_scans: bool,
    finding_cfg: odg.findings.Finding,
    issue_replicator_config: odg.extensions_cfg.IssueReplicatorConfig | None,
    component_descriptor_lookup: ocm.ComponentDescriptorLookup,
    delivery_service_client: delivery.client.DeliveryServiceClient,
):
    start_date = component.time_range.start_date if component.time_range else None
    end_date = component.time_range.end_date if component.time_range else None

    logger.info(
        f'Processing {component.component_name} ({component.version=}, '
        f'{component.max_versions_limit=}, {start_date=}, {end_date=})'
    )

    versions = delivery_service_client.greatest_component_versions(
        component_name=component.component_name,
        ocm_repo=component.ocm_repo,
        greatest_version=component.version,
        max_versions=component.max_versions_limit,
        start_date=start_date,
        end_date=end_date,
    )
    versions = sorted(versions, key=semver.VersionInfo.parse)

    logger.info(f'Retrieved {versions=}')

    total_scanned: set[EnrichedComponentArtefactId] = set()
    total_not_scanned: set[EnrichedComponentArtefactId] = set()
    component_artefact_ids_by_version: dict[str, set[EnrichedComponentArtefactId]] = {}
    count = 0

    for version in versions:
        count += 1
        logger.info(f'[{count}/{len(versions)}] - processing {version=}')

        component_id = ocm.ComponentIdentity(
            name=component.component_name,
            version=version,
        )

        if ocm_repo := component.ocm_repo:
            component_descriptor = component_descriptor_lookup(
                component_id,
                ocm_repository_lookup=lookups.init_ocm_repository_lookup(ocm_repo),
            )
        else:
            component_descriptor = component_descriptor_lookup(component_id)

        component_artefact_ids = set(iter_matching_component_artefact_ids(
            component=component_descriptor.component,
            finding_cfg=finding_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
        ))

        component_artefact_ids_by_version[version] = component_artefact_ids

        component_ids = {
            ocm.ComponentIdentity(
                name=component_artefact_id.component_name,
                version=component_artefact_id.component_version,
            ) for component_artefact_id in component_artefact_ids
        }

        artefact_scan_infos = tuple(
            odg.model.ArtefactMetadata.from_dict(artefact_scan_info_raw)
            for artefact_scan_info_raw in delivery_service_client.query_metadata(
                components=component_ids,
                type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
            )
        )

        for component_artefact_id in component_artefact_ids:
            if component_artefact_id_was_scanned(
                component_artefact_id=component_artefact_id,
                artefact_scan_infos=artefact_scan_infos,
                finding_cfg=finding_cfg,
            ):
                total_scanned.add(component_artefact_id)
            else:
                total_not_scanned.add(component_artefact_id)

    total = total_scanned.union(total_not_scanned)

    logger.info(f'{len(total)=}')
    logger.info(f'{len(total_scanned)=}')
    logger.info(f'{len(total_not_scanned)=}')

    component_ids = {
        ocm.ComponentIdentity(
            name=component_artefact_id.component_name,
            version=component_artefact_id.component_version,
        ) for component_artefact_id in total_scanned
    }

    findings = tuple()
    chunk_size = 30

    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    for chunked_component_ids in chunks(list(component_ids), chunk_size):
        findings += tuple(
            odg.model.ArtefactMetadata.from_dict(finding_raw)
            for finding_raw in delivery_service_client.query_metadata(
                components=chunked_component_ids,
                type=finding_cfg.type,
            )
        )

    known_issues = known_github_issues(
        component_name=component.component_name,
        issue_replicator_config=issue_replicator_config,
    ) or []
    logger.info(f'{len(known_issues)=}')

    sprints = sprint_dates(
        delivery_service_client=delivery_service_client,
    )
    logger.info(f'{len(sprints)=}')

    total_with_findings: list[EnrichedComponentArtefactId] = []
    total_without_findings: list[EnrichedComponentArtefactId] = []
    issue_urls_by_component_artefact_id: dict[EnrichedComponentArtefactId, set[str]] = {}
    dashboard_url_by_component_artefact_id: dict[EnrichedComponentArtefactId, str] = {}

    for component_artefact_id in total_scanned:
        if not (filtered_findings := tuple(iter_findings_for_component_artefact_id(
            component_artefact_id=component_artefact_id,
            findings=findings,
        ))):
            total_without_findings.append(component_artefact_id)
            continue

        total_with_findings.append(component_artefact_id)

        filtered_issue_urls = tuple(iter_matching_github_issue_urls(
            component_artefact_id=component_artefact_id,
            findings=filtered_findings,
            issues=known_issues,
            sprints=sprints,
            finding_cfg=finding_cfg,
        ))

        issue_urls_by_component_artefact_id[component_artefact_id] = set(filtered_issue_urls)

        delivery_dashboard_url = rescore.utility.delivery_dashboard_rescoring_url(
            base_url=issue_replicator_config.delivery_dashboard_url,
            component_artefact_id=component_artefact_id,
            finding_type=finding_cfg.type,
        )

        dashboard_url_by_component_artefact_id[component_artefact_id] = delivery_dashboard_url

    logger.info(f'{len(total_with_findings)=}')
    logger.info(f'{len(total_without_findings)=}')

    logger.info('rendering report to mako template (github pages) ...')

    write_github_pages(
        outpath=report_filename,
        reports_dirname=reports_dirname,
        component_name=component.component_name,
        component_versions=versions,
        start_date=start_date,
        end_date=end_date,
        finding_cfg=finding_cfg,
        total=total,
        scanned=total_scanned,
        not_scanned=total_not_scanned,
        with_findings=total_with_findings,
        issue_urls_by_component_artefact_id=issue_urls_by_component_artefact_id,
        dashboard_url_by_component_artefact_id=dashboard_url_by_component_artefact_id,
    )

    if trigger_absent_scans and total_not_scanned:
        # XXX we still have to figure out how to check if BLIs are supported for a certain datasource
        # e.g. there are no BLIs for diki findings -> control via configuration for now
        delivery_service_client.create_backlog_item(
            service=finding_cfg.type.datasource(),
            artefacts=total_not_scanned,
        )

    os.makedirs(reports_dirname, exist_ok=True)

    for version in versions:
        component_artefact_ids = component_artefact_ids_by_version[version]

        scanned: list[EnrichedComponentArtefactId] = []
        not_scanned: list[EnrichedComponentArtefactId] = []
        with_findings: list[EnrichedComponentArtefactId] = []

        for component_artefact_id in component_artefact_ids:
            if component_artefact_id in total_scanned:
                scanned.append(component_artefact_id)
            else:
                not_scanned.append(component_artefact_id)

            if component_artefact_id in total_with_findings:
                with_findings.append(component_artefact_id)

        template = mako.template.Template(
            filename=version_report_path,
            output_encoding='utf-8',
        )

        with open(os.path.join(reports_dirname, f'{version}.md'), 'wb') as f:
            f.write(template.render(
                component_name=component.component_name,
                component_version=version,
                finding_name=finding_cfg.type.display_name(),
                total=component_artefact_ids,
                scanned=scanned,
                not_scanned=not_scanned,
                with_findings=with_findings,
                issue_urls_by_component_artefact_id=issue_urls_by_component_artefact_id,
                dashboard_url_by_component_artefact_id=dashboard_url_by_component_artefact_id,
            ))


def generate_report(
    findings_report_config: odg.extensions_cfg.FindingsReportConfig,
    finding_cfgs: list[odg.findings.Finding],
    issue_replicator_config: odg.extensions_cfg.IssueReplicatorConfig | None,
    component_descriptor_lookup: ocm.ComponentDescriptorLookup,
    delivery_service_client: delivery.client.DeliveryServiceClient,
):
    for findings_report_mapping in findings_report_config.mappings:
        logger.info(f'Starting report generation for type "{findings_report_mapping.type}"')

        for finding_cfg in finding_cfgs:
            if finding_cfg.type is findings_report_mapping.type:
                break
        else:
            raise ValueError(f'No finding cfg found for type "{findings_report_mapping.type}"')

        repo_url = findings_report_mapping.github_repository
        parsed_repo_url = util.urlparse(repo_url)

        github_api_lookup = lookups.github_api_lookup()
        github_api = github_api_lookup(repo_url)

        org, repo = parsed_repo_url.path.strip('/').split('/')[:2]

        repository = github_api.repository(org, repo)

        git_cfg = gitutil.GitCfg(
            repo_url=repository.clone_url,
            auth=('x-access-token', github_api.session.auth.token),
            auth_type=gitutil.AuthType.HTTP_TOKEN,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            git_helper = gitutil.GitHelper.clone_into(
                target_directory=tmp_dir,
                git_cfg=git_cfg,
                checkout_branch=findings_report_mapping.branch,
            )

            generate_report_for_component_and_finding_type(
                component=findings_report_mapping.component,
                report_filename=os.path.join(tmp_dir, findings_report_mapping.filename),
                reports_dirname=os.path.join(tmp_dir, findings_report_mapping.dirname),
                trigger_absent_scans=findings_report_mapping.trigger_absent_scans,
                finding_cfg=finding_cfg,
                issue_replicator_config=issue_replicator_config,
                component_descriptor_lookup=component_descriptor_lookup,
                delivery_service_client=delivery_service_client,
            )

            message = f'Update report for type `{findings_report_mapping.type}`'

            # token is only valid for 30min -> generate a new one
            repository = odg.extensions_cfg.github_repository(
                repo=findings_report_mapping.github_repository,
            )

            with github.pullrequest.commit_and_push_to_tmp_branch(
                repository=repository,
                git_helper=git_helper,
                commit_message=message,
                target_branch=findings_report_mapping.branch,
                delete_on_exit=findings_report_mapping.auto_merge,
            ) as tmp_branch_name:
                pull_request: github3.pulls.PullRequest = repository.create_pull(
                    title=message,
                    base=findings_report_mapping.branch,
                    head=tmp_branch_name,
                )

                if findings_report_mapping.auto_merge:
                    logger.info(
                        f'Merging PR#{pull_request.number} -> {findings_report_mapping.branch}'
                    )
                    pull_request.merge()

        logger.info(f'Finished report generation for type "{finding_cfg.type}"')


def main():
    parsed_arguments = odg.util.parse_args()

    namespace = parsed_arguments.k8s_namespace
    delivery_service_url = parsed_arguments.delivery_service_url
    kubernetes_api = odg.util.kubernetes_api(parsed_arguments)

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.FINDINGS_REPORT,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.FINDINGS_REPORT,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    findings_report_config = extensions_cfg.findings_report
    issue_replicator_config = extensions_cfg.issue_replicator

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    finding_cfgs: list[odg.findings.Finding] = odg.findings.Finding.from_file(findings_cfg_path)

    if not delivery_service_url:
        delivery_service_url = findings_report_config.delivery_service_url

    delivery_service_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_service_client,
    )

    generate_report(
        findings_report_config=findings_report_config,
        finding_cfgs=finding_cfgs,
        issue_replicator_config=issue_replicator_config,
        component_descriptor_lookup=component_descriptor_lookup,
        delivery_service_client=delivery_service_client,
    )


if __name__ == '__main__':
    main()
