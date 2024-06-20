import collections
import collections.abc
import dataclasses
import enum
import datetime
import functools
import logging
import re
import requests
import textwrap
import time
import urllib.parse

import github3
import github3.issues.comment
import github3.issues.issue
import github3.issues.milestone

import ci.util
import cnudie.iter
import delivery.client
import delivery.model
import dso.cvss
import dso.labels
import dso.model
import gci.componentmodel as cm
import github.compliance.issue as gci
import github.compliance.milestone as gcmi
import github.compliance.model as gcm
import github.compliance.report as gcr
import github.retry
import github.user
import github.util
import version as version_util

import config


logger = logging.getLogger(__name__)


class IssueComments(enum.StrEnum):
    NO_FINDINGS = 'closing ticket because there are no longer unassessed findings'
    NOT_IN_BOM = 'closing ticket because scanned element is no longer present in BoM'


@dataclasses.dataclass(frozen=True)
class AggregatedFinding:
    finding: dso.model.ArtefactMetadata
    severity: gcm.Severity
    rescorings: tuple[dso.model.ArtefactMetadata]

    def calculate_latest_processing_date(
        self,
        sprints: tuple[datetime.date],
        max_processing_days: gcm.MaxProcessingTimesDays=None,
    ) -> datetime.date | None:
        if not self.severity:
            return None

        if not max_processing_days:
            max_processing_days = gcm.MaxProcessingTimesDays()
        max_days = max_processing_days.for_severity(severity=self.severity)

        date = self.finding.discovery_date + datetime.timedelta(days=max_days)

        for sprint in sorted(sprints):
            if sprint >= date:
                break
        else:
            logger.warning(
                f'could not determine target sprint for {self.finding=} with {self.severity=}, '
                f'will use unchanged latest processing {date=}'
            )
            return date

        return sprint


def is_remaining_quota_too_low(
    gh_api: github3.GitHub,
    relative_gh_quota_minimum: float=0.2,
) -> bool:
    rate_limit = gh_api.rate_limit().get('resources', dict()).get('core', dict()).get('limit', -1)
    rate_limit_remaining = gh_api.ratelimit_remaining
    logger.info(f'{rate_limit_remaining=} {rate_limit=}')
    if rate_limit_remaining < relative_gh_quota_minimum * rate_limit:
        return True
    return False


def wait_for_quota_if_required(
    gh_api: github3.GitHub,
    relative_gh_quota_minimum: float=0.2,
):
    if not is_remaining_quota_too_low(
        gh_api=gh_api,
        relative_gh_quota_minimum=relative_gh_quota_minimum,
    ):
        return

    reset_timestamp = gh_api.rate_limit().get('resources', dict()).get('core', dict()).get('reset')
    if not reset_timestamp:
        return

    reset_datetime = datetime.datetime.fromtimestamp(reset_timestamp)
    time_until_reset = datetime.datetime.now() - reset_datetime
    logger.warning(
        f'github quota too low, will sleep for {time_until_reset} sec until {reset_datetime}'
    )
    time.sleep(time_until_reset.total_seconds())


@functools.cache
@github.retry.retry_and_throttle
def _all_issues(
    repository,
    state: str='all',
    number: int=-1, # -1 means all issues
):
    return set(repository.issues(state=state, number=number))


def _issue_assignees(
    issue_replicator_config: config.IssueReplicatorConfig,
    delivery_client: delivery.client.DeliveryServiceClient,
    artefact: cnudie.iter.Node | cnudie.iter.ArtefactNode,
) -> tuple[set[str], set[delivery.model.Status]]:
    assignees: set[str] = set()
    statuses: set[delivery.model.Status] = set()

    try:
        responsibles, statuses = delivery_client.component_responsibles(
            component=artefact.component,
            artifact=artefact.artefact,
        )
        statuses = set(statuses)

        gh_users = delivery.client.github_users_from_responsibles(
            responsibles=responsibles,
            github_url=issue_replicator_config.github_issues_repository.html_url,
        )

        github_api = issue_replicator_config.github_api_lookup(
            issue_replicator_config.github_issues_repository.html_url,
        )

        assignees = set(
            gh_user.username.lower()
            for gh_user in gh_users
            if github.user.is_user_active(
                username=gh_user.username,
                github=github_api,
            )
        )
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.warning(f'delivery service returned 404 for {artefact.artefact=}')
        else:
            raise

    valid_assignees = set(
        a.lower()
        for a in gcr._valid_issue_assignees(
            repository=issue_replicator_config.github_issues_repository,
        )
    )

    if invalid_assignees := (assignees - valid_assignees):
        logger.warning(
            f'unable to assign {invalid_assignees} to issues in repository '
            f'{issue_replicator_config.github_issues_repository.html_url}. Please make sure '
            'the users have the necessary permissions to see issues in the repository.'
        )
        assignees -= invalid_assignees
        logger.info(
            f'removed invalid assignees {invalid_assignees} from target assignees for '
            f'issue. Remaining assignees: {assignees}'
        )

    return assignees, statuses


def _issue_milestone(
    issue_replicator_config: config.IssueReplicatorConfig,
    delivery_client: delivery.client.DeliveryServiceClient,
    latest_processing_date: datetime.date,
) -> tuple[github3.issues.milestone.Milestone | None, list[github3.issues.milestone.Milestone]]:
    sprints = gcmi.target_sprints(
        delivery_svc_client=delivery_client,
        latest_processing_date=latest_processing_date,
        sprints_count=12,
    )

    return gcmi.find_or_create_sprint_milestone(
        repo=issue_replicator_config.github_issues_repository,
        sprints=sprints,
    )


def _issue_title(
    issue_type: str,
    artefact: cnudie.iter.Node | cnudie.iter.ArtefactNode,
    milestone: github3.issues.milestone.Milestone,
) -> str:
    title = f'[{issue_type}]'

    if milestone:
        title += f' - [{milestone.title}]'

    return title + f' - {artefact.component_id.name}:{artefact.artefact.name}'


def _artefact_to_str(artefact: cnudie.iter.Node | cnudie.iter.ArtefactNode) -> str:
    return (
        f'{artefact.component_id.name}:{artefact.component_id.version}:'
        f'{artefact.artefact.name}:{artefact.artefact.version}'
    )


def _delivery_dashboard_url(
    base_url: str,
    component: cm.Component,
    sprint_name: str=None,
):
    url = ci.util.urljoin(
        base_url,
        '#/component'
    )

    query_params = {
        'name': component.name,
        'version': component.version,
        'view': 'bom',
        'rootExpanded': True,
    }

    if sprint_name:
        query_params['sprints'] = sprint_name

    query = urllib.parse.urlencode(
        query=query_params,
    )

    return f'{url}?{query}'


def _vulnerability_template_vars(
    issue_replicator_config: config.IssueReplicatorConfig,
    artefacts: tuple[cnudie.iter.Node | cnudie.iter.ArtefactNode],
    findings_by_versions: dict[str, tuple[AggregatedFinding]],
    summary: str,
    sprint_name: str=None,
) -> dict[str, str]:
    # find artefact with greatest version to use its label
    greatest_version = version_util.greatest_version(
        versions=set(artefact.component_id.version for artefact in artefacts)
    )
    for artefact in artefacts:
        if artefact.component_id.version == greatest_version:
            break

    cve_rescoring_rules = issue_replicator_config.cve_rescoring_rules
    rescore_label = artefact.artefact.find_label(
        name=dso.labels.CveCategorisationLabel.name,
    )
    if not rescore_label:
        rescore_label = artefact.component.find_label(
            name=dso.labels.CveCategorisationLabel.name,
        )

    if rescore_label:
        rescore_label: dso.labels.CveCategorisationLabel = dso.labels.deserialise_label(
            label=rescore_label,
        )
        cve_categorisation = rescore_label.value
    else:
        cve_categorisation = None

    summary += '# Summary of found vulnerabilities'

    def _group_findings(
        findings: tuple[AggregatedFinding],
    ) -> dict[str, dict[str, list[AggregatedFinding]]]:
        '''
        returns `findings` grouped by the affected package of the finding and the CVE
        '''
        grouped_findings = dict()

        for finding in findings:
            package_name = finding.finding.data.package_name

            if not package_name in grouped_findings:
                grouped_findings[package_name] = collections.defaultdict(list)

            grouped_findings[package_name][finding.finding.data.cve].append(finding)

        return grouped_findings

    def _grouped_findings_to_table_row(
        findings: list[AggregatedFinding],
    ) -> str:
        finding = findings[0].finding
        rescorings = findings[0].rescorings

        def _vulnerability_str():
            _vuln_str = f'`{finding.data.cve}` | `{finding.data.cvss_v3_score}` | '

            if rescorings:
                severity = dso.cvss.CVESeverity[rescorings[0].data.severity]
                _vuln_str += f'`{severity.name}` (rescored) |'
            else:
                severity = dso.cvss.CVESeverity[finding.data.severity]
                _vuln_str += f'`{severity.name}` |'

            if not (cve_rescoring_rules and cve_categorisation and finding.data.cvss):
                return _vuln_str

            orig_sev = dso.cvss.CVESeverity[finding.data.severity]

            rules = tuple(dso.cvss.matching_rescore_rules(
                rescoring_rules=cve_rescoring_rules,
                categorisation=cve_categorisation,
                cvss=finding.data.cvss,
            ))

            rescored = dso.cvss.rescore(
                rescoring_rules=rules,
                severity=orig_sev,
            )

            if severity is rescored:
                return _vuln_str

            return _vuln_str + f' `{rescored.name}`'

        versions = ', <br/>'.join((f'`{f.finding.data.package_version}`' for f in sorted(
            findings,
            key=lambda finding: # try to sort by version
                [x for x in finding.finding.data.package_version.split('.')]
                if finding.finding.data.package_version
                else [f'{finding.finding.data.package_version}'],
        )))

        return f'\n| `{finding.data.package_name}` | {_vulnerability_str()} | {versions} |'

    for version_key, findings in sorted(
        findings_by_versions.items(),
        key=lambda version: version[0],
    ):
        for artefact in artefacts:
            if f'{artefact.component_id.version}:{artefact.artefact.version}' == version_key:
                break
        else:
            raise ValueError(version_key) # this line should never be reached

        summary += f'\n### {_artefact_to_str(artefact=artefact)}\n'

        if issue_replicator_config.delivery_dashboard_url:
            delivery_dashboard_url = _delivery_dashboard_url(
                base_url=issue_replicator_config.delivery_dashboard_url,
                component=artefact.component,
                sprint_name=sprint_name,
            )
            summary += f'[Delivery-Dashboard]({delivery_dashboard_url}) (use for assessments)\n'

        report_urls = {(
            f'[BDBA {finding.finding.data.product_id}]'
            f'({finding.finding.data.report_url})'
        ) for finding in findings}
        report_urls_str = '\n'.join(sorted(report_urls))

        summary += f'{report_urls_str}\n'

        summary += (
            '\n| Affected Package | CVE | CVE Score | Severity | Rescoring Suggestion | Package Version(s) |' # noqa: E501
            '\n| ---------------- | :-: | :-------: | :------: | :------------------: | ------------------ |' # noqa: E501
        ) + ''.join(
            _grouped_findings_to_table_row(findings=grouped_findings_by_cve)
            for _, grouped_findings_by_package in sorted(
                _group_findings(findings=findings).items(),
                key=lambda grouped_finding: grouped_finding[0], # sort by package name
            )
            for grouped_findings_by_cve in sorted(
                grouped_findings_by_package.values(),
                key=lambda grouped_findings: (
                    -grouped_findings[0].finding.data.cvss_v3_score,
                    grouped_findings[0].finding.data.cve,
                ),
            )
        )
        summary += '\n---'

    return {
        'summary': summary,
    }


def _malware_template_vars(
    issue_replicator_config: config.IssueReplicatorConfig,
    artefacts: tuple[cnudie.iter.Node | cnudie.iter.ArtefactNode],
    findings_by_versions: dict[str, tuple[AggregatedFinding]],
    summary: str,
    sprint_name: str=None,
) -> dict[str, str]:

    def iter_findings(
        aggregated_findings: tuple[AggregatedFinding],
    ) -> collections.abc.Generator[tuple[str, str, str], None, None]:
        for af in aggregated_findings:
            finding_details: dso.model.MalwareFindingDetails = af.finding.data.finding
            yield finding_details.malware, finding_details.filename, finding_details.content_digest

    summary += '# Summary of found Malware'

    for version_key, findings in sorted(
        findings_by_versions.items(),
        key=lambda version: version[0],
    ):
        for artefact in artefacts:
            if f'{artefact.component_id.version}:{artefact.artefact.version}' == version_key:
                break
        else:
            raise ValueError(version_key) # this line should never be reached

        summary += f'\n### {_artefact_to_str(artefact=artefact)}\n'

        if issue_replicator_config.delivery_dashboard_url:
            delivery_dashboard_url = _delivery_dashboard_url(
                base_url=issue_replicator_config.delivery_dashboard_url,
                component=artefact.component,
                sprint_name=sprint_name,
            )
            summary += f'[Delivery-Dashboard]({delivery_dashboard_url}) (use for assessments)\n'

        summary += (
            '\n| Malware | Filename | Content Digest |'
            '\n| --- | --- | --- |'
        ) + ''.join(
            f'\n| {malware} | {filename} | {content_digest} |'
            for malware, filename, content_digest in iter_findings(findings)
        )
        summary += '\n---'

    return {
        'summary': summary,
    }


def _license_template_vars(
    issue_replicator_config: config.IssueReplicatorConfig,
    artefacts: tuple[cnudie.iter.Node | cnudie.iter.ArtefactNode],
    findings_by_versions: dict[str, tuple[AggregatedFinding]],
    summary: str,
    sprint_name: str=None,
) -> dict[str, str]:
    summary += '# Summary of found licenses'

    def _group_findings(
        findings: tuple[AggregatedFinding],
    ) -> dict[str, dict[str, list[AggregatedFinding]]]:
        '''
        returns `findings` grouped by the affected package of the finding and the license name
        '''
        grouped_findings = dict()

        for finding in findings:
            package_name = finding.finding.data.package_name

            if not package_name in grouped_findings:
                grouped_findings[package_name] = collections.defaultdict(list)

            grouped_findings[package_name][finding.finding.data.license.name].append(finding)

        return grouped_findings

    def _grouped_findings_to_table_row(
        findings: list[AggregatedFinding],
    ) -> str:
        finding = findings[0].finding
        rescorings = findings[0].rescorings

        def _license_str():
            if rescorings:
                severity = gcm.Severity[rescorings[0].data.severity]
                return f'`{finding.data.license.name}` | `{severity.name}` (rescored)'

            severity = gcm.Severity[finding.data.severity]
            return f'`{finding.data.license.name}` | `{severity.name}`'

        versions = ', <br/>'.join((f'`{f.finding.data.package_version}`' for f in sorted(
            findings,
            key=lambda finding: # try to sort by version
                [x for x in finding.finding.data.package_version.split('.')]
                if finding.finding.data.package_version
                else [f'{finding.finding.data.package_version}'],
        )))

        return f'\n| `{finding.data.package_name}` | {_license_str()} | {versions} |'

    for version_key, findings in sorted(
        findings_by_versions.items(),
        key=lambda version: version[0],
    ):
        for artefact in artefacts:
            if f'{artefact.component_id.version}:{artefact.artefact.version}' == version_key:
                break
        else:
            raise ValueError(version_key) # this line should never be reached

        summary += f'\n### {_artefact_to_str(artefact=artefact)}\n'

        if issue_replicator_config.delivery_dashboard_url:
            delivery_dashboard_url = _delivery_dashboard_url(
                base_url=issue_replicator_config.delivery_dashboard_url,
                component=artefact.component,
                sprint_name=sprint_name,
            )
            summary += f'[Delivery-Dashboard]({delivery_dashboard_url}) (use for assessments)\n'

        report_urls = {(
            f'[BDBA {finding.finding.data.product_id}]'
            f'({finding.finding.data.report_url})'
        ) for finding in findings}
        report_urls_str = '\n'.join(sorted(report_urls))

        summary += f'{report_urls_str}\n'

        summary += (
            '\n| Affected Package | License | Severity | Package Version(s) |'
            '\n| ---------------- | :-----: | :------: | ------------------ |'
        ) + ''.join(
            _grouped_findings_to_table_row(findings=grouped_findings_by_license)
            for _, grouped_findings_by_package in sorted(
                _group_findings(findings=findings).items(),
                key=lambda grouped_finding: grouped_finding[0], # sort by package name
            )
            for grouped_findings_by_license in sorted(
                grouped_findings_by_package.values(),
                key=lambda grouped_findings: grouped_findings[0].finding.data.license.name,
            )
        )
        summary += '\n---'

    return {
        'summary': summary,
    }


def _template_vars(
    issue_replicator_config: config.IssueReplicatorConfig,
    issue_type: str,
    artefacts: tuple[cnudie.iter.Node | cnudie.iter.ArtefactNode],
    findings: tuple[AggregatedFinding],
    latest_processing_date: datetime.date,
    sprint_name: str=None,
) -> dict:
    # retrieve all distinct component- and resource-versions and store information whether their
    # artefact has findings or not (required for explicit depiction afterwards)
    findings_by_versions: dict[str, tuple[dso.model.ArtefactMetadata]] = dict()

    c_versions_have_findings: dict[str, bool] = dict()
    a_versions_have_findings: dict[str, bool] = dict()
    artefact_urls: set[str] = set()

    for artefact in artefacts:
        c_version = artefact.component_id.version
        a_version = artefact.artefact.version

        filtered_findings = tuple(
            finding for finding in findings
            if (
                finding.finding.artefact.component_version == c_version and
                finding.finding.artefact.artefact.artefact_version == a_version
            )
        )

        artefact_urls.add(gcr._artifact_url(artifact=artefact.artefact))
        if filtered_findings:
            findings_by_versions[f'{c_version}:{a_version}'] = filtered_findings

            c_versions_have_findings[c_version] = True
            a_versions_have_findings[a_version] = True
        else:
            c_versions_have_findings[c_version] = c_versions_have_findings.get(c_version, False)
            a_versions_have_findings[a_version] = a_versions_have_findings.get(a_version, False)

    c_versions = tuple(version for version in c_versions_have_findings.keys())
    c_versions_str = ', '.join(sorted(c_versions))

    c_versions_with_findings = tuple(
        version for version, has_findings
        in c_versions_have_findings.items()
        if has_findings
    )
    c_versions_with_findings_str = ', '.join(sorted(c_versions_with_findings))

    a_versions = tuple(version for version in a_versions_have_findings.keys())
    a_versions_str = ', '.join(sorted(a_versions))

    a_versions_with_findings = tuple(
        version for version, has_findings
        in a_versions_have_findings.items()
        if has_findings
    )
    a_versions_with_findings_str = ', '.join(sorted(a_versions_with_findings))

    a_urls_str = '<br/>'.join(sorted(artefact_urls))

    artefact = artefacts[0]

    summary = textwrap.dedent(f'''\
        # Compliance Status Summary

        |    |    |
        | -- | -- |
        | Component | {artefact.component_id.name} |
        | {gcr._pluralise('Component-Version', len(c_versions))} | {c_versions_str} |
        | {gcr._pluralise(
            prefix='Component-Version',
            count=len(c_versions_with_findings),
        )} with Findings | {c_versions_with_findings_str} |
        | Artefact  | {artefact.artefact.name} |
        | {gcr._pluralise('Artefact-Version', len(a_versions))} | {a_versions_str} |
        | {gcr._pluralise(
            prefix='Artefact-Version',
            count=len(a_versions_with_findings),
        )} with Findings | {a_versions_with_findings_str} |
        | Artefact-Type | {artefact.artefact.type} |
        | {gcr._pluralise('URL', len(artefact_urls))} | {a_urls_str} |
        | Latest Processing Date | {latest_processing_date} |
    ''')

    if findings:
        summary += (
            '\nThe aforementioned '
            f'{gcr._pluralise(artefact.artefact.type, len(a_versions_with_findings))} '
            'yielded findings relevant for future release decisions.\n'
        )

    template_variables = {
        'component_name': artefact.component_id.name,
        'component_version': c_versions_with_findings_str,
        'resource_name': artefact.artefact.name,
        'resource_version': a_versions_with_findings_str,
        'resource_type': artefact.artefact.type,
        'artifact_name': artefact.artefact.name,
        'artifact_version': a_versions_with_findings_str,
        'artifact_type': artefact.artefact.type,
    }

    if not findings:
        template_variables |= {
            'summary': summary,
        }
    elif issue_type == gci._label_bdba:
        template_variables |= _vulnerability_template_vars(
            issue_replicator_config=issue_replicator_config,
            artefacts=artefacts,
            findings_by_versions=findings_by_versions,
            summary=summary,
            sprint_name=sprint_name,
        )
    elif issue_type == gci._label_licenses:
        template_variables |= _license_template_vars(
            issue_replicator_config=issue_replicator_config,
            artefacts=artefacts,
            findings_by_versions=findings_by_versions,
            summary=summary,
            sprint_name=sprint_name,
        )
    elif issue_type == gci._label_malware:
        template_variables |= _malware_template_vars(
            issue_replicator_config=issue_replicator_config,
            artefacts=artefacts,
            findings_by_versions=findings_by_versions,
            summary=summary,
            sprint_name=sprint_name,
        )

    return template_variables


@github.retry.retry_and_throttle
def close_issue_if_present(
    issue_replicator_config: config.IssueReplicatorConfig,
    issue: github3.issues.issue.ShortIssue,
    closing_reason: IssueComments,
):
    if not issue or issue.state != 'open':
        return

    logger.info(f'labels for issue for closing: {[l.name for l in issue.original_labels]}')

    issue.create_comment(closing_reason)
    if not github.util.close_issue(issue):
        repository_url = issue_replicator_config.github_issues_repository.html_url
        logger.warning(f'failed to close {issue.id=} with {repository_url=}')


@github.retry.retry_and_throttle
def update_issue(
    issue: github3.issues.issue.ShortIssue,
    issue_type: str,
    body: str,
    title: str=None,
    labels: set[str]=set(),
    assignees: set[str]=set(),
    milestone: github3.issues.milestone.Milestone=None,
):
    assignees = tuple(assignees) # conversion to tuple required for issue update (JSON serialisation)

    labels = sorted(gci._search_labels(
        issue_type=issue_type,
        extra_labels=labels,
    ))

    kwargs = {
        'state': 'open',
        'labels': labels,
    }

    if title:
        kwargs['title'] = title

    if not issue.assignees and assignees:
        kwargs['assignees'] = assignees

    if milestone and not issue.milestone:
        kwargs['milestone'] = milestone.number

    issue.edit(
        body=body,
        **kwargs,
    )


def create_or_update_or_close_issue(
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    finding_type_issue_replication_cfg: config.FindingTypeIssueReplicationCfgBase,
    delivery_client: delivery.client.DeliveryServiceClient,
    issue_type: str,
    artefacts: tuple[cnudie.iter.Node | cnudie.iter.ArtefactNode],
    findings: tuple[AggregatedFinding],
    correlation_id: str,
    latest_processing_date: datetime.date,
    is_in_bom: bool,
    is_scanned: bool,
):
    def labels_to_preserve(
        issue: github3.issues.issue.ShortIssue,
    ) -> collections.abc.Generator[str, None, None]:
        ctx_label_regex = {f'{gci._label_prefix_ctx}.*'} # always keep ctx_labels

        preserve_labels_regexes = (
            issue_replicator_config.github_issue_labels_to_preserve | ctx_label_regex
        )

        for label in issue.original_labels:
            for pattern in preserve_labels_regexes:
                if re.fullmatch(pattern=pattern, string=label.name):
                    yield label.name
                    break

    labels = {
        correlation_id,
        f'{gci._label_prefix_ctx}/{cfg_name}',
    }

    known_issues = _all_issues(
        repository=issue_replicator_config.github_issues_repository,
        state='open',
    ) | _all_issues(
        repository=issue_replicator_config.github_issues_repository,
        state='closed',
        number=issue_replicator_config.number_included_closed_issues,
    )

    issues: tuple[github3.issues.issue.ShortIssue] = tuple(gci.enumerate_issues(
        known_issues=known_issues,
        issue_type=issue_type,
        extra_labels=labels,
    ))

    if (issues_count := len(issues)) > 1:
        # it is possible, that multiple _closed_ issues exist for one correlation id
        # if that's the case, re-use the latest issue (greatest id)
        open_issues = tuple(issue for issue in issues if issue.state == 'open')
        if len(open_issues) > 1:
            raise RuntimeError(f'more than one open issue found for {issue_type=} {correlation_id=}')

        issue = sorted(issues, key=lambda issue: issue.id, reverse=True)[0]
    elif issues_count == 1:
        issue = issues[0]
        labels = labels | set(labels_to_preserve(issue=issue))
    else:
        issue = None

    if not is_in_bom:
        return close_issue_if_present(
            issue_replicator_config=issue_replicator_config,
            issue=issue,
            closing_reason=IssueComments.NOT_IN_BOM,
        )

    if is_scanned and not findings:
        return close_issue_if_present(
            issue_replicator_config=issue_replicator_config,
            issue=issue,
            closing_reason=IssueComments.NO_FINDINGS,
        )

    if not is_scanned and (not issue or issue.state != 'open'):
        # not scanned yet but no open issue found either -> nothing to do
        return

    if finding_type_issue_replication_cfg.enable_issue_assignees:
        assignees, assignees_statuses = _issue_assignees(
            issue_replicator_config=issue_replicator_config,
            delivery_client=delivery_client,
            artefact=artefacts[0],
        )
    else:
        assignees = set()
        assignees_statuses = set()

    milestone, failed_milestones = _issue_milestone(
        issue_replicator_config=issue_replicator_config,
        delivery_client=delivery_client,
        latest_processing_date=latest_processing_date,
    )

    title = _issue_title(
        issue_type=issue_type,
        artefact=artefacts[0],
        milestone=milestone,
    )

    if milestone:
        sprint_name = milestone.title.lstrip('sprint-')
    else:
        sprint_name = None

    template_variables = _template_vars(
        issue_replicator_config=issue_replicator_config,
        issue_type=issue_type,
        artefacts=artefacts,
        findings=findings,
        latest_processing_date=latest_processing_date,
        sprint_name=sprint_name,
    )

    for issue_template_cfg in issue_replicator_config.github_issue_template_cfgs:
        if issue_template_cfg.type == issue_type:
            break
    else:
        raise ValueError(f'no template for {issue_type=}')

    body = issue_template_cfg.body.format(**template_variables)

    if latest_processing_date < datetime.date.today():
        labels.add(gci._label_overdue)

    if not is_scanned:
        labels.add(gci._label_scan_pending)

    if not is_scanned or issue:
        return update_issue(
            issue=issue,
            issue_type=issue_type,
            body=body,
            title=title,
            labels=labels,
            assignees=assignees,
            milestone=milestone,
        )

    return gci._create_issue(
        issue_type=issue_type,
        repository=issue_replicator_config.github_issues_repository,
        body=body,
        title=title,
        extra_labels=labels,
        assignees=assignees,
        assignees_statuses=assignees_statuses,
        milestone=milestone,
        failed_milestones=failed_milestones,
    )
