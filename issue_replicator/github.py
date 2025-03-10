import collections
import collections.abc
import dataclasses
import enum
import datetime
import functools
import json
import logging
import re
import textwrap
import time
import urllib.parse

import cachetools
import github3
import github3.issues.issue
import github3.issues.milestone
import github3.repos
import requests

import cnudie.iter
import cnudie.retrieve
import delivery.client
import delivery.model
import dso.model
import github.compliance.milestone as gcmi
import github.retry
import github.user
import github.util
import ocm.util

import k8s.util
import odg.extensions_cfg
import odg.findings
import rescore.utility
import util


logger = logging.getLogger(__name__)


class IssueComments(enum.StrEnum):
    NO_FINDINGS = 'closing ticket because there are no longer unassessed findings'
    NOT_IN_BOM = 'closing ticket because scanned element is no longer present in BoM'


class IssueLabels(enum.StrEnum):
    OVERDUE = 'overdue'
    SCAN_PENDING = 'scan-pending'


@dataclasses.dataclass
class AggregatedFinding:
    finding: dso.model.ArtefactMetadata
    rescorings: list[dso.model.ArtefactMetadata] = dataclasses.field(default_factory=list)
    latest_processing_date: datetime.date | None = None

    @property
    def severity(self) -> str:
        if self.rescorings:
            return self.rescorings[0].data.severity

        return self.finding.data.severity


@dataclasses.dataclass
class FindingGroup:
    artefact: dso.model.ComponentArtefactId
    findings: tuple[AggregatedFinding]

    def summary(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        delivery_dashboard_url: str,
        finding_cfg: odg.findings.Finding,
        sprint_name: str | None=None,
    ) -> str:
        ocm_node = k8s.util.get_ocm_node(
            component_descriptor_lookup=component_descriptor_lookup,
            artefact=self.artefact,
        )

        artefact_non_group_properties = finding_cfg.issues.strip_artefact(
            artefact=self.artefact,
            keep_group_attributes=False,
        )

        summary = textwrap.dedent(f'''\
            {_artefact_to_str(artefact_non_group_properties)}
            {_artefact_url(ocm_node=ocm_node)}

        ''')

        delivery_dashboard_url = _delivery_dashboard_url(
            base_url=delivery_dashboard_url,
            component_artefact_id=self.artefact,
            finding_type=finding_cfg.type,
            sprint_name=sprint_name,
        )
        summary += f'[Delivery-Dashboard]({delivery_dashboard_url}) (use for assessments)\n'

        return summary


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

    reset_datetime = datetime.datetime.fromtimestamp(reset_timestamp, tz=datetime.timezone.utc)
    time_until_reset = reset_datetime - datetime.datetime.now(tz=datetime.timezone.utc)
    logger.warning(f'github quota too low, will sleep {time_until_reset} until {reset_datetime}')
    time.sleep(time_until_reset.total_seconds())


@functools.cache
@github.retry.retry_and_throttle
def _all_issues(
    repository,
    state: str='all',
    number: int=-1, # -1 means all issues
):
    return set(repository.issues(state=state, number=number))


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


@cachetools.cached(cachetools.TTLCache(maxsize=4096, ttl=60 * 60))
def _valid_issue_assignees(
    repository: github3.repos.Repository,
) -> set[str]:
    return set(
        u.login for u in repository.assignees()
    )


def _issue_assignees(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    delivery_client: delivery.client.DeliveryServiceClient,
    artefact: dso.model.ComponentArtefactId,
) -> tuple[set[str], set[delivery.model.Status]]:
    assignees: set[str] = set()
    statuses: set[delivery.model.Status] = set()

    try:
        responsibles, statuses = delivery_client.component_responsibles(
            name=artefact.component_name,
            version=artefact.component_version,
            artifact=artefact.artefact.artefact_name,
        )
        statuses = set(statuses)

        gh_users = delivery.client.github_users_from_responsibles(
            responsibles=responsibles,
            github_url=mapping.repository.html_url,
        )

        assignees = set(
            gh_user.username.lower()
            for gh_user in gh_users
            if github.user.is_user_active(
                username=gh_user.username,
                github=mapping.github_api,
            )
        )
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.warning(
                f'delivery service returned 404 for {artefact.component_name=}, '
                f'{artefact.component_version=}, {artefact.artefact.artefact_name=}'
            )
        else:
            raise

    valid_assignees = set(
        assignee.lower()
        for assignee in _valid_issue_assignees(
            repository=mapping.repository,
        )
    )

    if invalid_assignees := (assignees - valid_assignees):
        logger.warning(
            f'unable to assign {invalid_assignees} to issues in repository '
            f'{mapping.repository.html_url}. Please make sure the users have the necessary '
            'permissions to see issues in the repository.'
        )
        assignees -= invalid_assignees
        logger.info(
            f'removed invalid assignees {invalid_assignees} from target assignees for '
            f'issue. Remaining assignees: {assignees}'
        )

    return assignees, statuses


def _issue_milestone(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    delivery_client: delivery.client.DeliveryServiceClient,
    latest_processing_date: datetime.date,
) -> tuple[github3.issues.milestone.Milestone | None, list[github3.issues.milestone.Milestone]]:
    sprints = gcmi.target_sprints(
        delivery_svc_client=delivery_client,
        latest_processing_date=latest_processing_date,
    )

    return gcmi.find_or_create_sprint_milestone(
        repo=mapping.repository,
        sprints=sprints,
        milestone_cfg=mapping.milestones,
    )


def _artefact_to_str(
    artefact: dso.model.ComponentArtefactId,
) -> str:
    id_str = '<br>'.join(
        f'{k}: {v}'
        for k, v in artefact.as_dict_repr().items()
    )

    if not id_str:
        return ''

    # <pre>...</pre> is a code block like ```...``` which allows linebreaks using <br>
    # (this is required for markdown tables)
    return '<pre>' + id_str + '</pre>'


def _artefact_url(
    ocm_node: cnudie.iter.ArtefactNode,
) -> str:
    artefact_url = ocm.util.artifact_url(
        component=ocm_node.component,
        artifact=ocm_node.artefact,
    )

    return '<details><summary>Artefact-URL</summary><pre>' + artefact_url + '</pre></details>'


def _delivery_dashboard_url(
    base_url: str,
    component_artefact_id: dso.model.ComponentArtefactId,
    finding_type: odg.findings.FindingType,
    sprint_name: str=None,
):
    url = util.urljoin(
        base_url,
        '#/component'
    )

    query_params = {
        'name': component_artefact_id.component_name,
        'version': component_artefact_id.component_version,
        'view': 'bom',
        'rootExpanded': True,
        'findingType': finding_type,
    }

    if sprint_name:
        query_params['sprints'] = sprint_name

    if artefact_id := component_artefact_id.artefact:
        rescore_artefacts = (
            f'{artefact_id.artefact_name}|{artefact_id.artefact_version}|'
            f'{artefact_id.artefact_type}|{component_artefact_id.artefact_kind}'
        )

        if artefact_id.artefact_extra_id:
            rescore_artefacts += f'|{json.dumps(artefact_id.artefact_extra_id)}'

        query_params['rescoreArtefacts'] = rescore_artefacts

    query = urllib.parse.urlencode(
        query=query_params,
    )

    return f'{url}?{query}'


def _vulnerability_template_vars(
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str,
    sprint_name: str | None=None,
) -> dict[str, str]:
    summary += '# Summary of found vulnerabilities'

    def _group_findings(
        findings: tuple[AggregatedFinding],
    ) -> dict[str, dict[str, list[AggregatedFinding]]]:
        '''
        returns `findings` grouped by the affected package of the finding and the CVE
        '''
        grouped_findings_by_package = dict()

        for finding in findings:
            package_name = finding.finding.data.package_name
            cve = finding.finding.data.cve

            if not package_name in grouped_findings_by_package:
                grouped_findings_by_package[package_name] = collections.defaultdict(list)

            grouped_findings_by_package[package_name][cve].append(finding)

        return grouped_findings_by_package

    def _grouped_findings_to_table_row(
        findings: list[AggregatedFinding],
    ) -> str:
        finding = findings[0].finding
        rescorings = findings[0].rescorings
        severity = findings[0].severity

        def _vulnerability_str():
            _vuln_str = f'`{finding.data.cve}` | `{finding.data.cvss_v3_score}` | '
            _vuln_str += f'`{severity}` (rescored) |' if rescorings else f'`{severity}` |'

            if not (cve_rescoring_rules and cve_categorisation and finding.data.cvss):
                return _vuln_str

            rules = tuple(rescore.utility.matching_rescore_rules(
                rescoring_rules=cve_rescoring_rules,
                categorisation=cve_categorisation,
                cvss=finding.data.cvss,
            ))

            current_categorisation = odg.findings.categorise_finding(
                finding_cfg=finding_cfg,
                finding_property=finding.data.cvss_v3_score,
            )

            rescored_categorisation = rescore.utility.rescore_finding(
                finding_cfg=finding_cfg,
                current_categorisation=current_categorisation,
                rescoring_rules=rules,
                operations=finding_cfg.rescoring_ruleset.operations,
            )

            if rescored_categorisation.id == current_categorisation.id:
                return _vuln_str

            return _vuln_str + f' `{rescored_categorisation.display_name}`'

        versions = ', <br/>'.join((f'`{f.finding.data.package_version}`' for f in sorted(
            findings,
            key=lambda finding: # try to sort by version
                [x for x in finding.finding.data.package_version.split('.')]
                if finding.finding.data.package_version
                else [f'{finding.finding.data.package_version}'],
        )))

        return f'\n| `{finding.data.package_name}` | {_vulnerability_str()} | {versions} |'

    cve_rescoring_rules = []
    if finding_cfg.rescoring_ruleset:
        cve_rescoring_rules = finding_cfg.rescoring_ruleset.rules

    for finding_group in finding_groups:
        summary += '\n' + finding_group.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            finding_cfg=finding_cfg,
            sprint_name=sprint_name,
        )

        report_urls = {(
            f'[BDBA {finding.finding.data.product_id}]'
            f'({finding.finding.data.report_url})'
        ) for finding in finding_group.findings}
        report_urls_str = '\n'.join(sorted(report_urls))
        summary += f'{report_urls_str}\n'

        ocm_node = k8s.util.get_ocm_node(
            component_descriptor_lookup=component_descriptor_lookup,
            artefact=finding_group.artefact,
        )

        cve_categorisation = rescore.utility.find_cve_categorisation(ocm_node)

        summary += (
            '\n| Affected Package | CVE | CVE Score | Severity | Rescoring Suggestion | Package Version(s) |' # noqa: E501
            '\n| ---------------- | :-: | :-------: | :------: | :------------------: | ------------------ |' # noqa: E501
        ) + ''.join(
            _grouped_findings_to_table_row(findings=grouped_findings_by_cve)
            for _, grouped_findings_by_package in sorted(
                _group_findings(findings=finding_group.findings).items(),
                key=lambda grouped_finding: grouped_finding[0], # sort by package name
            )
            for grouped_findings_by_cve in sorted(
                grouped_findings_by_package.values(),
                key=lambda group: (
                    -group[0].finding.data.cvss_v3_score,
                    group[0].finding.data.cve,
                ),
            )
        )
        summary += '\n---'

    return {
        'summary': summary,
    }


def _malware_template_vars(
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str,
    sprint_name: str | None=None,
) -> dict[str, str]:
    summary += '# Summary of found Malware'

    def iter_findings(
        aggregated_findings: tuple[AggregatedFinding],
    ) -> collections.abc.Generator[tuple[str, str, str], None, None]:
        for af in aggregated_findings:
            finding_details: dso.model.MalwareFindingDetails = af.finding.data.finding
            yield finding_details.malware, finding_details.filename, finding_details.content_digest

    for finding_group in finding_groups:
        summary += '\n' + finding_group.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            finding_cfg=finding_cfg,
            sprint_name=sprint_name,
        )

        summary += (
            '\n| Malware | Filename | Content Digest |'
            '\n| --- | --- | --- |'
        ) + ''.join(
            f'\n| {malware} | {filename} | {content_digest} |'
            for malware, filename, content_digest in iter_findings(finding_group.findings)
        )
        summary += '\n---'

    return {
        'summary': summary,
    }


def _sast_template_vars(
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str,
    sprint_name: str | None=None,
) -> dict[str, str]:
    summary += '# Summary of found SAST issues'

    def iter_findings(
        aggragated_findings: tuple[AggregatedFinding],
    ) -> collections.abc.Generator[tuple[str, str, str, str], None, None]:
        for af in aggragated_findings:
            sast_finding: dso.model.SastFinding = af.finding.data
            sast_status = sast_finding.sast_status
            sub_type = sast_finding.sub_type
            severity = sast_finding.severity

            if sub_type is dso.model.SastSubType.LOCAL_LINTING:
                issue_text = 'No evidence about SAST-linting was found.'
            elif sub_type is dso.model.SastSubType.CENTRAL_LINTING:
                issue_text = 'No central linting found.'
            else:
                issue_text = 'Unknown SAST issue subtype.'

            yield sast_status, severity, sub_type, issue_text

    for finding_group in finding_groups:
        summary += '\n' + finding_group.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            finding_cfg=finding_cfg,
            sprint_name=sprint_name,
        )

        summary += (
            '\n| SAST Status | Severity | Sub Type | Issue Text |'
            '\n| --- | --- | --- | --- |'
        )
        for sast_status, severity, sub_type, issue_text in iter_findings(finding_group.findings):
            summary += f'\n| {sast_status} | {severity} | {sub_type} | {issue_text} |'

        summary += '\n---'

    return {
        'summary': summary,
    }


def _license_template_vars(
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str,
    sprint_name: str=None,
) -> dict[str, str]:
    summary += '# Summary of found licenses'

    def _group_findings(
        findings: tuple[AggregatedFinding],
    ) -> dict[str, dict[str, list[AggregatedFinding]]]:
        '''
        returns `findings` grouped by the affected package of the finding and the license name
        '''
        grouped_findings_by_package = dict()

        for finding in findings:
            package_name = finding.finding.data.package_name
            license_name = finding.finding.data.license.name

            if not package_name in grouped_findings_by_package:
                grouped_findings_by_package[package_name] = collections.defaultdict(list)

            grouped_findings_by_package[package_name][license_name].append(finding)

        return grouped_findings_by_package

    def _grouped_findings_to_table_row(
        findings: list[AggregatedFinding],
    ) -> str:
        finding = findings[0].finding
        rescorings = findings[0].rescorings
        severity = findings[0].severity

        def _license_str():
            if rescorings:
                return f'`{finding.data.license.name}` | `{severity}` (rescored)'

            return f'`{finding.data.license.name}` | `{severity}`'

        versions = ', <br/>'.join((f'`{f.finding.data.package_version}`' for f in sorted(
            findings,
            key=lambda finding: # try to sort by version
                [x for x in finding.finding.data.package_version.split('.')]
                if finding.finding.data.package_version
                else [f'{finding.finding.data.package_version}'],
        )))

        return f'\n| `{finding.data.package_name}` | {_license_str()} | {versions} |'

    for finding_group in finding_groups:
        summary += '\n' + finding_group.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            finding_cfg=finding_cfg,
            sprint_name=sprint_name,
        )

        report_urls = {(
            f'[BDBA {finding.finding.data.product_id}]'
            f'({finding.finding.data.report_url})'
        ) for finding in finding_group.findings}
        report_urls_str = '\n'.join(sorted(report_urls))
        summary += f'{report_urls_str}\n'

        summary += (
            '\n| Affected Package | License | Severity | Package Version(s) |'
            '\n| ---------------- | :-----: | :------: | ------------------ |'
        ) + ''.join(
            _grouped_findings_to_table_row(findings=grouped_findings_by_license)
            for _, grouped_findings_by_package in sorted(
                _group_findings(findings=finding_group.findings).items(),
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


def _diki_template_vars(
    finding_groups: list[FindingGroup],
    summary: str,
) -> dict[str, str]:
    # GitHub has a maximum character limit of 65,536
    MAX_SUMMARY_SIZE = 60000

    findings: list[AggregatedFinding] = []
    for finding_group in finding_groups:
        findings.extend(finding_group.findings)

    def _targets_table(
        targets: list[dict],
    ) -> str:
        table = ''
        unique_keys = set()
        for t in targets:
            unique_keys.update(t.keys())
        unique_keys = list(unique_keys)

        unique_keys.sort()
        if 'details' in unique_keys:
            unique_keys.remove('details')
            unique_keys.append('details')

        column_titles = '|'
        column_separation = '|'
        for key in unique_keys:
            column_titles += f' {key} |'
            column_separation += ':-:|'

        table += f'{column_titles}\n'
        table += f'{column_separation}\n'
        for t in targets:
            current_row = '|'
            for key in unique_keys:
                if key in t:
                    current_row += f' {t[key]} |'
                else:
                    current_row += ' |'
            table += f'{current_row}\n'
        return table

    shortened_summary = summary
    for finding in findings:

        finging_rule = finding.finding.data
        finding_str = '\n'
        finding_str += f'# Failed {finging_rule.ruleset_id}:{finging_rule.ruleset_version}'
        finding_str += f' rule with ID {finging_rule.rule_id} - {finging_rule.severity}\n'
        finding_str += '\n'
        finding_str += '### Failed checks:\n'

        summary += finding_str
        shortened_summary += finding_str

        for check in finging_rule.checks:
            check_msg_str = '\n'
            check_msg_str += f'Message: {check.message}\n'
            check_msg_str += 'Targets:\n'
            check_msg_str += '\n'

            summary += check_msg_str
            shortened_summary += check_msg_str

            match check.targets:
                # process merged checks
                case dict():
                    for key, value in check.targets.items():
                        if value:
                            shortened_summary += f'**{key}**: {len(value)} targets\n'
                            summary += '<details>\n'
                            summary += f'<summary>{key}:</summary>\n\n'
                            summary += _targets_table(value)
                            summary += '</details>\n\n'
                        else:
                            shortened_summary += f'**{key}**\n'
                            summary += f'**{key}**\n'
                # process single checks
                case list():
                    if len(check.targets) == 0:
                        shortened_summary += 'n/a\n'
                        summary += 'n/a\n'
                    else:
                        shortened_summary += f'{len(check.targets)} targets\n'
                        summary += _targets_table(check.targets)
                case None:
                    shortened_summary += 'n/a\n'
                    summary += 'n/a\n'
                case _:
                    raise TypeError(check.targets) # this line should never be reached

    return {
        'summary': summary if len(summary) <= MAX_SUMMARY_SIZE else shortened_summary,
    }


def _template_vars(
    finding_cfg: odg.findings.Finding,
    artefacts: collections.abc.Iterable[dso.model.ComponentArtefactId],
    artefacts_without_scan: collections.abc.Iterable[dso.model.ComponentArtefactId],
    findings: collections.abc.Sequence[AggregatedFinding],
    latest_processing_date: datetime.date,
    delivery_dashboard_url: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    sprint_name: str | None=None,
) -> dict:
    '''
    Fills a dictionary with template variables intended to be used to fill a template for a GitHub
    issue. The most prominent template variable is called `summary`. It contains a table showing
    information on the artefact the issue is opened for as well as more detailed information on the
    actual findings per artefact. The summary table first depicts the properties which are used to
    group the artefacts (so the properties which all artefacts have in common) and then the remaining
    properties per artefact. Also, artefacts which were not scanned yet are reported (if there are
    any).
    '''
    artefact_sorting_key = lambda artefact: (
        artefact.component_name,
        artefact.component_version,
        artefact.artefact_kind,
        artefact.artefact.artefact_type,
        artefact.artefact.artefact_name,
        artefact.artefact.artefact_version,
        artefact.artefact.normalised_artefact_extra_id,
    )

    sorted_artefacts = sorted(artefacts, key=artefact_sorting_key)
    sorted_artefacts_without_scan = sorted(artefacts_without_scan, key=artefact_sorting_key)

    artefact = sorted_artefacts[0]

    rescoring_url = _delivery_dashboard_url(
        base_url=delivery_dashboard_url,
        component_artefact_id=artefact,
        finding_type=finding_cfg.type,
        sprint_name=sprint_name,
    )

    summary = textwrap.dedent('''\
        # Compliance Status Summary

        |    |    |
        | -- | -- |
    ''')

    # first of all, display the artefact properties which are used for grouping in the summary table
    artefact_group_properties = finding_cfg.issues.strip_artefact(
        artefact=artefact,
        keep_group_attributes=True,
    )

    if component_name := artefact_group_properties.component_name:
        summary += f'| Component | {component_name} |\n'
    if component_version := artefact_group_properties.component_version:
        summary += f'| Component-Version | {component_version} |\n'
    if artefact_kind := artefact_group_properties.artefact_kind:
        summary += f'| Artefact-Kind | {artefact_kind} |\n'
    if artefact_name := artefact_group_properties.artefact.artefact_name:
        summary += f'| Artefact | {artefact_name} |\n'
    if artefact_version := artefact_group_properties.artefact.artefact_version:
        summary += f'| Artefact-Version | {artefact_version} |\n'
    if artefact_type := artefact_group_properties.artefact.artefact_type:
        summary += f'| Artefact-Type | {artefact_type} |\n'
    if artefact_extra_id := artefact_group_properties.artefact.artefact_extra_id:
        id_str = '<br>'.join(sorted(f'{k}: {v}' for k, v in artefact_extra_id.items()))
        summary += f'| Artefact-Extra-Id | <pre>{id_str}</pre> |\n'

    summary += f'| Latest Processing Date | {latest_processing_date} |\n'

    # assign the findings to the artefact of the group they belong to
    finding_groups: list[FindingGroup] = []
    for artefact in sorted_artefacts:
        findings_for_artefact = tuple(
            finding for finding in findings
            if (
                finding.finding.artefact.component_name == artefact.component_name
                and (
                    # finding's component version might be `None`, i.e. for BDBA findings
                    not finding.finding.artefact.component_version
                    or finding.finding.artefact.component_version == artefact.component_version
                ) and finding.finding.artefact.artefact_kind is artefact.artefact_kind
                and finding.finding.artefact.artefact.artefact_name
                    == artefact.artefact.artefact_name
                and finding.finding.artefact.artefact.artefact_version
                    == artefact.artefact.artefact_version
                and finding.finding.artefact.artefact.artefact_type
                    == artefact.artefact.artefact_type
                and finding.finding.artefact.artefact.normalised_artefact_extra_id
                    == artefact.artefact.normalised_artefact_extra_id
            )
        )

        if not findings_for_artefact:
            continue

        finding_groups.append(FindingGroup(
            artefact=artefact,
            findings=findings_for_artefact,
        ))

    # secondly, display the combinations of artefact properties which are not part of the group
    artefacts_non_group_properties = [
        finding_cfg.issues.strip_artefact(
            artefact=finding_group.artefact,
            keep_group_attributes=False,
        ) for finding_group in finding_groups
    ]

    artefacts_non_group_properties_str = ''.join(
        _artefact_to_str(artefact=artefact_non_group_properties)
        for artefact_non_group_properties in artefacts_non_group_properties
    )

    if artefacts_non_group_properties:
        summary += f'| {util.pluralise('ID', len(artefacts_non_group_properties))} | {artefacts_non_group_properties_str} |\n\n' # noqa: E501

    # lastly, display the artefacts which were not scanned yet
    artefacts_without_scan_str = ''.join(
        _artefact_to_str(artefact=artefact_without_scan)
        for artefact_without_scan in sorted_artefacts_without_scan
    )

    if sorted_artefacts_without_scan:
        summary += f'| {util.pluralise('Artefact', len(sorted_artefacts_without_scan))} without Scan | {artefacts_without_scan_str} |\n\n' # noqa: E501

    template_variables = {
        'component_name': component_name,
        'component_version': component_version,
        'artefact_kind': artefact_kind,
        'artefact_name': artefact_name,
        'artefact_version': artefact_version,
        'artefact_type': artefact_type,
        'resource_type': artefact_type, # TODO deprecated -> remove once all templates are adjusted
        'rescoring_url': rescoring_url,
    }

    if not findings:
        summary += (
            '**The scan of the recent artefact version is currently pending, '
            'hence no findings may show up.**'
        )

        template_variables |= {
            'summary': summary,
        }

        return template_variables

    summary += (
        f'The aforementioned {util.pluralise('artefact', len(artefacts_non_group_properties))} '
        'yielded findings relevant for future release decisions.\n'
    )

    if finding_cfg.type is odg.findings.FindingType.VULNERABILITY:
        template_variables |= _vulnerability_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.findings.FindingType.LICENSE:
        template_variables |= _license_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.findings.FindingType.MALWARE:
        template_variables |= _malware_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.findings.FindingType.SAST:
        template_variables |= _sast_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.findings.FindingType.DIKI:
        template_variables |= _diki_template_vars(
            finding_groups=finding_groups,
            summary=summary,
        )

    return template_variables


@github.retry.retry_and_throttle
def close_issue_if_present(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    issue: github3.issues.issue.ShortIssue,
    closing_reason: IssueComments,
):
    if not issue or issue.state != 'open':
        return

    logger.info(f'labels for issue for closing: {[l.name for l in issue.original_labels]}')

    issue.create_comment(closing_reason)
    if not github.util.close_issue(issue):
        repository_url = mapping.repository.html_url
        logger.warning(f'failed to close {issue.id=} with {repository_url=}')


@github.retry.retry_and_throttle
def update_issue(
    issue: github3.issues.issue.ShortIssue,
    body: str,
    title: str=None,
    labels: set[str]=set(),
    assignees: set[str]=set(),
    milestone: github3.issues.milestone.Milestone=None,
):
    kwargs = {
        'state': 'open',
        'labels': sorted(labels),
    }

    if title:
        kwargs['title'] = title

    if not issue.assignees and assignees:
        # conversion to tuple required for issue update (JSON serialisation)
        kwargs['assignees'] = tuple(assignees)

    if milestone and (not issue.milestone or issue.state == 'closed'):
        kwargs['milestone'] = milestone.number

    issue.edit(
        body=body,
        **kwargs,
    )


@github.retry.retry_and_throttle
def create_issue(
    repository: github3.repos.Repository,
    body: str,
    title: str,
    milestone: github3.issues.milestone.Milestone | None,
    failed_milestones: list[github3.issues.milestone.Milestone],
    assignees: set[str],
    assignees_statuses: set[str],
    labels: set[str],
) -> github3.issues.issue.ShortIssue:
    try:
        issue = repository.create_issue(
            title=title,
            body=body,
            milestone=milestone.number if milestone else None,
            labels=sorted(labels),
            assignees=tuple(assignees),
        )

        if assignees_statuses:
            comment_body = textwrap.dedent('''\
                There have been anomalies during initial ticket assignment, please see details below:
                | Message Type | Message |
                | --- | --- |'''
            )
            for status in assignees_statuses:
                comment_body += f'\n|`{status.type}`|`{status.msg}`'

            issue.create_comment(comment_body)

        if failed_milestones:
            milestone_comment = (
                'Failed to automatically assign ticket to one of these milestones: '
                f'{", ".join([milestone.title for milestone in failed_milestones])}. '
                'Milestones were probably closed before all associated findings were assessed. '
            )
            if milestone:
                milestone_comment += f'Ticket was assigned to {milestone.title} as a fallback.'

            issue.create_comment(milestone_comment)

        return issue

    except github3.exceptions.GitHubError as ghe:
        logger.warning(f'received error trying to create issue: {ghe=}')
        logger.warning(f'{ghe.message=} {ghe.code=} {ghe.errors=}')
        logger.warning(f'{labels=} {assignees=}')
        raise ghe


def _create_or_update_issue(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    artefacts: tuple[dso.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    issues: tuple[github3.issues.issue.ShortIssue],
    milestone: github3.issues.milestone.Milestone | None,
    failed_milestones: list[github3.issues.milestone.Milestone],
    latest_processing_date: datetime.date,
    is_scanned: bool,
    artefacts_without_scan: set[dso.model.ComponentArtefactId],
    delivery_dashboard_url: str,
    sprint_name: str=None,
    assignees: set[str]=set(),
    assignees_statuses: set[str]=set(),
    labels: set[str]=set(),
):
    def labels_to_preserve(
        issue: github3.issues.issue.ShortIssue,
    ) -> collections.abc.Generator[str, None, None]:
        for label in issue.original_labels:
            for pattern in mapping.github_issue_labels_to_preserve:
                if re.fullmatch(pattern=pattern, string=label.name):
                    yield label.name
                    break

    if (issues_count := len(issues)) > 1:
        # it is possible, that multiple _closed_ issues exist for one issue id
        # if that's the case, re-use the latest issue (greatest id)
        open_issues = tuple(issue for issue in issues if issue.state == 'open')
        if len(open_issues) > 1:
            logger.warning(f'more than one open issue found for {labels=}')
            return
        issue = sorted(issues, key=lambda issue: issue.id, reverse=True)[0]
    elif issues_count == 1:
        issue = issues[0]
    else:
        issue = None

    if issue:
        labels = labels | set(labels_to_preserve(issue=issue))

    if findings:
        title = finding_cfg.issues.issue_title(findings[0].finding)
    else:
        # in case there are no findings here, there must already be an open issue which is going to
        # be updated to "scan-pending", hence it will already have a title which does not have to be
        # updated
        title = None

    is_overdue = latest_processing_date < datetime.date.today()

    template_variables = _template_vars(
        finding_cfg=finding_cfg,
        component_descriptor_lookup=component_descriptor_lookup,
        artefacts=artefacts,
        findings=findings,
        artefacts_without_scan=artefacts_without_scan,
        latest_processing_date=latest_processing_date,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name='Overdue' if is_overdue else sprint_name,
    )

    body = finding_cfg.issues.template.format(**template_variables)

    if is_overdue:
        labels.add(IssueLabels.OVERDUE)

    if not is_scanned:
        labels.add(IssueLabels.SCAN_PENDING)

    if not is_scanned or issue:
        return update_issue(
            issue=issue,
            body=body,
            title=title,
            labels=labels,
            assignees=assignees,
            milestone=milestone,
        )

    return create_issue(
        repository=mapping.repository,
        body=body,
        title=title,
        milestone=milestone,
        failed_milestones=failed_milestones,
        assignees=assignees,
        assignees_statuses=assignees_statuses,
        labels=labels,
    )


def _create_or_update_or_close_issue_per_finding(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    artefacts: collections.abc.Iterable[dso.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    issue_id: str,
    issues: tuple[github3.issues.issue.ShortIssue],
    milestone: github3.issues.milestone.Milestone,
    failed_milestones: None | list[github3.issues.milestone.Milestone],
    latest_processing_date: datetime.date,
    is_scanned: bool,
    artefacts_without_scan: set[dso.model.ComponentArtefactId],
    delivery_dashboard_url: str,
    sprint_name: str=None,
    assignees: set[str]=set(),
    assignees_statuses: set[str]=set(),
    labels: set[str]=set(),
):
    processed_issues = set()
    for finding in findings:

        data = finding.finding.data
        finding_labels = labels | {
            data.key,
        }

        finding_issues = filter_issues_for_labels(
            issues=issues,
            labels=(issue_id, finding_cfg.type, data.key),
        )
        processed_issues.update(finding_issues)

        _create_or_update_issue(
            mapping=mapping,
            finding_cfg=finding_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            artefacts=artefacts,
            findings=(finding,),
            issues=finding_issues,
            milestone=milestone,
            failed_milestones=failed_milestones,
            latest_processing_date=latest_processing_date,
            is_scanned=is_scanned,
            artefacts_without_scan=artefacts_without_scan,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
            assignees=assignees,
            assignees_statuses=assignees_statuses,
            labels=finding_labels,
        )

    for issue in issues:
        if issue not in processed_issues and issue.state == 'open':
            close_issue_if_present(
                mapping=mapping,
                issue=issue,
                closing_reason=IssueComments.NO_FINDINGS,
            )


def create_or_update_or_close_issue(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    artefacts: collections.abc.Iterable[dso.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    issue_id: str,
    latest_processing_date: datetime.date,
    is_in_bom: bool,
    artefacts_without_scan: set[dso.model.ComponentArtefactId],
    delivery_dashboard_url: str,
):
    is_scanned = len(artefacts_without_scan) == 0

    labels = set(finding_cfg.issues.labels) | {
        issue_id,
        finding_cfg.type,
    }

    known_issues = _all_issues(
        repository=mapping.repository,
        state='open',
    ) | _all_issues(
        repository=mapping.repository,
        state='closed',
        number=mapping.number_included_closed_issues,
    )

    issues = filter_issues_for_labels(
        issues=known_issues,
        labels=(issue_id, finding_cfg.type),
    )

    if not is_in_bom:
        for issue in issues:
            close_issue_if_present(
                mapping=mapping,
                issue=issue,
                closing_reason=IssueComments.NOT_IN_BOM,
            )
        return

    if is_scanned and not findings:
        for issue in issues:
            close_issue_if_present(
                mapping=mapping,
                issue=issue,
                closing_reason=IssueComments.NO_FINDINGS,
            )
        return

    if not is_scanned:
        for issue in issues:
            if issue.state == 'open':
                break
        else:
            # not scanned yet but no open issue found either -> nothing to do
            return

    if finding_cfg.issues.enable_assignees:
        assignees, assignees_statuses = _issue_assignees(
            mapping=mapping,
            delivery_client=delivery_client,
            artefact=artefacts[0],
        )
    else:
        assignees = set()
        assignees_statuses = set()

    milestone, failed_milestones = _issue_milestone(
        mapping=mapping,
        delivery_client=delivery_client,
        latest_processing_date=latest_processing_date,
    )

    if milestone:
        sprint_name = milestone.title.lstrip('sprint-')
    else:
        sprint_name = None

    if finding_cfg.issues.enable_per_finding:
        return _create_or_update_or_close_issue_per_finding(
            mapping=mapping,
            finding_cfg=finding_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            artefacts=artefacts,
            findings=findings,
            issue_id=issue_id,
            issues=issues,
            milestone=milestone,
            failed_milestones=failed_milestones,
            latest_processing_date=latest_processing_date,
            is_scanned=is_scanned,
            artefacts_without_scan=artefacts_without_scan,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
            assignees=assignees,
            assignees_statuses=assignees_statuses,
            labels=labels,
        )

    return _create_or_update_issue(
        mapping=mapping,
        finding_cfg=finding_cfg,
        component_descriptor_lookup=component_descriptor_lookup,
        artefacts=artefacts,
        findings=findings,
        issues=issues,
        milestone=milestone,
        failed_milestones=failed_milestones,
        latest_processing_date=latest_processing_date,
        is_scanned=is_scanned,
        artefacts_without_scan=artefacts_without_scan,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
        assignees=assignees,
        assignees_statuses=assignees_statuses,
        labels=labels,
    )
