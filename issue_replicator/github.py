import collections
import collections.abc
import dataclasses
import enum
import datetime
import functools
import json
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
import cnudie.retrieve
import delivery.client
import delivery.model
import dso.cvss
import dso.labels
import dso.model
import github.compliance.issue as gci
import github.compliance.milestone as gcmi
import github.compliance.model as gcm
import github.compliance.report as gcr
import github.retry
import github.user
import github.util
import rescore.utility
import version as version_util

import config
import k8s.util


logger = logging.getLogger(__name__)


class IssueComments(enum.StrEnum):
    NO_FINDINGS = 'closing ticket because there are no longer unassessed findings'
    NOT_IN_BOM = 'closing ticket because scanned element is no longer present in BoM'


@dataclasses.dataclass
class AggregatedFinding:
    finding: dso.model.ArtefactMetadata
    severity: gcm.Severity
    rescorings: tuple[dso.model.ArtefactMetadata]

    def calculate_latest_processing_date(
        self,
        sprints: collections.abc.Iterable[datetime.date],
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


@dataclasses.dataclass
class GroupedFindings:
    component_name: str
    component_versions: set[str]
    artefact_kind: dso.model.ArtefactKind
    artefact: dso.model.LocalArtefactId
    findings: tuple[AggregatedFinding]

    def summary(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        delivery_dashboard_url: str | None=None,
        cfg_name: str | None=None,
        sprint_name: str | None=None,
    ) -> str:
        component_version = version_util.greatest_version(
            versions=self.component_versions,
        )

        component_artefact_id = dso.model.ComponentArtefactId(
            component_name=self.component_name,
            component_version=component_version,
            artefact_kind=self.artefact_kind,
            artefact=self.artefact,
        )

        ocm_node = k8s.util.get_ocm_node(
            component_descriptor_lookup=component_descriptor_lookup,
            artefact=component_artefact_id,
        )

        summary = textwrap.dedent(f'''\
            ### {self.artefact.artefact_name}:{self.artefact.artefact_version}
            {_artefact_id_to_str(artefact_id=self.artefact, include_version=False)}
            {_artefact_url(ocm_node=ocm_node)}

        ''')

        if delivery_dashboard_url:
            delivery_dashboard_url = _delivery_dashboard_url(
                cfg_name=cfg_name,
                base_url=delivery_dashboard_url,
                component_artefact_id=component_artefact_id,
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


def _issue_assignees(
    issue_replicator_config: config.IssueReplicatorConfig,
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
            logger.warning(
                f'delivery service returned 404 for {artefact.component_name=}, '
                f'{artefact.component_version=}, {artefact.artefact.artefact_name=}'
            )
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
    )

    return gcmi.find_or_create_sprint_milestone(
        repo=issue_replicator_config.github_issues_repository,
        sprints=sprints,
        milestone_cfg=issue_replicator_config.milestone_cfg,
    )


def _issue_title(
    issue_type: str,
    artefact: dso.model.ComponentArtefactId,
    extra: str,
) -> str:
    title = f'[{issue_type}] - {artefact.component_name}:{artefact.artefact.artefact_name}'

    if extra:
        title += f' - [{extra}]'

    return title


def _artefact_id_to_str(
    artefact_id: dso.model.LocalArtefactId,
    include_version: bool=True,
) -> str:
    id = {
        **({'version': artefact_id.artefact_version} if include_version else {}),
        **artefact_id.artefact_extra_id,
    }

    if not id:
        return ''

    id_str = '<br>'.join(
        f'{k}: {v}'
        for k, v in id.items()
    )

    # <pre>...</pre> is a code block like ```...``` which allows linebreaks using <br>
    # (this is required for markdown tables)
    return '<pre>' + id_str + '</pre>'


def _artefact_url(
    ocm_node: cnudie.iter.ArtefactNode,
) -> str:
    artefact_url = gcr._artifact_url(
        component=ocm_node.component,
        artifact=ocm_node.artefact,
    )

    return '<details><summary>Artefact-URL</summary><pre>' + artefact_url + '</pre></details>'


def _delivery_dashboard_url(
    cfg_name: str,
    base_url: str,
    component_artefact_id: dso.model.ComponentArtefactId,
    sprint_name: str=None,
):
    url = ci.util.urljoin(
        base_url,
        '#/component'
    )

    query_params = {
        'name': component_artefact_id.component_name,
        'version': component_artefact_id.component_version,
        'view': 'bom',
        'rootExpanded': True,
        'scanConfigName': cfg_name,
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
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    grouped_findings: list[GroupedFindings],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    sprint_name: str=None,
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

            rules = tuple(rescore.utility.matching_rescore_rules(
                rescoring_rules=cve_rescoring_rules,
                categorisation=cve_categorisation,
                cvss=finding.data.cvss,
            ))

            rescored = rescore.utility.rescore_severity(
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

    cve_rescoring_rules = []
    if issue_replicator_config.cve_rescoring_ruleset:
        cve_rescoring_rules = issue_replicator_config.cve_rescoring_ruleset.rules

    for grouped_finding in grouped_findings:
        summary += '\n' + grouped_finding.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=issue_replicator_config.delivery_dashboard_url,
            cfg_name=cfg_name,
            sprint_name=sprint_name,
        )

        report_urls = {(
            f'[BDBA {finding.finding.data.product_id}]'
            f'({finding.finding.data.report_url})'
        ) for finding in grouped_finding.findings}
        report_urls_str = '\n'.join(sorted(report_urls))
        summary += f'{report_urls_str}\n'

        component_version = version_util.greatest_version(
            versions=grouped_finding.component_versions,
        )
        ocm_node = k8s.util.get_ocm_node(
            component_descriptor_lookup=component_descriptor_lookup,
            artefact=dso.model.ComponentArtefactId(
                component_name=grouped_finding.component_name,
                component_version=component_version,
                artefact_kind=grouped_finding.artefact_kind,
                artefact=grouped_finding.artefact,
            ),
        )

        rescore_label = ocm_node.artefact.find_label(
            name=dso.labels.CveCategorisationLabel.name,
        )
        if not rescore_label:
            rescore_label = ocm_node.component.find_label(
                name=dso.labels.CveCategorisationLabel.name,
            )

        if rescore_label:
            rescore_label: dso.labels.CveCategorisationLabel = dso.labels.deserialise_label(
                label=rescore_label,
            )
            cve_categorisation = rescore_label.value
        else:
            cve_categorisation = None

        summary += (
            '\n| Affected Package | CVE | CVE Score | Severity | Rescoring Suggestion | Package Version(s) |' # noqa: E501
            '\n| ---------------- | :-: | :-------: | :------: | :------------------: | ------------------ |' # noqa: E501
        ) + ''.join(
            _grouped_findings_to_table_row(findings=grouped_findings_by_cve)
            for _, grouped_findings_by_package in sorted(
                _group_findings(findings=grouped_finding.findings).items(),
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
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    grouped_findings: list[GroupedFindings],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    sprint_name: str=None,
) -> dict[str, str]:
    summary += '# Summary of found Malware'

    def iter_findings(
        aggregated_findings: tuple[AggregatedFinding],
    ) -> collections.abc.Generator[tuple[str, str, str], None, None]:
        for af in aggregated_findings:
            finding_details: dso.model.MalwareFindingDetails = af.finding.data.finding
            yield finding_details.malware, finding_details.filename, finding_details.content_digest

    for grouped_finding in grouped_findings:
        summary += '\n' + grouped_finding.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=issue_replicator_config.delivery_dashboard_url,
            cfg_name=cfg_name,
            sprint_name=sprint_name,
        )

        summary += (
            '\n| Malware | Filename | Content Digest |'
            '\n| --- | --- | --- |'
        ) + ''.join(
            f'\n| {malware} | {filename} | {content_digest} |'
            for malware, filename, content_digest in iter_findings(grouped_finding.findings)
        )
        summary += '\n---'

    return {
        'summary': summary,
    }


def _license_template_vars(
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    grouped_findings: list[GroupedFindings],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
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

    for grouped_finding in grouped_findings:
        summary += '\n' + grouped_finding.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=issue_replicator_config.delivery_dashboard_url,
            cfg_name=cfg_name,
            sprint_name=sprint_name,
        )

        report_urls = {(
            f'[BDBA {finding.finding.data.product_id}]'
            f'({finding.finding.data.report_url})'
        ) for finding in grouped_finding.findings}
        report_urls_str = '\n'.join(sorted(report_urls))
        summary += f'{report_urls_str}\n'

        summary += (
            '\n| Affected Package | License | Severity | Package Version(s) |'
            '\n| ---------------- | :-----: | :------: | ------------------ |'
        ) + ''.join(
            _grouped_findings_to_table_row(findings=grouped_findings_by_license)
            for _, grouped_findings_by_package in sorted(
                _group_findings(findings=grouped_finding.findings).items(),
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
    grouped_findings: list[GroupedFindings],
    summary: str,
) -> dict[str, str]:
    # GitHub has a maximum character limit of 65,536
    MAX_SUMMARY_SIZE = 60000

    findings: list[AggregatedFinding] = []
    for grouped_finding in grouped_findings:
        findings.extend(grouped_finding.findings)

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
                        if value is None:
                            shortened_summary += f'{key}: 0 targets\n'
                            summary += f'{key}: 0 targets\n'
                            continue
                        shortened_summary += f'{key}: {len(value)} targets\n'
                        summary += '<details>\n'
                        summary += f'<summary>{key}:</summary>\n\n'
                        summary += _targets_table(value)
                        summary += '</details>\n\n'
                # process single checks
                case list():
                    shortened_summary += f'{len(check.targets)} targets\n'
                    if len(check.targets) == 0:
                        summary += '0 targets\n'
                    else:
                        summary += _targets_table(check.targets)
                case None:
                    shortened_summary += '0 targets\n'
                    summary += '0 targets\n'
                case _:
                    raise TypeError(check.targets) # this line should never be reached

    return {
        'summary': summary if len(summary) <= MAX_SUMMARY_SIZE else shortened_summary,
    }


def _template_vars(
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    issue_type: str,
    artefacts: tuple[dso.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    artefact_ids_without_scan: set[dso.model.LocalArtefactId],
    latest_processing_date: datetime.date,
    sprint_name: str=None,
) -> dict:
    # contained `artefacts` may only differ in their `component_version`, `artefact_version`,
    # and `artefact_extra_id` (we aggregate the issues across those properties)
    artefact = artefacts[0]
    component_name = artefact.component_name
    artefact_kind = artefact.artefact_kind
    artefact_name = artefact.artefact.artefact_name
    artefact_type = artefact.artefact.artefact_type

    # all component versions which have artefacts with findings -> required for summary table
    component_versions: set[str] = set()
    # findings per artefact id for the detailed view
    grouped_findings: dict[dso.model.LocalArtefactId, GroupedFindings] = dict()

    for artefact in artefacts:
        component_version = artefact.component_version
        artefact_id = artefact.artefact

        if artefact_id in grouped_findings:
            component_versions.add(component_version)
            grouped_findings[artefact_id].component_versions.add(component_version)
            continue

        filtered_findings = tuple(
            finding for finding in findings
            if finding.finding.artefact.artefact == artefact_id
        )

        if not filtered_findings:
            # artefact has no findings for this datatype-sprint combination
            continue

        component_versions.add(component_version)
        grouped_findings[artefact_id] = GroupedFindings(
            component_name=component_name,
            component_versions={component_version},
            artefact_kind=artefact_kind,
            artefact=artefact_id,
            findings=filtered_findings,
        )

    c_versions_str = ', '.join(sorted(component_versions))

    artefact_ids = sorted(
        grouped_findings.keys(),
        key=lambda id: (id.artefact_version, id.normalised_artefact_extra_id),
    )
    artefact_ids_str = ''.join(
        _artefact_id_to_str(artefact_id=artefact_id)
        for artefact_id in artefact_ids
    )

    artefact_ids_without_scan = sorted(
        artefact_ids_without_scan,
        key=lambda id: (id.artefact_version, id.normalised_artefact_extra_id),
    )
    artefacts_without_scan_str = ''.join(
        _artefact_id_to_str(artefact_id=artefact_id_without_scan)
        for artefact_id_without_scan in artefact_ids_without_scan
    )

    summary = textwrap.dedent(f'''\
        # Compliance Status Summary

        |    |    |
        | -- | -- |
        | Component | {component_name} |
        | {gcr._pluralise('Component-Version', len(component_versions))} | {c_versions_str} |
        | Artefact | {artefact_name} |
        | Artefact-Type | {artefact_type} |
        | {gcr._pluralise('Artefact-Id', len(artefact_ids))} | {artefact_ids_str} |
        | Latest Processing Date | {latest_processing_date} |
    ''')

    if artefact_ids_without_scan:
        summary += f'| {gcr._pluralise('Artefact', len(artefact_ids_without_scan))} without Scan | {artefacts_without_scan_str} |\n\n' # noqa: E501

    if findings:
        summary += (
            f'\nThe aforementioned {gcr._pluralise(artefact_type, len(artefact_ids))} '
            'yielded findings relevant for future release decisions.\n'
        )
    else:
        summary += (
            '**The scan of the recent artefact version is currently pending, '
            'hence no findings may show up.**'
        )

    template_variables = {
        'component_name': component_name,
        'component_version': c_versions_str,
        'artefact_kind': artefact_kind,
        'artefact_name': artefact_name,
        'artefact_type': artefact_type,
        'resource_type': artefact_type, # TODO deprecated -> remove once all templates are adjusted
    }

    sorted_grouped_findings = sorted(
        (grouped_finding for grouped_finding in grouped_findings.values()),
        key=lambda grouped_finding: (
            grouped_finding.artefact.artefact_version,
            grouped_finding.artefact.normalised_artefact_extra_id,
        ),
    )

    if not findings:
        template_variables |= {
            'summary': summary,
        }
    elif issue_type == gci._label_bdba:
        template_variables |= _vulnerability_template_vars(
            cfg_name=cfg_name,
            issue_replicator_config=issue_replicator_config,
            grouped_findings=sorted_grouped_findings,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            sprint_name=sprint_name,
        )
    elif issue_type == gci._label_licenses:
        template_variables |= _license_template_vars(
            cfg_name=cfg_name,
            issue_replicator_config=issue_replicator_config,
            grouped_findings=sorted_grouped_findings,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            sprint_name=sprint_name,
        )
    elif issue_type == gci._label_malware:
        template_variables |= _malware_template_vars(
            cfg_name=cfg_name,
            issue_replicator_config=issue_replicator_config,
            grouped_findings=sorted_grouped_findings,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            sprint_name=sprint_name,
        )
    elif issue_type == gci._label_diki:
        template_variables |= _diki_template_vars(
            grouped_findings=sorted_grouped_findings,
            summary=summary,
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

    if milestone and (not issue.milestone or issue.state == 'closed'):
        kwargs['milestone'] = milestone.number

    issue.edit(
        body=body,
        **kwargs,
    )


def _create_or_update_issue(
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    issue_type: str,
    artefacts: tuple[dso.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    issues: tuple[github3.issues.issue.ShortIssue],
    milestone: github3.issues.milestone.Milestone,
    failed_milestones: None | list[github3.issues.milestone.Milestone],
    latest_processing_date: datetime.date,
    is_scanned: bool,
    artefact_ids_without_scan: set[dso.model.LocalArtefactId],
    extra_title: str=None,
    sprint_name: str=None,
    assignees: set[str]=set(),
    assignees_statuses: set[str]=set(),
    labels: set[str]=set(),
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

    if (issues_count := len(issues)) > 1:
        # it is possible, that multiple _closed_ issues exist for one correlation id
        # if that's the case, re-use the latest issue (greatest id)
        open_issues = tuple(issue for issue in issues if issue.state == 'open')
        if len(open_issues) > 1:
            logger.warning(f'more than one open issue found for {labels=}')
            return
        issue = sorted(issues, key=lambda issue: issue.id, reverse=True)[0]
    elif issues_count == 1:
        issue = issues[0]
        labels = labels | set(labels_to_preserve(issue=issue))
    else:
        issue = None

    title = _issue_title(
        issue_type=issue_type,
        artefact=artefacts[0],
        extra=extra_title,
    )

    is_overdue = latest_processing_date < datetime.date.today()

    template_variables = _template_vars(
        cfg_name=cfg_name,
        issue_replicator_config=issue_replicator_config,
        component_descriptor_lookup=component_descriptor_lookup,
        issue_type=issue_type,
        artefacts=artefacts,
        findings=findings,
        artefact_ids_without_scan=artefact_ids_without_scan,
        latest_processing_date=latest_processing_date,
        sprint_name='Overdue' if is_overdue else sprint_name,
    )

    for issue_template_cfg in issue_replicator_config.github_issue_template_cfgs:
        if issue_template_cfg.type == issue_type:
            break
    else:
        raise ValueError(f'no template for {issue_type=}')

    body = issue_template_cfg.body.format(**template_variables)

    if is_overdue:
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


def _create_or_update_or_close_issue_per_finding(
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    issue_type: str,
    artefacts: collections.abc.Iterable[dso.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    issues: tuple[github3.issues.issue.ShortIssue],
    milestone: github3.issues.milestone.Milestone,
    failed_milestones: None | list[github3.issues.milestone.Milestone],
    latest_processing_date: datetime.date,
    is_scanned: bool,
    artefact_ids_without_scan: set[dso.model.LocalArtefactId],
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

        finding_issues: tuple[github3.issues.issue.ShortIssue] = tuple(gci.enumerate_issues(
            known_issues=issues,
            issue_type=issue_type,
            extra_labels=finding_labels,
        ))
        processed_issues.update(finding_issues)

        _create_or_update_issue(
            cfg_name=cfg_name,
            issue_replicator_config=issue_replicator_config,
            component_descriptor_lookup=component_descriptor_lookup,
            issue_type=issue_type,
            artefacts=artefacts,
            findings=(finding,),
            issues=finding_issues,
            milestone=milestone,
            failed_milestones=failed_milestones,
            latest_processing_date=latest_processing_date,
            is_scanned=is_scanned,
            artefact_ids_without_scan=artefact_ids_without_scan,
            extra_title=data.key,
            sprint_name=sprint_name,
            assignees=assignees,
            assignees_statuses=assignees_statuses,
            labels=finding_labels,
        )

    for issue in issues:
        if issue not in processed_issues and issue.state == 'open':
            close_issue_if_present(
                issue_replicator_config=issue_replicator_config,
                issue=issue,
                closing_reason=IssueComments.NO_FINDINGS,
            )


def create_or_update_or_close_issue(
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    finding_type_issue_replication_cfg: config.FindingTypeIssueReplicationCfgBase,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    issue_type: str,
    artefacts: collections.abc.Iterable[dso.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    correlation_id: str,
    latest_processing_date: datetime.date,
    is_in_bom: bool,
    artefact_ids_without_scan: set[dso.model.LocalArtefactId],
):
    is_scanned = len(artefact_ids_without_scan) == 0

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

    if not is_in_bom:
        for issue in issues:
            close_issue_if_present(
                issue_replicator_config=issue_replicator_config,
                issue=issue,
                closing_reason=IssueComments.NOT_IN_BOM,
            )
        return

    if is_scanned and not findings:
        for issue in issues:
            close_issue_if_present(
                issue_replicator_config=issue_replicator_config,
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

    if milestone:
        sprint_name = milestone.title.lstrip('sprint-')
    else:
        sprint_name = None

    if finding_type_issue_replication_cfg.enable_issue_per_finding:
        return _create_or_update_or_close_issue_per_finding(
            cfg_name=cfg_name,
            issue_replicator_config=issue_replicator_config,
            component_descriptor_lookup=component_descriptor_lookup,
            issue_type=issue_type,
            artefacts=artefacts,
            findings=findings,
            issues=issues,
            milestone=milestone,
            failed_milestones=failed_milestones,
            latest_processing_date=latest_processing_date,
            is_scanned=is_scanned,
            artefact_ids_without_scan=artefact_ids_without_scan,
            sprint_name=sprint_name,
            assignees=assignees,
            assignees_statuses=assignees_statuses,
            labels=labels,
        )

    return _create_or_update_issue(
        cfg_name=cfg_name,
        issue_replicator_config=issue_replicator_config,
        component_descriptor_lookup=component_descriptor_lookup,
        issue_type=issue_type,
        artefacts=artefacts,
        findings=findings,
        issues=issues,
        milestone=milestone,
        failed_milestones=failed_milestones,
        latest_processing_date=latest_processing_date,
        is_scanned=is_scanned,
        artefact_ids_without_scan=artefact_ids_without_scan,
        sprint_name=sprint_name,
        assignees=assignees,
        assignees_statuses=assignees_statuses,
        labels=labels,
    )
