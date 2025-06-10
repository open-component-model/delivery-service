import collections
import collections.abc
import dataclasses
import enum
import datetime
import functools
import hashlib
import json
import logging
import re
import textwrap
import time
import urllib.parse

import github3
import github3.issues.issue
import github3.issues.milestone
import github3.repos

import cnudie.iter
import cnudie.retrieve
import delivery.client
import delivery.model
import github.compliance.milestone as gcmi
import github.limits
import github.retry
import github.util
import ocm.util

import k8s.util
import odg.extensions_cfg
import odg.findings
import odg.model
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
    finding: odg.model.ArtefactMetadata
    rescorings: list[odg.model.ArtefactMetadata] = dataclasses.field(default_factory=list)
    due_date: datetime.date | None = None

    @property
    def severity(self) -> str:
        if self.rescorings:
            return self.rescorings[0].data.severity

        return self.finding.data.severity


@dataclasses.dataclass
class FindingGroup:
    artefact: odg.model.ComponentArtefactId
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


def _issue_milestone(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    delivery_client: delivery.client.DeliveryServiceClient,
    due_date: datetime.date,
) -> tuple[github3.issues.milestone.Milestone | None, list[github3.issues.milestone.Milestone]]:
    sprints = gcmi.target_sprints(
        delivery_svc_client=delivery_client,
        due_date=due_date,
    )

    return gcmi.find_or_create_sprint_milestone(
        repo=mapping.repository,
        sprints=sprints,
        milestone_cfg=mapping.milestones,
    )


def _artefact_to_str(
    artefact: odg.model.ComponentArtefactId,
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
    component_artefact_id: odg.model.ComponentArtefactId,
    finding_type: odg.model.Datatype,
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
            finding_details: odg.model.MalwareFindingDetails = af.finding.data.finding
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
            sast_finding: odg.model.SastFinding = af.finding.data
            sast_status = sast_finding.sast_status
            sub_type = sast_finding.sub_type
            severity = sast_finding.severity

            if sub_type is odg.model.SastSubType.LOCAL_LINTING:
                issue_text = 'No evidence about SAST-linting was found.'
            elif sub_type is odg.model.SastSubType.CENTRAL_LINTING:
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

        finding_rule = finding.finding.data
        finding_str = '\n'
        finding_str += '# Failed rule summary\n'
        finding_str += '|    |    |\n'
        finding_str += '| -- | -- |\n'
        finding_str += f'| Ruleset ID | {finding_rule.ruleset_id} |\n'
        finding_str += f'| Ruleset Name | {finding_rule.ruleset_name} |\n'
        finding_str += f'| Ruleset Version | {finding_rule.ruleset_version} |\n'
        finding_str += f'| Rule ID | {finding_rule.rule_id} |\n'
        finding_str += f'| Rule Name | {finding_rule.rule_name} |\n'
        finding_str += f'| Severity | {finding_rule.severity} |\n'

        rule_desc = ""
        match finding_rule.ruleset_id:
            case "disa-kubernetes-stig":
                rule_desc = f'[DISA STIG viewer - {finding_rule.rule_id}](https://stigviewer.com/stigs/kubernetes/2024-08-22/finding/V-{finding_rule.rule_id})'  # noqa: E501
            case "security-hardened-shoot-cluster":
                diki_vers_for_ruleset_vers = {
                    'v0.1.0': 'v0.14.0',
                    'v0.2.0': 'v0.15.0',
                    'v0.2.1': 'v0.15.1',
                }
                diki_version = diki_vers_for_ruleset_vers.get(finding_rule.ruleset_version, 'main')

                rule_desc = f'[Security Hardened Shoot Cluster Guide - {finding_rule.rule_id}](https://github.com/gardener/diki/blob/{diki_version}/docs/rulesets/security-hardened-shoot-cluster/ruleset.md#{finding_rule.rule_id})' # noqa: E501
            case "security-hardened-k8s":
                diki_vers_for_ruleset_vers = {
                    'v0.1.0': 'v0.15.0',
                }
                diki_version = diki_vers_for_ruleset_vers.get(finding_rule.ruleset_version, 'main')

                rule_desc = f'[Security Hardened Kubernetes Cluster Guide - {finding_rule.rule_id}](https://github.com/gardener/diki/blob/{diki_version}/docs/rulesets/security-hardened-k8s/ruleset.md#{finding_rule.rule_id})' # noqa: E501
        if len(rule_desc) > 0:
            finding_str += f'| Rule Description | {rule_desc} |\n'
        finding_str += '\n'
        finding_str += '### Failed checks:\n'

        summary += finding_str
        shortened_summary += finding_str

        for check in finding_rule.checks:
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


def _crypto_template_vars(
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str,
    sprint_name: str | None=None,
) -> dict[str, str]:
    summary += '# Summary of found crypto issues'

    def iter_findings(
        aggragated_findings: tuple[AggregatedFinding],
    ) -> collections.abc.Generator[tuple[str, str, str, str, list[str]], None, None]:
        for af in sorted(
            aggragated_findings,
            key=lambda af: (
                af.finding.data.standard,
                af.finding.data.asset.asset_type,
                af.finding.data.severity,
                sorted(af.finding.data.asset.names),
            ),
        ):
            crypto_finding: odg.model.CryptoFinding = af.finding.data

            standard = crypto_finding.standard
            asset_type = crypto_finding.asset.asset_type
            severity = crypto_finding.severity
            names = [name for name in crypto_finding.asset.names if name]

            yield standard, asset_type, severity, names

    for finding_group in finding_groups:
        summary += '\n' + finding_group.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            finding_cfg=finding_cfg,
            sprint_name=sprint_name,
        )

        summary += (
            '\n| Standard | Asset Type | Severity | Names |'
            '\n| -------- | ---------- | :------: | ----- |'
        )
        for standard, asset_type, severity, names in iter_findings(
            aggragated_findings=finding_group.findings,
        ):
            summary += textwrap.dedent(f'''
                | `{standard}` | `{asset_type}` | `{severity}` | \
                {', <br/>'.join(f'`{name}`' for name in sorted(names))} | \
            ''')

        summary += '\n---'

    return {
        'summary': summary,
    }


def _osid_template_vars(
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    summary: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str,
    sprint_name: str | None=None,
) -> dict[str, str]:
    summary += '# Summary of found Issues related to Operating-System versioning policies'

    def iter_findings(
        aggregated_findings: tuple[AggregatedFinding],
    ) -> collections.abc.Generator[tuple[str, str, str, str], None, None]:
        for af in aggregated_findings:
            osid_finding: odg.model.OsIdFinding = af.finding.data
            os_name = osid_finding.osid.NAME
            greatest_version = osid_finding.greatest_version
            detected_version = osid_finding.osid.VERSION_ID
            issue_text = osid_finding.status_description

            yield os_name, detected_version, greatest_version, issue_text

    for finding_group in finding_groups:
        summary += '\n' + finding_group.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            finding_cfg=finding_cfg,
            sprint_name=sprint_name,
        )

        summary += (
            '\n| OS Name | Detected Version | Greatest Version | Issue Text |'
            '\n| --- | --- | --- | --- |'
        )
        for os_name, detected_version, greatest_version, issue_text in iter_findings(
            aggregated_findings=finding_group.findings
        ):
            summary += (
                f'\n| {os_name} | {detected_version} | {greatest_version} | {issue_text} |'
            )

        summary += '\n---'

    return {
        'summary': summary,
    }


def _inventory_template_vars(finding_groups: list[FindingGroup], summary: str) -> dict[str, str]:
    findings: list[AggregatedFinding] = []
    for finding_group in finding_groups:
        findings.extend(finding_group.findings)

    summary += '\n'
    for item in findings:
        data = item.finding.data
        summary += f'# {data.summary} - {data.provider_name} - {data.resource_name}\n'
        summary += '|    |    |\n'
        summary += '| -- | -- |\n'
        for k, v in data.attributes.items():
            summary += f'| {k} | {v} |\n'

    return {
        'summary': summary,
    }


def _falco_template_vars(finding_groups: list[FindingGroup], summary: str) -> dict[str, str]:
    for finding_group in finding_groups:
        finding_group: FindingGroup
        for aggregated_finding in finding_group.findings:
            aggregated_finding: AggregatedFinding
            am: odg.model.ArtefactMetadata = aggregated_finding.finding
            finding: odg.model.FalcoFinding = am.data
            content = _falco_process_event(finding)

    return content


def _falco_process_event(finding: odg.model.FalcoFinding) -> dict[str, str]:
    content = ""
    if finding.subtype == odg.model.FalcoFindingSubType.EVENT_GROUP:
        content = _falco_gen_event_content(finding)
    elif finding.subtype == odg.model.FalcoFindingSubType.INTERACTIVE_EVENT_GROUP:
        content = _falco_gen_interactive_content(finding)

    return content


def _falco_gen_interactive_content(finding: odg.model.FalcoFinding) -> dict[str, str]:
    title = "# Falco Interactive Event Group Detected"
    text = """
An interactive session was detected on the cluster. This may be a legitimate action
(e.g., an interactive debug session) or could indicate suspicious activity.

**Actions required:**
- Confirm the session was initiated by you by reviewing the event stream.
- Check the time and activity to ensure they match your actions.
- If the session was legitimate, triage this ticket using the available methods.
- If the session was not initiated by you, or the activity does not match, notify the
security team.

**Do not close this ticket manually; it will be updated automatically.**
"""

    info = (
        "### Summary:\n"
        "\n"
        f"- **Landscape:** {finding.finding.landscape}\n"
        f"- **Project:** {finding.finding.project}\n"
        f"- **Cluster:** {finding.finding.cluster}\n"
        f"- **Hostname:** {finding.finding.hostname}\n"
        f"- **Event count:** {finding.finding.count}\n"
        f"- **Hash:** `{finding.finding.group_hash}`\n"
    )

    finding_content: odg.model.FalcoInteractiveEventGroup = finding.finding
    events = _build_falco_interactive_event_content(finding_content)

    content = {"title": title, "text": text, "info": info, "events": events}
    return content


def _falco_gen_event_content(finding: odg.model.FalcoFinding) -> dict[str, str]:
    title = "# Falco Event Group Detected"
    text = """One or more Falco events were detected in the landscape. These events may
be false positives or could indicate an
attack.

**Please take the following actions:**
- Review the event stream to determine if the events are false positives.
- If they are false positives, triage this ticket using the available methods.
- Implement a Falco exception as suggested in this ticket.
- If you cannot confirm the events are false positives, inform the security team.

If you triage this ticket, no new tickets for similar events will be created for the next 30 days.

**Do not close this ticket manually; it will be updated automatically.**
"""

    # finding_content: odg.model.FalcoEventGroup = finding.finding
    content = {"title": title, "text": text}

    return content


def _build_falco_interactive_event_content(finding_content: odg.model.FalcoEventGroup) -> str:
    events = "### Events:\n\n"
    for i, event in enumerate(finding_content.events):
        output_lines = [f"{k}: {v}" for k, v in event.output.items()]
        output_block = "```\n" + "\n".join(output_lines) + "\n```"

        event_str = (
            f"- **Rule:** {event.rule}\n"
            f"- **Time:** {event.time}\n"
            f"- **Message:** `{event.message}`\n"
            + "<blockquote>\n"
            + _markdown_collapsible_section(summary="Output Fields", details_markdown=output_block)
            + "</blockquote>\n"
        )

        events += (
            _markdown_collapsible_section(summary=f"Event {i}", details_markdown=event_str) + "\n\n"
        )
    return events


def _markdown_collapsible_section(summary: str, details_markdown: str) -> str:
    return (
        "<details>\n"
        f"<summary><strong>{summary}</strong></summary>\n\n"
        f"{details_markdown}\n"
        "</details>\n"
    )


def _template_vars(
    finding_cfg: odg.findings.Finding,
    artefacts: collections.abc.Iterable[odg.model.ComponentArtefactId],
    artefacts_without_scan: collections.abc.Iterable[odg.model.ComponentArtefactId],
    findings: collections.abc.Sequence[AggregatedFinding],
    due_date: datetime.date,
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

    summary += f'| Due Date | {due_date} |\n'

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

    if finding_cfg.type is odg.model.Datatype.VULNERABILITY_FINDING:
        template_variables |= _vulnerability_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.model.Datatype.LICENSE_FINDING:
        template_variables |= _license_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.model.Datatype.MALWARE_FINDING:
        template_variables |= _malware_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.model.Datatype.SAST_FINDING:
        template_variables |= _sast_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.model.Datatype.DIKI_FINDING:
        template_variables |= _diki_template_vars(
            finding_groups=finding_groups,
            summary=summary,
        )
    elif finding_cfg.type is odg.model.Datatype.CRYPTO_FINDING:
        template_variables |= _crypto_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.model.Datatype.OSID_FINDING:
        template_variables |= _osid_template_vars(
            finding_cfg=finding_cfg,
            finding_groups=finding_groups,
            summary=summary,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
    elif finding_cfg.type is odg.model.Datatype.INVENTORY_FINDING:
        template_variables |= _inventory_template_vars(
            finding_groups=finding_groups,
            summary=summary,
        )
    elif finding_cfg.type is odg.model.Datatype.FALCO_FINDING:
        template_variables |= _falco_template_vars(
            finding_groups=finding_groups,
            summary=summary,
        )
    else:
        template_variables |= {
            'summary': summary,
        }

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
    title: str,
    labels: set[str],
    assignees: set[str],
    assignee_mode: odg.model.ResponsibleAssigneeModes,
    milestone: github3.issues.milestone.Milestone,
):
    kwargs = {
        'state': 'open',
        'labels': sorted(labels),
    }

    if title:
        kwargs['title'] = title

    if assignee_mode is odg.model.ResponsibleAssigneeModes.EXTEND:
        assignees |= set(issue.assignees)
        # conversion to tuple required for issue update (JSON serialisation)
        kwargs['assignees'] = tuple(assignees)
    elif assignee_mode is odg.model.ResponsibleAssigneeModes.OVERWRITE:
        kwargs['assignees'] = tuple(assignees)
    elif assignee_mode is odg.model.ResponsibleAssigneeModes.SKIP:
        if not issue.assignees:
            kwargs['assignees'] = tuple(assignees)
    else:
        raise ValueError(f'unknown {assignee_mode=}')

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
    assignees_statuses: set[delivery.model.Status] | None,
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
    artefacts: tuple[odg.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    issues: tuple[github3.issues.issue.ShortIssue],
    milestone: github3.issues.milestone.Milestone | None,
    failed_milestones: list[github3.issues.milestone.Milestone],
    due_date: datetime.date,
    is_scanned: bool,
    artefacts_without_scan: set[odg.model.ComponentArtefactId],
    delivery_dashboard_url: str,
    sprint_name: str,
    assignees: set[str],
    assignees_statuses: set[delivery.model.Status] | None,
    assignee_mode: odg.model.ResponsibleAssigneeModes,
    labels: set[str],
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

    is_overdue = due_date < datetime.date.today()

    template_variables = _template_vars(
        finding_cfg=finding_cfg,
        component_descriptor_lookup=component_descriptor_lookup,
        artefacts=artefacts,
        findings=findings,
        artefacts_without_scan=artefacts_without_scan,
        due_date=due_date,
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
            assignee_mode=assignee_mode,
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
    artefacts: collections.abc.Iterable[odg.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    issue_id: str,
    issues: tuple[github3.issues.issue.ShortIssue],
    milestone: github3.issues.milestone.Milestone,
    failed_milestones: None | list[github3.issues.milestone.Milestone],
    due_date: datetime.date,
    is_scanned: bool,
    artefacts_without_scan: set[odg.model.ComponentArtefactId],
    delivery_dashboard_url: str,
    sprint_name: str,
    assignees: set[str],
    assignees_statuses: set[delivery.model.Status] | None,
    assignee_mode: odg.model.ResponsibleAssigneeModes,
    labels: set[str],
):
    processed_issues = set()
    for finding in findings:
        data = finding.finding.data

        data_digest = hashlib.shake_128(
            data.key.encode(),
            usedforsecurity=False,
        ).hexdigest(int(github.limits.label / 2))

        finding_labels = labels | {data_digest}

        if len(data.key) <= github.limits.label:
            # XXX required for backwards compatibility, remove once all existing issues have the
            # digest-based data key label set
            finding_labels |= {data.key}
            labels_for_filtering = (issue_id, finding_cfg.type, data.key)
        else:
            labels_for_filtering = (issue_id, finding_cfg.type, data_digest)

        finding_issues = filter_issues_for_labels(
            issues=issues,
            labels=labels_for_filtering,
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
            due_date=due_date,
            is_scanned=is_scanned,
            artefacts_without_scan=artefacts_without_scan,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
            assignees=assignees,
            assignees_statuses=assignees_statuses,
            assignee_mode=assignee_mode,
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
    artefacts: collections.abc.Iterable[odg.model.ComponentArtefactId],
    findings: tuple[AggregatedFinding],
    issue_id: str,
    due_date: datetime.date,
    is_in_bom: bool,
    artefacts_without_scan: set[odg.model.ComponentArtefactId],
    delivery_dashboard_url: str,
    assignees: set[str],
    assignees_statuses: set[delivery.model.Status] | None,
    assignee_mode: odg.model.ResponsibleAssigneeModes,
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

    milestone, failed_milestones = _issue_milestone(
        mapping=mapping,
        delivery_client=delivery_client,
        due_date=due_date,
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
            due_date=due_date,
            is_scanned=is_scanned,
            artefacts_without_scan=artefacts_without_scan,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
            assignees=assignees,
            assignees_statuses=assignees_statuses,
            assignee_mode=assignee_mode,
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
        due_date=due_date,
        is_scanned=is_scanned,
        artefacts_without_scan=artefacts_without_scan,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
        assignees=assignees,
        assignees_statuses=assignees_statuses,
        assignee_mode=assignee_mode,
        labels=labels,
    )
