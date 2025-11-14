import collections
import collections.abc
import copy
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

import cnudie.retrieve
import delivery.client
import delivery.model
import github.compliance.milestone as gcmi
import github.limits
import github.retry
import github.util
import ocm.iter
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
    historical_due_dates: list[datetime.date | None] = dataclasses.field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.rescorings:
            return self.rescorings[0].data.severity

        return self.finding.data.severity


@dataclasses.dataclass
class FindingGroup:
    artefact: odg.model.ComponentArtefactId
    findings: tuple[AggregatedFinding]
    historical_findings: tuple[AggregatedFinding]

    def summary(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        finding_cfg: odg.findings.Finding,
        delivery_dashboard_url: str | None=None,
        sprint_name: str | None=None,
    ) -> str:
        ocm_node = k8s.util.get_ocm_node(
            component_descriptor_lookup=component_descriptor_lookup,
            artefact=self.artefact,
            absent_ok=True,
        )

        artefact_non_group_properties = finding_cfg.issues.strip_artefact(
            artefact=self.artefact,
            keep_group_attributes=False,
        )

        summary = textwrap.dedent(f'''\
            {_artefact_to_str(artefact_non_group_properties)}
            {_artefact_url(ocm_node=ocm_node)}

        ''')

        if delivery_dashboard_url:
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

    repo = odg.extensions_cfg.github_repository(mapping.github_repository)

    return gcmi.find_or_create_sprint_milestone(
        repo=repo,
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
    ocm_node: ocm.iter.ArtefactNode | None,
) -> str:
    if not ocm_node:
        return ''

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


def _severity_str(
    aggregated_finding: AggregatedFinding,
    finding_group: FindingGroup,
    finding_cfg: odg.findings.Finding,
) -> str:
    categorisation = finding_cfg.categorisation_by_id(aggregated_finding.severity)

    if aggregated_finding.rescorings:
        return f'`{categorisation.display_name}` (rescored)'

    return f'`{categorisation.display_name}`'


def _rescoring_comment(
    aggregated_finding: AggregatedFinding,
    finding_group: FindingGroup,
) -> str:
    if not aggregated_finding.rescorings:
        return ''

    if not (comment := aggregated_finding.rescorings[0].data.comment):
        return ''

    return comment


def _issue_ref(
    due_date: datetime.date | None,
    artefact: odg.model.ComponentArtefactId,
    finding_cfg: odg.findings.Finding,
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    additional_labels: collections.abc.Iterable[str] | None=None,
) -> str:
    if not due_date:
        return '' # finding is already resolved -> no open issue left

    issue_id = finding_cfg.issues.issue_id(
        artefact=artefact,
        due_date=due_date,
    )

    labels = [issue_id, finding_cfg.type]
    if additional_labels:
        labels.extend(additional_labels)

    if not (matching_issues := filter_issues_for_labels(
        issues=known_issues,
        labels=labels,
    )):
        return ''

    issue_number = matching_issues[0].number

    return f'[#{issue_number}](https://{mapping.github_repository}/issues/{issue_number})'


TableColumnHeader = str
TableCellContent = str
TableCallback = dict[
    TableColumnHeader,
    collections.abc.Callable[[AggregatedFinding, FindingGroup], TableCellContent],
]


def table_callback_to_table(
    finding_group: FindingGroup,
    aggregated_findings: tuple[AggregatedFinding],
    table_callback: TableCallback | None=None,
) -> str:
    if not table_callback or not aggregated_findings:
        return ''

    column_names = table_callback.keys()
    column_callbacks = table_callback.values()

    table = '| ' + ' | '.join(column_names) + ' |\n'
    table += '| ' + ' | '.join('---' for _ in column_names) + ' |\n'

    for af in aggregated_findings:
        table += '| ' + ' | '.join(callback(af, finding_group) for callback in column_callbacks) + ' |\n' # noqa: E501

    return table


def findings_summary(
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    findings_table_callback: TableCallback | None=None,
    historical_findings_table_callback: TableCallback | None=None,
    report_urls_callback: collections.abc.Callable[[FindingGroup], list[str]] | None=None,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    '''
    Creates summaries (long, normal, short) for the specified finding type and finding groups with
    the following structure for each finding group:

    - artefact-id of the finding group
    - link to the rescoring UI of the delivery-dashboard -> `delivery_dashboard_url`
    - list of report url (long & normal only) -> `report_urls_callback`
    - table containing all belonging findings (long & normal only) -> `findings_table_callback`
    - table containing all historical findings (long) -> `historical_findings_table_callback`
    '''
    finding_name = finding_cfg.type.removeprefix('finding/')
    summary_long = summary = summary_short = f'# Summary of found {finding_name} findings\n'

    for finding_group in finding_groups:
        group_summary = finding_group.summary(
            component_descriptor_lookup=component_descriptor_lookup,
            finding_cfg=finding_cfg,
            delivery_dashboard_url=delivery_dashboard_url,
            sprint_name=sprint_name,
        )
        summary_long += group_summary
        summary += group_summary
        summary_short += group_summary

        if report_urls_callback:
            report_urls = '\n'.join(report_urls_callback(finding_group)) + '\n'
            summary_long += report_urls
            summary += report_urls

        findings_table = table_callback_to_table(
            finding_group=finding_group,
            aggregated_findings=finding_group.findings,
            table_callback=findings_table_callback,
        )
        summary_long += findings_table
        summary += findings_table

        if finding_group.historical_findings and historical_findings_table_callback:
            historical_findings_table = '<details><summary>Historical Findings</summary>\n\n'
            historical_findings_table += table_callback_to_table(
                finding_group=finding_group,
                aggregated_findings=finding_group.historical_findings,
                table_callback=historical_findings_table_callback,
            )
            historical_findings_table += '</details>\n'

            summary_long += historical_findings_table

        summary_long += '\n---\n'
        summary += '\n---\n'
        summary_short += '\n---\n'

    return summary_long, summary, summary_short


def fallback_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    def default_callback(
        aggregated_finding: AggregatedFinding,
        finding_group: FindingGroup,
        attr: str,
    ) -> str:
        value = getattr(aggregated_finding.finding.data, attr)

        if isinstance(value, (str, int, float)):
            return f'`{value}`'.replace('\n', ' ')
        return util.dict_to_json_factory(value).replace('\n', ' ')

    finding_table_callback = {
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
    }
    if finding_groups and finding_groups[0].findings:
        aggregated_finding = finding_groups[0].findings[0]
        raw = dataclasses.asdict(aggregated_finding.finding.data)
        for key in raw.keys():
            title = key.title().replace('_', ' ')
            if title in finding_table_callback:
                continue # don't overwrite explicitly set callbacks
            callback = functools.partial(default_callback, attr=key)
            finding_table_callback[title] = callback

    historical_table_callback = {
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Due Date': lambda f, _: f'`{f.due_date.isoformat()}`' if f.due_date else '',
        'Reason': _rescoring_comment,
        'Ref': lambda f, g: _issue_ref(
            due_date=f.due_date,
            artefact=g.artefact,
            finding_cfg=finding_cfg,
            known_issues=known_issues,
            mapping=mapping,
        ),
    }
    if finding_groups and finding_groups[0].historical_findings:
        aggregated_finding = finding_groups[0].historical_findings[0]
        raw = dataclasses.asdict(aggregated_finding.finding.data)
        for key in raw.keys():
            title = key.title().replace('_', ' ')
            if title in historical_table_callback:
                continue # don't overwrite explicitly set callbacks
            callback = functools.partial(default_callback, attr=key)
            historical_table_callback[title] = callback

    return findings_summary(
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        component_descriptor_lookup=component_descriptor_lookup,
        findings_table_callback=finding_table_callback,
        historical_findings_table_callback=historical_table_callback,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )


def crypto_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    def names_str(
        aggregated_finding: AggregatedFinding,
        finding_group: FindingGroup,
    ) -> str:
        return '<br/>'.join(sorted(
            f'`{name}`'
            for name in aggregated_finding.finding.data.asset.names
            if name
        ))

    finding_table_callback = {
        'Standard': lambda f, _: f'`{f.finding.data.standard}`',
        'Asset Type': lambda f, _: f'`{f.finding.data.asset.asset_type}`',
        'Names': names_str,
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
    }

    historical_table_callback = {
        'Standard': lambda f, _: f'`{f.finding.data.standard}`',
        'Asset Type': lambda f, _: f'`{f.finding.data.asset.asset_type}`',
        'Names': names_str,
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Due Date': lambda f, _: f'`{f.due_date.isoformat()}`' if f.due_date else '',
        'Reason': _rescoring_comment,
        'Ref': lambda f, g: _issue_ref(
            due_date=f.due_date,
            artefact=g.artefact,
            finding_cfg=finding_cfg,
            known_issues=known_issues,
            mapping=mapping,
        ),
    }

    return findings_summary(
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        component_descriptor_lookup=component_descriptor_lookup,
        findings_table_callback=finding_table_callback,
        historical_findings_table_callback=historical_table_callback,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )


def diki_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    def _targets_table(
        targets: list[dict],
    ) -> str:
        unique_keys = set()
        for target in targets:
            unique_keys.update(target.keys())
        unique_keys = list(unique_keys)
        unique_keys.sort()
        if 'details' in unique_keys:
            unique_keys.remove('details')
            unique_keys.append('details')

        table = '| ' + ' | '.join(key.title() for key in unique_keys) + ' |\n'
        table += '| ' + ' | '.join(':-:' for _ in unique_keys) + ' |\n'

        for target in targets:
            table += '| ' + ' | '.join(target.get(key, '') for key in unique_keys) + ' |\n'

        return table

    summary_long = summary = summary_short = '# Summary of found diki findings\n'

    for finding_group in finding_groups:
        for aggregated_finding in finding_group.findings:
            finding_rule: odg.model.DikiFinding = aggregated_finding.finding.data

            severity = _severity_str(
                aggregated_finding=aggregated_finding,
                finding_group=finding_group,
                finding_cfg=finding_cfg,
            )

            finding_str = textwrap.dedent(f'''\
                ## Failed rule summary
                |    |    |
                | -- | -- |
                | Ruleset ID | {finding_rule.ruleset_id} |
                | Ruleset Name | {finding_rule.ruleset_name} |
                | Ruleset Version | {finding_rule.ruleset_version} |
                | Rule ID | {finding_rule.rule_id} |
                | Rule Name | {finding_rule.rule_name} |
            ''')

            if finding_rule.ruleset_id == 'disa-kubernetes-stig':
                rule_desc = f'[DISA STIG viewer - {finding_rule.rule_id}](https://stigviewer.com/stigs/kubernetes/2024-08-22/finding/V-{finding_rule.rule_id})' # noqa: E501
            elif finding_rule.ruleset_id == 'security-hardened-shoot-cluster':
                diki_version = {
                    'v0.1.0': 'v0.14.0',
                    'v0.2.0': 'v0.15.0',
                    'v0.2.1': 'v0.15.1',
                }.get(finding_rule.ruleset_version, 'main')

                rule_desc = f'[Security Hardened Shoot Cluster Guide - {finding_rule.rule_id}](https://github.com/gardener/diki/blob/{diki_version}/docs/rulesets/security-hardened-shoot-cluster/ruleset.md#{finding_rule.rule_id})' # noqa: E501
            elif finding_rule.ruleset_id == 'security-hardened-k8s':
                diki_version = {
                    'v0.1.0': 'v0.15.0',
                }.get(finding_rule.ruleset_version, 'main')

                rule_desc = f'[Security Hardened Kubernetes Cluster Guide - {finding_rule.rule_id}](https://github.com/gardener/diki/blob/{diki_version}/docs/rulesets/security-hardened-k8s/ruleset.md#{finding_rule.rule_id})' # noqa: E501
            else:
                rule_desc = None

            if rule_desc:
                finding_str += f'| Rule Description | {rule_desc} |\n'

            if discovery_date := aggregated_finding.finding.discovery_date:
                finding_str += f'| Initial Discovery Date | {discovery_date.isoformat()} |\n'

            finding_str += f'| Severity | {severity} |\n'

            if rescoring_comment := _rescoring_comment(
                aggregated_finding=aggregated_finding,
                finding_group=finding_group,
            ):
                finding_str += f'| Rescoring Comment | {rescoring_comment} |\n'

            data_digest = hashlib.shake_128(
                finding_rule.key.encode(),
                usedforsecurity=False,
            ).hexdigest(int(github.limits.label / 2))

            issue_refs = []
            for historical_due_date in aggregated_finding.historical_due_dates:
                if issue_ref := _issue_ref(
                    due_date=historical_due_date,
                    artefact=finding_group.artefact,
                    finding_cfg=finding_cfg,
                    known_issues=known_issues,
                    mapping=mapping,
                    additional_labels=[data_digest],
                ):
                    issue_refs.append(issue_ref)
            if issue_refs:
                finding_str += f'| Issue Refs | {', '.join(sorted(issue_refs))} |\n'

            if delivery_dashboard_url:
                delivery_dashboard_url = _delivery_dashboard_url(
                    base_url=delivery_dashboard_url,
                    component_artefact_id=finding_group.artefact,
                    finding_type=finding_cfg.type,
                    sprint_name=sprint_name,
                )
                finding_str += f'\n[Delivery-Dashboard]({delivery_dashboard_url}) (use for assessments)\n' # noqa: E501

            summary_long += finding_str + '### Failed checks:\n'
            summary += finding_str + '### Failed checks:\n'
            summary_short += finding_str

            for check in finding_rule.checks:
                check_msg_str = textwrap.dedent(f'''
                    Message: {check.message}
                    Targets:
                ''')

                summary_long += check_msg_str
                summary += check_msg_str

                if not check.targets:
                    summary_long += 'n/a\n'
                    summary += 'n/a\n'

                elif isinstance(check.targets, dict):
                    # process merged checks
                    for key, value in check.targets.items():
                        if value:
                            summary_long += f'<details><summary>{key}:</summary>\n\n'
                            summary_long += _targets_table(value)
                            summary_long += '</details>\n\n'
                            summary += f'**{key}**: {len(value)} targets\n'
                        else:
                            summary_long += f'**{key}**\n'
                            summary += f'**{key}**\n'

                elif isinstance(check.targets, list):
                    # process single checks
                    summary_long += _targets_table(check.targets)
                    summary += f'{len(check.targets)} targets\n'

                else:
                    raise TypeError(check.targets) # this line should never be reached

    return summary_long, summary, summary_short


def falco_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    summary_long = summary = summary_short = '# Summary of found falco findings\n'

    for finding_group in finding_groups:
        for aggregated_finding in finding_group.findings:
            finding: odg.model.FalcoFinding = aggregated_finding.finding.data

            if finding.subtype is odg.model.FalcoFindingSubType.EVENT_GROUP:
                finding_title = '## Falco Event Group Detected'
            elif finding.subtype is odg.model.FalcoFindingSubType.INTERACTIVE_EVENT_GROUP:
                finding_title = '## Falco Interactive Event Group Detected'
            else:
                raise ValueError(finding.subtype)

            severity = _severity_str(
                aggregated_finding=aggregated_finding,
                finding_group=finding_group,
                finding_cfg=finding_cfg,
            )

            finding_str = textwrap.dedent(f'''\
                {finding_title}
                |    |    |
                | -- | -- |
                | Severity | {severity} |
            ''')

            if rescoring_comment := _rescoring_comment(
                aggregated_finding=aggregated_finding,
                finding_group=finding_group,
            ):
                finding_str += f'| Rescoring Comment | {rescoring_comment} |\n'

            data_digest = hashlib.shake_128(
                finding.key.encode(),
                usedforsecurity=False,
            ).hexdigest(int(github.limits.label / 2))

            issue_refs = []
            for historical_due_date in aggregated_finding.historical_due_dates:
                if issue_ref := _issue_ref(
                    due_date=historical_due_date,
                    artefact=finding_group.artefact,
                    finding_cfg=finding_cfg,
                    known_issues=known_issues,
                    mapping=mapping,
                    additional_labels=[data_digest],
                ):
                    issue_refs.append(issue_ref)
            if issue_refs:
                finding_str += f'| Issue Refs | {', '.join(sorted(issue_refs))} |\n'

            if delivery_dashboard_url:
                delivery_dashboard_url = _delivery_dashboard_url(
                    base_url=delivery_dashboard_url,
                    component_artefact_id=finding_group.artefact,
                    finding_type=finding_cfg.type,
                    sprint_name=sprint_name,
                )
                finding_str += f'\n\n[Delivery-Dashboard]({delivery_dashboard_url}) (use for assessments)\n' # noqa: E501

            finding_summary_long, finding_summary, finding_summary_short = finding.summary

            summary_long += finding_str + '\n' + finding_summary_long
            summary += finding_str + '\n' + finding_summary
            summary_short += finding_str + '\n' + finding_summary_short

    return summary_long, summary, summary_short


def ghas_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    finding_table_callback = {
        'Secret Type': lambda f, _: f'`{f.finding.data.secret_type}`',
        'Secret': lambda f, _: f'`{f.finding.data.secret}`',
        'Path': lambda f, _: f'`{f.finding.data.path}`',
        'Line': lambda f, _: f'`{f.finding.data.line}`',
        'Display Name': lambda f, _: f'`{f.finding.data.secret_type_display_name}`',
        'Ref': lambda f, _: f'[ref]({f.finding.data.html_url})',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
    }

    historical_table_callback = {
        'Secret Type': lambda f, _: f'`{f.finding.data.secret_type}`',
        'Secret': lambda f, _: f'`{f.finding.data.secret}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Due Date': lambda f, _: f'`{f.due_date.isoformat()}`' if f.due_date else '',
        'Reason': _rescoring_comment,
        'Ref': lambda f, g: _issue_ref(
            due_date=f.due_date,
            artefact=g.artefact,
            finding_cfg=finding_cfg,
            known_issues=known_issues,
            mapping=mapping,
        ),
    }

    return findings_summary(
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        component_descriptor_lookup=component_descriptor_lookup,
        findings_table_callback=finding_table_callback,
        historical_findings_table_callback=historical_table_callback,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )


def inventory_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    summary_long = summary = summary_short = '# Summary of found inventory findings\n'

    for finding_group in finding_groups:
        for aggregated_finding in finding_group.findings:
            finding: odg.model.InventoryFinding = aggregated_finding.finding.data

            severity = _severity_str(
                aggregated_finding=aggregated_finding,
                finding_group=finding_group,
                finding_cfg=finding_cfg,
            )

            finding_str = textwrap.dedent(f'''\
                ## {finding.summary} - {finding.provider_name} - {finding.resource_name}
                |    |    |
                | -- | -- |
            ''')

            for key, value in finding.attributes.items():
                finding_str += f'| {key.title().replace('_', ' ')} | {value} |\n'

            finding_str += f'| Severity | {severity} |\n'

            if rescoring_comment := _rescoring_comment(
                aggregated_finding=aggregated_finding,
                finding_group=finding_group,
            ):
                finding_str += f'| Rescoring Comment | {rescoring_comment} |\n'

            data_digest = hashlib.shake_128(
                finding.key.encode(),
                usedforsecurity=False,
            ).hexdigest(int(github.limits.label / 2))

            issue_refs = []
            for historical_due_date in aggregated_finding.historical_due_dates:
                if issue_ref := _issue_ref(
                    due_date=historical_due_date,
                    artefact=finding_group.artefact,
                    finding_cfg=finding_cfg,
                    known_issues=known_issues,
                    mapping=mapping,
                    additional_labels=[data_digest],
                ):
                    issue_refs.append(issue_ref)
            if issue_refs:
                finding_str += f'| Issue Refs | {', '.join(sorted(issue_refs))} |\n'

            if delivery_dashboard_url:
                delivery_dashboard_url = _delivery_dashboard_url(
                    base_url=delivery_dashboard_url,
                    component_artefact_id=finding_group.artefact,
                    finding_type=finding_cfg.type,
                    sprint_name=sprint_name,
                )
                finding_str += f'\n[Delivery-Dashboard]({delivery_dashboard_url}) (use for assessments)\n' # noqa: E501

            summary_long += finding_str
            summary += finding_str
            summary_short += finding_str

    return summary_long, summary, summary_short


def kyverno_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    summary_long = summary = summary_short = '# Summary of found kyverno findings\n'

    for finding_group in finding_groups:
        for aggregated_finding in finding_group.findings:
            finding: odg.model.KyvernoFinding = aggregated_finding.finding.data

            if finding.subtype is odg.model.KyvernoFindingSubType.POLICY_REPORT_SUMMARY:
                finding_title = '## Kyverno Policy Report Summary'
            elif finding.subtype is odg.model.KyvernoFindingSubType.POLICY_REPORT:
                finding_title = '## Kyverno Policy Report'
            else:
                raise ValueError(finding.subtype)

            severity = _severity_str(
                aggregated_finding=aggregated_finding,
                finding_group=finding_group,
                finding_cfg=finding_cfg,
            )

            finding_str = textwrap.dedent(f'''\
                {finding_title}
                |    |    |
                | -- | -- |
                | Severity | {severity} |
            ''')

            if rescoring_comment := _rescoring_comment(
                aggregated_finding=aggregated_finding,
                finding_group=finding_group,
            ):
                finding_str += f'| Rescoring Comment | {rescoring_comment} |\n'

            data_digest = hashlib.shake_128(
                finding.key.encode(),
                usedforsecurity=False,
            ).hexdigest(int(github.limits.label / 2))

            issue_refs = []
            for historical_due_date in aggregated_finding.historical_due_dates:
                if issue_ref := _issue_ref(
                    due_date=historical_due_date,
                    artefact=finding_group.artefact,
                    finding_cfg=finding_cfg,
                    known_issues=known_issues,
                    mapping=mapping,
                    additional_labels=[data_digest],
                ):
                    issue_refs.append(issue_ref)
            if issue_refs:
                finding_str += f'| Issue Refs | {', '.join(sorted(issue_refs))} |\n'

            if delivery_dashboard_url:
                delivery_dashboard_url = _delivery_dashboard_url(
                    base_url=delivery_dashboard_url,
                    component_artefact_id=finding_group.artefact,
                    finding_type=finding_cfg.type,
                    sprint_name=sprint_name,
                )
                finding_str += f'\n\n[Delivery-Dashboard]({delivery_dashboard_url}) (use for assessments)\n' # noqa: E501

            finding_summary_long, finding_summary, finding_summary_short = finding.summary

            summary_long += finding_str + '\n' + finding_summary_long
            summary += finding_str + '\n' + finding_summary
            summary_short += finding_str + '\n' + finding_summary_short

    return summary_long, summary, summary_short


def license_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    finding_table_callback = {
        'Affected Package': lambda f, _: f'`{f.finding.data.package_name}`',
        'Package Version': lambda f, _: f'`{f.finding.data.package_version}`',
        'License': lambda f, _: f'`{f.finding.data.license.name}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
    }

    historical_table_callback = {
        'Affected Package': lambda f, _: f'`{f.finding.data.package_name}`',
        'Package Version': lambda f, _: f'`{f.finding.data.package_version}`',
        'License': lambda f, _: f'`{f.finding.data.license.name}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Due Date': lambda f, _: f'`{f.due_date.isoformat()}`' if f.due_date else '',
        'Reason': _rescoring_comment,
        'Ref': lambda f, g: _issue_ref(
            due_date=f.due_date,
            artefact=g.artefact,
            finding_cfg=finding_cfg,
            known_issues=known_issues,
            mapping=mapping,
        ),
    }

    report_urls_callback = lambda finding_group: sorted({
        f'[BDBA {finding.finding.data.product_id}]({finding.finding.data.report_url})'
        for finding in finding_group.findings
    })

    return findings_summary(
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        component_descriptor_lookup=component_descriptor_lookup,
        findings_table_callback=finding_table_callback,
        historical_findings_table_callback=historical_table_callback,
        report_urls_callback=report_urls_callback,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )


def malware_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    finding_table_callback = {
        'Malware': lambda f, _: f'`{f.finding.data.finding.malware}`',
        'Filename': lambda f, _: f'`{f.finding.data.finding.filename}`',
        'Content Digest': lambda f, _: f'`{f.finding.data.finding.content_digest}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
    }

    historical_table_callback = {
        'Malware': lambda f, _: f'`{f.finding.data.finding.malware}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Due Date': lambda f, _: f'`{f.due_date.isoformat()}`' if f.due_date else '',
        'Reason': _rescoring_comment,
        'Ref': lambda f, g: _issue_ref(
            due_date=f.due_date,
            artefact=g.artefact,
            finding_cfg=finding_cfg,
            known_issues=known_issues,
            mapping=mapping,
        ),
    }

    return findings_summary(
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        component_descriptor_lookup=component_descriptor_lookup,
        findings_table_callback=finding_table_callback,
        historical_findings_table_callback=historical_table_callback,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )


def osid_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    finding_table_callback = {
        'OS Name': lambda f, _: f'`{f.finding.data.osid.NAME}`',
        'Detected Version': lambda f, _: f'`{f.finding.data.osid.VERSION_ID}`',
        'Greatest Version': lambda f, _: f'`{f.finding.data.greatest_version}`',
        'Issue Text': lambda f, _: f.finding.data.status_description,
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
    }

    historical_table_callback = {
        'OS Name': lambda f, _: f'`{f.finding.data.osid.NAME}`',
        'Detected Version': lambda f, _: f'`{f.finding.data.osid.VERSION_ID}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Due Date': lambda f, _: f'`{f.due_date.isoformat()}`' if f.due_date else '',
        'Reason': _rescoring_comment,
        'Ref': lambda f, g: _issue_ref(
            due_date=f.due_date,
            artefact=g.artefact,
            finding_cfg=finding_cfg,
            known_issues=known_issues,
            mapping=mapping,
        ),
    }

    return findings_summary(
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        component_descriptor_lookup=component_descriptor_lookup,
        findings_table_callback=finding_table_callback,
        historical_findings_table_callback=historical_table_callback,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )


def sast_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    def sub_type_to_description(
        sub_type: odg.model.SastSubType,
    ) -> str:
        if sub_type is odg.model.SastSubType.LOCAL_LINTING:
            return 'No evidence about SAST-linting was found.'
        elif sub_type is odg.model.SastSubType.CENTRAL_LINTING:
            return 'No central linting found.'
        return 'Unknown SAST issue subtype.'

    finding_table_callback = {
        'SAST Status': lambda f, _: f'`{f.finding.data.sast_status}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Sub Type': lambda f, _: f'`{f.finding.data.sub_type}`',
        'Issue Text': lambda f, _: sub_type_to_description(f.finding.data.sub_type),
    }

    historical_table_callback = {
        'SAST Status': lambda f, _: f'`{f.finding.data.sast_status}`',
        'Sub Type': lambda f, _: f'`{f.finding.data.sub_type}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Due Date': lambda f, _: f'`{f.due_date.isoformat()}`' if f.due_date else '',
        'Reason': _rescoring_comment,
        'Ref': lambda f, g: _issue_ref(
            due_date=f.due_date,
            artefact=g.artefact,
            finding_cfg=finding_cfg,
            known_issues=known_issues,
            mapping=mapping,
        ),
    }

    return findings_summary(
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        component_descriptor_lookup=component_descriptor_lookup,
        findings_table_callback=finding_table_callback,
        historical_findings_table_callback=historical_table_callback,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )


def vulnerability_summary(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    finding_groups: list[FindingGroup],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str | None=None,
    sprint_name: str | None=None,
) -> tuple[str, str, str]:
    def rescoring_suggestion(
        aggregated_finding: AggregatedFinding,
        finding_group: FindingGroup,
    ) -> str:
        if not aggregated_finding.finding.data.cvss:
            return ''

        if not finding_cfg.rescoring_ruleset or not finding_cfg.rescoring_ruleset.rules:
            return ''

        ocm_node = k8s.util.get_ocm_node(
            component_descriptor_lookup=component_descriptor_lookup,
            artefact=finding_group.artefact,
        )

        if not (cve_categorisation := rescore.utility.find_cve_categorisation(ocm_node)):
            return ''

        rules = tuple(rescore.utility.matching_rescore_rules(
            rescoring_rules=finding_cfg.rescoring_ruleset.rules,
            categorisation=cve_categorisation,
            cvss=aggregated_finding.finding.data.cvss,
        ))

        current_categorisation = odg.findings.categorise_finding(
            finding_cfg=finding_cfg,
            finding_property=aggregated_finding.finding.data.cvss_v3_score,
        )

        rescored_categorisation = rescore.utility.rescore_finding(
            finding_cfg=finding_cfg,
            current_categorisation=current_categorisation,
            rescoring_rules=rules,
            operations=finding_cfg.rescoring_ruleset.operations,
        )

        if rescored_categorisation.id == current_categorisation.id:
            return ''

        return f'`{rescored_categorisation.display_name}`'

    def package_versions_str(
        aggregated_finding: AggregatedFinding,
        finding_group: FindingGroup,
    ) -> str:
        return ', <br/>'.join(
            f'`{package_version}`'
            for package_version in sorted(
                aggregated_finding.finding.data.package_version,
                key=util.version_sorting_key,
            )
        )

    finding_table_callback = {
        'Affected Package': lambda f, _: f'`{f.finding.data.package_name}`',
        'CVE': lambda f, _: f'`{f.finding.data.cve}`',
        'CVE Score': lambda f, _: f'`{f.finding.data.cvss_v3_score}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Rescoring Suggestion': rescoring_suggestion,
        'Package Version(s)': package_versions_str,
    }

    historical_table_callback = {
        'Affected Package': lambda f, _: f'`{f.finding.data.package_name}`',
        'CVE': lambda f, _: f'`{f.finding.data.cve}`',
        'Severity': lambda f, g: _severity_str(
            aggregated_finding=f,
            finding_group=g,
            finding_cfg=finding_cfg,
        ),
        'Due Date': lambda f, _: f'`{f.due_date.isoformat()}`' if f.due_date else '',
        'Reason': _rescoring_comment,
        'Ref': lambda f, g: _issue_ref(
            due_date=f.due_date,
            artefact=g.artefact,
            finding_cfg=finding_cfg,
            known_issues=known_issues,
            mapping=mapping,
        ),
    }

    report_urls_callback = lambda finding_group: sorted({
        f'[BDBA {finding.finding.data.product_id}]({finding.finding.data.report_url})'
        for finding in finding_group.findings
    })

    def group_aggregated_findings(
        aggregated_findings: tuple[AggregatedFinding],
    ) -> tuple[AggregatedFinding]:
        '''
        returns `findings` grouped by the affected package of the finding and the CVE
        '''
        findings_by_package_and_cve = collections.defaultdict(dict)

        for aggregated_finding in aggregated_findings:
            package_name = aggregated_finding.finding.data.package_name
            package_version = aggregated_finding.finding.data.package_version
            cve = aggregated_finding.finding.data.cve

            if finding := findings_by_package_and_cve[package_name].get(cve):
                finding.finding.data.package_version.append(package_version)
            else:
                finding = copy.deepcopy(aggregated_finding)
                finding.finding.data.package_version = [package_version]
                findings_by_package_and_cve[package_name][cve] = finding

        return tuple(
            findings_for_package_and_cve
            for _, findings_for_package_by_cve in sorted(
                findings_by_package_and_cve.items(),
                key=lambda finding_by_package_and_cve: finding_by_package_and_cve[0], # package name
            )
            for findings_for_package_and_cve in sorted(
                findings_for_package_by_cve.values(),
                key=lambda finding_for_package_and_cve: (
                    -finding_for_package_and_cve.finding.data.cvss_v3_score,
                    finding_for_package_and_cve.finding.data.cve,
                ),
            )
        )

    for finding_group in finding_groups:
        finding_group.findings = group_aggregated_findings(
            aggregated_findings=finding_group.findings,
        )
        finding_group.historical_findings = group_aggregated_findings(
            aggregated_findings=finding_group.historical_findings,
        )

    return findings_summary(
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        component_descriptor_lookup=component_descriptor_lookup,
        findings_table_callback=finding_table_callback,
        historical_findings_table_callback=historical_table_callback,
        report_urls_callback=report_urls_callback,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )


def template_issue_body(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    finding_cfg: odg.findings.Finding,
    artefacts: collections.abc.Iterable[odg.model.ComponentArtefactId],
    artefacts_without_scan: collections.abc.Iterable[odg.model.ComponentArtefactId],
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    findings: collections.abc.Sequence[AggregatedFinding],
    historical_findings: collections.abc.Sequence[AggregatedFinding],
    due_date: datetime.date,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_dashboard_url: str,
    sprint_name: str | None=None,
) -> str:
    '''
    Returns a formatted GitHub issue body based on the template specified in the `finding_cfg`.
    Therefore, it fills a selection of template variables (see below), the most prominent template
    variable is called `summary`. It contains a table showing information on the artefact the issue
    is opened for as well as more detailed information on the actual findings per artefact. The
    summary table first depicts the properties which are used to group the artefacts (so the
    properties which all artefacts have in common) and then the remaining properties per artefact.
    Also, artefacts which were not scanned yet are reported (if there are any).
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

    artefact_summary = textwrap.dedent('''\
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
        artefact_summary += f'| Component | {component_name} |\n'
    if component_version := artefact_group_properties.component_version:
        artefact_summary += f'| Component-Version | {component_version} |\n'
    if artefact_kind := artefact_group_properties.artefact_kind:
        artefact_summary += f'| Artefact-Kind | {artefact_kind} |\n'
    if artefact_name := artefact_group_properties.artefact.artefact_name:
        artefact_summary += f'| Artefact | {artefact_name} |\n'
    if artefact_version := artefact_group_properties.artefact.artefact_version:
        artefact_summary += f'| Artefact-Version | {artefact_version} |\n'
    if artefact_type := artefact_group_properties.artefact.artefact_type:
        artefact_summary += f'| Artefact-Type | {artefact_type} |\n'
    if artefact_extra_id := artefact_group_properties.artefact.artefact_extra_id:
        id_str = '<br>'.join(sorted(f'{k}: {v}' for k, v in artefact_extra_id.items()))
        artefact_summary += f'| Artefact-Extra-Id | <pre>{id_str}</pre> |\n'

    artefact_summary += f'| Due Date | {due_date} |\n'

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

        historical_findings_for_artefact = tuple(
            finding for finding in historical_findings
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

        if not findings_for_artefact and not historical_findings_for_artefact:
            continue

        finding_groups.append(FindingGroup(
            artefact=artefact,
            findings=findings_for_artefact,
            historical_findings=historical_findings_for_artefact,
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

    artefact_summary_long = artefact_summary_short = artefact_summary

    if artefacts_non_group_properties:
        artefact_summary_long += f'| {util.pluralise('ID', len(artefacts_non_group_properties))} | {artefacts_non_group_properties_str} |\n\n' # noqa: E501

    # lastly, display the artefacts which were not scanned yet
    artefacts_without_scan_str = ''.join(
        _artefact_to_str(artefact=artefact_without_scan)
        for artefact_without_scan in sorted_artefacts_without_scan
    )

    if sorted_artefacts_without_scan:
        artefact_summary_long += f'| {util.pluralise('Artefact', len(sorted_artefacts_without_scan))} without Scan | {artefacts_without_scan_str} |\n\n' # noqa: E501

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

    if not findings and not historical_findings:
        artefact_summary_long += (
            '**The scan of the recent artefact version is currently pending, '
            'hence no findings may show up.**'
        )

        template_variables['summary'] = artefact_summary_long

        return finding_cfg.issues.template.format(**template_variables)

    elif findings:
        artefact_summary_long += (
            f'The aforementioned {util.pluralise('artefact', len(artefacts_non_group_properties))} '
            'yielded findings relevant for future release decisions.\n'
        )

    else:
        # there are only historical findings, which means the issue is about to being closed but the
        # body should still be updated to show the actual state of resolved findings
        pass

    summary_function = {
        odg.model.Datatype.CRYPTO_FINDING: crypto_summary,
        odg.model.Datatype.DIKI_FINDING: diki_summary,
        odg.model.Datatype.FALCO_FINDING: falco_summary,
        odg.model.Datatype.GHAS_FINDING: ghas_summary,
        odg.model.Datatype.INVENTORY_FINDING: inventory_summary,
        odg.model.Datatype.KYVERNO_FINDING: kyverno_summary,
        odg.model.Datatype.LICENSE_FINDING: license_summary,
        odg.model.Datatype.MALWARE_FINDING: malware_summary,
        odg.model.Datatype.OSID_FINDING: osid_summary,
        odg.model.Datatype.SAST_FINDING: sast_summary,
        odg.model.Datatype.VULNERABILITY_FINDING: vulnerability_summary,
    }.get(finding_cfg.type, fallback_summary)

    summary_variants = summary_function(
        mapping=mapping,
        finding_cfg=finding_cfg,
        finding_groups=finding_groups,
        known_issues=known_issues,
        component_descriptor_lookup=component_descriptor_lookup,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name=sprint_name,
    )

    # order is important -> prefer long version
    for artefact_summary_variant in (artefact_summary_long, artefact_summary_short):
        for summary_variant in summary_variants:
            template_variables['summary'] = artefact_summary_variant + summary_variant
            issue_body = finding_cfg.issues.template.format(**template_variables)
            if len(issue_body) <= github.limits.issue_body:
                return issue_body

    raise RuntimeError(f'{len(issue_body)=} exceeds {github.limits.issue_body=}')


@github.retry.retry_and_throttle
def close_issue_if_present(
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    issue: github3.issues.issue.ShortIssue,
    closing_reason: IssueComments,
    body: str | None=None,
):
    '''
    Closes the `issue` if it is still open. Prior to closing, the issue body can be optionally
    edited by providing the `body` param (an empty value will keep the body as-is) and a comment
    stating the `closing_reason` is added.
    '''
    if not issue or issue.state != 'open':
        return

    logger.info(f'labels for issue for closing: {[l.name for l in issue.original_labels]}')

    if body:
        issue.edit(body=body)
    issue.create_comment(closing_reason)
    if not github.util.close_issue(issue):
        logger.warning(f'failed to close {issue.id=} with {mapping.github_repository=}')


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
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    findings: tuple[AggregatedFinding],
    historical_findings: tuple[AggregatedFinding],
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
) -> github3.issues.issue.ShortIssue | None:
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

    body = template_issue_body(
        mapping=mapping,
        finding_cfg=finding_cfg,
        component_descriptor_lookup=component_descriptor_lookup,
        artefacts=artefacts,
        known_issues=known_issues,
        findings=findings,
        historical_findings=historical_findings,
        artefacts_without_scan=artefacts_without_scan,
        due_date=due_date,
        delivery_dashboard_url=delivery_dashboard_url,
        sprint_name='Overdue' if is_overdue else sprint_name,
    )

    if is_overdue:
        labels.add(IssueLabels.OVERDUE)

    if not is_scanned:
        if not issue:
            # there is no scan yet but we have no open issue either -> nothing to do (yet)
            return

        labels.add(IssueLabels.SCAN_PENDING)

    if issue:
        return update_issue(
            issue=issue,
            body=body,
            title=title,
            labels=labels,
            assignees=assignees,
            assignee_mode=assignee_mode,
            milestone=milestone,
        )

    repository = odg.extensions_cfg.github_repository(mapping.github_repository)

    return create_issue(
        repository=repository,
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
    known_issues: collections.abc.Sequence[github3.issues.issue.ShortIssue],
    findings: tuple[AggregatedFinding],
    historical_findings: tuple[AggregatedFinding],
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
    created_issues = set()

    for finding in findings:
        data = finding.finding.data

        data_digest = hashlib.shake_128(
            data.key.encode(),
            usedforsecurity=False,
        ).hexdigest(int(github.limits.label / 2))

        finding_labels = labels | {data_digest}

        labels_for_filtering = (issue_id, finding_cfg.type, data_digest)

        finding_issues = filter_issues_for_labels(
            issues=set(issues) | created_issues,
            labels=labels_for_filtering,
        )
        processed_issues.update(finding_issues)

        if created_issue := _create_or_update_issue(
            mapping=mapping,
            finding_cfg=finding_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            artefacts=artefacts,
            known_issues=known_issues,
            findings=(finding,),
            historical_findings=historical_findings,
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
        ):
            created_issues.add(created_issue)

    for issue in set(issues):
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
    historical_findings: tuple[AggregatedFinding],
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

    repository = odg.extensions_cfg.github_repository(mapping.github_repository)

    known_issues = _all_issues(
        repository=repository,
        state='open',
    ) | _all_issues(
        repository=repository,
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
            if historical_findings:
                body = template_issue_body(
                    mapping=mapping,
                    finding_cfg=finding_cfg,
                    artefacts=artefacts,
                    artefacts_without_scan=artefacts_without_scan,
                    known_issues=known_issues,
                    findings=findings,
                    historical_findings=historical_findings,
                    due_date=due_date,
                    component_descriptor_lookup=component_descriptor_lookup,
                    delivery_dashboard_url=delivery_dashboard_url,
                )
            else:
                # in case issue is closed because of version bump, don't remove all findings
                body = None

            close_issue_if_present(
                mapping=mapping,
                issue=issue,
                closing_reason=IssueComments.NO_FINDINGS,
                body=body,
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
            known_issues=known_issues,
            findings=findings,
            historical_findings=historical_findings,
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
        known_issues=known_issues,
        findings=findings,
        historical_findings=historical_findings,
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
