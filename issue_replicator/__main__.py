import collections.abc
import dataclasses
import datetime
import functools
import logging

import cachetools
import github3.repos

import ci.log
import cnudie.retrieve
import delivery.client
import delivery.model
import github.user

import issue_replicator.github
import k8s.logging
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths
import rescore.utility
import util


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


@functools.cache
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


def _iter_findings_for_artefact(
    delivery_client: delivery.client.DeliveryServiceClient,
    artefacts: collections.abc.Iterable[odg.model.ComponentArtefactId],
    finding_type: odg.model.Datatype,
    finding_source: odg.model.Datasource,
    chunk_size: int=10,
) -> collections.abc.Generator[issue_replicator.github.AggregatedFinding, None, None]:
    findings: list[odg.model.ArtefactMetadata] = []
    rescorings: list[odg.model.ArtefactMetadata] = []

    for idx in range(0, len(artefacts), chunk_size):
        chunked_artefacts = artefacts[idx:min(idx + chunk_size, len(artefacts))]

        findings.extend([
            odg.model.ArtefactMetadata.from_dict(raw)
            for raw in delivery_client.query_metadata(
                artefacts=chunked_artefacts,
                type=[odg.model.Datatype.ARTEFACT_SCAN_INFO, finding_type],
            )
        ])

        rescorings.extend([
            odg.model.ArtefactMetadata.from_dict(raw)
            for raw in delivery_client.query_metadata(
                artefacts=chunked_artefacts,
                type=odg.model.Datatype.RESCORING,
                referenced_type=finding_type,
            )
        ])

    for finding in findings:
        if finding.meta.type == odg.model.Datatype.ARTEFACT_SCAN_INFO:
            if finding.meta.datasource == finding_source:
                yield issue_replicator.github.AggregatedFinding(finding)
            continue

        filtered_rescorings = rescore.utility.rescorings_for_finding_by_specificity(
            finding=finding,
            rescorings=rescorings,
        )

        yield issue_replicator.github.AggregatedFinding(
            finding=finding,
            rescorings=filtered_rescorings,
        )


def _iter_findings_with_due_dates(
    findings: collections.abc.Iterable[issue_replicator.github.AggregatedFinding],
    finding_cfg: odg.findings.Finding,
    due_dates: collections.abc.Iterable[datetime.date],
) -> collections.abc.Generator[issue_replicator.github.AggregatedFinding, None, None]:
    sprint_due_dates = sorted(due_dates)

    for finding in findings:
        if finding.finding.meta.type == odg.model.Datatype.ARTEFACT_SCAN_INFO:
            yield finding
            continue

        categorisation = finding_cfg.categorisation_by_id(finding.severity)

        if not (due_date := categorisation.effective_due_date(
            finding=finding.finding,
            rescoring=finding.rescorings[0] if finding.rescorings else None,
        )):
            continue # finding does not have to be processed anymore

        for sprint_due_date in sprint_due_dates:
            if sprint_due_date >= due_date:
                finding.due_date = sprint_due_date
                break
        else:
            logger.warning(f'could not determine target sprint for {finding=})')
            continue

        yield finding


def _group_findings_by_due_date(
    findings: collections.abc.Sequence[issue_replicator.github.AggregatedFinding],
    due_dates: collections.abc.Iterable[datetime.date],
) -> collections.abc.Generator[
    tuple[
        tuple[issue_replicator.github.AggregatedFinding], # findings
        datetime.date, # latest processing date
    ],
    None,
    None,
]:
    for due_date in due_dates:
        filtered_findings = tuple(
            finding for finding in findings
            if finding.due_date == due_date
        )

        yield filtered_findings, due_date


def _responsibles_from_responsible_infos(
    artefacts: collections.abc.Sequence[odg.model.ComponentArtefactId],
    finding_type: odg.model.Datatype,
    delivery_client: delivery.client.DeliveryServiceClient,
) -> tuple[list[dict] | None, odg.model.ResponsibleAssigneeModes | None]:
    '''
    If at least one responsible-info exists for one of the passed-in `artefacts` and the
    `finding_type` (even if it contains an empty list of responsibles), these responsibles are
    returned together with the defined `assignee_mode`. If no such info exists, `None` is returned
    instead.
    '''
    responsible_infos_raw = delivery_client.query_metadata(
        artefacts=artefacts,
        type=odg.model.Datatype.RESPONSIBLES,
        referenced_type=finding_type,
    )

    if not responsible_infos_raw:
        return None, None

    responsibles: list[dict] = []
    assignee_mode: odg.model.ResponsibleAssigneeModes | None = None

    for responsible_info_raw in responsible_infos_raw:
        current_responsibles = responsible_info_raw['meta']['responsibles']
        if assignee_mode_raw := responsible_info_raw['meta']['assignee_mode']:
            assignee_mode = odg.model.ResponsibleAssigneeModes(assignee_mode_raw)

        responsibles += [
            responsible['identifiers']
            for responsible in current_responsibles
        ]

    return responsibles, assignee_mode


def _responsibles_from_overwrites(
    artefact_metadata: collections.abc.Iterable[odg.model.ArtefactMetadata],
) -> tuple[list[dict] | None, odg.model.ResponsibleAssigneeModes | None]:
    '''
    If at least one of the specified `artefact_metadata` entries contains responsible overwrites
    (responsibles != `None`), a list of these responsibles is returned together with the defined
    `assignee_mode`. Otherwise, `None` is returned.
    '''
    responsibles: list[dict] | None = None
    assignee_mode: odg.model.ResponsibleAssigneeModes | None = None

    for artefact_metadatum in artefact_metadata:
        # explicitly check for `None` here as an empty list is allowed to overwrite responsibles
        if (current_responsibles := artefact_metadatum.meta.responsibles) is None:
            continue

        if responsibles is None:
            responsibles = []

        responsibles += [
            util.dict_serialisation(responsible.identifiers)
            for responsible in current_responsibles
        ]
        assignee_mode = artefact_metadatum.meta.assignee_mode

    return responsibles, assignee_mode


def _responsibles(
    artefact_metadata: collections.abc.Iterable[odg.model.ArtefactMetadata],
    artefacts: collections.abc.Sequence[odg.model.ComponentArtefactId],
    finding_type: odg.model.Datatype,
    default_assignee_mode: odg.model.ResponsibleAssigneeModes,
    delivery_client: delivery.client.DeliveryServiceClient,
) -> tuple[
    list[dict] | None,
    odg.model.ResponsibleAssigneeModes,
    list[delivery.model.Status] | None,
]:
    '''
    If responsibles can be retrieved via overwrites, a list of these responsibles is returned
    together with the defined `assignee_mode`. Otherwise, responsibles are determined via
    responsible-info entries created by the responsibles-extension or, as last fallback, via the
    delivery-service api together with their `assignee_mode` and `statuses`.
    '''
    current_responsibles, assignee_mode = _responsibles_from_overwrites(
        artefact_metadata=artefact_metadata,
    )

    if current_responsibles is not None:
        return current_responsibles, assignee_mode or default_assignee_mode, None

    current_responsibles, assignee_mode = _responsibles_from_responsible_infos(
        artefacts=artefacts,
        finding_type=finding_type,
        delivery_client=delivery_client,
    )

    if current_responsibles is not None:
        return current_responsibles, assignee_mode or default_assignee_mode, None

    artefact = artefacts[0]
    component_responsibles, statuses = delivery_client.component_responsibles(
        name=artefact.component_name,
        version=artefact.component_version,
        artifact=artefact.artefact.artefact_name,
        absent_ok=True,
    )

    return component_responsibles, default_assignee_mode, statuses


@cachetools.cached(cachetools.TTLCache(maxsize=4096, ttl=60 * 60))
def _valid_issue_assignees(
    repository: github3.repos.Repository,
) -> set[str]:
    return set(assignee.login.lower() for assignee in repository.assignees())


def _github_assignees(
    responsibles: collections.abc.Iterable[dict] | None,
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
) -> set[str]:
    if not responsibles:
        return set()

    repository = odg.extensions_cfg.github_repository(mapping.github_repository)
    gh_api = odg.extensions_cfg.github_api(mapping.github_repository)

    gh_usernames = delivery.client.github_usernames_from_responsibles(
        responsibles=responsibles,
        github_url=repository.html_url,
    )

    assignees = set(
        gh_username.lower()
        for gh_username in gh_usernames
        if github.user.is_user_active(
            username=gh_username,
            github=gh_api,
        )
    )

    valid_assignees = _valid_issue_assignees(repository)

    if invalid_assignees := (assignees - valid_assignees):
        logger.warning(
            f'unable to assign {invalid_assignees} to issues in repository '
            f'{repository.html_url}. Please make sure the users have the necessary '
            'permissions to see issues in the repository.'
        )
        assignees -= invalid_assignees
        logger.info(
            f'removed invalid assignees {invalid_assignees} from target assignees for '
            f'issue. Remaining assignees: {assignees}'
        )

    return assignees


def replicate_issue_for_finding_type(
    artefact: odg.model.ComponentArtefactId,
    finding_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    delivery_dashboard_url: str,
    due_dates: collections.abc.Iterable[datetime.date],
):
    finding_type = finding_cfg.type
    finding_source = finding_type.datasource()

    logger.info(f'updating issues for {finding_type=} and {finding_source=}')

    artefact_group = finding_cfg.issues.strip_artefact(
        artefact=artefact,
        keep_group_attributes=True,
    )

    active_compliance_snapshots = tuple(
        compliance_snapshot
        for raw in delivery_client.query_metadata(
            artefacts=(artefact_group,),
            type=odg.model.Datatype.COMPLIANCE_SNAPSHOTS,
        )
        if (
            (compliance_snapshot := odg.model.ArtefactMetadata.from_dict(raw))
            and compliance_snapshot.data.is_active
        )
    )
    logger.info(f'{len(active_compliance_snapshots)=}')

    artefacts = tuple({
        cs.artefact for cs in active_compliance_snapshots
    })
    logger.info(f'{len(artefacts)=}')

    if is_in_bom := len(active_compliance_snapshots) > 0 and finding_cfg.matches(artefact):
        findings = _iter_findings_for_artefact(
            delivery_client=delivery_client,
            artefacts=artefacts,
            finding_type=finding_type,
            finding_source=finding_source,
        )

        findings = tuple(_iter_findings_with_due_dates(
            findings=findings,
            finding_cfg=finding_cfg,
            due_dates=due_dates,
        ))
        logger.info(f'{len(findings)=}')
    else:
        # we don't need to query any findings, as all open issues will be closed anyways
        logger.info('artefact is not in the BoM anymore, will not query any findings')
        findings = tuple()

    findings_by_due_date = _group_findings_by_due_date(
        findings=findings,
        due_dates=due_dates,
    )

    artefact_scan_infos = [
        finding.finding
        for finding in findings
        if finding.finding.meta.type == odg.model.Datatype.ARTEFACT_SCAN_INFO
    ]

    # `artefacts` are retrieved from all active compliance snapshots, whereas `scanned_artefacts`
    # are retrieved from the existing findings. The difference is that `scanned_artefacts` may not
    # contain any component version (i.e. for BDBA findings) because they're deduplicated across
    # multiple component versions. In contrast, all compliance snapshots hold a component version
    # and thus `artefacts` do as well. Now, to determine artefacts which have not been scanned yet,
    # both sides have to be normalised in that the component version is not considered. Also, the
    # attributes by which artefacts are grouped are dropped as they are equal anyways.
    all_artefacts = {
        finding_cfg.issues.strip_artefact(
            artefact=dataclasses.replace(
                artefact,
                component_version=None,
            ),
            keep_group_attributes=False,
        ) for artefact in artefacts
    }
    scanned_artefacts = {
        finding_cfg.issues.strip_artefact(
            artefact=dataclasses.replace(
                artefact_scan_info.artefact,
                component_version=None,
            ),
            keep_group_attributes=False,
        ) for artefact_scan_info in artefact_scan_infos
    }
    artefacts_without_scan = all_artefacts - scanned_artefacts

    if (
        finding_cfg.issues.enable_assignees
        and is_in_bom
        and len(artefacts_without_scan) == 0
    ):
        # only lookup responsibles in artefact scan info objects for now
        responsibles, assignee_mode, statuses = _responsibles(
            artefact_metadata=artefact_scan_infos,
            artefacts=artefacts,
            finding_type=finding_cfg.type,
            default_assignee_mode=finding_cfg.issues.default_assignee_mode,
            delivery_client=delivery_client,
        )
        github_assignees = _github_assignees(
            responsibles=responsibles,
            mapping=mapping,
        )
    else:
        github_assignees = set()
        assignee_mode = finding_cfg.issues.default_assignee_mode
        statuses = None

    for findings, due_date in findings_by_due_date:
        issue_id = finding_cfg.issues.issue_id(
            artefact=artefact,
            due_date=due_date,
        )

        issue_replicator.github.create_or_update_or_close_issue(
            mapping=mapping,
            finding_cfg=finding_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            artefacts=artefacts,
            findings=findings,
            issue_id=issue_id,
            due_date=due_date,
            is_in_bom=is_in_bom,
            artefacts_without_scan=artefacts_without_scan,
            delivery_dashboard_url=delivery_dashboard_url,
            assignees=github_assignees,
            assignees_statuses=statuses,
            assignee_mode=assignee_mode,
        )


def replicate_issue(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.IssueReplicatorConfig,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    **kwargs,
):
    logger.info(f'starting issue replication of {artefact}')

    if not (due_dates := sprint_dates(delivery_client=delivery_client)):
        logger.warning('did not find any sprints, exiting...')
        return

    # cache clear is necessary to prevent creating duplicated issues
    issue_replicator.github._all_issues.cache_clear()

    mapping = extension_cfg.mapping(artefact.component_name)
    gh_api = odg.extensions_cfg.github_api(mapping.github_repository)
    issue_replicator.github.wait_for_quota_if_required(gh_api=gh_api)

    for finding_cfg in finding_cfgs:
        replicate_issue_for_finding_type(
            artefact=artefact,
            finding_cfg=finding_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            mapping=mapping,
            delivery_dashboard_url=extension_cfg.delivery_dashboard_url,
            due_dates=due_dates,
        )

    logger.info(f'finished issue replication of {artefact}')


def main():
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    finding_cfgs = odg.findings.Finding.from_file(findings_cfg_path)
    finding_cfgs = [finding_cfg for finding_cfg in finding_cfgs if finding_cfg.issues.enable_issues]

    replicate_issue_callback = functools.partial(
        replicate_issue,
        finding_cfgs=finding_cfgs,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
        callback=replicate_issue_callback,
    )


if __name__ == '__main__':
    main()
