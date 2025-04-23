import argparse
import atexit
import collections.abc
import dataclasses
import datetime
import logging
import os
import signal
import sys
import time

import ci.log
import cnudie.retrieve
import delivery.client
import dso.model

import consts
import ctx_util
import issue_replicator.github
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups
import odg.extensions_cfg
import odg.findings
import paths
import rescore.utility


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')

ready_to_terminate = True
wants_to_terminate = False


def handle_sigterm_and_sigint(signum, frame):
    global wants_to_terminate

    sig = signal.Signals(signum)
    if sig not in (signal.SIGTERM, signal.SIGINT):
        raise ValueError(sig)

    # also terminate if > 1 termination signals were received
    if ready_to_terminate or wants_to_terminate:
        sys.exit(0)

    # grace period to finish current issue replication is defined in the replica set
    # after this period, the issue replication will be terminated anyways by k8s means
    logger.info(
        f'{sig.name} signal received, will try to finish current issue replication and then exit'
    )
    wants_to_terminate = True


def _iter_findings_for_artefact(
    delivery_client: delivery.client.DeliveryServiceClient,
    artefacts: collections.abc.Iterable[dso.model.ComponentArtefactId],
    finding_type: odg.findings.FindingType,
    finding_source: str,
    chunk_size: int=10,
) -> collections.abc.Generator[issue_replicator.github.AggregatedFinding, None, None]:
    findings: list[dso.model.ArtefactMetadata] = []
    rescorings: list[dso.model.ArtefactMetadata] = []

    for idx in range(0, len(artefacts), chunk_size):
        chunked_artefacts = artefacts[idx:min(idx + chunk_size, len(artefacts))]

        findings.extend(delivery_client.query_metadata(
            artefacts=chunked_artefacts,
            type=[dso.model.Datatype.ARTEFACT_SCAN_INFO, finding_type],
        ))

        rescorings.extend(delivery_client.query_metadata(
            artefacts=chunked_artefacts,
            type=dso.model.Datatype.RESCORING,
            referenced_type=finding_type,
        ))

    for finding in findings:
        if finding.meta.type == dso.model.Datatype.ARTEFACT_SCAN_INFO:
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


def _iter_findings_with_processing_dates(
    findings: collections.abc.Iterable[issue_replicator.github.AggregatedFinding],
    finding_cfg: odg.findings.Finding,
    sprints: collections.abc.Sequence[datetime.date],
) -> collections.abc.Generator[issue_replicator.github.AggregatedFinding, None, None]:
    sprints = sorted(sprints)

    for finding in findings:
        if finding.finding.meta.type == dso.model.Datatype.ARTEFACT_SCAN_INFO:
            yield finding
            continue

        categorisation = finding_cfg.categorisation_by_id(finding.severity)

        if not (due_date := categorisation.effective_due_date(
            finding=finding.finding,
            rescoring=finding.rescorings[0] if finding.rescorings else None,
        )):
            continue # finding does not have to be processed anymore

        for sprint in sprints:
            if sprint >= due_date:
                finding.due_date = sprint
                break
        else:
            logger.warning(f'could not determine target sprint for {finding=})')
            continue

        yield finding


def _group_findings_by_due_date(
    findings: collections.abc.Sequence[issue_replicator.github.AggregatedFinding],
    sprints: collections.abc.Sequence[datetime.date],
) -> collections.abc.Generator[
    tuple[
        tuple[issue_replicator.github.AggregatedFinding], # findings
        datetime.date, # latest processing date
    ],
    None,
    None,
]:
    for sprint in sprints:
        filtered_findings = tuple(
            finding for finding in findings
            if finding.due_date == sprint
        )

        yield filtered_findings, sprint


def replicate_issue_for_finding_type(
    artefact: dso.model.ComponentArtefactId,
    finding_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    mapping: odg.extensions_cfg.IssueReplicatorMapping,
    delivery_dashboard_url: str,
):
    finding_type = finding_cfg.type
    finding_source = dso.model.Datatype.datatype_to_datasource(finding_type)

    logger.info(f'updating issues for {finding_type=} and {finding_source=}')

    artefact_group = finding_cfg.issues.strip_artefact(
        artefact=artefact,
        keep_group_attributes=True,
    )

    compliance_snapshots = delivery_client.query_metadata(
        artefacts=(artefact_group,),
        type=dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
    )
    logger.info(f'{len(compliance_snapshots)=}')

    active_compliance_snapshots = tuple(
        cs for cs in compliance_snapshots
        if cs.data.current_state().status is dso.model.ComplianceSnapshotStatuses.ACTIVE
    )
    logger.info(f'{len(active_compliance_snapshots)=}')

    issue_ids_by_due_date: dict[datetime.date, str] = dict()
    for compliance_snapshot in compliance_snapshots:
        due_date = compliance_snapshot.data.due_date

        if due_date in issue_ids_by_due_date:
            continue

        issue_ids_by_due_date[due_date] = finding_cfg.issues.issue_id(
            artefact=artefact,
            due_date=due_date,
        )

    active_sprints = set()
    for compliance_snapshot in active_compliance_snapshots:
        active_sprints.add(compliance_snapshot.data.due_date)

    if not (all_sprints := list(issue_ids_by_due_date.keys())):
        logger.warning('did not find any sprints, exiting...')
        return

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

        findings = tuple(_iter_findings_with_processing_dates(
            findings=findings,
            finding_cfg=finding_cfg,
            sprints=active_sprints,
        ))
        logger.info(f'{len(findings)=}')
    else:
        # we don't need to query any findings, as all open issues will be closed anyways
        logger.info('artefact is not in the BoM anymore, will not query any findings')
        findings = tuple()

    findings_by_due_date = _group_findings_by_due_date(
        findings=findings,
        sprints=all_sprints,
    )

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
                finding.finding.artefact,
                component_version=None,
            ),
            keep_group_attributes=False,
        ) for finding in findings
        if finding.finding.meta.type == dso.model.Datatype.ARTEFACT_SCAN_INFO
    }
    artefacts_without_scan = all_artefacts - scanned_artefacts

    for findings, due_date in findings_by_due_date:
        issue_id = issue_ids_by_due_date.get(due_date)

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
        )


def replicate_issue(
    artefact: dso.model.ComponentArtefactId,
    issue_replicator_cfg: odg.extensions_cfg.IssueReplicatorConfig,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
):
    logger.info(f'starting issue replication of {artefact}')

    mapping = issue_replicator_cfg.mapping(artefact.component_name)
    issue_replicator.github.wait_for_quota_if_required(gh_api=mapping.github_api)

    for finding_cfg in finding_cfgs:
        replicate_issue_for_finding_type(
            artefact=artefact,
            finding_cfg=finding_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            mapping=mapping,
            delivery_dashboard_url=issue_replicator_cfg.delivery_dashboard_url,
        )

    logger.info(f'finished issue replication of {artefact}')


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='specify kubernetes cluster to interact with',
        default=os.environ.get('K8S_CFG_NAME'),
    )
    parser.add_argument(
        '--kubeconfig',
        help='''
            specify kubernetes cluster to interact with extensions (and logs); if both
            `k8s-cfg-name` and `kubeconfig` are set, `k8s-cfg-name` takes precedence
        ''',
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with',
        default=os.environ.get('K8S_TARGET_NAMESPACE'),
    )
    parser.add_argument(
        '--extensions-cfg-path',
        help='path to the `extensions_cfg.yaml` file that should be used',
    )
    parser.add_argument(
        '--findings-cfg-path',
        help='path to the `findings.yaml` file that should be used',
    )
    parser.add_argument(
        '--delivery-service-url',
        help='''
            specify the url of the delivery service to use instead of the one configured in the
            respective extensions configuration
        ''',
    )
    parser.add_argument('--cache-dir', default=default_cache_dir)

    parsed_arguments = parser.parse_args()

    if not parsed_arguments.k8s_namespace:
        raise ValueError(
            'k8s namespace must be set, either via argument "--k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


def main():
    signal.signal(signal.SIGTERM, handle_sigterm_and_sigint)
    signal.signal(signal.SIGINT, handle_sigterm_and_sigint)

    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace
    delivery_service_url = parsed_arguments.delivery_service_url

    secret_factory = ctx_util.secret_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(
            kubeconfig_path=parsed_arguments.kubeconfig,
        )

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    issue_replicator_cfg = extensions_cfg.issue_replicator

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    finding_cfgs = odg.findings.Finding.from_file(findings_cfg_path)
    finding_cfgs = [finding_cfg for finding_cfg in finding_cfgs if finding_cfg.issues.enable_issues]

    if not delivery_service_url:
        delivery_service_url = issue_replicator_cfg.delivery_service_url

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_client,
    )

    global ready_to_terminate
    while not wants_to_terminate:
        ready_to_terminate = False

        backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
            service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )

        if not backlog_crd:
            ready_to_terminate = True
            sleep_interval = consts.BACKLOG_ITEM_SLEEP_INTERVAL_SECONDS
            logger.info(f'no open backlog item found, will sleep for {sleep_interval} sec')
            time.sleep(sleep_interval)
            continue

        name = backlog_crd.get('metadata').get('name')
        logger.info(f'processing backlog item {name}')

        backlog_item = k8s.backlog.BacklogItem.from_dict(
            backlog_item=backlog_crd.get('spec'),
        )

        # cache clear is necessary to prevent creating duplicated issues
        issue_replicator.github._all_issues.cache_clear()
        replicate_issue(
            artefact=backlog_item.artefact,
            issue_replicator_cfg=issue_replicator_cfg,
            finding_cfgs=finding_cfgs,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
        )

        k8s.util.delete_custom_resource(
            crd=k8s.model.BacklogItemCrd,
            name=name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )
        logger.info(f'processed and deleted backlog item {name}')

        time.sleep(2) # throttle github-api-requests


if __name__ == '__main__':
    main()
