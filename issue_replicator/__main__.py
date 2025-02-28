import argparse
import atexit
import collections.abc
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
import github.compliance.issue as gci

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
    global ready_to_terminate, wants_to_terminate

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
    finding_types: list[odg.findings.FindingType],
    chunk_size: int=10,
) -> collections.abc.Generator[issue_replicator.github.AggregatedFinding, None, None]:
    if not artefacts or not finding_types:
        return

    findings: list[dso.model.ArtefactMetadata] = []
    rescorings: list[dso.model.ArtefactMetadata] = []

    for idx in range(0, len(artefacts), chunk_size):
        chunked_artefacts = artefacts[idx:min(idx + chunk_size, len(artefacts))]

        findings.extend(delivery_client.query_metadata(
            artefacts=chunked_artefacts,
            type=[dso.model.Datatype.ARTEFACT_SCAN_INFO] + finding_types,
        ))

        rescorings.extend(delivery_client.query_metadata(
            artefacts=chunked_artefacts,
            type=dso.model.Datatype.RESCORING,
            referenced_type=finding_types,
        ))

    for finding in findings:
        if finding.meta.type == dso.model.Datatype.ARTEFACT_SCAN_INFO:
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
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    sprints: collections.abc.Sequence[datetime.date],
) -> collections.abc.Generator[issue_replicator.github.AggregatedFinding, None, None]:
    sprints = sorted(sprints)

    for finding in findings:
        if (finding_type := finding.finding.meta.type) == dso.model.Datatype.ARTEFACT_SCAN_INFO:
            yield finding
            continue

        for finding_cfg in finding_cfgs:
            if finding_cfg.type == finding_type:
                break
        else:
            raise RuntimeError(f'did not find finding cfg for type "{finding_type}"')

        for categorisation in finding_cfg.categorisations:
            if categorisation.id == finding.severity:
                break
        else:
            raise ValueError(
                f'did not find categorisation with name "{finding.severity}" for {finding_type=}'
            )

        if (allowed_processing_time := categorisation.allowed_processing_time) is None:
            continue # finding does not have to be processed anymore

        latest_processing_date = finding.finding.discovery_date + allowed_processing_time

        for sprint in sprints:
            if sprint >= latest_processing_date:
                finding.latest_processing_date = sprint
                break
        else:
            logger.warning(
                f'could not determine target sprint for {finding=}, will use earliest sprint'
            )
            # we checked that at least one sprint exists earlier
            finding.latest_processing_date = sprints[0]

        yield finding


def _group_findings_by_cfg_source_and_date(
    findings: collections.abc.Sequence[issue_replicator.github.AggregatedFinding],
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    sprints: collections.abc.Sequence[datetime.date],
) -> collections.abc.Generator[
    tuple[
        tuple[issue_replicator.github.AggregatedFinding], # findings
        odg.findings.Finding,
        dso.model.Datasource,
        datetime.date, # latest processing date
    ],
    None,
    None,
]:
    for sprint in sprints:
        for finding_cfg in finding_cfgs:
            datasource = dso.model.Datatype.datatype_to_datasource(finding_cfg.type)

            filtered_findings = tuple(
                finding for finding in findings
                if (
                    finding.finding.meta.type == finding_cfg.type
                    and finding.finding.meta.datasource == datasource
                    and finding.latest_processing_date == sprint
                )
            )

            yield filtered_findings, finding_cfg, datasource, sprint


def replicate_issue(
    artefact: dso.model.ComponentArtefactId,
    issue_replicator_cfg: odg.extensions_cfg.IssueReplicatorConfig,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
):
    # issues are grouped across multiple versions + extra identities, hence ignoring properties here
    artefact.component_version = None
    artefact.artefact.artefact_version = None
    artefact.artefact.artefact_extra_id = dict()

    logger.info(f'starting issue replication of {artefact}')

    mapping = issue_replicator_cfg.mapping(artefact.component_name)

    compliance_snapshots = delivery_client.query_metadata(
        artefacts=(artefact,),
        type=dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
    )
    logger.info(f'{len(compliance_snapshots)=}')

    active_compliance_snapshots = tuple(
        cs for cs in compliance_snapshots
        if cs.data.current_state().status is dso.model.ComplianceSnapshotStatuses.ACTIVE
    )
    logger.info(f'{len(active_compliance_snapshots)=}')

    correlation_ids_by_latest_processing_date: dict[datetime.date, str] = dict()
    for compliance_snapshot in compliance_snapshots:
        date = compliance_snapshot.data.latest_processing_date

        if date in correlation_ids_by_latest_processing_date:
            continue

        correlation_id = compliance_snapshot.data.correlation_id
        correlation_ids_by_latest_processing_date[date] = correlation_id

    active_sprints = set()
    for compliance_snapshot in active_compliance_snapshots:
        active_sprints.add(compliance_snapshot.data.latest_processing_date)

    if not (all_sprints := list(correlation_ids_by_latest_processing_date.keys())):
        logger.warning('did not find any sprints, exiting...')
        return

    artefacts = tuple({
        cs.artefact for cs in active_compliance_snapshots
    })
    logger.info(f'{len(artefacts)=}')

    finding_types = [
        finding_cfg.type
        for finding_cfg in finding_cfgs
        if finding_cfg.issues.enable_issues and any(finding_cfg.matches(a) for a in artefacts)
    ]
    logger.info(f'{finding_types=}')

    findings = _iter_findings_for_artefact(
        delivery_client=delivery_client,
        artefacts=artefacts,
        finding_types=finding_types,
    )

    findings = tuple(_iter_findings_with_processing_dates(
        findings=findings,
        finding_cfgs=finding_cfgs,
        sprints=active_sprints,
    ))
    logger.info(f'{len(findings)=}')

    scanned_artefacts_by_datasource = {
        (
            finding.finding.meta.datasource,
            finding.finding.artefact,
        ) for finding in findings
        if finding.finding.meta.type == dso.model.Datatype.ARTEFACT_SCAN_INFO
    }

    findings_by_cfg_source_and_date = _group_findings_by_cfg_source_and_date(
        findings=findings,
        finding_cfgs=finding_cfgs,
        sprints=all_sprints,
    )

    def _issue_type(
        finding_type: odg.findings.FindingType,
        finding_source: str,
    ) -> str:
        if (
            finding_type is odg.findings.FindingType.VULNERABILITY
            and finding_source == dso.model.Datasource.BDBA
        ):
            return gci._label_bdba

        elif (
            finding_type is odg.findings.FindingType.LICENSE
            and finding_source == dso.model.Datasource.BDBA
        ):
            return gci._label_licenses

        elif (
            finding_type is odg.findings.FindingType.MALWARE
            and finding_source == dso.model.Datasource.CLAMAV
        ):
            return gci._label_malware

        elif (
            finding_type is odg.findings.FindingType.SAST
            and finding_source == dso.model.Datasource.SAST
        ):
            return gci._label_sast

        elif (
            finding_type is odg.findings.FindingType.DIKI
            and finding_source == dso.model.Datasource.DIKI
        ):
            return gci._label_diki

        else:
            raise NotImplementedError(f'{finding_type=} is not supported for {finding_source=}')

    is_in_bom = len(active_compliance_snapshots) > 0

    # `artefacts` are retrieved from all active compliance snapshots, whereas `scanned_artefacts`
    # are retrieved from the existing findings. The difference is that `scanned_artefacts` may not
    # contain any component version (i.e. for BDBA findings) because they're deduplicated across
    # multiple component versions. In contrast, all compliance snapshots hold a component version
    # and thus `artefacts` do as well. Now, to determine artefacts which have not been scanned yet,
    # both sides have to be normalised in that the component version is not considered.
    all_artefact_ids = {
        a.artefact for a in artefacts
    }

    issue_replicator.github.wait_for_quota_if_required(gh_api=mapping.github_api)
    for findings, finding_cfg, finding_source, date in findings_by_cfg_source_and_date:
        correlation_id = correlation_ids_by_latest_processing_date.get(date)

        issue_type = _issue_type(
            finding_type=finding_cfg.type,
            finding_source=finding_source,
        )

        scanned_artefact_ids = {
            scanned_artefact.artefact
            for datasource, scanned_artefact in scanned_artefacts_by_datasource
            if datasource == finding_source
        }

        artefact_ids_without_scan = all_artefact_ids - scanned_artefact_ids

        issue_replicator.github.create_or_update_or_close_issue(
            mapping=mapping,
            finding_cfg=finding_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            issue_type=issue_type,
            artefacts=artefacts,
            findings=findings,
            correlation_id=correlation_id,
            latest_processing_date=date,
            is_in_bom=is_in_bom,
            artefact_ids_without_scan=artefact_ids_without_scan,
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

    global ready_to_terminate, wants_to_terminate
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
