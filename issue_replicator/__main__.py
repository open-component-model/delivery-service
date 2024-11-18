import argparse
import atexit
import collections.abc
import datetime
import functools
import logging
import os
import signal
import sys
import time

import dateutil.parser

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.model
import github.compliance.issue as gci
import github.compliance.model as gcm

import config
import ctx_util
import issue_replicator.github
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups
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


def deserialise_issue_replicator_configuration(
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> config.IssueReplicatorConfig:
    scan_cfg_crd = kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
        group=k8s.model.ScanConfigurationCrd.DOMAIN,
        version=k8s.model.ScanConfigurationCrd.VERSION,
        plural=k8s.model.ScanConfigurationCrd.PLURAL_NAME,
        namespace=namespace,
        name=cfg_name,
    )

    if scan_cfg_crd and (spec := scan_cfg_crd.get('spec')):
        issue_replicator_config = config.deserialise_issue_replicator_config(spec_config=spec)
    else:
        issue_replicator_config = None

    if not issue_replicator_config:
        logger.warning(
            f'no issue replicator configuration for config elem {cfg_name} set, '
            'job is not able to process current issue replicator backlog and will terminate'
        )
        sys.exit(0)

    return issue_replicator_config


def _iter_findings_for_artefact(
    delivery_client: delivery.client.DeliveryServiceClient,
    artefacts: collections.abc.Iterable[dso.model.ComponentArtefactId],
    chunk_size: int=10,
) -> collections.abc.Generator[issue_replicator.github.AggregatedFinding]:
    if not artefacts:
        return

    findings: list[dso.model.ArtefactMetadata] = []
    rescorings: list[dso.model.ArtefactMetadata] = []

    for idx in range(0, len(artefacts), chunk_size):
        chunked_artefacts = artefacts[idx:min(idx + chunk_size, len(artefacts))]

        findings.extend(delivery_client.query_metadata(
            artefacts=chunked_artefacts,
            type=(
                dso.model.Datatype.ARTEFACT_SCAN_INFO,
                dso.model.Datatype.VULNERABILITY,
                dso.model.Datatype.LICENSE,
                dso.model.Datatype.MALWARE_FINDING,
                dso.model.Datatype.DIKI_FINDING,
            ),
        ))

        rescorings.extend(delivery_client.query_metadata(
            artefacts=chunked_artefacts,
            type=dso.model.Datatype.RESCORING,
            referenced_type=(
                dso.model.Datatype.VULNERABILITY,
                dso.model.Datatype.LICENSE,
                dso.model.Datatype.MALWARE_FINDING,
            ),
        ))

    for finding in findings:
        filtered_rescorings = rescore.utility.rescorings_for_finding_by_specificity(
            finding=finding,
            rescorings=rescorings,
        )

        if filtered_rescorings:
            severity = gcm.Severity[filtered_rescorings[0].data.severity]
        elif finding.meta.type != dso.model.Datatype.ARTEFACT_SCAN_INFO:
            # artefact scan info does not have any severity but is just retrieved to evaluate
            # whether a scan exists for the given artefacts (if no finding is found)
            severity = gcm.Severity[finding.data.severity]
        else:
            severity = None

        yield issue_replicator.github.AggregatedFinding(
            finding=finding,
            severity=severity,
            rescorings=filtered_rescorings,
        )


def _group_findings_by_type_and_date(
    issue_replicator_config: config.IssueReplicatorConfig,
    delivery_client: delivery.client.DeliveryServiceClient,
    findings: collections.abc.Iterable[issue_replicator.github.AggregatedFinding],
    latest_processing_dates: set[str],
) -> collections.abc.Generator[
    tuple[
        dso.model.Datatype, # finding type (e.g. vulnerability, license, malware...)
        dso.model.Datasource,
        datetime.date, # latest processing date
        tuple[issue_replicator.github.AggregatedFinding], # findings
    ],
    None,
    None,
]:
    '''
    Groups all findings by finding type and latest processing date. Also, thresholds provided by
    configuration are applied on the findings before yielding.
    '''
    sprints = sprint_dates(delivery_client=delivery_client)

    datasource_for_datatype = {
        dso.model.Datatype.VULNERABILITY: dso.model.Datasource.BDBA,
        dso.model.Datatype.LICENSE: dso.model.Datasource.BDBA,
        dso.model.Datatype.MALWARE_FINDING: dso.model.Datasource.CLAMAV,
        dso.model.Datatype.DIKI_FINDING: dso.model.Datasource.DIKI,
    }

    for latest_processing_date in latest_processing_dates:
        date = dateutil.parser.isoparse(latest_processing_date).date()

        for finding_type_cfg in issue_replicator_config.finding_type_issue_replication_cfgs:
            finding_type = finding_type_cfg.finding_type
            finding_source = datasource_for_datatype.get(finding_type)

            filtered_findings = tuple(
                finding for finding in findings
                if (
                    finding.finding.meta.type == finding_type and
                    finding.finding.meta.datasource == finding_source and
                    finding.calculate_latest_processing_date(
                        sprints=sprints,
                        max_processing_days=issue_replicator_config.max_processing_days,
                    ) == date
                )
            )

            if (
                finding_type == dso.model.Datatype.VULNERABILITY
                and isinstance(finding_type_cfg, config.VulnerabilityIssueReplicationCfg)
            ):
                filtered_findings = tuple(
                    finding for finding in filtered_findings
                    if finding.finding.data.cvss_v3_score >= finding_type_cfg.cve_threshold
                )

            yield (
                finding_type,
                finding_source,
                date,
                filtered_findings,
            )


def replicate_issue(
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    backlog_item: k8s.backlog.BacklogItem,
):
    artefact = backlog_item.artefact

    # issues are grouped across multiple versions + extra identities, hence ignoring properties here
    artefact.component_version = None
    artefact.artefact.artefact_version = None
    artefact.artefact.artefact_extra_id = dict()

    logger.info(f'starting issue replication of {artefact}')

    compliance_snapshots = [
        cs for cs in delivery_client.query_metadata(
            artefacts=(artefact,),
            type=dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
        ) if cs.data.cfg_name == cfg_name # TODO mv to delivery service
    ]
    logger.info(f'{len(compliance_snapshots)=}')

    active_compliance_snapshots = tuple(
        cs for cs in compliance_snapshots
        if cs.data.current_state().status is dso.model.ComplianceSnapshotStatuses.ACTIVE
    )
    logger.info(f'{len(active_compliance_snapshots)=}')

    correlation_ids_by_latest_processing_date: dict[str, str] = dict()
    for compliance_snapshot in compliance_snapshots:
        date = compliance_snapshot.data.latest_processing_date.isoformat()

        if date in correlation_ids_by_latest_processing_date:
            continue

        correlation_id = compliance_snapshot.data.correlation_id
        correlation_ids_by_latest_processing_date[date] = correlation_id

    artefacts = tuple({
        cs.artefact for cs in active_compliance_snapshots
    })
    logger.info(f'{len(artefacts)=}')

    findings = tuple(_iter_findings_for_artefact(
        delivery_client=delivery_client,
        artefacts=artefacts,
    ))
    logger.info(f'{len(findings)=}')

    scanned_artefacts_by_datasource = {
        (
            finding.finding.meta.datasource,
            finding.finding.artefact,
        ) for finding in findings
        if finding.finding.meta.type == dso.model.Datatype.ARTEFACT_SCAN_INFO
    }

    findings_by_type_and_date = _group_findings_by_type_and_date(
        issue_replicator_config=issue_replicator_config,
        delivery_client=delivery_client,
        findings=findings,
        latest_processing_dates=correlation_ids_by_latest_processing_date.keys(),
    )

    def _issue_type(
        finding_type: str,
        finding_source: str,
    ) -> str:
        if (
            finding_type == dso.model.Datatype.VULNERABILITY
            and finding_source == dso.model.Datasource.BDBA
        ):
            return gci._label_bdba

        elif (
            finding_type == dso.model.Datatype.LICENSE
            and finding_source == dso.model.Datasource.BDBA
        ):
            return gci._label_licenses

        elif (
            finding_type == dso.model.Datatype.MALWARE_FINDING
            and finding_source == dso.model.Datasource.CLAMAV
        ):
            return gci._label_malware

        elif (
            finding_type == dso.model.Datatype.DIKI_FINDING
            and finding_source == dso.model.Datasource.DIKI
        ):
            return gci._label_diki

        else:
            raise NotImplementedError(f'{finding_type=} is not supported for {finding_source=}')

    def _find_finding_type_issue_replication_cfg(
        finding_cfgs: collections.abc.Iterable[config.FindingTypeIssueReplicationCfgBase],
        finding_type: str,
        absent_ok: bool=False,
    ) -> config.FindingTypeIssueReplicationCfgBase:
        for finding_cfg in finding_cfgs:
            if finding_cfg.finding_type == finding_type:
                return finding_cfg

        if absent_ok:
            return None

        return ValueError(f'no finding-type specific cfg found for {finding_type=}')

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

    for finding_type, finding_source, date, findings in findings_by_type_and_date:
        correlation_id = correlation_ids_by_latest_processing_date.get(date.isoformat())

        finding_type_issue_replication_cfg = _find_finding_type_issue_replication_cfg(
            finding_cfgs=issue_replicator_config.finding_type_issue_replication_cfgs,
            finding_type=finding_type,
        )

        issue_type = _issue_type(
            finding_type=finding_type,
            finding_source=finding_source,
        )

        scanned_artefact_ids = {
            scanned_artefact.artefact
            for datasource, scanned_artefact in scanned_artefacts_by_datasource
            if datasource == finding_source
        }

        artefact_ids_without_scan = all_artefact_ids - scanned_artefact_ids

        issue_replicator.github.create_or_update_or_close_issue(
            cfg_name=cfg_name,
            issue_replicator_config=issue_replicator_config,
            finding_type_issue_replication_cfg=finding_type_issue_replication_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            issue_type=issue_type,
            artefacts=artefacts,
            findings=findings,
            correlation_id=correlation_id,
            latest_processing_date=date,
            is_in_bom=is_in_bom,
            artefact_ids_without_scan=artefact_ids_without_scan,
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
        '--cfg-name',
        help='''
            specify the context the process should run in, not relevant for the artefact
            enumerator as well as backlog controller as these are context independent
        ''',
        default=os.environ.get('CFG_NAME'),
    )
    parser.add_argument(
        '--delivery-service-url',
        help='''
            specify the url of the delivery service to use instead of the one configured in the
            respective scan configuration
        ''',
    )
    parser.add_argument('--cache-dir', default=default_cache_dir)

    parsed_arguments = parser.parse_args()

    if not parsed_arguments.k8s_namespace:
        raise ValueError(
            'k8s namespace must be set, either via argument "--k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    if not parsed_arguments.cfg_name:
        raise ValueError(
            'name of the to-be-used scan configuration must be set, either via '
            'argument "--cfg-name" or via environment variable "CFG_NAME"'
        )

    return parsed_arguments


def main():
    signal.signal(signal.SIGTERM, handle_sigterm_and_sigint)
    signal.signal(signal.SIGINT, handle_sigterm_and_sigint)

    parsed_arguments = parse_args()
    cfg_name = parsed_arguments.cfg_name
    namespace = parsed_arguments.k8s_namespace
    delivery_service_url = parsed_arguments.delivery_service_url

    cfg_factory = ctx_util.cfg_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = cfg_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(
            kubeconfig_path=parsed_arguments.kubeconfig,
        )

    k8s.logging.init_logging_thread(
        service=config.Services.ISSUE_REPLICATOR,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=config.Services.ISSUE_REPLICATOR,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    issue_replicator_config = deserialise_issue_replicator_configuration(
        cfg_name=cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not delivery_service_url:
        delivery_service_url = issue_replicator_config.delivery_service_url

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        cfg_factory=cfg_factory,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_client,
    )

    global ready_to_terminate, wants_to_terminate
    github_api = issue_replicator_config.github_api_lookup(
        issue_replicator_config.github_issues_repository.html_url,
    )
    while not wants_to_terminate:
        ready_to_terminate = True
        issue_replicator.github.wait_for_quota_if_required(
            gh_api=github_api,
        )
        ready_to_terminate = False

        backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
            service=config.Services.ISSUE_REPLICATOR,
            cfg_name=cfg_name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )

        if not backlog_crd:
            ready_to_terminate = True
            sleep_interval = issue_replicator_config.lookup_new_backlog_item_interval
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
            cfg_name=cfg_name,
            issue_replicator_config=issue_replicator_config,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            backlog_item=backlog_item,
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
