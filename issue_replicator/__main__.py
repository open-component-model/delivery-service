import argparse
import atexit
import collections.abc
import datetime
import dateutil.parser
import functools
import logging
import os
import signal
import sys
import time

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.model
import gci.componentmodel as cm
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
import rescoring_util


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


def _artefacts_for_backlog_item_and_components(
    issue_replicator_config: config.IssueReplicatorConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    backlog_item: k8s.backlog.BacklogItem,
    components: set[cm.ComponentIdentity],
) -> collections.abc.Generator[cnudie.iter.Node | cnudie.iter.ArtefactNode, None, None]:
    '''
    yields all artefact nodes which can be found in the given `components` and which are
    referenced by the `backlog_item` (independent of the supplied version since the issue
    will span all versions). Also, filters provided by the `issue_replicator_config` will
    be applied.
    '''
    seen_version_pairs = set()

    artefact_kind = backlog_item.artefact.artefact_kind

    for component in components:
        component = component_descriptor_lookup(cm.ComponentIdentity(
            name=component.name,
            version=component.version
        )).component

        if artefact_kind is dso.model.ArtefactKind.RESOURCE:
            artefacts = component.resources
        elif artefact_kind is dso.model.ArtefactKind.SOURCE:
            artefacts = component.sources
        else:
            raise NotImplementedError(artefact_kind)

        # ignore version since we consider all versions for the same ticket
        for artefact in artefacts:
            if artefact.name != backlog_item.artefact.artefact.artefact_name:
                continue
            if artefact.type != backlog_item.artefact.artefact.artefact_type:
                continue
            # currently, we do not set the extraIdentity in the backlog items
            # TODO-Extra-Id: uncomment below code once extraIdentities are handled properly
            # if dso.model.normalise_artefact_extra_id(
            #     artefact_extra_id=artefact.extraIdentity,
            #     artefact_version=artefact.version,
            # ) != backlog_item.artefact.artefact.normalised_artefact_extra_id(
            #     remove_duplicate_version=True,
            # ):
            #     continue

            # found artefact of backlog item in component's artefact
            if artefact_kind is dso.model.ArtefactKind.RESOURCE:
                artefact_node = cnudie.iter.ResourceNode(
                    path=(cnudie.iter.NodePathEntry(component),),
                    resource=artefact,
                )
            elif artefact_kind is dso.model.ArtefactKind.SOURCE:
                artefact_node = cnudie.iter.SourceNode(
                    path=(cnudie.iter.NodePathEntry(component),),
                    source=artefact,
                )
            else:
                raise RuntimeError('this line should never be reached')

            if not artefact_node.resource.type in issue_replicator_config.artefact_types:
                continue

            if not issue_replicator_config.node_filter(artefact_node):
                continue

            # check if pair of component version and artefact version was already handled
            # -> this is the case, if the same artefact exists with different extra identities
            # (which we are not able to handle properly yet and thus only handle once)
            version_pair = f'{component.version}:{artefact.version}'
            if version_pair in seen_version_pairs:
                continue
            seen_version_pairs.add(version_pair)

            yield artefact_node


def _iter_findings_for_artefact(
    delivery_client: delivery.client.DeliveryServiceClient,
    artefact: dso.model.ComponentArtefactId,
    components: set[cm.ComponentIdentity],
) -> collections.abc.Generator[issue_replicator.github.AggregatedFinding]:
    if not components:
        return tuple()

    findings_for_components = delivery_client.query_metadata(
        components=components,
        type=(
            dso.model.Datatype.ARTEFACT_SCAN_INFO,
            dso.model.Datatype.VULNERABILITY,
            dso.model.Datatype.LICENSE,
            dso.model.Datatype.MALWARE_FINDING,
        ),
    )

    rescorings_for_components = delivery_client.query_metadata(
        components=components,
        type=dso.model.Datatype.RESCORING,
        referenced_type=(
            dso.model.Datatype.VULNERABILITY,
            dso.model.Datatype.LICENSE,
            dso.model.Datatype.MALWARE_FINDING,
        ),
    )

    for finding in findings_for_components:
        if not (
            finding.artefact.artefact_kind == artefact.artefact_kind
            and finding.artefact.artefact.artefact_name == artefact.artefact.artefact_name
            and finding.artefact.artefact.artefact_type == artefact.artefact.artefact_type
            # TODO-Extra-Id: uncomment below code once extraIdentities are handled properly
            # and finding.artefact.artefact.normalised_artefact_extra_id()
            #     == artefact.artefact.normalised_artefact_extra_id()
        ):
            continue

        rescorings = rescoring_util.rescorings_for_finding_by_specificity(
            finding=finding,
            rescorings=rescorings_for_components,
        )

        if rescorings:
            severity = gcm.Severity[rescorings[0].data.severity]
        elif finding.meta.type != dso.model.Datatype.ARTEFACT_SCAN_INFO:
            # artefact scan info does not have any severity but is just retrieved to evaluate
            # whether a scan exists for the given artefacts (if no finding is found)
            severity = gcm.Severity[finding.data.severity]
        else:
            severity = None

        yield issue_replicator.github.AggregatedFinding(
            finding=finding,
            severity=severity,
            rescorings=rescorings,
        )


def _findings_for_type_and_date(
    issue_replicator_config: config.IssueReplicatorConfig,
    latest_processing_date: datetime.date,
    sprints: tuple[datetime.date],
    type: str,
    source: str,
    findings: tuple[issue_replicator.github.AggregatedFinding],
) -> tuple[tuple[issue_replicator.github.AggregatedFinding], bool]:
    '''
    filters the provided `findings` by `type`, `source` and also by `latest_processing_date` and
    returns whether a scan of the artefacts exists for the given source
    '''
    findings_for_source = tuple(
        finding for finding in findings
        if finding.finding.meta.datasource == source
    )

    filtered_findings = tuple(
        finding for finding in findings_for_source
        if (
            finding.finding.meta.type == type and
            finding.calculate_latest_processing_date(
                sprints=sprints,
                max_processing_days=issue_replicator_config.max_processing_days,
            ) == latest_processing_date
        )
    )

    return filtered_findings, len(findings_for_source) > 0


def _findings_by_type_and_date(
    issue_replicator_config: config.IssueReplicatorConfig,
    delivery_client: delivery.client.DeliveryServiceClient,
    artefact: dso.model.ComponentArtefactId,
    components: set[cm.ComponentIdentity],
    latest_processing_dates: set[str],
) -> collections.abc.Generator[
    tuple[
        dso.model.Datatype, # finding type (e.g. vulnerability, license, malware...)
        dso.model.Datasource,
        datetime.date, # latest processing date
        tuple[issue_replicator.github.AggregatedFinding], # findings
        bool, # scan exists
    ],
    None,
    None,
]:
    '''
    yields all findings (of configured types) of the given `artefact` in `components`, grouped by
    finding type and latest processing date. Also, it yields the information whether the artefact
    was scanned at all which is determined based on if there is a "dummy finding". Thresholds
    provided by configuration are applied on the findings before yielding.
    '''
    findings = tuple(_iter_findings_for_artefact(
        delivery_client=delivery_client,
        artefact=artefact,
        components=components,
    ))
    logger.info(f'{len(findings)=}')

    sprints = sprint_dates(delivery_client=delivery_client)

    datasource_for_datatype = {
        dso.model.Datatype.VULNERABILITY: dso.model.Datasource.BDBA,
        dso.model.Datatype.LICENSE: dso.model.Datasource.BDBA,
        dso.model.Datatype.MALWARE_FINDING: dso.model.Datasource.CLAMAV,
    }

    for latest_processing_date in latest_processing_dates:
        date = dateutil.parser.isoparse(latest_processing_date).date()

        for finding_type_cfg in issue_replicator_config.finding_type_issue_replication_cfgs:
            finding_type = finding_type_cfg.finding_type
            finding_source = datasource_for_datatype.get(finding_type)

            filtered_findings, is_scanned = _findings_for_type_and_date(
                issue_replicator_config=issue_replicator_config,
                latest_processing_date=date,
                sprints=sprints,
                type=finding_type,
                source=finding_source,
                findings=findings,
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
                is_scanned,
            )


def replicate_issue(
    cfg_name: str,
    issue_replicator_config: config.IssueReplicatorConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    backlog_item: k8s.backlog.BacklogItem,
):
    artefact = backlog_item.artefact
    logger.info(
        f'starting issue replication of {backlog_item.artefact.artefact_kind} '
        f'{artefact.artefact.artefact_name} of component {artefact.component_name}'
    )

    compliance_snapshots = delivery_client.query_metadata(
        type=dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
    )
    compliance_snapshots_for_artefact = tuple(
        compliance_snapshot for compliance_snapshot in compliance_snapshots
        if (
            compliance_snapshot.data.cfg_name == cfg_name
            and compliance_snapshot.artefact.artefact_kind == artefact.artefact_kind
            and compliance_snapshot.artefact.component_name == artefact.component_name
            and compliance_snapshot.artefact.artefact.artefact_name
                == artefact.artefact.artefact_name
            and compliance_snapshot.artefact.artefact.artefact_type
                == artefact.artefact.artefact_type
            # TODO-Extra-Id: uncomment below code once extraIdentities are handled properly
            # and compliance_snapshot.artefact.artefact.normalised_artefact_extra_id(
            #     remove_duplicate_version=True,
            # ) == artefact.artefact.normalised_artefact_extra_id(
            #     remove_duplicate_version=True,
            # )
        )
    )

    active_compliance_snapshots_for_artefact = tuple(
        compliance_snapshot for compliance_snapshot in compliance_snapshots_for_artefact
        if (
            compliance_snapshot.data.current_state().status ==
            dso.model.ComplianceSnapshotStatuses.ACTIVE
        )
    )
    logger.info(f'{len(active_compliance_snapshots_for_artefact)=}')

    correlation_ids_by_latest_processing_date: dict[str, str] = dict()
    for compliance_snapshot in compliance_snapshots_for_artefact:
        date = compliance_snapshot.data.latest_processing_date.isoformat()

        if date in correlation_ids_by_latest_processing_date:
            continue

        correlation_id = compliance_snapshot.data.correlation_id
        correlation_ids_by_latest_processing_date[date] = correlation_id

    components = set(cm.ComponentIdentity(
        name=compliance_snapshot.artefact.component_name,
        version=compliance_snapshot.artefact.component_version,
    ) for compliance_snapshot in active_compliance_snapshots_for_artefact)
    logger.info(f'{len(components)=}')

    artefacts = tuple(_artefacts_for_backlog_item_and_components(
        issue_replicator_config=issue_replicator_config,
        component_descriptor_lookup=component_descriptor_lookup,
        backlog_item=backlog_item,
        components=components,
    ))

    findings_by_type_and_date = _findings_by_type_and_date(
        issue_replicator_config=issue_replicator_config,
        delivery_client=delivery_client,
        artefact=artefact,
        components=components,
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

    is_in_bom = len(active_compliance_snapshots_for_artefact) > 0
    for finding_type, finding_source, date, findings, is_scanned in findings_by_type_and_date:
        correlation_id = correlation_ids_by_latest_processing_date.get(date.isoformat())

        finding_type_issue_replication_cfg = _find_finding_type_issue_replication_cfg(
            finding_cfgs=issue_replicator_config.finding_type_issue_replication_cfgs,
            finding_type=finding_type,
        )

        issue_type = _issue_type(
            finding_type=finding_type,
            finding_source=finding_source,
        )

        issue_replicator.github.create_or_update_or_close_issue(
            cfg_name=cfg_name,
            issue_replicator_config=issue_replicator_config,
            finding_type_issue_replication_cfg=finding_type_issue_replication_cfg,
            delivery_client=delivery_client,
            issue_type=issue_type,
            artefacts=artefacts,
            findings=findings,
            correlation_id=correlation_id,
            latest_processing_date=date,
            is_in_bom=is_in_bom,
            is_scanned=is_scanned,
        )

    logger.info(
        f'finished issue replication of {backlog_item.artefact.artefact_kind} '
        f'{artefact.artefact.artefact_name} of component {artefact.component_name}'
    )


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='specify kubernetes cluster to interact with',
        default=os.environ.get('K8S_CFG_NAME'),
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with',
        default=os.environ.get('K8S_TARGET_NAMESPACE'),
    )
    parser.add_argument(
        '--cfg-name',
        help=(
            'specify the context the process should run in, not relevant for the artefact '
            'enumerator as well as backlog controller as these are context independent'
        ),
        default=os.environ.get('CFG_NAME'),
    )
    parser.add_argument(
        '--delivery-service-url',
        help=(
            'specify the url of the delivery service to use instead of the one configured in the '
            'respective scan configuration'
        ),
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
        kubernetes_api = k8s.util.kubernetes_api()

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

        k8s.backlog.delete_backlog_crd(
            name=name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )
        logger.info(f'processed and deleted backlog item {name}')

        time.sleep(2) # throttle github-api-requests


if __name__ == '__main__':
    main()
