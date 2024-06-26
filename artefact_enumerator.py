'''
This module reads all Kubernetes CRDs of type "ScanConfiguration" and starts a
separate thread for each of these configurations. Then it retrieves all artefacts
of the specified components and types and updates their respective compliance
snapshot in the delivery database. If certain changes apply to the compliance
snapshots, a corresponding backlog item is created as a result.
'''
import argparse
import atexit
import collections
import collections.abc
import datetime
import hashlib
import logging
import os
import threading
import typing

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.model
import gci.componentmodel as cm

import config
import ctx_util
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


def deserialise_scan_configurations(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> collections.abc.Generator[tuple[str, config.ScanConfiguration, None, None]]:
    scan_cfg_crds = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.ScanConfigurationCrd.DOMAIN,
        version=k8s.model.ScanConfigurationCrd.VERSION,
        plural=k8s.model.ScanConfigurationCrd.PLURAL_NAME,
        namespace=namespace,
    ).get('items')

    for scan_cfg_crd in scan_cfg_crds:
        if not (spec := scan_cfg_crd.get('spec')):
            continue

        cfg_name = scan_cfg_crd.get('metadata').get('name')

        yield cfg_name, config.deserialise_scan_configuration(
            spec_config=spec,
            included_services=(
                config.Services.ARTEFACT_ENUMERATOR,
                config.Services.BDBA,
                config.Services.ISSUE_REPLICATOR,
                config.Services.CLAMAV,
            ),
        )


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


def correlation_id(
    artefact: dso.model.ComponentArtefactId,
    latest_processing_date: datetime.date,
    version: str='v1',
) -> str:
    '''
    the correlation id neither contains the `component_version` nor the
    `artefact_version` to group compliance snapshots of the same artefact
    across different versions (e.g. necessary for GitHub tracking issues).
    Also, a version prefix is added to be able to differentiate correlation
    ids in case their calculation changed
    '''
    digest_str = (
        artefact.component_name + artefact.artefact_kind +
        artefact.artefact.artefact_name + artefact.artefact.artefact_type +
        latest_processing_date.isoformat()
    )
    digest = hashlib.shake_128(digest_str.encode('utf-8')).hexdigest(
        length=23,
    )

    return f'{version}/{digest}'


def create_compliance_snapshot(
    cfg_name: str,
    artefact: dso.model.ComponentArtefactId,
    latest_processing_date: datetime.date,
    now: datetime.datetime=datetime.datetime.now(),
    today: datetime.date=datetime.date.today(),
) -> dso.model.ArtefactMetadata:
    meta = dso.model.Metadata(
        datasource=dso.model.Datasource.ARTEFACT_ENUMERATOR,
        type=dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
        creation_date=now,
        last_update=now,
    )

    data = dso.model.ComplianceSnapshot(
        cfg_name=cfg_name,
        latest_processing_date=latest_processing_date,
        correlation_id=correlation_id(
            artefact=artefact,
            latest_processing_date=latest_processing_date,
        ),
        state=[dso.model.ComplianceSnapshotState(
            timestamp=now,
            status=dso.model.ComplianceSnapshotStatuses.ACTIVE,
        )],
    )

    return dso.model.ArtefactMetadata(
        artefact=artefact,
        meta=meta,
        data=data,
        discovery_date=today,
    )


def _iter_artefact_nodes(
    components: tuple[config.Component],
    artefact_types: tuple[str],
    node_filter: typing.Callable[[cnudie.iter.Node], bool],
    delivery_client: delivery.client.DeliveryServiceClient,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
) -> collections.abc.Generator[cnudie.iter.Node, None, None]:
    for component in components:
        versions = delivery_client.greatest_component_versions(
            component_name=component.component_name,
            max_versions=component.max_versions_limit,
            greatest_version=component.version,
            ocm_repo=component.ocm_repo,
            version_filter=component.version_filter,
        )

        for version in versions:
            if component.ocm_repo:
                ocm_repo_url = component.ocm_repo.oci_ref
            else:
                ocm_repo_url = None

            component = component_descriptor_lookup(
                cm.ComponentIdentity(
                    name=component.component_name,
                    version=version,
                ),
                ctx_repo=ocm_repo_url,
            ).component

            # note: adjust node filter here once other artefacts become processable as well
            yield from cnudie.iter.iter(
                component=component,
                lookup=component_descriptor_lookup,
                node_filter=lambda node: (
                    cnudie.iter.Filter.resources(node) and
                    node.artefact.type in artefact_types and
                    node_filter(node)
                ),
            )


def _iter_artefacts(
    components: tuple[config.Component],
    artefact_types: tuple[str],
    node_filter: typing.Callable[[cnudie.iter.Node], bool],
    delivery_client: delivery.client.DeliveryServiceClient,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
) -> collections.abc.Generator[dso.model.ComponentArtefactId, None, None]:
    seen_artefact_refs = set()

    for artefact_node in _iter_artefact_nodes(
        components=components,
        artefact_types=artefact_types,
        node_filter=node_filter,
        delivery_client=delivery_client,
        component_descriptor_lookup=component_descriptor_lookup,
    ):
        component = artefact_node.component_id
        artefact = artefact_node.artefact
        if isinstance(artefact_node, cnudie.iter.ResourceNode):
            artefact_kind = dso.model.ArtefactKind.RESOURCE
        elif isinstance(artefact_node, cnudie.iter.SourceNode):
            artefact_kind = dso.model.ArtefactKind.SOURCE
        else:
            artefact_kind = dso.model.ArtefactKind.ARTEFACT

        # explicitly remove extraIdentity here to only handle one artefact each
        # TODO-Extra-Id uncomment below code once extraIdentities are handled properly
        artefact_ref = dso.model.ComponentArtefactId(
            component_name=component.name,
            component_version=component.version,
            artefact_kind=artefact_kind,
            artefact=dso.model.LocalArtefactId(
                artefact_name=artefact.name,
                artefact_version=artefact.version,
                artefact_type=artefact.type,
                # artefact_extra_id=artefact.extraIdentity,
            )
        )

        if artefact_ref in seen_artefact_refs:
            continue
        seen_artefact_refs.add(artefact_ref)

        yield artefact_ref


def _create_and_update_compliance_snapshots_of_artefact(
    cfg_name: str,
    artefact: dso.model.ComponentArtefactId,
    compliance_snapshots: list[dso.model.ArtefactMetadata],
    sprints: tuple[datetime.date],
    now: datetime.datetime=datetime.datetime.now(),
    today: datetime.date=datetime.date.today(),
) -> tuple[list[dso.model.ArtefactMetadata], bool]:
    update_is_required = False

    for sprint_date in sprints:
        if any(
            compliance_snapshot for compliance_snapshot in compliance_snapshots
            if compliance_snapshot.data.latest_processing_date == sprint_date
        ):
            # compliance snapshot already exists for this artefact for this sprint
            continue

        compliance_snapshots.append(create_compliance_snapshot(
            cfg_name=cfg_name,
            artefact=artefact,
            latest_processing_date=sprint_date,
            now=now,
            today=today,
        ))
        update_is_required = True

    if update_is_required:
        logger.info(f'created compliance snapshots for {artefact=}')

    for compliance_snapshot in compliance_snapshots:
        if (
            compliance_snapshot.data.current_state().status !=
            dso.model.ComplianceSnapshotStatuses.ACTIVE
        ):
            compliance_snapshot.data.state.append(dso.model.ComplianceSnapshotState(
                timestamp=now,
                status=dso.model.ComplianceSnapshotStatuses.ACTIVE,
            ))
            compliance_snapshot.data.purge_old_states()
            update_is_required = True

    return compliance_snapshots, update_is_required


def _calculate_backlog_item_priority(
    service: config.Services,
    compliance_snapshots: list[dso.model.ArtefactMetadata],
    interval: int,
    status: dso.model.ComplianceSnapshotStatuses | str | int | None=None,
    now: datetime.datetime=datetime.datetime.now(),
) -> k8s.backlog.BacklogPriorities:
    '''
    - interval has passed -> priority LOW
    - compliance snapshot was just created -> priority HIGH
    - compliance snapshot status has changed -> priority HIGH
    '''
    priority = k8s.backlog.BacklogPriorities.NONE

    for compliance_snapshot in compliance_snapshots:
        current_state = compliance_snapshot.data.current_state(
            service=service,
        )

        if not current_state or (status and status != current_state.status):
            priority = max(priority, k8s.backlog.BacklogPriorities.HIGH)
            # the priority won't change anymore in this loop -> early exit
            break

        elif now - current_state.timestamp >= datetime.timedelta(
            seconds=interval,
        ):
            priority = max(priority, k8s.backlog.BacklogPriorities.LOW)

    return priority


def _findings_for_artefact(
    delivery_client: delivery.client.DeliveryServiceClient,
    artefact: dso.model.ComponentArtefactId,
    types: tuple[dso.model.Datatype],
) -> tuple[dso.model.ArtefactMetadata]:
    component = cm.ComponentIdentity(
        name=artefact.component_name,
        version=artefact.component_version,
    )

    findings = delivery_client.query_metadata(
        components=(component,),
        type=types,
    )

    return tuple(
        finding for finding in findings
        if finding.artefact == artefact
    )


def _create_backlog_item(
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: dso.model.ComponentArtefactId,
    compliance_snapshots: list[dso.model.ArtefactMetadata],
    service: config.Services,
    interval_seconds: int,
    status: dso.model.ComplianceSnapshotStatuses | str | int | None=None,
    now: datetime.datetime=datetime.datetime.now(),
) -> tuple[list[dso.model.ArtefactMetadata], bool]:
    priority = _calculate_backlog_item_priority(
        service=service,
        compliance_snapshots=compliance_snapshots,
        interval=interval_seconds,
        now=now,
        status=status,
    )

    if not priority:
        # no need to create a backlog item for this artefact
        return compliance_snapshots, False

    # there is a need to create a new backlog item, thus update issue replicator state for
    # every compliance snapshot of this artefact so that the configured replication interval
    # can be acknowledged correctly; otherwise, the replication might happen to often because
    # the state of some compliance snapshots for the artefact might not have changed
    for compliance_snapshot in compliance_snapshots:
        compliance_snapshot.data.state.append(dso.model.ComplianceSnapshotState(
            timestamp=now,
            status=status,
            service=service,
        ))
        compliance_snapshot.data.purge_old_states(
            service=service
        )

    was_created = k8s.backlog.create_unique_backlog_item(
        service=service,
        cfg_name=cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        artefact=artefact,
        priority=priority,
    )
    if was_created:
        logger.info(f'created {service} backlog item with {priority=} for {artefact=}')

    return compliance_snapshots, True


def _process_compliance_snapshots_of_artefact(
    cfg_name: str,
    scan_config: config.ScanConfiguration,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    delivery_client: delivery.client.DeliveryServiceClient,
    artefact: dso.model.ComponentArtefactId,
    compliance_snapshots: list[dso.model.ArtefactMetadata],
    sprints: tuple[datetime.date],
    types: tuple[dso.model.Datatype],
    now: datetime.datetime=datetime.datetime.now(),
    today: datetime.date=datetime.date.today(),
):
    compliance_snapshots, update_is_required = _create_and_update_compliance_snapshots_of_artefact(
        cfg_name=cfg_name,
        artefact=artefact,
        compliance_snapshots=compliance_snapshots,
        sprints=sprints,
        now=now,
        today=today,
    )

    if scan_config.bdba_config:
        compliance_snapshots, bdba_update_is_required = _create_backlog_item(
            cfg_name=cfg_name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=config.Services.BDBA,
            interval_seconds=scan_config.bdba_config.rescan_interval,
            now=now,
        )
        update_is_required |= bdba_update_is_required

    if scan_config.issue_replicator_config:
        findings = _findings_for_artefact(
            delivery_client=delivery_client,
            artefact=artefact,
            types=types,
        )
        compliance_snapshots, issue_update_is_required = _create_backlog_item(
            cfg_name=cfg_name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=config.Services.ISSUE_REPLICATOR,
            interval_seconds=scan_config.issue_replicator_config.replication_interval,
            status=len(findings),
            now=now,
        )
        update_is_required |= issue_update_is_required

    if scan_config.clamav_config:
        interval = scan_config.clamav_config.rescan_interval
        compliance_snapshots, malware_update_is_required = _create_backlog_item(
            cfg_name=cfg_name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=config.Services.CLAMAV,
            interval_seconds=interval,
            now=now,
        )
        update_is_required |= malware_update_is_required

    if not update_is_required:
        logger.info(
            f'{len(compliance_snapshots)} compliance snapshots did not change, '
            f'no need to update in delivery-db ({artefact=})'
        )
        return

    delivery_client.update_metadata(data=compliance_snapshots)
    logger.info(
        f'updated {len(compliance_snapshots)} compliance snapshots in delivery-db ({artefact=})'
    )


def _process_inactive_compliance_snapshots(
    cfg_name: str,
    scan_config: config.ScanConfiguration,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    delivery_client: delivery.client.DeliveryServiceClient,
    compliance_snapshots: list[dso.model.ArtefactMetadata],
    now: datetime.datetime=datetime.datetime.now(),
):
    cs_by_artefact = collections.defaultdict(list)

    for compliance_snapshot in compliance_snapshots:
        cs_by_artefact[compliance_snapshot.artefact].append(compliance_snapshot)

    for compliance_snapshots in cs_by_artefact.values():
        artefact = compliance_snapshots[0].artefact
        update_is_required = False
        deletable_compliance_snapshots: list[dso.model.ArtefactMetadata] = []

        for compliance_snapshot in compliance_snapshots:
            current_general_state = compliance_snapshot.data.current_state()

            if current_general_state.status != dso.model.ComplianceSnapshotStatuses.INACTIVE:
                compliance_snapshot.data.state.append(dso.model.ComplianceSnapshotState(
                    timestamp=now,
                    status=dso.model.ComplianceSnapshotStatuses.INACTIVE,
                ))
                compliance_snapshot.data.purge_old_states()
                current_general_state = compliance_snapshot.data.current_state()
                update_is_required = True

                if scan_config.issue_replicator_config:
                    compliance_snapshot.data.state.append(dso.model.ComplianceSnapshotState(
                        timestamp=now,
                        status=0,
                        service=config.Services.ISSUE_REPLICATOR,
                    ))
                    compliance_snapshot.data.purge_old_states(
                        service=config.Services.ISSUE_REPLICATOR,
                    )

            if now - current_general_state.timestamp >= datetime.timedelta(
                seconds=scan_config.artefact_enumerator_config.compliance_snapshot_grace_period,
            ):
                deletable_compliance_snapshots.append(compliance_snapshot)

        if update_is_required:
            delivery_client.update_metadata(data=compliance_snapshots)
            logger.info(
                f'updated {len(compliance_snapshots)} inactive compliance snapshots in delivery-db '
                f'({artefact=})'
            )

            if scan_config.issue_replicator_config:
                priority = k8s.backlog.BacklogPriorities.HIGH
                was_created = k8s.backlog.create_unique_backlog_item(
                    service=config.Services.ISSUE_REPLICATOR,
                    cfg_name=cfg_name,
                    namespace=namespace,
                    kubernetes_api=kubernetes_api,
                    artefact=artefact,
                    priority=priority,
                )
                if was_created:
                    logger.info(
                        f'created issue replicator backlog item with {priority=} for inactive '
                        f'{artefact=}'
                    )

        if deletable_compliance_snapshots:
            delivery_client.delete_metadata(data=deletable_compliance_snapshots)
            logger.info(
                f'deleted {len(deletable_compliance_snapshots)} inactive compliance snapshots in '
                f'delivery-db ({artefact=})'
            )


def enumerate_artefacts(
    cfg_name: str,
    scan_config: config.ScanConfiguration,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    delivery_client: delivery.client.DeliveryServiceClient,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    types: tuple[dso.model.Datatype],
):
    '''
    retrieves first of all the unique artefacts referenced by the configured components as well
    as all compliance snapshots belonging to the given `cfg_name`. These compliance snapshots are
    differentiated between "active" (still referenced by one of the before retrieved artefacts)
    and "inactive" (not referenced anymore). While iterating the artefacts, the active compliance
    snapshots are being created/updated (status change) and based on this, it is evaluated if a
    new backlog item must be created (and if yes, it will be created). The inactive compliance
    snapshots are also being updated (status change) and if the configured grace period has passed,
    they are deleted from the delivery-db. Also, for each artefact becoming inactive, a backlog item
    for the issue replicator must be created.
    '''
    # store current date + time to ensure they are consistent for whole enumeration
    now = datetime.datetime.now()
    today = datetime.date.today()

    time_range = scan_config.artefact_enumerator_config.sprints_time_range
    logger.info(f'{time_range=}')
    sprints = tuple(
        date for date in sprint_dates(delivery_client=delivery_client)
        if not time_range or (date >= time_range.start_date and date <= time_range.end_date)
    )
    logger.info(f'{len(sprints)=}')

    artefacts = set(_iter_artefacts(
        components=scan_config.artefact_enumerator_config.components,
        artefact_types=scan_config.artefact_enumerator_config.artefact_types,
        node_filter=scan_config.artefact_enumerator_config.node_filter,
        delivery_client=delivery_client,
        component_descriptor_lookup=component_descriptor_lookup,
    ))
    logger.info(f'{len(artefacts)=}')

    compliance_snapshots = delivery_client.query_metadata(
        type=dso.model.Datatype.COMPLIANCE_SNAPSHOTS,
    )
    compliance_snapshots = [
        compliance_snapshot for compliance_snapshot in compliance_snapshots
        if compliance_snapshot.data.cfg_name == cfg_name # TODO mv to delivery service
    ]
    logger.info(f'{len(compliance_snapshots)=}')

    active_compliance_snapshots = tuple(
        compliance_snapshot for compliance_snapshot in compliance_snapshots
        if compliance_snapshot.artefact in artefacts
    )
    logger.info(f'{len(active_compliance_snapshots)=}')
    inactive_compliance_snapshots = tuple(
        compliance_snapshot for compliance_snapshot in compliance_snapshots
        if compliance_snapshot.artefact not in artefacts
    )
    logger.info(f'{len(inactive_compliance_snapshots)=}')

    for artefact in artefacts:
        compliance_snapshots = [
            compliance_snapshot for compliance_snapshot in active_compliance_snapshots
            if compliance_snapshot.artefact == artefact
        ]

        _process_compliance_snapshots_of_artefact(
            cfg_name=cfg_name,
            scan_config=scan_config,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            delivery_client=delivery_client,
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            sprints=sprints,
            types=types,
            now=now,
            today=today,
        )

    _process_inactive_compliance_snapshots(
        cfg_name=cfg_name,
        scan_config=scan_config,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        delivery_client=delivery_client,
        compliance_snapshots=inactive_compliance_snapshots,
        now=now,
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
            'k8s namespace must be set, either via argument "k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


def main():
    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace

    cfg_factory = ctx_util.cfg_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = cfg_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api()

    k8s.logging.init_logging_thread(
        service=config.Services.ARTEFACT_ENUMERATOR,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=config.Services.ARTEFACT_ENUMERATOR,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    scan_configs_for_cfg_name = deserialise_scan_configurations(
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    types = (
        dso.model.Datatype.VULNERABILITY,
        dso.model.Datatype.LICENSE,
        dso.model.Datatype.MALWARE_FINDING,
    )

    for cfg_name, scan_config in scan_configs_for_cfg_name:
        if not (delivery_service_url := parsed_arguments.delivery_service_url):
            delivery_service_url = scan_config.artefact_enumerator_config.delivery_service_url

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

        thread = threading.Thread(
            target=enumerate_artefacts,
            args=(
                cfg_name,
                scan_config,
                namespace,
                kubernetes_api,
                delivery_client,
                component_descriptor_lookup,
                types,
            ),
        )
        thread.name = cfg_name
        thread.start()


if __name__ == '__main__':
    main()
