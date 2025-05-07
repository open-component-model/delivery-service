import argparse
import atexit
import collections
import collections.abc
import datetime
import logging
import os

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import ocm

import ctx_util
import k8s.backlog
import k8s.logging
import k8s.runtime_artefacts
import k8s.util
import lookups
import odg.extensions_cfg
import odg.findings
import odg.model
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


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


def create_compliance_snapshot(
    artefact: odg.model.ComponentArtefactId,
    due_date: datetime.date,
    now: datetime.datetime=datetime.datetime.now(),
    today: datetime.date=datetime.date.today(),
) -> odg.model.ArtefactMetadata:
    meta = odg.model.Metadata(
        datasource=odg.model.Datasource.ARTEFACT_ENUMERATOR,
        type=odg.model.Datatype.COMPLIANCE_SNAPSHOTS,
        creation_date=now,
        last_update=now,
    )

    data = odg.model.ComplianceSnapshot(
        due_date=due_date,
        state=[odg.model.ComplianceSnapshotState(
            timestamp=now,
            status=odg.model.ComplianceSnapshotStatuses.ACTIVE,
        )],
    )

    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=meta,
        data=data,
        discovery_date=today,
    )


def _iter_ocm_artefacts(
    components: collections.abc.Iterable[odg.extensions_cfg.Component],
    delivery_client: delivery.client.DeliveryServiceClient,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
) -> collections.abc.Generator[odg.model.ComponentArtefactId, None, None]:
    for component in components:
        versions = delivery_client.greatest_component_versions(
            component_name=component.component_name,
            max_versions=component.max_versions_limit,
            greatest_version=component.version,
            ocm_repo=component.ocm_repo,
            version_filter=component.version_filter,
        )

        for version in versions:
            component_id = ocm.ComponentIdentity(
                name=component.component_name,
                version=version,
            )

            if ocm_repo := component.ocm_repo:
                component = component_descriptor_lookup(
                    component_id,
                    ocm_repository_lookup=cnudie.retrieve.ocm_repository_lookup(ocm_repo),
                ).component
            else:
                component = component_descriptor_lookup(component_id).component

            for artefact_node in cnudie.iter.iter(
                component=component,
                lookup=component_descriptor_lookup,
                node_filter=cnudie.iter.Filter.artefacts,
            ):
                yield odg.model.component_artefact_id_from_ocm(
                    component=artefact_node.component,
                    artefact=artefact_node.artefact,
                )


def _create_and_update_compliance_snapshots_of_artefact(
    artefact: odg.model.ComponentArtefactId,
    compliance_snapshots: list[odg.model.ArtefactMetadata],
    sprints: tuple[datetime.date],
    now: datetime.datetime=datetime.datetime.now(),
    today: datetime.date=datetime.date.today(),
) -> tuple[list[odg.model.ArtefactMetadata], bool]:
    update_is_required = False

    for sprint_date in sprints:
        if any(
            compliance_snapshot for compliance_snapshot in compliance_snapshots
            if compliance_snapshot.data.due_date == sprint_date
        ):
            # compliance snapshot already exists for this artefact for this sprint
            continue

        compliance_snapshots.append(create_compliance_snapshot(
            artefact=artefact,
            due_date=sprint_date,
            now=now,
            today=today,
        ))
        update_is_required = True

    if update_is_required:
        logger.info(f'created compliance snapshots for {artefact=}')

    for compliance_snapshot in compliance_snapshots:
        if (
            compliance_snapshot.data.current_state().status !=
            odg.model.ComplianceSnapshotStatuses.ACTIVE
        ):
            compliance_snapshot.data.state.append(odg.model.ComplianceSnapshotState(
                timestamp=now,
                status=odg.model.ComplianceSnapshotStatuses.ACTIVE,
            ))
            compliance_snapshot.data.purge_old_states()
            update_is_required = True

    return compliance_snapshots, update_is_required


def _calculate_backlog_item_priority(
    service: odg.extensions_cfg.Services,
    compliance_snapshots: list[odg.model.ArtefactMetadata],
    interval: int,
    now: datetime.datetime=datetime.datetime.now(),
    status: int | None=None,
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


def _create_backlog_item(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: odg.model.ComponentArtefactId,
    compliance_snapshots: list[odg.model.ArtefactMetadata],
    service: odg.extensions_cfg.Services,
    interval_seconds: int,
    now: datetime.datetime=datetime.datetime.now(),
    status: int | None=None,
) -> tuple[list[odg.model.ArtefactMetadata], bool]:
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

    # there is a need to create a new backlog item, thus update the state for every compliance
    # snapshot of this artefact so that the configured interval can be acknowledged correctly;
    # otherwise, the trigger might happen to often because the state of some compliance snapshots
    # for the artefact might not have changed
    for compliance_snapshot in compliance_snapshots:
        compliance_snapshot.data.state.append(odg.model.ComplianceSnapshotState(
            timestamp=now,
            status=status,
            service=service,
        ))
        compliance_snapshot.data.purge_old_states(
            service=service,
        )

    was_created = k8s.backlog.create_unique_backlog_item(
        service=service,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        artefact=artefact,
        priority=priority,
    )
    if was_created:
        logger.info(f'created {service} backlog item with {priority=} for {artefact=}')

    return compliance_snapshots, True


def _create_backlog_item_for_extension(
    finding_cfgs: collections.abc.Iterable[odg.findings.Finding],
    finding_types: collections.abc.Sequence[odg.findings.FindingType],
    artefact: odg.model.ComponentArtefactId,
    compliance_snapshots: list[odg.model.ArtefactMetadata],
    service: odg.extensions_cfg.Services,
    interval_seconds: int,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    now: datetime.datetime=datetime.datetime.now(),
) -> tuple[list[odg.model.ArtefactMetadata], bool]:
    if not any(
        finding_cfg for finding_cfg in finding_cfgs
        if (
            finding_cfg.type in finding_types
            and finding_cfg.matches(artefact)
        )
    ):
        # findings are filtered out for this artefact anyways -> no need to create a BLI
        return compliance_snapshots, False

    return _create_backlog_item(
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        artefact=artefact,
        compliance_snapshots=compliance_snapshots,
        service=service,
        interval_seconds=interval_seconds,
        now=now,
    )


def _process_compliance_snapshots_of_artefact(
    extensions_cfg: odg.extensions_cfg.ExtensionsConfiguration,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    delivery_client: delivery.client.DeliveryServiceClient,
    artefact: odg.model.ComponentArtefactId,
    compliance_snapshots: list[odg.model.ArtefactMetadata],
    sprints: tuple[datetime.date],
    now: datetime.datetime=datetime.datetime.now(),
    today: datetime.date=datetime.date.today(),
):
    compliance_snapshots, metadata_update_required = _create_and_update_compliance_snapshots_of_artefact( # noqa: E501
        artefact=artefact,
        compliance_snapshots=compliance_snapshots,
        sprints=sprints,
        now=now,
        today=today,
    )

    if (
        extensions_cfg.bdba
        and extensions_cfg.bdba.enabled
        and extensions_cfg.bdba.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshots, snapshots_have_changed = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.findings.FindingType.VULNERABILITY, odg.findings.FindingType.LICENSE),
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=odg.extensions_cfg.Services.BDBA,
            interval_seconds=extensions_cfg.bdba.interval,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            now=now,
        )
        metadata_update_required |= snapshots_have_changed

    if (
        extensions_cfg.clamav
        and extensions_cfg.clamav.enabled
        and extensions_cfg.clamav.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshots, snapshots_have_changed = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.findings.FindingType.MALWARE,),
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=odg.extensions_cfg.Services.CLAMAV,
            interval_seconds=extensions_cfg.clamav.interval,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            now=now,
        )
        metadata_update_required |= snapshots_have_changed

    if (
        extensions_cfg.crypto
        and extensions_cfg.crypto.enabled
        and extensions_cfg.crypto.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshots, snapshots_have_changed = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.findings.FindingType.CRYPTO,),
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=odg.extensions_cfg.Services.CRYPTO,
            interval_seconds=extensions_cfg.crypto.interval,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            now=now,
        )
        metadata_update_required |= snapshots_have_changed

    if (
        extensions_cfg.issue_replicator
        and extensions_cfg.issue_replicator.enabled
    ):
        # if the number of executed scans has changed, trigger an issue update
        scan_count = len(delivery_client.query_metadata(
            artefacts=(artefact,),
            type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
        ))

        compliance_snapshots, snapshots_have_changed = _create_backlog_item(
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
            interval_seconds=extensions_cfg.issue_replicator.interval,
            now=now,
            status=scan_count,
        )
        metadata_update_required |= snapshots_have_changed

    if (
        extensions_cfg.sast
        and extensions_cfg.sast.enabled
        and extensions_cfg.sast.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshots, snapshots_have_changed = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.findings.FindingType.SAST,),
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=odg.extensions_cfg.Services.SAST,
            interval_seconds=extensions_cfg.sast.interval,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            now=now,
        )
        metadata_update_required |= snapshots_have_changed

    if (
        extensions_cfg.osid
        and extensions_cfg.osid.enabled
        and extensions_cfg.osid.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshots, snapshots_have_changed = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.findings.FindingType.OSID,),
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            service=odg.extensions_cfg.Services.OSID,
            interval_seconds=extensions_cfg.osid.interval,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            now=now,
        )
        metadata_update_required |= snapshots_have_changed

    if not metadata_update_required:
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
    extensions_cfg: odg.extensions_cfg.ExtensionsConfiguration,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    delivery_client: delivery.client.DeliveryServiceClient,
    compliance_snapshots: list[odg.model.ArtefactMetadata],
    now: datetime.datetime=datetime.datetime.now(),
):
    cs_by_artefact = collections.defaultdict(list)

    for compliance_snapshot in compliance_snapshots:
        cs_by_artefact[compliance_snapshot.artefact].append(compliance_snapshot)

    for compliance_snapshots in cs_by_artefact.values():
        artefact = compliance_snapshots[0].artefact
        update_is_required = False
        deletable_compliance_snapshots: list[odg.model.ArtefactMetadata] = []

        for compliance_snapshot in compliance_snapshots:
            current_general_state = compliance_snapshot.data.current_state()

            if current_general_state.status != odg.model.ComplianceSnapshotStatuses.INACTIVE:
                compliance_snapshot.data.state.append(odg.model.ComplianceSnapshotState(
                    timestamp=now,
                    status=odg.model.ComplianceSnapshotStatuses.INACTIVE,
                ))
                compliance_snapshot.data.purge_old_states()
                current_general_state = compliance_snapshot.data.current_state()
                update_is_required = True

            if now - current_general_state.timestamp >= datetime.timedelta(
                seconds=extensions_cfg.artefact_enumerator.compliance_snapshot_grace_period,
            ):
                deletable_compliance_snapshots.append(compliance_snapshot)

        if update_is_required:
            delivery_client.update_metadata(data=compliance_snapshots)
            logger.info(
                f'updated {len(compliance_snapshots)} inactive compliance snapshots in delivery-db '
                f'({artefact=})'
            )

            if extensions_cfg.issue_replicator:
                priority = k8s.backlog.BacklogPriorities.HIGH
                was_created = k8s.backlog.create_unique_backlog_item(
                    service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
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
    extensions_cfg: odg.extensions_cfg.ExtensionsConfiguration,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    delivery_client: delivery.client.DeliveryServiceClient,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
):
    '''
    Retrieves first of all the unique artefacts referenced by the configured components and the
    available runtime artefacts from the respective custom resources as well as all compliance
    snapshots. These compliance snapshots are differentiated between "active" (still referenced by
    one of the artefacts retrieved before) and "inactive" (not referenced anymore). While iterating
    the artefacts, the active compliance snapshots are being created/updated (status change) and
    based on this, it is evaluated if a new backlog item must be created (and if yes, it will be
    created). The inactive compliance snapshots are also being updated (status change) and if the
    configured grace period has passed, they are deleted from the delivery-db. Also, for each
    artefact becoming inactive, a backlog item for the issue replicator will be be created.
    '''
    # store current date + time to ensure they are consistent for whole enumeration
    now = datetime.datetime.now()
    today = datetime.date.today()

    time_range = extensions_cfg.artefact_enumerator.sprints_relative_time_range
    logger.info(f'{time_range=}')
    sprints = tuple(
        date for date in sprint_dates(delivery_client=delivery_client)
        if not time_range or (date >= time_range.start_date and date <= time_range.end_date)
    )
    logger.info(f'{len(sprints)=}')

    ocm_artefacts = set(_iter_ocm_artefacts(
        components=extensions_cfg.artefact_enumerator.components,
        delivery_client=delivery_client,
        component_descriptor_lookup=component_descriptor_lookup,
    ))
    logger.info(f'{len(ocm_artefacts)=}')

    runtime_artefacts = {
        runtime_artefact.artefact
        for runtime_artefact in k8s.runtime_artefacts.iter_runtime_artefacts(
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )
    }
    logger.info(f'{len(runtime_artefacts)=}')

    artefacts = ocm_artefacts | runtime_artefacts
    logger.info(f'{len(artefacts)=}')

    compliance_snapshots = delivery_client.query_metadata(
        type=odg.model.Datatype.COMPLIANCE_SNAPSHOTS,
    )
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
            extensions_cfg=extensions_cfg,
            finding_cfgs=finding_cfgs,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            delivery_client=delivery_client,
            artefact=artefact,
            compliance_snapshots=compliance_snapshots,
            sprints=sprints,
            now=now,
            today=today,
        )

    _process_inactive_compliance_snapshots(
        extensions_cfg=extensions_cfg,
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
            'k8s namespace must be set, either via argument "k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


def main():
    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace

    secret_factory = ctx_util.secret_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(
            kubeconfig_path=parsed_arguments.kubeconfig,
        )

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.ARTEFACT_ENUMERATOR,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.ARTEFACT_ENUMERATOR,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    finding_cfgs = odg.findings.Finding.from_file(findings_cfg_path)

    if not (delivery_service_url := parsed_arguments.delivery_service_url):
        delivery_service_url = extensions_cfg.artefact_enumerator.delivery_service_url

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

    enumerate_artefacts(
        extensions_cfg=extensions_cfg,
        finding_cfgs=finding_cfgs,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        delivery_client=delivery_client,
        component_descriptor_lookup=component_descriptor_lookup,
    )


if __name__ == '__main__':
    main()
