import atexit
import collections
import collections.abc
import dataclasses
import datetime
import logging

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import ocm

import k8s.backlog
import k8s.logging
import k8s.runtime_artefacts
import k8s.util
import lookups
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


@dataclasses.dataclass
class UncommittedBacklogItem:
    '''
    To prevent backlog items from being created too early, i.e. when the compliance snapshots have
    not been updated yet in the delivery-db, all to-be-created backlog items are collected and
    created at the very end, once all compliance snapshots have been updated.
    '''
    artefact: odg.model.ComponentArtefactId
    priority: k8s.backlog.BacklogPriorities
    service: odg.extensions_cfg.Services


def create_compliance_snapshot(
    artefact: odg.model.ComponentArtefactId,
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


def _create_or_update_compliance_snapshot_of_artefact(
    artefact: odg.model.ComponentArtefactId,
    compliance_snapshot: odg.model.ArtefactMetadata | None,
    now: datetime.datetime=datetime.datetime.now(),
    today: datetime.date=datetime.date.today(),
) -> odg.model.ArtefactMetadata:
    if not compliance_snapshot:
        logger.info(f'creating compliance snapshot for {artefact=}')
        return create_compliance_snapshot(
            artefact=artefact,
            now=now,
            today=today,
        )

    if not compliance_snapshot.data.is_active:
        logger.info(f'updating state of compliance snapshot for {artefact=}')
        compliance_snapshot.data.update_state(odg.model.ComplianceSnapshotState(
            timestamp=now,
            status=odg.model.ComplianceSnapshotStatuses.ACTIVE,
        ))

    return compliance_snapshot


def _calculate_backlog_item_priority(
    service: odg.extensions_cfg.Services,
    compliance_snapshot: odg.model.ArtefactMetadata,
    interval: int,
    now: datetime.datetime=datetime.datetime.now(),
    status: int | None=None,
) -> k8s.backlog.BacklogPriorities:
    '''
    - interval has passed -> priority LOW
    - compliance snapshot was just created -> priority HIGH
    - compliance snapshot status has changed -> priority HIGH
    '''
    current_state = compliance_snapshot.data.current_state(
        service=service,
    )

    if not current_state or (status and status != current_state.status):
        return k8s.backlog.BacklogPriorities.HIGH

    elif now - current_state.timestamp >= datetime.timedelta(
        seconds=interval,
    ):
        return k8s.backlog.BacklogPriorities.LOW

    return k8s.backlog.BacklogPriorities.NONE


def _create_backlog_item(
    artefact: odg.model.ComponentArtefactId,
    compliance_snapshot: odg.model.ArtefactMetadata,
    service: odg.extensions_cfg.Services,
    interval_seconds: int,
    now: datetime.datetime=datetime.datetime.now(),
    status: int | None=None,
) -> tuple[odg.model.ArtefactMetadata, UncommittedBacklogItem | None]:
    priority = _calculate_backlog_item_priority(
        service=service,
        compliance_snapshot=compliance_snapshot,
        interval=interval_seconds,
        now=now,
        status=status,
    )

    if not priority:
        # no need to create a backlog item for this artefact
        return compliance_snapshot, None

    # there is a need to create a new backlog item, thus update the state of the compliance snapshot
    # of this artefact so that the configured interval can be acknowledged correctly
    compliance_snapshot.data.update_state(odg.model.ComplianceSnapshotState(
        timestamp=now,
        status=status,
        service=service,
    ))

    uncommitted_backlog_item = UncommittedBacklogItem(
        artefact=artefact,
        priority=priority,
        service=service,
    )

    return compliance_snapshot, uncommitted_backlog_item


def _create_backlog_item_for_extension(
    finding_cfgs: collections.abc.Iterable[odg.findings.Finding],
    finding_types: collections.abc.Sequence[odg.model.Datatype],
    artefact: odg.model.ComponentArtefactId,
    compliance_snapshot: odg.model.ArtefactMetadata,
    service: odg.extensions_cfg.Services,
    interval_seconds: int,
    now: datetime.datetime=datetime.datetime.now(),
) -> tuple[odg.model.ArtefactMetadata, UncommittedBacklogItem | None]:
    if not any(
        finding_cfg for finding_cfg in finding_cfgs
        if (
            finding_cfg.type in finding_types
            and finding_cfg.matches(artefact)
        )
    ):
        # findings are filtered out for this artefact anyways -> no need to create a BLI
        return compliance_snapshot, None

    return _create_backlog_item(
        artefact=artefact,
        compliance_snapshot=compliance_snapshot,
        service=service,
        interval_seconds=interval_seconds,
        now=now,
    )


def _process_compliance_snapshot_of_artefact(
    extensions_cfg: odg.extensions_cfg.ExtensionsConfiguration,
    finding_cfgs: collections.abc.Sequence[odg.findings.Finding],
    delivery_client: delivery.client.DeliveryServiceClient,
    artefact: odg.model.ComponentArtefactId,
    compliance_snapshot: odg.model.ArtefactMetadata | None,
    now: datetime.datetime=datetime.datetime.now(),
    today: datetime.date=datetime.date.today(),
) -> tuple[odg.model.ArtefactMetadata, list[UncommittedBacklogItem]]:
    compliance_snapshot = _create_or_update_compliance_snapshot_of_artefact(
        artefact=artefact,
        compliance_snapshot=compliance_snapshot,
        now=now,
        today=today,
    )
    uncommitted_backlog_items = []

    if (
        extensions_cfg.bdba
        and extensions_cfg.bdba.enabled
        and extensions_cfg.bdba.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshot, uncommitted_backlog_item = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(
                odg.model.Datatype.VULNERABILITY_FINDING,
                odg.model.Datatype.LICENSE_FINDING,
            ),
            artefact=artefact,
            compliance_snapshot=compliance_snapshot,
            service=odg.extensions_cfg.Services.BDBA,
            interval_seconds=extensions_cfg.bdba.interval,
            now=now,
        )
        if uncommitted_backlog_item:
            uncommitted_backlog_items.append(uncommitted_backlog_item)

    if (
        extensions_cfg.clamav
        and extensions_cfg.clamav.enabled
        and extensions_cfg.clamav.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshot, uncommitted_backlog_item = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.model.Datatype.MALWARE_FINDING,),
            artefact=artefact,
            compliance_snapshot=compliance_snapshot,
            service=odg.extensions_cfg.Services.CLAMAV,
            interval_seconds=extensions_cfg.clamav.interval,
            now=now,
        )
        if uncommitted_backlog_item:
            uncommitted_backlog_items.append(uncommitted_backlog_item)

    if (
        extensions_cfg.crypto
        and extensions_cfg.crypto.enabled
        and extensions_cfg.crypto.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshot, uncommitted_backlog_item = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.model.Datatype.CRYPTO_FINDING,),
            artefact=artefact,
            compliance_snapshot=compliance_snapshot,
            service=odg.extensions_cfg.Services.CRYPTO,
            interval_seconds=extensions_cfg.crypto.interval,
            now=now,
        )
        if uncommitted_backlog_item:
            uncommitted_backlog_items.append(uncommitted_backlog_item)

    if (
        extensions_cfg.issue_replicator
        and extensions_cfg.issue_replicator.enabled
    ):
        # if the number of executed scans has changed, trigger an issue update
        scan_count = len(delivery_client.query_metadata(
            artefacts=(artefact,),
            type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
        ))

        compliance_snapshot, uncommitted_backlog_item = _create_backlog_item(
            artefact=artefact,
            compliance_snapshot=compliance_snapshot,
            service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
            interval_seconds=extensions_cfg.issue_replicator.interval,
            now=now,
            status=scan_count,
        )
        if uncommitted_backlog_item:
            uncommitted_backlog_items.append(uncommitted_backlog_item)

    if (
        extensions_cfg.responsibles
        and extensions_cfg.responsibles.enabled
    ):
        compliance_snapshot, uncommitted_backlog_item = _create_backlog_item(
            artefact=artefact,
            compliance_snapshot=compliance_snapshot,
            service=odg.extensions_cfg.Services.RESPONSIBLES,
            interval_seconds=extensions_cfg.responsibles.interval,
            now=now,
        )
        if uncommitted_backlog_item:
            uncommitted_backlog_items.append(uncommitted_backlog_item)

    if (
        extensions_cfg.sast
        and extensions_cfg.sast.enabled
        and extensions_cfg.sast.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshot, uncommitted_backlog_item = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.model.Datatype.SAST_FINDING,),
            artefact=artefact,
            compliance_snapshot=compliance_snapshot,
            service=odg.extensions_cfg.Services.SAST,
            interval_seconds=extensions_cfg.sast.interval,
            now=now,
        )
        if uncommitted_backlog_item:
            uncommitted_backlog_items.append(uncommitted_backlog_item)

    if (
        extensions_cfg.osid
        and extensions_cfg.osid.enabled
        and extensions_cfg.osid.is_supported(artefact_kind=artefact.artefact_kind)
    ):
        compliance_snapshot, uncommitted_backlog_item = _create_backlog_item_for_extension(
            finding_cfgs=finding_cfgs,
            finding_types=(odg.model.Datatype.OSID_FINDING,),
            artefact=artefact,
            compliance_snapshot=compliance_snapshot,
            service=odg.extensions_cfg.Services.OSID,
            interval_seconds=extensions_cfg.osid.interval,
            now=now,
        )
        if uncommitted_backlog_item:
            uncommitted_backlog_items.append(uncommitted_backlog_item)

    logger.info(f'updated compliance snapshot ({artefact=})')
    return compliance_snapshot, uncommitted_backlog_items


def _process_inactive_compliance_snapshots(
    extensions_cfg: odg.extensions_cfg.ExtensionsConfiguration,
    delivery_client: delivery.client.DeliveryServiceClient,
    compliance_snapshots: list[odg.model.ArtefactMetadata],
    now: datetime.datetime=datetime.datetime.now(),
) -> collections.abc.Generator[
    tuple[
        odg.model.ArtefactMetadata,
        UncommittedBacklogItem | None,
], None, None]:
    cs_by_artefact: dict[odg.model.ComponentArtefactId, odg.model.ArtefactMetadata] = {}
    deletable_compliance_snapshots: list[odg.model.ArtefactMetadata] = []

    for compliance_snapshot in compliance_snapshots:
        cs_by_artefact[compliance_snapshot.artefact] = compliance_snapshot

    for artefact, compliance_snapshot in cs_by_artefact.items():
        updated_compliance_snapshot = None
        uncommitted_backlog_item = None

        if compliance_snapshot.data.is_active:
            compliance_snapshot.data.update_state(odg.model.ComplianceSnapshotState(
                timestamp=now,
                status=odg.model.ComplianceSnapshotStatuses.INACTIVE,
            ))
            updated_compliance_snapshot = compliance_snapshot
            logger.info(f'updated inactive compliance snapshot ({artefact=})')

            if (
                extensions_cfg.issue_replicator
                and extensions_cfg.issue_replicator.enabled
            ):
                uncommitted_backlog_item = UncommittedBacklogItem(
                    artefact=artefact,
                    priority=k8s.backlog.BacklogPriorities.HIGH,
                    service=odg.extensions_cfg.Services.ISSUE_REPLICATOR,
                )

        if now - compliance_snapshot.data.current_state().timestamp >= datetime.timedelta(
            seconds=extensions_cfg.artefact_enumerator.compliance_snapshot_grace_period,
        ):
            deletable_compliance_snapshots.append(compliance_snapshot)

        elif updated_compliance_snapshot:
            yield updated_compliance_snapshot, uncommitted_backlog_item

    if not deletable_compliance_snapshots:
        return

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

    compliance_snapshots = tuple(
        odg.model.ArtefactMetadata.from_dict(raw)
        for raw in delivery_client.query_metadata(
            type=odg.model.Datatype.COMPLIANCE_SNAPSHOTS,
        )
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

    active_cs_by_artefact: dict[odg.model.ComponentArtefactId, odg.model.ArtefactMetadata] = {}
    for compliance_snapshot in active_compliance_snapshots:
        active_cs_by_artefact[compliance_snapshot.artefact] = compliance_snapshot

    updated_compliance_snapshots = []
    all_uncommitted_backlog_items = []

    for artefact in artefacts:
        compliance_snapshot, uncommitted_backlog_items = _process_compliance_snapshot_of_artefact(
            extensions_cfg=extensions_cfg,
            finding_cfgs=finding_cfgs,
            delivery_client=delivery_client,
            artefact=artefact,
            compliance_snapshot=active_cs_by_artefact.get(artefact),
            now=now,
            today=today,
        )
        updated_compliance_snapshots.append(compliance_snapshot)
        all_uncommitted_backlog_items.extend(uncommitted_backlog_items)

    for compliance_snapshot, uncommitted_backlog_item in _process_inactive_compliance_snapshots(
        extensions_cfg=extensions_cfg,
        delivery_client=delivery_client,
        compliance_snapshots=inactive_compliance_snapshots,
        now=now,
    ):
        updated_compliance_snapshots.append(compliance_snapshot)
        if uncommitted_backlog_item:
            all_uncommitted_backlog_items.append(uncommitted_backlog_item)

    logger.info(f'updating {len(updated_compliance_snapshots)} compliance snapshots in delivery-db')
    delivery_client.update_metadata(data=updated_compliance_snapshots)

    for uncommitted_backlog_item in all_uncommitted_backlog_items:
        service = uncommitted_backlog_item.service
        priority = uncommitted_backlog_item.priority
        artefact = uncommitted_backlog_item.artefact

        was_created = k8s.backlog.create_unique_backlog_item(
            service=service,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            artefact=artefact,
            priority=priority,
        )
        if was_created:
            logger.info(f'created {service} backlog item with {priority=} for {artefact=}')


def main():
    parsed_arguments = odg.util.parse_args()
    kubernetes_api = odg.util.kubernetes_api(parsed_arguments)
    namespace = parsed_arguments.k8s_namespace

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
