#!/usr/bin/env python3
import argparse
import atexit
import collections.abc
import datetime
import enum
import logging
import os
import signal
import sys
import time

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.labels
import dso.model
import ocm

import consts
import ctx_util
import k8s.backlog
import k8s.util
import k8s.model
import k8s.logging
import lookups
import odg.findings
import odg.scan_cfg
import paths
import rescore.model
import rescore.utility


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')

ready_to_terminate = True
wants_to_terminate = False


def handle_termination_signal(*args):
    global ready_to_terminate, wants_to_terminate

    # also terminate if > 1 termination signals were received
    if ready_to_terminate or wants_to_terminate:
        sys.exit(0)

    # grace period to finish current scan is defined in the replica set
    # after this period, the scan will be terminated anyways by k8s means
    logger.info('termination signal received, will try to finish current scan and then exit')
    wants_to_terminate = True


class AnalysisLabel(enum.StrEnum):
    SAST = 'sast'


def has_local_linter(
    resources: list[ocm.Resource],
) -> bool:
    for resource in resources:
        if not (label := resource.find_label(name=dso.labels.PurposeLabel.name)):
            continue

        label_content = dso.labels.deserialise_label(label)
        if AnalysisLabel.SAST.value in label_content.value:
            return True

    return False


def find_scan_policy(
    snode: cnudie.iter.SourceNode
) -> dso.labels.ScanPolicy | None:
    if label := snode.source.find_label(name=dso.labels.SourceScanLabel.name):
        label_content = dso.labels.deserialise_label(label)
        return label_content.value.policy

    # Fallback to component-level label
    if label := snode.component.find_label(name=dso.labels.SourceScanLabel.name):
        label_content = dso.labels.deserialise_label(label)
        return label_content.value.policy

    # No label found
    return None


def create_missing_linter_finding(
    artefact: dso.model.ComponentArtefactId,
    sub_type: dso.model.SastSubType,
    categorisation: odg.findings.FindingCategorisation,
    creation_timestamp: datetime.datetime=datetime.datetime.now(tz=datetime.timezone.utc),
) -> dso.model.ArtefactMetadata | None:
    return dso.model.ArtefactMetadata(
        artefact=artefact,
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.SAST_LINT_CHECK,
            type=dso.model.Datatype.SAST_FINDING,
            creation_date=creation_timestamp,
            last_update=creation_timestamp,
        ),
        data=dso.model.SastFinding(
            sast_status=dso.model.SastStatus.NO_LINTER,
            severity=categorisation.name,
            sub_type=sub_type,
        ),
        discovery_date=creation_timestamp.date(),
    )


def iter_sast_metadata(
    sast_config: odg.scan_cfg.SASTConfig,
    sast_finding_config: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    version_lookup: cnudie.retrieve.VersionLookupByComponent,
    creation_timestamp: datetime.datetime=datetime.datetime.now(datetime.timezone.utc),
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    '''
    Generates SAST metadata for all components defined in the configuration.
    '''

    for component in sast_config.components:
        component_versions = fetch_component_versions(
            component=component,
            component_descriptor_lookup=component_descriptor_lookup,
            version_lookup=version_lookup,
        )

        for component_version in component_versions:
            component_descriptor = component_descriptor_lookup(
                ocm.ComponentIdentity(
                    name=component.component_name,
                    version=component_version,
                )
            )
            yield from iter_artefact_metadata(
                component_descriptor=component_descriptor,
                component_descriptor_lookup=component_descriptor_lookup,
                sast_finding_config=sast_finding_config,
                creation_timestamp=creation_timestamp,
            )


def fetch_component_versions(
    component: odg.scan_cfg.Component,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    version_lookup: cnudie.retrieve.VersionLookupByComponent,
) -> list[str]:
    '''
    Filters and retrieves component versions based on the given configuration.

    1. If an explicit version is provided and the max_versions_limit is set to 1 (default),
       the specified version is used.
    2. Otherwise, all versions of the component are fetched:
       - If a time range (`timerange_days`) is specified, versions are filtered to match the range.
       - If no time range is specified, all versions are considered.
    3. If max_versions_limit is set, the versions are limited accordingly.
    '''
    logger.info(f'Fetching versions for component: {component.component_name}')
    if component.version and component.max_versions_limit == 1:
        logger.info(f'Using explicit version: {component.version}')
        return [component.version]

    versions = version_lookup(component.component_name)

    if component.version_filter is config.VersionFilter.RELEASES_ONLY:
        versions = [
            v for v in versions
            if version.is_final(v)
        ]

    versions = sorted(
        versions,
        key=lambda v: version.parse_to_semver(v, invalid_semver_ok=False)
    )

    if component.timerange_days:
        start_date = datetime.date.today()
        end_date = start_date - datetime.timedelta(component.timerange_days)
        versions = [
            version for version in versions
            if end_date <= util.get_creation_date(
                component=component_descriptor_lookup(
                    ocm.ComponentIdentity(
                        name=component.component_name,
                        version=version,
                    )
                ).component
            ).date() <= start_date
        ]
        logger.info(f'{len(versions)} versions found within timerange: {component.timerange_days}')

    if not component.max_versions_limit:
        return versions

    if component.version:
        index = versions.index(component.version)
        versions = versions[:index + 1]

    if component.max_versions_limit == -1:
        return versions

    return versions[-component.max_versions_limit:]


def iter_sast_artefacts_for_sub_type(
    sast_finding_config: odg.findings.Finding,
    sub_type: dso.model.SastSubType,
    artefact: dso.model.ComponentArtefactId,
    creation_timestamp: datetime.datetime=datetime.datetime.now(datetime.timezone.utc),
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    categorisation = odg.findings.categorise_finding(
        finding_cfg=sast_finding_config,
        finding_property=sub_type,
    )

    if not categorisation:
        return

    missing_linter_finding = create_missing_linter_finding(
        artefact=artefact,
        sub_type=sub_type,
        categorisation=categorisation,
        creation_timestamp=creation_timestamp,
    )

    if not missing_linter_finding:
        return

    yield missing_linter_finding

    rescoring = rescore.utility.rescoring_for_sast_finding(
        finding=missing_linter_finding,
        sast_finding_cfg=sast_finding_config,
        categorisation=categorisation,
        user=dso.model.User(
            username='sast-extension-auto-rescoring',
            type='sast-extension-user'
        ),
        creation_timestamp=creation_timestamp,
    )

    if not rescoring:
        return

    yield rescoring


def iter_artefact_metadata(
    artefact: dso.model.ComponentArtefactId,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    sast_finding_config: odg.findings.Finding,
    sast_config: odg.scan_cfg.SASTConfig,
    creation_timestamp: datetime.datetime = datetime.datetime.now(datetime.timezone.utc),
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    '''
    Processes source nodes for a given component descriptor, yielding SAST metadata.
    Handles resource filtering, local linter findings, and rescoring logic.
    '''
    if not sast_finding_config.matches(artefact):
        logger.info(f'SAST findings are filtered out for {artefact=}, skipping...')
        return

    if not sast_config.is_supported(artefact_kind=artefact.artefact_kind):
        if sast_config.on_unsupported is odg.scan_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by the SAST extension, maybe the filter '
                'configurations have to be adjusted to filter out this artefact kind'
            )
        return

    source_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    if len(source_node.component.sources) == 1:
        resources = source_node.component.resources
    else:
        resources = [
            resource
            for resource in source_node.component.resources
            for src_ref in resource.srcRefs
            # only support identity selector for now
            if src_ref.identitySelector.get('name') == source_node.source.name
        ]

    if not has_local_linter(resources):
        yield from iter_sast_artefacts_for_sub_type(
            sast_finding_config=sast_finding_config,
            sub_type=dso.model.SastSubType.LOCAL_LINTING,
            artefact=artefact,
            creation_timestamp=creation_timestamp,
        )

    if not find_scan_policy(source_node) is dso.labels.ScanPolicy.SKIP:
        yield from iter_sast_artefacts_for_sub_type(
            sast_finding_config=sast_finding_config,
            sub_type=dso.model.SastSubType.CENTRAL_LINTING,
            artefact=artefact,
            creation_timestamp=creation_timestamp,
        )

    yield dso.model.ArtefactMetadata(
        artefact=artefact,
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.SAST_LINT_CHECK,
            type=dso.model.Datatype.ARTEFACT_SCAN_INFO,
            creation_date=creation_timestamp,
            last_update=creation_timestamp,
        ),
        data={},
        discovery_date=creation_timestamp.date(),
    )


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='kubernetes cluster to use',
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
        '--scan-cfg-path',
        help='path to the `scan_cfg.yaml` file that should be used',
    )
    parser.add_argument(
        '--findings-cfg-path',
        help='path to the `findings.yaml` file that should be used',
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

    return parsed_arguments


def main():
    signal.signal(signal.SIGTERM, handle_termination_signal)
    signal.signal(signal.SIGINT, handle_termination_signal)

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
        service=odg.scan_cfg.Services.SAST_LINT_CHECK,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.scan_cfg.Services.SAST_LINT_CHECK,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (scan_cfg_path := parsed_arguments.scan_cfg_path):
        scan_cfg_path = paths.scan_cfg_path()

    scan_config = odg.scan_cfg.ScanConfiguration.from_file(scan_cfg_path)
    sast_config = scan_config.sast

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    sast_finding_config = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.findings.FindingType.SAST,
    )

    if not sast_finding_config:
        logger.info('SAST findings are disabled, exiting...')
        return

    if not delivery_service_url:
        delivery_service_url = sast_config.delivery_service_url

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
            service=odg.scan_cfg.Services.SAST_LINT_CHECK,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )

        if not backlog_crd:
            ready_to_terminate = True
            sleep_interval_seconds = consts.BACKLOG_ITEM_SLEEP_INTERVAL_SECONDS
            logger.info(f'no open backlog item found, will sleep for {sleep_interval_seconds=}')
            time.sleep(sleep_interval_seconds)
            continue

        name = backlog_crd.get('metadata').get('name')
        logger.info(f'processing backlog item {name}')

        backlog_item = k8s.backlog.BacklogItem.from_dict(
            backlog_item=backlog_crd.get('spec'),
        )

        all_metadata = list(
            iter_artefact_metadata(
                artefact=backlog_item.artefact,
                component_descriptor_lookup=component_descriptor_lookup,
                sast_finding_config=sast_finding_config,
                sast_config=sast_config,
            )
        )

        delivery_client.update_metadata(data=all_metadata)

        k8s.util.delete_custom_resource(
            crd=k8s.model.BacklogItemCrd,
            name=name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )
        logger.info(f'processed and deleted backlog item {name}')


if __name__ == '__main__':
    main()
