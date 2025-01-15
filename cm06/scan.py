#!/usr/bin/env python3
import argparse
import atexit
import datetime
import enum
import logging
import os

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.labels
import dso.model
import github.compliance.model
import ocm
import version

import config
import components
import ctx_util
import k8s.util
import k8s.model
import k8s.logging
import lookups
import rescore.model
import rescore.utility


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


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


def deserialise_sast_configuration(
    scan_cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> config.SASTConfig:
    scan_cfg_crd = kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
        group=k8s.model.ScanConfigurationCrd.DOMAIN,
        version=k8s.model.ScanConfigurationCrd.VERSION,
        plural=k8s.model.ScanConfigurationCrd.PLURAL_NAME,
        namespace=namespace,
        name=scan_cfg_name,
    )
    if scan_cfg_crd and (spec := scan_cfg_crd.get('spec')):
        sast_config = config.deserialise_sast_config(spec_config=spec)
    else:
        sast_config = None

    if not sast_config:
        raise ValueError(
            f'No SAST configuration found for scan config {scan_cfg_name} in namespace {namespace}'
        )

    return sast_config


def fetch_all_versions(
    component_name: str,
    version_lookup: cnudie.retrieve.VersionLookupByComponent,
    version_filter: config.VersionFilter=config.VersionFilter.RELEASES_ONLY,
) -> list[str]:
    versions = version_lookup(component_name)

    if version_filter is config.VersionFilter.RELEASES_ONLY:
        versions = [
            v for v in versions
            if version.is_final(
                version=v
            )
        ]

    return sorted(
        versions,
        key=lambda v: version.parse_to_semver(
            version=v,
            invalid_semver_ok=False,
        )
    )


def versions_from_time_range(
    component_name: str,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    versions: list[str],
    start_date: datetime.date,
    end_date: datetime.date,
    max_versions: int,
) -> list[str]:
    filtered_versions = [
        version for version in versions
        if end_date <= components.get_creation_date(
            component=component_descriptor_lookup(
                ocm.ComponentIdentity(
                    name=component_name,
                    version=version,
                )
            ).component
        ).date() <= start_date
    ]

    if max_versions == -1:
        return filtered_versions

    return filtered_versions[-max_versions:]


def limit_versions(
    versions: list[str],
    greatest_version: str,
    max_versions: int,
) -> list[str]:
    '''
    Returns a subset of the greatest versions from a sorted list.

    Filters the input `versions` list (assumed to be sorted in ascending order)
    to include only versions up to `greatest_version` and limits the result
    to `max_versions` if specified.
    '''
    if greatest_version:
        index = versions.index(greatest_version)
        versions = versions[:index + 1]

    if not max_versions == -1:
        return versions[-max_versions:]

    return versions


def create_missing_linter_finding(
    snode: cnudie.iter.SourceNode,
    sub_type: dso.model.SastSubType,
    time_now: datetime.datetime,
) -> dso.model.ArtefactMetadata:
    return dso.model.ArtefactMetadata(
        artefact=dso.model.ComponentArtefactId(
            component_name=snode.component.name,
            component_version=snode.component.version,
            artefact=dso.model.LocalArtefactId(
                artefact_name=snode.source.name,
                artefact_type=snode.source.type,
                artefact_version=snode.source.version,
                artefact_extra_id=snode.source.extraIdentity,
            ),
            artefact_kind=dso.model.ArtefactKind.SOURCE,
        ),
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.SAST_LINT_CHECK,
            type=dso.model.Datatype.SAST_FINDING,
            creation_date=time_now,
            last_update=time_now,
        ),
        data=dso.model.SastFinding(
            sast_status=dso.model.SastStatus.NO_LINTER,
            severity=str(github.compliance.model.Severity.BLOCKER),
            sub_type=sub_type,
        ),
        discovery_date=time_now.date(),
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
        '--scan-cfg-name',
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

    if not parsed_arguments.scan_cfg_name:
        raise ValueError(
            'name of the to-be-used scan configuration must be set, either via '
            'argument "--scan-cfg-name" or via environment variable "CFG_NAME"'
        )

    return parsed_arguments


def main():
    parsed_arguments = parse_args()
    scan_cfg_name = parsed_arguments.scan_cfg_name
    namespace = parsed_arguments.k8s_namespace
    delivery_service_url = parsed_arguments.delivery_service_url

    cfg_factory = ctx_util.cfg_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = cfg_factory.kubernetes_cfg(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(
            kubeconfig_path=parsed_arguments.kubeconfig,
        )

    k8s.logging.init_logging_thread(
        service=config.Services.SAST_LINT_CHECK,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=config.Services.SAST_LINT_CHECK,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    sast_config = deserialise_sast_configuration(
        scan_cfg_name=scan_cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

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

    all_metadata = []
    time_now = datetime.datetime.now(datetime.timezone.utc)

    for component in sast_config.components:
        '''
        filters and retrieves component versions based on the given cfg

        1. if an explicit version is provided and the max_versions_limit is set to 1 (default),
           the specified version is used
        2. otherwise, all versions of the component are fetched
            - if a time range (`audit_timerange_days`) is specified,
              versions are filtered to match the range and limited by `max_versions`
            - if no time range is specified, filters the input to include only versions
              up to `greatest_version`.
        '''
        if component.version and component.max_versions_limit == 1:
            component_versions = component.version
        else:
            versions = fetch_all_versions(
                component_name=component.component_name,
                version_lookup=lookups.init_version_lookup(),
                version_filter=component.version_filter,
            )

            if component.audit_timerange_days:
                component_versions = versions_from_time_range(
                    component_name=component.component_name,
                    component_descriptor_lookup=component_descriptor_lookup,
                    versions=versions,
                    start_date=time_now.date(),
                    end_date=time_now.date() - datetime.timedelta(component.audit_timerange_days),
                    max_versions=component.max_versions_limit,
                )
            else:
                component_versions = limit_versions(
                    versions=versions,
                    greatest_version=component.version,
                    max_versions=component.max_versions_limit,
                )

        for component_version in sorted(
            component_versions,
            key=lambda v: version.parse_to_semver(v)
        ):
            component_descriptor = component_descriptor_lookup(
                ocm.ComponentIdentity(
                    name=component.component_name,
                    version=component_version,
                )
            )

            for snode in cnudie.iter.iter(
                component=component_descriptor.component,
                lookup=component_descriptor_lookup,
                node_filter=cnudie.iter.Filter.sources,
                prune_unique=True,
            ):

                all_metadata.append(
                    dso.model.ArtefactMetadata(
                        artefact=dso.model.ComponentArtefactId(
                            component_name=snode.component.name,
                            component_version=snode.component.version,
                            artefact=dso.model.LocalArtefactId(
                                artefact_name=snode.source.name,
                                artefact_type=snode.source.type,
                                artefact_version=snode.source.version,
                                artefact_extra_id=snode.source.extraIdentity,
                            ),
                            artefact_kind=dso.model.ArtefactKind.SOURCE,
                        ),
                        meta=dso.model.Metadata(
                            datasource=dso.model.Datasource.SAST_LINT_CHECK,
                            type=dso.model.Datatype.ARTEFACT_SCAN_INFO,
                            creation_date=time_now,
                            last_update=time_now,
                        ),
                        data={},
                        discovery_date=time_now.date(),
                    )
                )

                all_findings_for_rescoring = []
                resources = (
                    snode.component.resources
                    if len(snode.component.sources) == 1
                    else [
                        resource
                        for resource in snode.component.resources
                        for src_ref in (resource.srcRefs or [])
                        if src_ref.identitySelector.get('name') == snode.source.name
                    ]
                )

                if not has_local_linter(resources):
                    no_linter_local = create_missing_linter_finding(
                        snode=snode,
                        sub_type=dso.model.SastSubType.LOCAL_LINTING,
                        time_now=time_now,
                    )
                    all_metadata.append(no_linter_local)
                    all_findings_for_rescoring.append(no_linter_local)

                if not find_scan_policy(snode) is dso.labels.ScanPolicy.SKIP:
                    no_linter_central = create_missing_linter_finding(
                        snode=snode,
                        sub_type=dso.model.SastSubType.CENTRAL_LINTING,
                        time_now=time_now,
                    )
                    all_metadata.append(no_linter_central)
                    all_findings_for_rescoring.append(no_linter_central)

                if not all_findings_for_rescoring or not sast_config.sast_rescoring_ruleset:
                    continue

                rescored_metadata = rescore.utility.iter_sast_rescorings(
                    findings=all_findings_for_rescoring,
                    sast_rescoring_ruleset=sast_config.sast_rescoring_ruleset,
                    user=dso.model.User(
                        username='sast-extension-auto-rescoring',
                        type='sast-extension-user'
                    ),
                    time_now=time_now,
                )
                all_metadata.extend(rescored_metadata)

    delivery_client.update_metadata(data=all_metadata)


if __name__ == '__main__':
    main()
