#!/usr/bin/env python3
import argparse
import atexit
import datetime
import enum
import logging
import os
import semver
import sys

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.labels
import dso.model
import github.compliance.model
import ocm

import config
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
    component: ocm.Component
) -> bool:
    for resource in component.resources:
        if label := resource.find_label(name=dso.labels.PurposeLabel.name):
            label_content = dso.labels.deserialise_label(label)
            if AnalysisLabel.SAST.value in label_content.value:
                return True

    return False


def has_central_linter(
    component: ocm.Component
) -> bool:
    for source in component.sources:
        if label := source.find_label(name=dso.labels.SourceScanLabel.name):
            label_content = dso.labels.deserialise_label(label)
            if label_content.value.policy is dso.labels.ScanPolicy.SKIP:
                return True

    return False


def deserialise_cm06_configuration(
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
) -> config.CM06Config:
    scan_cfg_crd = kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
        group=k8s.model.ScanConfigurationCrd.DOMAIN,
        version=k8s.model.ScanConfigurationCrd.VERSION,
        plural=k8s.model.ScanConfigurationCrd.PLURAL_NAME,
        namespace=namespace,
        name=cfg_name,
    )
    if scan_cfg_crd and (spec := scan_cfg_crd.get('spec')):
        cm06_config = config.deserialise_cm06_config(spec_config=spec)
    else:
        cm06_config = None

    if not cm06_config:
        logger.warning(
            f'No CM06 configuration found for scan configuration {cfg_name} in namespace {namespace}'
        )
        sys.exit(0)

    return cm06_config


def get_landscape_versions(
    cm06_config: config.CM06Config,
    delivery_client: delivery.client.DeliveryServiceClient,
) -> list[str]:
    if cm06_config.component_version and cm06_config.audit_timerange_days:
        raise ValueError(
            'Cannot use both component_version and audit_timerange_days simultaneously.'
        )

    if cm06_config.component_version:
        return [cm06_config.component_version]

    # Default start_date to today
    start_date = datetime.date.today()
    # Calculate end_date based on audit_timerange_days
    end_date = start_date - datetime.timedelta(
        days=cm06_config.audit_timerange_days
    )

    return delivery_client.greatest_component_versions(
        component_name=cm06_config.component_name,
        start_date=end_date,
        end_date=start_date,
    )


def create_no_linter_finding(
    component_name: str,
    component_version: str,
    sub_type: dso.model.SastSubType,
    time_now: datetime.datetime,
) -> dso.model.ArtefactMetadata:
    return dso.model.ArtefactMetadata(
        artefact=dso.model.ComponentArtefactId(
            component_name=component_name,
            component_version=component_version,
            artefact=dso.model.LocalArtefactId(
                artefact_name=None,
                artefact_type=None,
            )
        ),
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.CM06,
            type=dso.model.Datatype.SAST_FINDING,
            creation_date=time_now,
            last_update=time_now,
        ),
        data=dso.model.SastFinding(
            component_context=component_name,
            sast_statuses=dso.model.SastStatus.NO_LINTER,
            severity=github.compliance.model.Severity.BLOCKER,
            sub_type=sub_type,
        ),
        discovery_date=time_now,
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
    parsed_arguments = parse_args()
    cfg_name = parsed_arguments.cfg_name
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
        service=config.Services.CM06,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=config.Services.CM06,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    cm06_config = deserialise_cm06_configuration(
        cfg_name=cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not delivery_service_url:
        delivery_service_url = cm06_config.delivery_service_url

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

    landscape_versions = get_landscape_versions(
        cm06_config=cm06_config,
        delivery_client=delivery_client,
    )

    new_metadata = []
    time_now = datetime.datetime.now(datetime.timezone.utc)

    for component_version in sorted(landscape_versions, key=semver.VersionInfo.parse):
        component_descriptor = component_descriptor_lookup(
            ocm.ComponentIdentity(
                name=cm06_config.component_name,
                version=component_version,
            )
        )

        component_nodes = cnudie.iter.iter(
            component=component_descriptor.component,
            lookup=component_descriptor_lookup,
            node_filter=cnudie.iter.Filter.components,
            prune_unique=True,
        )

        for cnode in component_nodes:
            new_metadata.append(
                dso.model.ArtefactMetadata(
                    artefact=dso.model.ComponentArtefactId(
                        component_name=cnode.component.name,
                        component_version=cnode.component.version,
                        artefact=dso.model.LocalArtefactId(
                            artefact_name=None,
                            artefact_type=None,
                        )
                    ),
                    meta=dso.model.Metadata(
                        datasource=dso.model.Datasource.CM06,
                        type=dso.model.Datatype.ARTEFACT_SCAN_INFO,
                        creation_date=time_now,
                        last_update=time_now,
                    ),
                    data=None,
                    discovery_date=time_now,
                )
            )

            all_findings_for_rescoring = []

            if not has_local_linter(cnode.component):
                no_linter_local = create_no_linter_finding(
                    component_name=cnode.component.name,
                    component_version=cnode.component.version,
                    sub_type=dso.model.SastSubType.LOCAL_LINTING,
                    time_now=time_now,
                )
                new_metadata.append(no_linter_local)
                all_findings_for_rescoring.append(no_linter_local)

            if not has_central_linter(cnode.component):
                no_linter_central = create_no_linter_finding(
                    component_name=cnode.component.name,
                    component_version=cnode.component.version,
                    sub_type=dso.model.SastSubType.CENTRAL_LINTING,
                    time_now=time_now,
                )
                new_metadata.append(no_linter_central)
                all_findings_for_rescoring.append(no_linter_central)

            if not all_findings_for_rescoring or not cm06_config.sast_rescoring_ruleset:
                continue

            for ruleset in cm06_config.sast_rescoring_ruleset:
                rescored_metadata = rescore.utility.iter_sast_rescorings(
                    findings=all_findings_for_rescoring,
                    sast_rescoring_ruleset=ruleset,
                    user=dso.model.User(
                        username='sast-extension-auto-rescoring'
                    ),
                )
                new_metadata.extend(rescored_metadata)

    delivery_client.update_metadata(data=new_metadata)


if __name__ == '__main__':
    main()
