#!/usr/bin/env python3
import argparse
import collections.abc
import datetime
import enum
import logging
import os

import semver

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
import dso.labels
import dso.model
import ocm

import ctx_util
import lookups

logger = logging.getLogger(__name__)
ci.log.configure_default_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


class AnalysisLabel(enum.StrEnum):
    LINT = 'lint'
    SAST = 'sast'


def has_non_sast_linting_resource(
    component: ocm.Component
) -> bool:
    for resource in component.resources:
        label = resource.find_label(name='gardener.cloud/purposes')
        if (label and AnalysisLabel.LINT.value in label.value and
            AnalysisLabel.SAST.value in label.value):
            return False

    return True


def find_skip_policy(
    component: ocm.Component
) -> bool:
    for source in component.sources:
        label = source.find_label(name=dso.labels.SourceScanLabel.name)
        if (label and isinstance(label.value, dict) and
            label.value.get('policy') == dso.labels.ScanPolicy.SKIP.value):
            return True

    return False


def _iter_non_sast_linting_findings(
    component_nodes: collections.abc.Iterable[cnudie.iter.ComponentNode],
) -> collections.abc.Generator[dso.model.ComponentArtefactId, None, None]:
    for cnode in component_nodes:
        if not find_skip_policy(cnode.component) and has_non_sast_linting_resource(cnode.component):
            yield dso.model.ComponentArtefactId(
                component_name=cnode.component.name,
                component_version=cnode.component.version,
                artefact=dso.model.LocalArtefactId(
                    artefact_name=None,
                    artefact_type=None,
                )
            )


def main():
    parser = argparse.ArgumentParser(description='Upload CM06 scan results to delivery database')

    parser.add_argument(
        '--delivery-service-url',
        type=str,
    )
    parser.add_argument(
        '--component-name',
        type=str,
    )
    parser.add_argument(
        '--audit-start-date',
        default=(datetime.date.today() - datetime.timedelta(days=180)),
        help='Audit start date in YYYY-MM-DD format'
    )
    parser.add_argument(
        '--audit-end-date',
        default=datetime.date.today(),
        help='Audit end date in YYYY-MM-DD format'
    )
    args = parser.parse_args()

    cfg_factory = ctx_util.cfg_factory()

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=args.delivery_service_url,
        ),
        cfg_factory=cfg_factory,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=default_cache_dir,
        delivery_client=delivery_client,
    )

    landscape_versions = delivery_client.greatest_component_versions(
        component_name=args.component_name,
        start_date=args.audit_start_date,
        end_date=args.audit_end_date,
    )

    existing_artefact_scan_infos = delivery_client.query_metadata(
        type=dso.model.Datatype.ARTEFACT_SCAN_INFO
    )

    existing_entries = {
        (artefact_scan_info.artefact.component_name, artefact_scan_info.artefact.component_version)
        for artefact_scan_info in existing_artefact_scan_infos
    }

    new_findings = []
    scan_info = []

    for component_version in sorted(landscape_versions, key=semver.VersionInfo.parse):

        component_descriptor = component_descriptor_lookup(ocm.ComponentIdentity(
            name=args.component_name,
            version=component_version,
        ))

        component_nodes = list(cnudie.iter.iter(
            component=component_descriptor.component,
            lookup=component_descriptor_lookup,
            node_filter=cnudie.iter.Filter.components,
            prune_unique=True,
        ))

        findings = list(_iter_non_sast_linting_findings(component_nodes))

        for cnode in component_nodes:
            if (cnode.component.name, cnode.component.version) in existing_entries:
                continue

            scan_info.append(
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
                        creation_date=datetime.datetime.now(),
                        last_update=datetime.datetime.now(),
                    ),
                    data={}
                )
            )
        for finding in findings:
            new_findings.append(finding)

    non_sast_linting_metadata = [
        dso.model.ArtefactMetadata(
            artefact=finding,
            meta=dso.model.Metadata(
                datasource=dso.model.Datasource.CM06,
                type=dso.model.Datatype.FINDING_NO_SAST_LINTING,
                creation_date=datetime.datetime.now(),
                last_update=datetime.datetime.now(),
            ),
            data={},
            discovery_date=datetime.datetime.now(),
        ) for finding in new_findings
    ]

    delivery_client.update_metadata(data=non_sast_linting_metadata+scan_info)


if __name__ == '__main__':
    main()
