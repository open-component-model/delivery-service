#!/usr/bin/env python3
import argparse
import collections.abc
import dataclasses
import datetime
import enum
import logging
import os

import semver

import ci.log
import cnudie.iter
import cnudie.retrieve
import delivery.client
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


@dataclasses.dataclass()
class ComponentSASTLintingInfo:
    component_name: str
    component_version: str
    artefact: dso.model.ComponentArtefactId


def find_non_sast_linting_resource(
    component: ocm.Component
) -> ocm.Resource | None:
    for source in component.sources:
        for find_label in source.labels:
            if find_label.name == 'cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1':
                if isinstance(find_label.value, dict) and find_label.value.get('policy') == 'skip':
                    return None

    for resource in component.resources:
        for find_label in resource.labels:
            if find_label.name != 'gardener.cloud/purposes':
                if not (
                    AnalysisLabel.LINT.value in find_label.value
                    and AnalysisLabel.SAST.value in find_label.value
                ):
                    return resource
    return None


def _iter_non_sast_linting_evidence(
    component_nodes: collections.abc.Iterable[cnudie.iter.ComponentNode],
) -> collections.abc.Generator[ComponentSASTLintingInfo, None, None]:
    for cnode in component_nodes:
        resource = find_non_sast_linting_resource(cnode.component)
        if resource:
            yield ComponentSASTLintingInfo(
                component_name=cnode.component.name,
                component_version=cnode.component.version,
                artefact=dso.model.component_artefact_id_from_ocm(
                    component=cnode.component,
                    artefact=resource
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
        '--ocm-repo-urls',
        type=str,
        nargs='+'
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

    landscape_versions = set()

    for ocm_url in args.ocm_repo_urls:
        ocm_repo = ocm.OciOcmRepository(baseUrl=ocm_url)

        versions_response = delivery_client.greatest_component_versions(
            component_name=args.component_name,
            ocm_repo=ocm_repo,
            start_date=args.audit_start_date,
            end_date=args.audit_end_date,
        )
        landscape_versions.update(versions_response)

    existing_artefact_scan_infos = delivery_client.query_metadata(
        type=dso.model.Datatype.EVIDENCE_SAST_LINTING,
    )

    existing_entries = {
        (artefact_scan_info.artefact.component_name, artefact_scan_info.artefact.component_version)
        for artefact_scan_info in existing_artefact_scan_infos
    }

    new_evidence = []

    for i, component_version in enumerate(
        sorted(landscape_versions, key=semver.VersionInfo.parse),
        start=1
    ):
        logger.info(f'Processing comp-version {component_version} [{i}/{len(landscape_versions)}]')

        component_descriptor = component_descriptor_lookup(ocm.ComponentIdentity(
            name=args.component_name,
            version=component_version,
        ))

        component_nodes = cnudie.iter.iter(
            component=component_descriptor.component,
            lookup=component_descriptor_lookup,
            node_filter=cnudie.iter.Filter.components,
            prune_unique=True,
        )

        evidence = list(_iter_non_sast_linting_evidence(component_nodes))

        for e in evidence:
            if (e.component_name, e.component_version) not in existing_entries:
                new_evidence.append(e)

    non_sast_linting_metadata = [
        dso.model.ArtefactMetadata(
            artefact=dso.model.ComponentArtefactId(
                component_name=evidence.component_name,
                component_version=evidence.component_version,
                artefact=evidence.artefact
            ),
            meta=dso.model.Metadata(
                datasource=dso.model.Datasource.CM06,
                type=dso.model.Datatype.EVIDENCE_SAST_LINTING,
                creation_date=datetime.datetime.now(),
                last_update=datetime.datetime.now(),
            ),
            data={},
            discovery_date=datetime.datetime.now(),
        ) for evidence in new_evidence
    ]
    if non_sast_linting_metadata:
        delivery_client.update_metadata(data=non_sast_linting_metadata)


if __name__ == '__main__':
    main()
