#!/usr/bin/env python3
import argparse
import datetime
import enum
import json
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
import rescore.model
import rescore.utility


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


class AnalysisLabel(enum.StrEnum):
    LINT = 'lint'
    SAST = 'sast'


def load_json_file(
    file_path: str
) -> dict:
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        logger.error(f'File {file_path} not found')
        raise
    except json.JSONDecodeError:
        logger.error(f'File {file_path} is not a valid JSON file')
        raise


def sast_status(
    component: ocm.Component
) -> rescore.model.SastStatus:
    has_local_linting = False
    has_central_linting = False

    for source in component.sources:
        label = source.find_label(name=dso.labels.SourceScanLabel.name)
        if label:
            label_content = dso.labels.deserialise_label(label)
            if label_content.value.policy.value in dso.labels.ScanPolicy.SKIP.value:
                has_local_linting = True
                break

    for resource in component.resources:
        label = resource.find_label(name=dso.labels.ResourceScanLabel.name)
        if label:
            label_content = dso.labels.deserialise_label(label)
            if AnalysisLabel.SAST.value in label_content.value:
                has_central_linting = True
                break

    if has_local_linting and has_central_linting:
        return rescore.model.SastStatus.CENTRAL_AND_LOCAL_LINTING
    elif has_local_linting:
        return rescore.model.SastStatus.LOCAL_LINTING
    elif has_central_linting:
        return rescore.model.SastStatus.CENTRAL_LINTING
    else:
        return rescore.model.SastStatus.NO_LINTING


def determine_component_context(
    component: ocm.Component
) -> str:
    for resource in component.resources:
        if resource.type == 'ociImage' and resource.access:
            image_reference = resource.access.imageReference

            if (
                image_reference
                and 'europe-docker_pkg_dev/gardener-project/' in image_reference
            ):
                return rescore.model.ComponentContext.PUBLIC.value

    return rescore.model.ComponentContext.SAP_INTERNAL.value


def generate_findings(
    component: ocm.Component,
    sast_status_value: rescore.model.SastStatus,
    time_now: datetime.datetime
) -> dso.model.ArtefactMetadata:

    data_field = dso.model.SastFinding(
        component_context=determine_component_context(
            component=component
        ),
        sast_status=sast_status_value.value,
        severity=rescore.model.Rescore.BLOCKER.value,
    )

    return dso.model.ArtefactMetadata(
        artefact=dso.model.ComponentArtefactId(
            component_name=component.name,
            component_version=component.version,
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
        data=data_field
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
        '--rescoring-config',
        required=True,
        help='Path to rescoring configuration file'
    )
    parser.add_argument(
        '--audit-start-date',
        default=(datetime.date.today() - datetime.timedelta(days=5)),
        help='Audit start date in YYYY-MM-DD format'
    )
    parser.add_argument(
        '--audit-end-date',
        default=datetime.date.today(),
        help='Audit end date in YYYY-MM-DD format'
    )
    args = parser.parse_args()

    sast_rescoring_cfg_raw = load_json_file(args.rescoring_config)

    sast_rescoring_rulesets = [
        # Pylint struggles with generic dataclasses, see: github.com/pylint-dev/pylint/issues/9488
        rescore.model.SastRescoringRuleSet( #noqa:E1123
            name=rule_set_raw['name'],
            description=rule_set_raw.get('description'),
            rules=list(
                rescore.model.sast_rescoring_rules(rule_set_raw['rules'])
            )
        )
        for rule_set_raw in sast_rescoring_cfg_raw['rescoringRuleSets']
    ]

    if not sast_rescoring_rulesets:
        logger.error('No SAST rescoring rulesets found in the configuration file')
        return

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

    new_metadata = []
    time_now = datetime.datetime.now(datetime.timezone.utc)

    for component_version in sorted(landscape_versions, key=semver.VersionInfo.parse):
        component_descriptor = component_descriptor_lookup(
            ocm.ComponentIdentity(
                name=args.component_name,
                version=component_version,
            )
        )

        component_nodes = list(
            cnudie.iter.iter(
                component=component_descriptor.component,
                lookup=component_descriptor_lookup,
                node_filter=cnudie.iter.Filter.components,
                prune_unique=True,
            )
        )

        for cnode in component_nodes:
            sast_status_value = sast_status(
                component=cnode.component
            )
            original_finding = generate_findings(
                component=cnode.component,
                sast_status_value=sast_status_value,
                time_now=time_now
            )
            new_metadata.append(original_finding)

            for ruleset in sast_rescoring_rulesets:
                rescored_metadata = rescore.utility.generate_sast_rescorings(
                    findings=[original_finding],
                    sast_rescoring_ruleset=ruleset,
                    user=dso.model.User(
                        username='sast-extension-auto-rescoring'
                    ),
                )
                new_metadata.extend(rescored_metadata)

    delivery_client.update_metadata(data=new_metadata)


if __name__ == '__main__':
    main()
