#!/usr/bin/env python3

import logging
import os

import yaml

import ccc.concourse
import ci.log
import ci.util
import cnudie.retrieve
import concourse.steps.component_descriptor_util as cdu
import ocm
import version


ci.log.configure_default_logging()
logger = logging.getLogger(__name__)
own_dir = os.path.abspath(os.path.dirname(__file__))


def parse_component_descriptor():
    descriptor_path = cdu.component_descriptor_path(
        ocm.SchemaVersion.V2,
    )
    return ocm.ComponentDescriptor.from_dict(
        ci.util.parse_yaml_file(descriptor_path),
    )


def retrieve_latest_released_descriptor(
    current_descriptor: ocm.ComponentDescriptor,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    version_lookup,
):
    current_component = current_descriptor.component

    greatest_version = version.greatest_version(
        versions=version_lookup(current_component.name),
        ignore_prerelease_versions=True,
    )

    return component_descriptor_lookup(
        ocm.ComponentIdentity(
            name=current_component.name,
            version=greatest_version,
        ),
    )


def trigger_release_job():
    concourse_client = ccc.concourse.client_from_env()

    logger.info('triggering release job {jn}'.format(jn=ci.util.check_env('RELEASE_JOB_NAME')))
    concourse_client.trigger_build(
        pipeline_name=ci.util.check_env('PIPELINE_NAME'),
        job_name=ci.util.check_env('RELEASE_JOB_NAME'),
    )


def ocm_repository_lookup():
    with open(os.path.join(own_dir, 'pipeline_definitions')) as f:
        parsed = yaml.safe_load(f)

    traits = parsed['delivery-service']['base_definition']['traits']
    component_descriptor_trait = traits['component_descriptor']
    ocm_repo_urls = [
        m['repository'] for m in component_descriptor_trait['ocm_repository_mappings']
    ]

    return cnudie.retrieve.ocm_repository_lookup(
        *ocm_repo_urls,
    )


def main():
    component_descriptor_lookup = cnudie.retrieve.create_default_component_descriptor_lookup(
        ocm_repository_lookup=ocm_repository_lookup(),
    )
    version_lookup = cnudie.retrieve.version_lookup(ocm_repository_lookup=ocm_repository_lookup())

    current_descriptor = parse_component_descriptor()
    latest_descriptor = retrieve_latest_released_descriptor(
        current_descriptor=current_descriptor,
        component_descriptor_lookup=component_descriptor_lookup,
        version_lookup=version_lookup,
    )

    component_diff = cnudie.retrieve.component_diff(
        left_component=latest_descriptor,
        right_component=current_descriptor,
        ignore_component_names=(ci.util.check_env('COMPONENT_NAME'),),
        component_descriptor_lookup=component_descriptor_lookup,
    )

    if not component_diff:
        logger.info('no differences were found between current and latest release')
        return

    logger.info('diffs were found since last released delivery-service version')

    for left_c, right_c in component_diff.cpairs_version_changed:
        logger.info(f'{left_c.name}: released: {left_c.version}, current: {right_c.version}')

    trigger_release_job()


if __name__ == '__main__':
    main()
