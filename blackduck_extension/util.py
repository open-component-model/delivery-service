import logging
import time
import urllib.parse

import blackduck.client

logger = logging.getLogger(__name__)


def extract_project_id(project: dict) -> str:
    href = project['_meta']['href']
    return urllib.parse.urlparse(href).path.rstrip('/').split('/')[-1]


def extract_project_group_id(project_group: dict) -> str:
    href = project_group['_meta']['href']
    return urllib.parse.urlparse(href).path.rstrip('/').split('/')[-1]


def wait_for_project(
    blackduck_client: blackduck.client.BlackDuckClient,
    project_name: str,
    max_retries: int=5,
    poll_interval_seconds: float=10.0,
) -> dict:
    if max_retries <= 0:
        raise RuntimeError(f'Project {project_name} not found after retries exhausted')

    project = blackduck_client.find_project_by_name(
        blackduck_client=blackduck_client,
        project_name=project_name,
    )
    if project:
        return project

    logger.info(f'Waiting for project {project_name} to appear (retries left: {max_retries})')
    time.sleep(poll_interval_seconds)

    return wait_for_project(
        blackduck_client=blackduck_client,
        project_name=project_name,
        max_retries=max_retries - 1,
        poll_interval_seconds=poll_interval_seconds,
    )


def wait_for_project_group(
    blackduck_client: blackduck.client.BlackDuckClient,
    project_group_name: str,
    max_retries: int=5,
    poll_interval_seconds: float=10.0,
) -> dict:
    if max_retries <= 0:
        raise RuntimeError(f'Project {project_group_name} not found after retries exhausted')

    project = blackduck_client.find_project_group_by_name(
        blackduck_client=blackduck_client,
        project_group_name=project_group_name,
    )
    if project:
        return project

    logger.info(f'Waiting for project {project_group_name} to appear (retries left: {max_retries})')
    time.sleep(poll_interval_seconds)

    return wait_for_project_group(
        blackduck_client=blackduck_client,
        project_group_name=project_group_name,
        max_retries=max_retries - 1,
        poll_interval_seconds=poll_interval_seconds,
    )
