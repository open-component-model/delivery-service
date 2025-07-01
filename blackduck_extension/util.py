import logging
import time

import blackduck.client

logger = logging.getLogger(__name__)


def find_project_by_name(
    blackduck_client: blackduck.client.BlackDuckClient,
    project_name: str,
) -> dict | None:
    projects = blackduck_client.get_project_by_name(project_name)

    if not projects:
        return None

    if len(projects) > 1:
        raise RuntimeError(
            f'Expected only one project for name "{project_name}", found multiple: {projects}'
        )

    return projects[0]


def wait_for_project(
    blackduck_client: blackduck.client.BlackDuckClient,
    project_name: str,
    max_retries: int = 5,
    poll_interval_seconds: float = 10.0,
) -> dict:
    if max_retries <= 0:
        raise RuntimeError(f'Project {project_name} not found after retries exhausted')

    project = find_project_by_name(blackduck_client, project_name)
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
