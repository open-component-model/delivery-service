import time
import logging

import blackduck.Client

import bdba.model

logger = logging.getLogger(__name__)


def find_project_by_name(
    blackduck_client: blackduck.Client,
    project_name: str,
    retries: int = 10,
    delay: float = 20.0,
) -> dict | None:
    params = {'q': [f"name:{project_name}"]}

    for attempt in range(retries):
        projects = [
            p for p in blackduck_client.get_resource('projects', params=params)
            if p['name'].casefold() == project_name.casefold()
        ]

        if len(projects) == 1:
            return projects[0]

        time.sleep(delay * 2 ** attempt)
        logger.info(f'Waiting for project {project_name} to appear (attempt {attempt+1}/{retries})')

    logger.warning(f'Project {project_name} not found after {retries} attempts')
    return None


def assign_usergroup_to_project(
    blackduck_client: blackduck.Client,
    project,
    usergroup_id: str
):
    project_href = project['_meta']['href']
    target_url = f'{project_href}/usergroups'
    headers = {
        'Accept': 'application/vnd.blackducksoftware.project-detail-4+json',
        'Content-Type': 'application/vnd.blackducksoftware.project-detail-4+json'
    }
    response = blackduck_client.session.post(
        target_url,
        headers=headers,
        json={
            'group': f'{blackduck_client.base_url}/api/usergroups/{usergroup_id}'
        }
    )
    response.raise_for_status()


def create_project(
    blackduck_client: blackduck.Client,
    project_name: str
):

    response = blackduck_client.session.post(
        '/api/projects',
        json={
            'name': project_name,
            'projectLevelAdjustments': True,
        }
    )
    response.raise_for_status()


def upload_bdio(
    blackduck_client: blackduck.Client,
    bdio: bdba.model.BDIO,
):
    file_name = f'{bdio.name}.bdio.jsonld'
    files = {
        'file': (file_name, bdio.as_blackduck_bytes(), 'application/ld+json')
    }

    response = blackduck_client.session.post(
        '/api/scan/data',
        headers={'Accept': 'application/vnd.blackducksoftware.bdio+json'},
        params={'mode': 'replace'},
        files=files,
    )
    response.raise_for_status()
    logger.info(f'Uploaded BDIO for {bdio.name}')
