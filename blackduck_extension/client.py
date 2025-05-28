import logging

import blackduck.Client

import bdba.model

logger = logging.getLogger(__name__)


class BlackDuckClient(blackduck.Client):
    def assign_usergroup_to_project(
        self,
        project: dict,
        usergroup_id: str
    ):
        project_href = project['_meta']['href']
        target_url = f'{project_href}/usergroups'
        headers = {
            'Accept': 'application/vnd.blackducksoftware.project-detail-4+json',
            'Content-Type': 'application/vnd.blackducksoftware.project-detail-4+json'
        }
        response = self.session.post(
            target_url,
            headers=headers,
            json={
                'group': f'{self.base_url}/api/usergroups/{usergroup_id}'
            }
        )
        response.raise_for_status()

    def create_project(
        self,
        project_name: str
    ):
        response = self.session.post(
            '/api/projects',
            json={
                'name': project_name,
                'projectLevelAdjustments': True,
            }
        )
        response.raise_for_status()

    def upload_bdio(
        self,
        bdio: bdba.model.BDIO,
    ):
        file_name = f'{bdio.name}.bdio.jsonld'
        files = {
            'file': (file_name, bdio.as_blackduck_bytes(), 'application/ld+json')
        }

        response = self.session.post(
            '/api/scan/data',
            headers={'Accept': 'application/vnd.blackducksoftware.bdio+json'},
            params={'mode': 'replace'},
            files=files,
        )
        response.raise_for_status()
        logger.info(f'Uploaded BDIO for {bdio.name}')
