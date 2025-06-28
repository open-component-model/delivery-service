import datetime
import functools
import logging

import dacite
import requests

import bdba.util
import blackduck.model

logger = logging.getLogger(__name__)


class BlackDuckApiRoutes:
    def __init__(
        self,
        base_url: str
    ):
        if base_url is None:
            raise ValueError(f'{base_url=} must not be None')
        self._base_url = base_url
        self._api_url = functools.partial(self._url, 'api')

    def _url(
        self,
        *parts
    ):
        return bdba.util.urljoin(
            self._base_url,
            *parts
        )

    def authenticate(self):
        return self._api_url('tokens', 'authenticate')

    def projects(self):
        return self._api_url('projects')

    def project_usergroups(
        self,
        project_id: int
    ):
        return self._api_url('projects', str(project_id), 'usergroups')

    def usergroups(
        self,
        group_id: str
    ):
        return self._api_url('usergroups', group_id)

    def upload_bdio(self):
        return self._api_url('scan', 'data')

    def project_groups(self):
        return self._api_url('project-groups')

    def project_group_usergroups(
        self,
        project_group_id: str
    ):
        return self._api_url('project-groups', project_group_id, 'usergroups')

    def project_group_assignment(
        self,
        project_id: str
    ):
        return self._api_url('projects', project_id, 'project-groups')


class BlackDuckClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        verify: bool = True
    ):
        self._routes = BlackDuckApiRoutes(base_url)
        self._api_token = token
        self._verify = verify
        self._session = requests.Session()

        self._bearer_token = None
        self._token_expiry = datetime.datetime.min

    def _authenticate(self):
        url = self._routes.authenticate()
        headers = {
            'Authorization': f'token {self._api_token}',
            'Accept': 'application/vnd.blackducksoftware.user-4+json',
        }
        resp = self._session.post(
            url=url,
            headers=headers,
            verify=self._verify,
            timeout=(4, 30)
        )
        resp.raise_for_status()
        data = resp.json()
        self._bearer_token = data['bearerToken']
        expires = data.get('expiresInMilliseconds', 0)
        self._token_expiry = datetime.datetime.now() + datetime.timedelta(milliseconds=expires)
        logger.debug(f'Authenticated; token valid until {self._token_expiry.isoformat()}')

    def _ensure_auth(self):
        if (
            not self._bearer_token
            or datetime.datetime.now() >= self._token_expiry - datetime.timedelta(seconds=30)
        ):
            logger.debug('Bearer token expired or about to expire, refreshing…')
            self._authenticate()

    def _request(
        self,
        method,
        url: str,
        **kwargs
    ) -> requests.Response:
        self._ensure_auth()
        headers = kwargs.pop('headers', {})
        headers.update({
            'Authorization': f'Bearer {self._bearer_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        })
        timeout = kwargs.pop('timeout', (4, 121))
        return functools.partial(
            method,
            url,
            headers=headers,
            verify=self._verify,
            timeout=timeout,
            **kwargs,
        )()

    def find_project_by_name(
        self,
        name: str
    ) -> blackduck.model.Project | None:
        url = self._routes.projects()
        resp = self._request(
            method=self._session.get,
            url=url,
            params={'q': [f'name:{name}']}
        )
        resp.raise_for_status()
        items = resp.json().get('items', [])
        if not items:
            return None
        if len(items) > 1:
            raise RuntimeError(f'Expected only one project named "{name}", but found: {items}')

        raw_data = items[0]

        return dacite.from_dict(
            data_class=blackduck.model.Project,
            data=dict(**raw_data, project_group=raw_data.get('projectGroup'))
        )

    def find_project_group_by_name(
        self,
        name: str
    ) -> blackduck.model.ProjectGroup | None:
        url = self._routes.project_groups()
        resp = self._request(
            method=self._session.get,
            url=url,
            params={'q': [f'name:{name}']}
        )
        resp.raise_for_status()
        items = resp.json().get('items', [])
        if not items:
            return None
        if len(items) > 1:
            raise RuntimeError(f'Expected only one project named "{name}", but found: {items}')

        return dacite.from_dict(
            data_class=blackduck.model.Project,
            data=items[0]
        )

    def create_project(
        self,
        project_name: str,
        project_group_id: str,
    ):
        url = self._routes.projects()
        payload = {
            'name': project_name,
            'projectGroup': self._routes.project_groups() + '/' + project_group_id
        }
        resp = self._request(
            method=self._session.post,
            url=url,
            json=payload,
        )
        resp.raise_for_status()

    def create_project_group(
        self,
        name: str,
        description: str = ''
    ):
        url = self._routes.project_groups()
        payload = {
            'name': name,
            'description': description,
        }
        resp = self._request(
            method=self._session.post,
            url=url,
            json=payload,
        )
        resp.raise_for_status()

    def assign_usergroup_to_project(
        self,
        project_id: str,
        usergroup_id: str
    ):
        url = self._routes.project_usergroups(
            project_id=project_id
        )
        payload = {
            'group': self._routes.usergroups(usergroup_id)
        }
        headers = {
            'Accept': 'application/vnd.blackducksoftware.project-detail-4+json',
            'Content-Type': 'application/vnd.blackducksoftware.project-detail-4+json',
        }
        resp = self._request(
            method=self._session.post,
            url=url,
            json=payload,
            headers=headers
        )
        resp.raise_for_status()

    def assign_usergroup_to_project_group(
        self,
        project_group_id: str,
        usergroup_id: str
    ):
        url = self._routes.project_group_usergroups(
            project_group_id=project_group_id
        )
        payload = {
            'group': self._routes.usergroups(usergroup_id),
        }
        headers = {
            'Accept': 'application/vnd.blackducksoftware.project-detail-5+json',
            'Content-Type': 'application/vnd.blackducksoftware.project-detail-5+json',
        }
        resp = self._request(
            method=self._session.post,
            url=url,
            json=payload,
            headers=headers,
        )
        resp.raise_for_status()

    def upload_bdio(
        self,
        bdio: bytes,
        mode: str = 'replace'
    ) -> None:
        url = self._routes.upload_bdio() + f'?mode={mode}'

        headers = {
            'Content-Type': 'application/ld+json',
            'Accept': 'application/json',
        }
        resp = self._request(
            method=self._session.post,
            url=url,
            data=bdio,
            headers=headers
        )
        resp.raise_for_status()
