import functools
import logging

import requests

logger = logging.getLogger(__name__)


class BlackDuckClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        verify: bool = True,
    ):
        self.base_url = base_url.rstrip('/')
        self._api_token = token
        self._tls_verify = verify
        self._session = requests.Session()

        self._bearer_token = self._authenticate()

    def _authenticate(self) -> str:
        url = f'{self.base_url}/api/tokens/authenticate'
        headers = {
            'Authorization': f'token {self._api_token}',
            'Accept': 'application/vnd.blackducksoftware.user-4+json',
        }

        logger.debug(f'Authenticating against BlackDuck at {url}')
        response = self._session.post(url, headers=headers, verify=self._tls_verify)
        response.raise_for_status()

        bearer = response.json()['bearerToken']
        logger.debug('Successfully retrieved bearer token')
        return bearer

    def _request(
        self,
        method,
        url,
        *args,
        **kwargs
    ):
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
            verify=self._tls_verify,
            timeout=timeout,
        )(*args, **kwargs)

    def _url(
        self,
        path: str
    ) -> str:
        return f'{self.base_url}/api/{path.lstrip("/")}'

    def _get(
        self,
        path: str,
        **kwargs
    ):
        return self._request(self._session.get, self._url(path), **kwargs)

    def _post(
        self,
        path: str,
        **kwargs
    ):
        return self._request(self._session.post, self._url(path), **kwargs)

    def get_project_by_name(
        self,
        name: str
    ) -> list[dict]:
        params = {'q': [f'name:{name}']}
        response = self._get('projects', params=params)
        response.raise_for_status()
        return response.json().get('items', [])

    def create_project(
        self,
        project_name: str
    ):
        payload = {
            'name': project_name,
        }
        response = self._post('projects', json=payload)
        response.raise_for_status()

    def assign_usergroup_to_project(
        self,
        project: dict,
        usergroup_id: str
    ):
        project_href = project['_meta']['href']
        target_url = f'{project_href}/usergroups'
        headers = {
            'Accept': 'application/vnd.blackducksoftware.project-detail-4+json',
            'Content-Type': 'application/vnd.blackducksoftware.project-detail-4+json',
        }
        payload = {
            'group': f'{self.base_url}/api/usergroups/{usergroup_id}',
        }

        response = self._request(
            method=self._session.post,
            url=target_url,
            headers=headers,
            json=payload,
        )
        response.raise_for_status()

    def upload_bdio(
        self,
        bdio: bytes,
        content_type: str = 'application/ld+json'
    ):
        headers = {
            'Content-Type': content_type,
            'Accept': 'application/json',
        }
        response = self._post('scan/data', data=bdio, headers=headers)
        response.raise_for_status()
        return response
