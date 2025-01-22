# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


import collections.abc
import datetime
import enum
import functools
import logging
import time
import traceback
import urllib.parse

import dacite
import dateutil.parser
import requests

import ci.log
import ci.util
import http_requests

import bdba.model as bm
import ctx_util
import secret_mgmt
import secret_mgmt.bdba


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()


def kebab_to_snake_case_keys(d: dict[str, dict | list | str | int]) -> dict:
    '''
    Highly opinionated function to convert the BDBA analysis result so that it can be processed by
    our BDBA model classes. In that, it converts kebab-cased keys recursively into snake_case (as
    expected by our model classes).
    '''
    result = {}

    for key, value in d.items():
        if isinstance(value, dict):
            value = kebab_to_snake_case_keys(value)
        elif isinstance(value, list):
            value = [
                kebab_to_snake_case_keys(v) if isinstance (v, dict) else v
                for v in value
            ]

        if not isinstance(key, str):
            raise TypeError(f'{key=} is expected to be of type "str", but is type "{type(key)}"')

        result[key.replace('-', '_')] = value

    return result


class BDBAApiRoutes:
    '''
    calculates API routes (URLs) for a subset of the URL endpoints exposed by
    "BDBA"

    Not intended to be instantiated by users of this module
    '''

    def __init__(self, base_url):
        self._base_url = ci.util.not_empty(base_url)
        self._api_url = functools.partial(self._url, 'api')
        self._rest_url = functools.partial(self._url, 'rest')

    def _url(self, *parts):
        return ci.util.urljoin(self._base_url, *parts)

    def apps(self, group_id=None, custom_attribs={}):
        url = self._api_url('apps')
        if group_id is not None:
            url = ci.util.urljoin(url, str(group_id))

        search_query = ' '.join(['meta:' + str(k) + '=' + str(v) for k,v in custom_attribs.items()])
        if search_query:
            url += '?' + urllib.parse.urlencode({'q': search_query})

        return url

    def login(self):
        return self._url('login') + '/'

    def pdf_report(self, product_id: int):
        return self._url('products', str(product_id), 'pdf-report')

    def groups(self):
        return self._api_url('groups')

    def upload(self, file_name):
        return self._api_url('upload', urllib.parse.quote_plus(file_name))

    def product(self, product_id: int):
        return self._api_url('product', str(product_id))

    def product_custom_data(self, product_id: int):
        return self._api_url('product', str(product_id), 'custom-data')

    def rescan(self, product_id):
        return self._api_url('product', str(product_id), 'rescan')

    def triage(self):
        return self._api_url('triage', 'vulnerability/')

    def version_override(self):
        return self._api_url('versionoverride/')

    # ---- "rest" routes (undocumented API)

    def scans(self, product_id: int):
        return self._rest_url('scans', str(product_id)) + '/'


class BDBAApi:
    def __init__(
        self,
        api_routes: BDBAApiRoutes,
        bdba_cfg: secret_mgmt.bdba.BDBA,
    ):
        self._routes = api_routes
        self._token = bdba_cfg.token
        self._tls_verify = bdba_cfg.tls_verify
        self._session = requests.Session()
        http_requests.mount_default_adapter(
            session=self._session,
        )

    def set_maximum_concurrent_connections(self, maximum_concurrent_connections: int):
        # mount new adapter with new parameters
        http_requests.mount_default_adapter(
            session=self._session,
            max_pool_size=maximum_concurrent_connections,
        )

    @http_requests.check_http_code
    def _request(self, method, *args, **kwargs):
        if 'headers' in kwargs:
            headers = kwargs['headers']
            del kwargs['headers']
        else:
            headers = {}

        headers['Authorization'] = f"Bearer {self._token}"

        try:
            timeout = kwargs.pop('timeout')
        except KeyError:
            timeout = (4, 121)

        return functools.partial(
            method,
            verify=self._tls_verify,
            cookies=None,
            headers=headers,
            timeout=timeout,
        )(*args, **kwargs)

    @http_requests.check_http_code
    def _get(self, *args, **kwargs):
        return self._request(self._session.get, *args, **kwargs)

    @http_requests.check_http_code
    def _post(self, *args, **kwargs):
        return self._request(self._session.post, *args, **kwargs)

    @http_requests.check_http_code
    def _put(self, *args, **kwargs):
        return self._request(self._session.put, *args, **kwargs)

    @http_requests.check_http_code
    def _delete(self, *args, **kwargs):
        return self._request(self._session.delete, *args, **kwargs)

    @http_requests.check_http_code
    def _patch(self, *args, **kwargs):
        return self._request(self._session.patch, *args, **kwargs)

    def _metadata_dict(self, custom_attributes):
        '''
        replaces "invalid" underscore characters (setting metadata fails silently if
        those are present). Note: dash characters are implcitly converted to underscore
        by BDBAA. Also, translates `None` to an empty string as header fields with
        `None` are going to be silently ignored while an empty string is used to remove
        a metadata attribute
        '''
        return {
            'META-' + str(k).replace('_', '-'): v if v is not None else ''
            for k,v in custom_attributes.items()
        }

    def upload(self,
        application_name: str,
        group_id: str,
        data: collections.abc.Generator[bytes, None, None],
        replace_id: int=None,
        custom_attribs={},
    ) -> bm.Result:
        url = self._routes.upload(file_name=application_name)

        headers = {'Group': str(group_id)}
        if replace_id:
            headers['Replace'] = str(replace_id)
        headers.update(self._metadata_dict(custom_attribs))

        result = self._put(
            url=url,
            headers=headers,
            data=data,
        ).json().get('results', {})

        return dacite.from_dict(
            data_class=bm.Result,
            data=kebab_to_snake_case_keys(result),
        )

    def delete_product(self, product_id: int):
        url = self._routes.product(product_id=product_id)

        try:
            self._delete(
                url=url,
            )
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # if the http status is 404 it is fine because the product should be deleted anyway
                logger.info(f'deletion of product {product_id} failed because it does not exist')
                return
            raise e

    def scan_result(self, product_id: int) -> bm.AnalysisResult:
        url = self._routes.product(product_id=product_id)

        result = self._get(
            url=url,
        ).json().get('results', {})

        return dacite.from_dict(
            data_class=bm.AnalysisResult,
            data=kebab_to_snake_case_keys(result),
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )

    def wait_for_scan_result(
        self,
        product_id: int,
        polling_interval_seconds: int=60,
    ) -> bm.AnalysisResult:
        def scan_finished():
            result = self.scan_result(product_id=product_id)
            if result.status is bm.ProcessingStatus.READY:
                return result
            elif result.status is bm.ProcessingStatus.FAILED:
                # failed scans do not contain package infos, raise to prevent side effects
                raise RuntimeError(f'scan failed; {result.fail_reason=}')
            else:
                return False

        result = scan_finished()
        while not result:
            # keep polling until result is ready
            time.sleep(polling_interval_seconds)
            result = scan_finished()
        return result

    def list_apps(self, group_id=None, custom_attribs={}) -> list[bm.Product]:
        # BDBA checks for substring match only.
        def full_match(analysis_result_attribs):
            if not custom_attribs:
                return True
            for attrib in custom_attribs:
                # attrib is guaranteed to be a key in analysis_result_attribs at this point
                if analysis_result_attribs[attrib] != custom_attribs[attrib]:
                    return False
            return True

        def _iter_matching_products(url: str):
            res = self._get(url=url)
            res.raise_for_status()
            res = res.json()
            products: list[dict] = res['products']

            for product in products:
                if not full_match(product.get('custom_data')):
                    continue
                yield dacite.from_dict(
                    data_class=bm.Product,
                    data=product,
                )

            if next_page_url := res.get('next'):
                yield from _iter_matching_products(url=next_page_url)

        url = self._routes.apps(group_id=group_id, custom_attribs=custom_attribs)
        return list(_iter_matching_products(url=url))

    def set_metadata(self, product_id: int, custom_attribs: dict):
        url = self._routes.product_custom_data(product_id=product_id)
        headers = self._metadata_dict(custom_attribs)

        result = self._post(
            url=url,
            headers=headers,
        )
        return result.json()

    def metadata(self, product_id: int):
        url = self._routes.product_custom_data(product_id=product_id)

        result = self._post(
            url=url,
            headers={},
        )
        return result.json().get('custom_data', {})

    def get_triages(
        self,
        component_name: str,
        component_version: str,
        vuln_id: str,
        scope: str,
        description: str,
    ):
        url = self._routes.triage()
        result = self._get(
            url=url,
            params={
                'component': component_name,
                'vuln_id': vuln_id,
                'scope': scope,
                'version': component_version,
                'description': description,
            }
        ).json()['triages']

        return [
            dacite.from_dict(
                data_class=bm.Triage,
                data=triage_dict,
                config=dacite.Config(
                    type_hooks={
                        datetime.datetime: dateutil.parser.isoparse,
                    },
                    cast=[enum.Enum],
                ),
            ) for triage_dict in result
        ]

    def add_triage(
        self,
        triage: bm.Triage,
        scope: bm.TriageScope=None,
        product_id=None,
        group_id=None,
        component_version=None,
    ):
        '''
        adds an existing BDBA triage to a specified target. The existing triage is usually
        retrieved from an already uploaded product (which is represented by `AnalysisResult`).
        This method is offered to support "transporting" existing triages.

        Note that - depending on the effective target scope, the `product_id`, `group_id` formal
        parameters are either required or forbidden.

        Note that BDBA will only accept triages for matching (component, vulnerabilities,
        version) tuples. In particular, triages for different component versions will be silently
        ignored. Explicitly pass `component_version` of target BDBA app (/product) to force
        BDBA into accepting the given triage.

        @param triage: the triage to "copy"
        @param scope: if given, overrides the triage's scope
        @param product_id: target product_id. required iff scope in FN, FH, R
        @param group_id: target group_id. required iff scope is G(ROUP)
        @param component_version: overwrite target component version
        '''
        # if no scope is set, use the one from passed triage
        scope = scope if scope else triage.scope

        # depending on the scope, different arguments are required
        if scope == bm.TriageScope.ACCOUNT_WIDE:
            pass
        elif scope in (bm.TriageScope.FILE_NAME, bm.TriageScope.FILE_HASH, bm.TriageScope.RESULT):
            ci.util.not_none(product_id)
        elif scope == bm.TriageScope.GROUP:
            ci.util.not_none(group_id)
        else:
            raise NotImplementedError()

        if not component_version:
            component_version = triage.version

        # "copy" data from existing triage
        triage_dict = {
            'component': triage.component,
            'version': component_version,
            'vulns': [triage.vuln_id],
            'scope': triage.scope.value,
            'reason': triage.reason,
            'description': triage.description,
        }

        if product_id:
            triage_dict['product_id'] = product_id

        if group_id:
            triage_dict['group_id'] = group_id

        return self.add_triage_raw(triage_dict=triage_dict)

    def add_triage_raw(
        self, triage_dict: dict
    ):
        url = self._routes.triage()
        try:
            res = self._put(
                url=url,
                json=triage_dict,
            ).json()
            return res
        except requests.exceptions.HTTPError as e:
            resp: requests.Response = e.response
            logger.warning(f'{url=} {resp.status_code=} {resp.content=} {triage_dict=}')
            traceback.print_exc()
            raise e

    # --- "rest" routes (undocumented API)
    def set_product_name(self, product_id: int, name: str):
        url = self._routes.product(product_id)

        self._patch(
            url=url,
            json={'name': name},
        )

    def rescan(self, product_id: int):
        url = self._routes.rescan(product_id)
        self._post(
            url=url,
        )

    def set_component_version(
        self,
        component_name: str,
        component_version: str,
        objects: list[str],
        scope: bm.VersionOverrideScope=bm.VersionOverrideScope.APP,
        app_id: int=None,
        group_id: int=None,
    ):
        '''
        @param component_name: component name as reported by bdba
        @param component_version: version to set as override
        @param objects: list of sha1-digests (as reported by BDBA)
        @param scope: see VersionOverrideScope enum
        '''
        url = self._routes.version_override()

        override_dict = {
            'component': component_name,
            'version': component_version,
            'objects': objects,
            'scope': scope.value,
        }

        if scope is bm.VersionOverrideScope.APP:
            if not app_id:
                raise RuntimeError(
                    'An App ID is required when overriding versions with App scope.'
                )
            override_dict['app_scope'] = app_id
        elif scope is bm.VersionOverrideScope.GROUP:
            if not group_id:
                raise RuntimeError(
                    'A Group ID is required when overriding versions with Group scope.'
                )
            override_dict['group_scope'] = group_id
        else:
            raise NotImplementedError

        return self._put(
            url=url,
            json=[override_dict],
        ).json()

    def pdf_report(self, product_id: int, cvss_version: bm.CVSSVersion=bm.CVSSVersion.V3):
        url = self._routes.pdf_report(product_id)

        if cvss_version is bm.CVSSVersion.V2:
            cvss_version_number = 2
        elif cvss_version is bm.CVSSVersion.V3:
            cvss_version_number = 3
        else:
            raise NotImplementedError(cvss_version)

        response = self._get(
            url=url,
            params={'cvss_version': cvss_version_number},
        )

        return response.content


def client(
    bdba_cfg: secret_mgmt.bdba.BDBA | None=None,
    group_id: int | None=None,
    url: str | None=None,
    secret_factory: secret_mgmt.SecretFactory | None=None,
) -> BDBAApi:
    '''
    Either pass `bdba_cfg` directly (or reference by name) or lookup `bdba_cfg` based on `group_id`
    and `url`, most specific cfg wins.
    '''

    if not secret_factory:
        secret_factory = ctx_util.secret_factory()

    if bdba_cfg:
        if isinstance(bdba_cfg, str):
            bdba_cfg = secret_factory.bdba(bdba_cfg)

        if bdba_cfg.matches(
            group_id=group_id,
            url=url,
        ) is secret_mgmt.bdba.MatchScore.NO_MATCH:
            raise ValueError(f'BDBA cfg does not match {group_id=} and {url=}')

    else:
        if not (bdba_cfg := secret_mgmt.bdba.find_cfg(
            secret_factory=secret_factory,
            group_id=group_id,
            url=url,
        )):
            raise ValueError(f'No BDBA cfg found for {group_id=} and {url=}')

    routes = BDBAApiRoutes(base_url=bdba_cfg.api_url)
    api = BDBAApi(
        api_routes=routes,
        bdba_cfg=bdba_cfg,
    )
    return api
