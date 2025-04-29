import requests

import caching
import util


def normalise_os_id(os_id: str) -> str:
    '''
    Some product identifiers differ from the ones we know.
    This function translates known difference from "our" identifier to the
    one EOL API can process.
    '''

    if os_id == 'amzn':
        return 'amazon-linux'

    return os_id


class EolRoutes:
    def __init__(
        self,
        base_url: str = 'https://endoflife.date/api',
    ):
        self._base_url = base_url

    def all_products(self):
        return util.urljoin(
            self._base_url,
            'all.json',
        )

    def cycles(
        self,
        product: str,
    ):
        return util.urljoin(
            self._base_url,
            f'{product}.json',
        )

    def cycle(
        self,
        cycle: int,
        product: str,
    ):
        return util.urljoin(
            self._base_url,
            product,
            f'{cycle}.json',
        )


class EolClient:
    '''
    API client for https://endoflife.date/docs/api.
    '''
    def __init__(
        self,
        routes: EolRoutes = EolRoutes(),
    ):
        self._routes = routes

    @caching.cached(caching.TTLFilesystemCache(ttl=60 * 60 * 24, max_total_size_mib=1)) # 24h
    def all_products(self) -> list[str]:
        res = requests.get(
            self._routes.all_products(),
            timeout=(4, 31),
        )
        res.raise_for_status()
        return res.json()

    @caching.cached(caching.TTLFilesystemCache(ttl=60 * 60 * 24, max_total_size_mib=200)) # 24h
    def cycles(
        self,
        product: str,
        absent_ok: bool = False,
    ) -> list[dict] | None:
        '''
        Returns release_cycles as described here https://endoflife.date/docs/api.
        If `absent_ok`, HTTP 404 returns `None`.
        '''
        res = requests.get(
            self._routes.cycles(product),
            timeout=(4, 31),
        )
        try:
            res.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if not absent_ok:
                raise
            if e.response.status_code == 404:
                return None
            raise
        return res.json()

    @caching.cached(caching.TTLFilesystemCache(ttl=60 * 60 * 24, max_total_size_mib=200)) # 24h
    def cycle(
        self,
        product: str,
        cycle: str,
        absent_ok: bool = False,
    ) -> dict | None:
        '''
        Returns single release_cycle as described here https://endoflife.date/docs/api.
        If `absent_ok`, HTTP 404 returns `None`.
        '''
        res = requests.get(
            self._routes.cycle(cycle, product),
            timeout=(4, 31),
        )
        try:
            res.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if not absent_ok:
                raise
            if e.response.status_code == 404:
                return None
            raise
        return res.json()
