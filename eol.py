import datetime
import typing

import cachetools
import dateutil.parser
import requests

import ci.util
import delivery.model as dm


def normalise_os_id(os_id: str) -> str:
    '''
    Some product identifiers differ from the ones we know.
    This function translates known difference from "our" identifier to the
    one EOL API can process.
    '''

    if os_id == 'amzn':
        return 'amazon-linux'

    return os_id


def os_release_info_from_release_cycle(
    release_cycle: dict,
) -> dm.OsReleaseInfo:
    def eol_date() -> bool | datetime.datetime | None:
        eol_date = release_cycle.get('extendedSupport')
        if eol_date is None:
            eol_date = release_cycle.get('eol')

        # unfortunately, eol-api yields inconsistent values for `eol` attribute (bool vs timestamp)
        if isinstance(eol_date, bool):
            return eol_date
        elif isinstance(eol_date, str):
            return dateutil.parser.isoparse(eol_date)
        else:
            return None

    def reached_eol(
        eol_date: datetime.datetime | bool=eol_date(),
    ) -> bool | None:
        if isinstance(eol_date, bool):
            return eol_date
        elif isinstance(eol_date, datetime.datetime):
            return eol_date < datetime.datetime.today()
        else:
            return None

    return dm.OsReleaseInfo(
        name=release_cycle['cycle'],
        # not provided for all products
        greatest_version=release_cycle.get('latest'),
        eol_date=eol_date(),
        reached_eol=reached_eol(),
    )


class EolRoutes:
    def __init__(
        self,
        base_url: str = 'https://endoflife.date/api',
    ):
        self._base_url = base_url

    def all_products(self):
        return ci.util.urljoin(
            self._base_url,
            'all.json',
        )

    def cycles(
        self,
        product: str,
    ):
        return ci.util.urljoin(
            self._base_url,
            f'{product}.json',
        )

    def cycle(
        self,
        cycle: int,
        product: str,
    ):
        return ci.util.urljoin(
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

    @cachetools.cached(cachetools.TTLCache(maxsize=1, ttl=60 * 60 * 24)) # 24h
    def all_products(self) -> typing.List[str]:
        res = requests.get(url=self._routes.all_products())
        res.raise_for_status()
        return res.json()

    @cachetools.cached(cachetools.TTLCache(maxsize=200, ttl=60 * 60 * 24)) # 24h
    def cycles(
        self,
        product: str,
        absent_ok: bool = False,
    ) -> typing.Optional[list[dict]]:
        '''
        Returns release_cycles as described here https://endoflife.date/docs/api.
        If `absent_ok`, HTTP 404 returns `None`.
        '''
        res = requests.get(
            url=self._routes.cycles(
                product=product,
            )
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

    @cachetools.cached(cachetools.TTLCache(maxsize=200, ttl=60 * 60 * 24)) # 24h
    def cycle(
        self,
        product: str,
        cycle: str,
        absent_ok: bool = False,
    ) -> typing.Optional[dict]:
        '''
        Returns single release_cycle as described here https://endoflife.date/docs/api.
        If `absent_ok`, HTTP 404 returns `None`.
        '''
        res = requests.get(
            url=self._routes.cycle(
                product=product,
                cycle=cycle,
            ),
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
