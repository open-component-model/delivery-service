import dataclasses
import enum

import secret_mgmt


class MatchScore(enum.IntEnum):
    '''
    States "how well" a BDBA cfg matches the required group id and/or api url. `PERFECT_MATCH`
    expresses that both properties are declared and match the required ones, `GOOD_MATCH` means
    only one property is declared/required and matches, `MATCH` states the properties are not
    declared so it is uncertain whether or not the cfg actually matches and `NO_MATCH` expresses
    that there is a mismatch between the required properties and the BDBA cfg.
    '''
    NO_MATCH = -1
    MATCH = 0
    GOOD_MATCH = 1
    PERFECT_MATCH = 2


@dataclasses.dataclass
class BDBA:
    api_url: str
    group_ids: list[int]
    token: str
    tls_verify: bool = True

    def matches(
        self,
        group_id: int | None=None,
        url: str=None,
    ) -> MatchScore:
        score = 0

        if url:
            if url.startswith(self.api_url):
                score += 1
            else:
                return MatchScore.NO_MATCH

        if group_id:
            if group_id in self.group_ids:
                score += 1
            elif self.group_ids:
                return MatchScore.NO_MATCH

        return MatchScore(score)


def find_cfg(
    secret_factory: secret_mgmt.SecretFactory,
    group_id: int | None,
    url: str | None,
) -> BDBA | None:
    bdba_cfgs: list[BDBA] = secret_factory.bdba()

    matching_cfgs = (
        bdba_cfg
        for bdba_cfg in bdba_cfgs
        if not bdba_cfg.matches(
            group_id=group_id,
            url=url,
        ) is MatchScore.NO_MATCH
    )

    sorted_matching_cfgs = sorted(
        matching_cfgs,
        key=lambda cfg: cfg.matches(
            group_id=group_id,
            url=url,
        ),
    )

    if not sorted_matching_cfgs:
        return None

    return sorted_matching_cfgs[-1]
