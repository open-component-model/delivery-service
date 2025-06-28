import dataclasses


@dataclasses.dataclass
class BlackDuck:
    api_url: str
    group_id: int | str
    token: str
