import dataclasses


@dataclasses.dataclass
class BlackDuck:
    api_url: str
    group_id: str
    token: str
