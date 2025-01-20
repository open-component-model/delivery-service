import dataclasses


@dataclasses.dataclass
class DeliveryDB:
    hostname: str
    port: int
    username: str
    password: str
    db_type: str = 'postgresql+psycopg'

    @property
    def url(self) -> str:
        return f'{self.db_type}://{self.username}:{self.password}@{self.hostname}:{self.port}'
