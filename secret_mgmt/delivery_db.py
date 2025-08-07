import dataclasses


@dataclasses.dataclass(kw_only=True)
class DeliveryDB:
    username: str = 'postgres'
    password: str

    def connection_url(
        self,
        namespace: str,
        service_name: str='delivery-db',
        port: int=5432,
        schema: str='postgresql+psycopg',
    ) -> str:
        hostname = f'{service_name}.{namespace}.svc.cluster.local'
        return f'{schema}://{self.username}:{self.password}@{hostname}:{port}'
