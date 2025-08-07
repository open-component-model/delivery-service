import dataclasses
import functools

import boto3

import secret_mgmt


@dataclasses.dataclass
class AWS:
    access_key_id: str
    secret_access_key: str
    region: str

    @functools.cached_property
    def session(self) -> boto3.Session:
        return boto3.Session(
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            region_name=self.region,
        )


def find_cfg(
    secret_factory: secret_mgmt.SecretFactory,
    secret_name: str | None=None,
) -> AWS | None:
    if secret_name:
        return secret_factory.aws(secret_name)

    aws_cfgs: list[AWS] = secret_factory.aws()

    if len(aws_cfgs) == 1:
        return aws_cfgs[0]

    raise ValueError(
        'AWS secret name must be specified if more than one secret is available (found '
        f'{len(aws_cfgs)})'
    )
