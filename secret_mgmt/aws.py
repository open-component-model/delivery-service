import dataclasses
import functools

import boto3


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
