import dataclasses
import datetime
import json
import typing


@dataclasses.dataclass(frozen=True)
class ExceptionMetric:
    service: str
    stacktrace: typing.List[str]
    request: str
    params: str
    creation_date: str

    @staticmethod
    def create(
        service: str,
        stacktrace: typing.List[str],
        request: typing.Optional[dict] = None,
        params: typing.Optional[dict] = None,
    ) -> 'ExceptionMetric':
        '''
        convenience method to create a `ExceptionMetric`
        '''
        return ExceptionMetric(
            creation_date=datetime.datetime.now().isoformat(),
            service=service,
            stacktrace=stacktrace,
            request=json.dumps(request),
            params=json.dumps(params),
        )


def index_name(
    obj: ExceptionMetric,
) -> str:
    if isinstance(obj, ExceptionMetric):
        return 'cicd_services_exception'

    raise NotImplementedError(obj)
