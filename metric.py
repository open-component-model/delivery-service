import dataclasses
import datetime
import json


@dataclasses.dataclass(frozen=True)
class ExceptionMetric:
    service: str
    stacktrace: list[str]
    request: str
    params: str
    creation_date: str

    @staticmethod
    def create(
        service: str,
        stacktrace: list[str],
        request: dict | None=None,
        params: dict | None=None,
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
