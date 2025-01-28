import collections.abc
import logging
import os


logger = logging.getLogger(__name__)

_own_dir = os.path.abspath(os.path.dirname(__file__))

_json_schema_path = os.path.join(_own_dir, 'schema')
token_jsonschema_path = os.path.join(_json_schema_path, 'token-payload-schema.yaml')

_responsibles_path = os.path.join(_own_dir, 'responsibles')
responsibles_username_negative_list_path = os.path.join(
    _responsibles_path,
    'responsibles_username_negative_list.yaml',
)

test_resources_apiserver_proxy = os.path.join(_own_dir, 'test/resources/apiserver-proxy.json')
test_resources_mcm = os.path.join(_own_dir, 'test/resources/machine-controller-manager.json')
test_resources_gardener_org_members = os.path.join(
    _own_dir,
    'test/resources/gardener_org_members.yaml',
)

_compliance_summary_path = os.path.join(_own_dir, 'compliance_summary')
artefact_metadata_cfg = os.path.join(_compliance_summary_path, 'artefact_metadata_cfg.yaml')

_features_path = os.path.join(_own_dir, 'features')

swagger_path = os.path.join(_own_dir, 'swagger', 'swagger.yaml')

_odg_path = os.path.join(_own_dir, 'odg')


def features_cfg_candidates() -> collections.abc.Generator[str | None, None, None]:
    yield os.environ.get('FEATURES_CFG_PATH')
    yield os.path.join(_features_path, 'features_cfg.yaml')


def scan_cfg_candidates() -> collections.abc.Generator[str | None, None, None]:
    yield os.environ.get('SCAN_CFG_PATH')
    yield os.path.join(_odg_path, 'scan_cfg.yaml')


def findings_cfg_candidates() -> collections.abc.Generator[str | None, None, None]:
    yield os.environ.get('FINDINGS_CFG_PATH')
    yield os.path.join(_odg_path, 'findings_cfg.yaml')


def find_path(
    candidates: collections.abc.Iterable[str | None],
    absent_ok: bool=False,
) -> str | None:
    for candidate in candidates:
        if not candidate:
            continue

        if not os.path.isfile(candidate):
            logger.warning(f'not an existing file: {candidate=}')
            continue

        return candidate

    if absent_ok:
        return None

    raise ValueError(f'did not find file at any of {candidates=}')


def features_cfg_path(
    absent_ok: bool=False,
) -> str | None:
    return find_path(
        candidates=features_cfg_candidates(),
        absent_ok=absent_ok,
    )


def scan_cfg_path(
    absent_ok: bool=False,
) -> str | None:
    return find_path(
        candidates=scan_cfg_candidates(),
        absent_ok=absent_ok,
    )


def findings_cfg_path(
    absent_ok: bool=False,
) -> str | None:
    return find_path(
        candidates=findings_cfg_candidates(),
        absent_ok=absent_ok,
    )
