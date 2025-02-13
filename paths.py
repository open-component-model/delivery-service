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


def features_cfg_candidates() -> collections.abc.Generator[str, None, None]:
    if features_cfg_path := os.environ.get('FEATURES_CFG_PATH'):
        yield features_cfg_path
    yield os.path.join(_features_path, 'features_cfg.yaml')


def extensions_cfg_candidates() -> collections.abc.Generator[str, None, None]:
    if extensions_cfg_path := os.environ.get('EXTENSIONS_CFG_PATH'):
        yield extensions_cfg_path
    yield os.path.join(_odg_path, 'extensions_cfg.yaml')


def findings_cfg_candidates() -> collections.abc.Generator[str, None, None]:
    if findings_cfg_path := os.environ.get('FINDINGS_CFG_PATH'):
        yield findings_cfg_path
    yield os.path.join(_odg_path, 'findings_cfg.yaml')


def ocm_repo_mappings_candidates() -> collections.abc.Generator[str, None, None]:
    if ocm_repo_mappings_path := os.environ.get('OCM_REPO_MAPPINGS_PATH'):
        yield ocm_repo_mappings_path
    yield os.path.join(_odg_path, 'ocm_repo_mappings.yaml')


def profiles_candidates() -> collections.abc.Generator[str, None, None]:
    if profiles_path := os.environ.get('PROFILES_PATH'):
        yield profiles_path
    yield os.path.join(_odg_path, 'profiles.yaml')


def find_path(
    candidates: collections.abc.Iterable[str],
    absent_ok: bool=False,
) -> str | None:
    for candidate in candidates:
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


def extensions_cfg_path(
    absent_ok: bool=False,
) -> str | None:
    return find_path(
        candidates=extensions_cfg_candidates(),
        absent_ok=absent_ok,
    )


def findings_cfg_path(
    absent_ok: bool=False,
) -> str | None:
    return find_path(
        candidates=findings_cfg_candidates(),
        absent_ok=absent_ok,
    )


def ocm_repo_mappings_path(
    absent_ok: bool=False,
) -> str | None:
    return find_path(
        candidates=ocm_repo_mappings_candidates(),
        absent_ok=absent_ok,
    )


def profiles_path(
    absent_ok: bool=False,
) -> str | None:
    return find_path(
        candidates=profiles_candidates(),
        absent_ok=absent_ok,
    )
