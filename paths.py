import os


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
features_cfg = os.path.join(_features_path, 'features_cfg.yaml')

swagger_path = os.path.join(_own_dir, 'swagger', 'swagger.yaml')


def features_cfg_path() -> str:
    if (
        (env_features_cfg_path := os.environ.get('FEATURES_CFG_PATH')) and
        os.path.isfile(env_features_cfg_path)
    ):
        return env_features_cfg_path

    if os.path.isfile(features_cfg):
        return features_cfg

    return None
