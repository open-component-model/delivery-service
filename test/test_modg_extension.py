import enum
import os

import dacite
import jsonpath_ng
import pytest
import yaml


import odg_operator.__main__ as odgc
import odg_operator.odg_model as odgm
import odg_operator.odg_util as odgu


_own_dir = os.path.abspath(os.path.dirname(__file__))
test_resources_extension_definitions = os.path.join(
    _own_dir,
    'resources/extension-definitions.yaml',
)


@pytest.fixture()
def extension_definitions():
    with open(test_resources_extension_definitions, 'r') as f:
        return list(yaml.safe_load_all(f))


def test_jsonpatch_patch():
    assert {'foo': {'bar': {'foo.bar': 42}}} == odgu.patch_jsonpath_into_dict('foo.bar."foo.bar"', 42) # noqa: E501


def test_extensions(extension_definitions):
    ds, dd, db = [
        dacite.from_dict(
            data=raw,
            data_class=odgm.ExtensionDefinition,
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )
        for raw in extension_definitions
    ]

    missing = set(odgc.iter_missing_dependencies(
        requested=(dd,),
        known=(ds, dd, db),
    ))
    assert missing == set([ds, db])

    context = {
        'base_url': 'my-domain.com',
        'target_namespace': 'my-target-namespace',
    }

    outputs = dict([
        (extension_definition.name, extension_definition.templated_outputs(context))
        for extension_definition in (dd, ds, db)
    ])

    ds_outputs = outputs['delivery-service']
    assert ds_outputs[0].name == 'delivery-service-url'
    assert ds_outputs[0].value == 'https://delivery-service.my-domain.com'

    outputs = odgc.outputs_as_jsonpath(outputs)
    path = jsonpath_ng.parse('dependencies.delivery-service.outputs.delivery-service-url')
    assert path.find(outputs)[0].value == 'https://delivery-service.my-domain.com'

    patched_values = [
        odgu.template_and_resolve_jsonpath(
            value=value_template.value,
            jsonpaths=outputs,
            substitution_context=context,
            value_type=value_template.value_type,
        )
        for value_template in dd.installation.value_templates
    ]
    assert patched_values[0] == 'my-target-namespace'
    assert patched_values[1] == ['delivery-dashboard.my-domain.com']
    assert patched_values[2] == 'https://delivery-service.my-domain.com'

    assert odgu.template_and_resolve_jsonpath(
        value={'foo': 'bar.${base_url}'},
        jsonpaths=outputs,
        substitution_context=context,
        value_type=odgm.ValueType.PYTHON_STRING_TEMPLATE,
    ) == {
        'foo': 'bar.my-domain.com',
    }
