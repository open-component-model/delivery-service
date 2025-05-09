import unittest.mock

import dacite
import jsonpath_ng
import pytest
import yaml

import odg_operator.odg_controller as odgc
import odg_operator.odg_model as odgm

import paths


@pytest.fixture()
def extension_definitions():
    with open(paths.test_resources_extension_definitions, 'r') as f:
        return list(yaml.safe_load_all(f))


@pytest.fixture
def component_mock():
    mock = unittest.mock.Mock()
    mock.component.resources = []
    mock.component.sources = []
    mock.component.componentReferences = []
    mock.component.find_label = lambda name: []
    return mock


def test_extensions(extension_definitions, component_mock):
    ds, dd, db = [
        dacite.from_dict(
            data=raw,
            data_class=odgm.ExtensionDefinition,
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
    }

    outputs = dict([
        (extension_definition.name, extension_definition.templated_outputs(context))
        for extension_definition in (dd, ds, db)
    ])

    ds_outputs = outputs['delivery-service']
    assert ds_outputs[0].name == 'delivery-service-url'
    assert ds_outputs[0].value == 'api.my-domain.com'

    output_paths = odgc.outputs_as_jsonpath(outputs)
    path = jsonpath_ng.parse('dependencies.delivery-service.outputs.delivery-service-url')
    assert path.find(output_paths)[0].value == 'api.my-domain.com'

    dd_instance: odgm.ExtensionInstance = odgm.ExtensionInstance.from_definition(
        extension_definition=dd,
        outputs=output_paths,
        # we know ocm lookup works
        component_descriptor_lookup=lambda _: component_mock,
        absent_ok=True,
    )
    assert dd_instance.values[0].value == 'api.my-domain.com'
