import odg.model
import odg.util


def test_convert_none_to_empty_string():
    # Test with ComponentArtefactId with None values at multiple levels
    artefact_id = odg.model.ComponentArtefactId(
        component_name='my-component',
        component_version=None,  # None value to be converted
        artefact_kind=odg.model.ArtefactKind.RESOURCE,
        artefact=odg.model.LocalArtefactId(
            artefact_name='my-artefact',
            artefact_version=None,  # None value to be converted
            artefact_type='my-artefact-type',
            artefact_extra_id={},
        ),
        references=[
            odg.model.ComponentArtefactId(
                component_name=None,  # None value to be converted
                component_version='1.0.0',
                artefact=odg.model.LocalArtefactId(
                    artefact_name='reference-artefact',
                    artefact_version='2.0.0',
                    artefact_type=None,  # None value to be converted
                ),
            ),
        ],
    )

    result = odg.util._convert_none_to_empty_string_for_component_artefact_id(artefact_id)

    # Check top-level None conversion
    assert result.component_name == 'my-component'
    assert result.component_version == ''  # was None
    assert result.artefact_kind == odg.model.ArtefactKind.RESOURCE

    # Check nested artefact None conversion
    assert result.artefact.artefact_name == 'my-artefact'
    assert result.artefact.artefact_version == ''  # was None
    assert result.artefact.artefact_type == 'my-artefact-type'

    # Check references list with nested None conversion
    assert len(result.references) == 1
    assert result.references[0].component_name == ''  # was None
    assert result.references[0].component_version == '1.0.0'
    assert result.references[0].artefact.artefact_name == 'reference-artefact'
    assert result.references[0].artefact.artefact_version == '2.0.0'
    assert result.references[0].artefact.artefact_type == ''  # was None


def test_convert_none_to_empty_string_no_none_values():
    # Test with ComponentArtefactId with no None values
    artefact_id = odg.model.ComponentArtefactId(
        component_name='my-component',
        component_version='1.0.0',
        artefact_kind=odg.model.ArtefactKind.RESOURCE,
        artefact=odg.model.LocalArtefactId(
            artefact_name='my-artefact',
            artefact_version='2.0.0',
            artefact_type='my-artefact-type',
            artefact_extra_id={'key': 'value'},
        ),
    )

    result = odg.util._convert_none_to_empty_string_for_component_artefact_id(artefact_id)

    # All values should remain unchanged
    assert result.component_name == 'my-component'
    assert result.component_version == '1.0.0'
    assert result.artefact_kind == odg.model.ArtefactKind.RESOURCE
    assert result.artefact.artefact_name == 'my-artefact'
    assert result.artefact.artefact_version == '2.0.0'
    assert result.artefact.artefact_type == 'my-artefact-type'
    assert result.artefact.artefact_extra_id == {'key': 'value'}


def test_convert_none_to_empty_string_none_artefact():
    # Test with None artefact field (LocalArtefactId type should remain None)
    artefact_id = odg.model.ComponentArtefactId(
        component_name=None,
        component_version=None,
        artefact=None,  # This should stay None (not converted to string)
        artefact_kind=None,  # This should stay None (not converted to string)
        references=[],
    )

    result = odg.util._convert_none_to_empty_string_for_component_artefact_id(artefact_id)

    assert result.component_name == ''  # String field: None -> ''
    assert result.component_version == ''  # String field: None -> ''
    assert result.artefact is None  # Non-string field: stays None
    assert result.artefact_kind is None  # Enum field: stays None
    assert result.references == []


def test_convert_none_to_empty_string_artefact_kind_preserved():
    # Test that artefact_kind None value is NOT converted to empty string
    # This is critical because ArtefactKind is an enum, not a string
    artefact_id = odg.model.ComponentArtefactId(
        component_name='test-component',
        component_version='1.0.0',
        artefact_kind=None,  # Should remain None, not become ''
        artefact=odg.model.LocalArtefactId(
            artefact_name='test-artefact',
        ),
    )

    result = odg.util._convert_none_to_empty_string_for_component_artefact_id(artefact_id)

    # artefact_kind should remain None (enum type)
    assert result.artefact_kind is None
    # But string fields should be converted
    assert result.component_name == 'test-component'
    assert result.component_version == '1.0.0'
