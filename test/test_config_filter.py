import pytest

import cnudie.iter
import ocm

import config_filter


@pytest.fixture
def node_path_entry():
    def _node_path_entry(
        name='TestComponent',
        version='1.2.3',
    ):
        return cnudie.iter.NodePathEntry(
            component=ocm.Component(
                resources=(),
                name=name,
                version=version,
                repositoryContexts=(),
                provider=None,
                sources=(),
                componentReferences=(),
            ),
        )
    return _node_path_entry


@pytest.fixture
def resource():
    def _resource(
        name='resourceName',
        version='1.2.3',
    ):
        return ocm.Resource(
            name=name,
            version=version,
            type='some-type',
            access=None,
        )
    return _resource


def test_unsupported_target_fails():
    test_config = config_filter.MatchingConfig(
        name='Some Config Name',
        rules=[
            config_filter.ConfigRule(
                target='Name',
                expression='TestComponent',
                matching_semantics=config_filter.ComponentFilterSemantics.INCLUDE,
            )
        ]
    )
    test_filter = config_filter.filter_for_matching_config(test_config)

    node = cnudie.iter.ComponentNode(path=())
    with pytest.raises(ValueError):
        test_filter(node)


def test_component_attr_included(node_path_entry):
    test_config = config_filter.MatchingConfig(
        name='Some Config Name',
        rules=[
            config_filter.ConfigRule(
                target='component.name',
                expression='TestComponent',
                matching_semantics=config_filter.ComponentFilterSemantics.INCLUDE,
            )
        ]
    )
    test_filter = config_filter.filter_for_matching_config(test_config)

    assert test_filter(
        cnudie.iter.ComponentNode(path=(
            node_path_entry(),
        ))
    )

    assert not test_filter(
        cnudie.iter.ComponentNode(path=(
            node_path_entry(name='unknown-component'),
        )
    ))


def test_component_attr_excluded(node_path_entry):
    test_config = config_filter.MatchingConfig(
        name='Some Config Name',
        rules=[
            config_filter.ConfigRule(
                target='component.name',
                expression='TestComponent',
                matching_semantics=config_filter.ComponentFilterSemantics.EXCLUDE,
            )
        ]
    )
    test_filter = config_filter.filter_for_matching_config(test_config)

    assert test_filter(
        cnudie.iter.ComponentNode(path=(
            node_path_entry(name='excluded-component'),
        )
    ))

    assert not test_filter(
        cnudie.iter.ComponentNode(path=(
            node_path_entry(name='TestComponent'),
        )
    ))


def test_multiple_component_rules(node_path_entry):
    test_config = config_filter.MatchingConfig(
        name='Some Config Name',
        rules=[
            config_filter.ConfigRule(
                target='component.name',
                expression='AName',
                matching_semantics=config_filter.ComponentFilterSemantics.INCLUDE,
            ),
            config_filter.ConfigRule(
                target='component.name',
                expression='AnotherName',
                matching_semantics=config_filter.ComponentFilterSemantics.INCLUDE,
            )
        ]
    )
    test_filter = config_filter.filter_for_matching_config(test_config)

    assert not test_filter(
        cnudie.iter.ComponentNode(path=(
            node_path_entry(name='AName'),
        )
    ))

    assert not test_filter(
        cnudie.iter.ComponentNode(path=(
            node_path_entry(name='AnotherName'),
        )
    ))

    assert not test_filter(
        cnudie.iter.ComponentNode(path=(
            node_path_entry(name='YetAnotherName'),
        )
    ))


def test_multiple_configs(node_path_entry, resource):
    # matching-configs are OR-ed
    test_configs = [
        config_filter.MatchingConfig(
            name='Some Config Name',
            rules=[
                config_filter.ConfigRule(
                    target='component.name',
                    expression='ComponentName',
                    matching_semantics=config_filter.ComponentFilterSemantics.INCLUDE,
                ),
            ]
        ),
        config_filter.MatchingConfig(
            name='Another Config Name',
            rules=[
                config_filter.ConfigRule(
                    target='resource.name',
                    expression='ResourceName',
                    matching_semantics=config_filter.ComponentFilterSemantics.INCLUDE,
                )
            ]
        ),
    ]
    test_filter = config_filter.filter_for_matching_configs(test_configs)

    assert test_filter(
        cnudie.iter.ResourceNode(
            path=(
                node_path_entry(name='ComponentName'),
            ),
            resource=resource(name='YetAnotherName'),
    ))

    assert not test_filter(
        cnudie.iter.ResourceNode(
            path=(
                node_path_entry(name='AnotherComponentName'),
            ),
            resource=resource(name='AnotherResource'),
    ))

    assert test_filter(
        cnudie.iter.ResourceNode(
            path=(
                node_path_entry(name='another-component'),
            ),
            resource=resource(name='ResourceName'),
    ))
