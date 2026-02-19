import enum
import os
import pathlib

import dacite
import pytest
import yaml

import ocm
import ocm.iter

import odg.extensions_cfg
import test_evidence_extension as tee


parent_dir = pathlib.Path(__file__).parent
resource_dir = os.path.abspath(
    os.path.join(
        parent_dir,
        'resources',
    ),
)


@pytest.fixture
def component() -> ocm.Component:
    path = os.path.join(
        resource_dir,
        'test_evidence_component_descriptor.yaml',
    )
    with open(path, 'r') as f:
        raw = yaml.safe_load(f)

    return dacite.from_dict(
        data=raw,
        data_class=ocm.ComponentDescriptor,
        config=dacite.Config(cast=[enum.Enum])
    ).component


@pytest.fixture
def extensions_cfg() -> odg.extensions_cfg.TestEvidenceConfig:
    return odg.extensions_cfg.TestEvidenceConfig(
        delivery_service_url='foo',
        external_artefacts_require_tests=False,
    )


def _find_resource_node(
    component: ocm.Component,
    resource_name: str,
) -> ocm.iter.ResourceNode | None:
    for rnode in ocm.iter.iter(
        component=component,
        recursion_depth=0,
        node_filter=ocm.iter.Filter.resources,
    ):
        rnode: ocm.iter.ResourceNode
        if rnode.resource.name == resource_name:
            return rnode

    raise ValueError(f'did not find resource for {resource_name=}')


def test_is_test_required(
    component: ocm.Component,
    extensions_cfg: odg.extensions_cfg.TestEvidenceConfig,
):
    artefact_not_requiring_tests = _find_resource_node(
        component=component,
        resource_name='build-result-not-requiring-tests',
    )
    assert tee.is_test_required(
        artefact_node=artefact_not_requiring_tests,
        extensions_cfg=extensions_cfg,
    ) is False

    artefact_requiring_tests = _find_resource_node(
        component=component,
        resource_name='build-result',
    )
    assert tee.is_test_required(
        artefact_node=artefact_requiring_tests,
        extensions_cfg=extensions_cfg,
    ) is True


def test_test_evidence_collection(
    component: ocm.Component,
):
    test_evidences = list(tee.iter_test_evidence_resources(
        component=component,
    ))
    assert len(test_evidences) == 1


def test_artefact_test_coverage(
    component: ocm.Component,
):
    test_evidences = list(tee.iter_test_evidence_resources(
        component=component,
    ))

    assert tee.has_artefact_test_coverage(
        artefact_name='build-result',
        test_evidences=test_evidences,
    ) == True

    assert tee.has_artefact_test_coverage(
        artefact_name='other-build-result',
        test_evidences=test_evidences,
    ) == False
