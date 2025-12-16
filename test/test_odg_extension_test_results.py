import pytest
import dacite
import enum
import ocm
import odg.model
import odg.findings
import test_results
import yaml
from pathlib import Path


@pytest.fixture
def component_descriptor() -> ocm.ComponentDescriptor:
    yaml_path = Path(__file__).parent / "resources" / \
                     "missing_test_results_component_descriptor.yaml"

    raw = yaml.safe_load(yaml_path.read_text())

    return dacite.from_dict(
        data=raw,
        data_class=ocm.ComponentDescriptor,
        config=dacite.Config(cast=[enum.Enum])
    )


@pytest.fixture
def missing_test_result_finding_cfg() -> odg.findings.Finding:
    yaml_path_finding = Path(__file__).parent / \
                             "resources" / "missing_test_result_finding.yaml"

    raw = yaml.safe_load(yaml_path_finding.read_text())

    categorisations = []

    for cat in raw["categorisations"]:
        selector = None

        if cat["selector"] is not None:
            selector = odg.findings.TestResultFindingSelector(
                status=cat["selector"]["status"]
            )

        categorisations.append(
            odg.findings.FindingCategorisation(
                id=cat["id"],
                display_name=cat["display_name"],
                value=cat["value"],
                allowed_processing_time=cat["allowed_processing_time"],
                rescoring=cat["rescoring"],
                selector=selector
            )
        )

    return odg.findings.Finding(
        type=odg.model.Datatype.TEST_RESULT_FINDING,
        filter=None,
        rescoring_ruleset=None,
        categorisations=categorisations
    )


def test_artefact_test_results_filter(
    component_descriptor: ocm.ComponentDescriptor,
    missing_test_result_finding_cfg: odg.findings.Finding
):

    resources_req_tests = list(test_results.iter_artefacts_requiring_tests(
        component=component_descriptor))

    test_resources = list(test_results.find_test_artefacts(
        component=component_descriptor))

    assert len(resources_req_tests) == len(test_resources)

 # mismatching test scope
    test_scope_values = component_descriptor.component.resources[0].labels[2].value

    test_scope_values.remove("job-image-1")

    test_resources = test_results.find_test_artefacts(
        component=component_descriptor)

    test_coverage = test_results.iter_artefacts_for_test_coverage(
        test_result_finding_config=missing_test_result_finding_cfg,
        component=component_descriptor,
        artefact=odg.model.ComponentArtefactId,
        sub_type=odg.model.TestStatus.NO_TEST)

    assert len(test_coverage) == 1

# no test scope

    labels = component_descriptor.component.resources[0].labels
    labels = [label for label in labels if not label.name ==
        'gardener.cloud/test-scope']

    component_descriptor.component.resources[0].labels = labels

    test_resources = test_results.find_test_artefacts(
        component=component_descriptor)

    test_coverage = test_results.iter_artefacts_for_test_coverage(
        component=component_descriptor,
        artefact=odg.model.ComponentArtefactId,
        test_result_finding_config=missing_test_result_finding_cfg,
        sub_type=odg.model.TestStatus.NO_TEST)

    assert len(test_coverage) == 0

# let's remove the test results
    component_descriptor.component.resources = [
        resource
        for resource in component_descriptor.component.resources
        if not resource.name == 'job-image-test-2' and not resource.name == 'job-image-test-1'
    ]

    test_resources = list(test_results.find_test_artefacts(
        component=component_descriptor))

    assert len(resources_req_tests) != len(test_resources)
