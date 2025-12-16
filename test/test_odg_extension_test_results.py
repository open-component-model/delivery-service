import os
import pytest
import dacite
import enum
import ocm
import odg.model
import odg.findings
import test_results


@pytest.fixture
def component_descriptor() -> ocm.ComponentDescriptor:
    raw = {
        'component': {
            'componentReferences': [],
            'creationTime': '2025-10-07T09:15:29Z',
            'labels': [],
            'name': 'this/is/my/component',
            'provider': 'Any',
            'repositoryContexts': [
                {
                    'baseUrl': 'foo',
                    'subPath': None,
                    'type': 'ociRegistry'
                }
            ],
            'resources': [
                {
                    'access': {
                        'localReference': 'foo',
                        'mediaType': 'application/data',
                        'referenceName': None,
                        'type': 'localBlob/v1'
                    },
                    'labels': [
                        {
                            'name': 'gardener.cloud/test-policy',
                            'value': False
                        },
                        {
                            'name': 'gardener.cloud/purposes',
                            'signing': False,
                            'value': ['test'],
                            'version': None
                        },
                        {
                            'name': 'gardener.cloud/test-scope',
                            'value': ['job-image-1', 'job-image-2', 'job-image-4']
                        }
                    ],
                    'name': 'job-image-test-1',
                    'relation': 'local',
                    'type': 'application/gzip',
                    'version': '1.2710.0'
                },
                {
                    'access': {
                        'localReference': 'bar',
                        'mediaType': 'application/data',
                        'referenceName': None,
                        'type': 'localBlob/v1'
                    },
                    'labels': [
                        {
                            'name': 'gardener.cloud/test-policy',
                            'value': False
                        },
                        {
                            'name': 'gardener.cloud/purposes',
                            'signing': False,
                            'value': ['test'],
                            'version': None
                        },
                        {
                            'name': 'gardener.cloud/test-scope',
                            'value': ['job-image-2']
                        }
                    ],
                    'name': 'job-image-test-2',
                    'relation': 'local',
                    'type': 'application/gzip',
                    'version': '1.2710.0'
                },
                {
                    'access': {
                        'imageReference': 'foo',
                        'type': 'ociRegistry'
                    },
                    'labels': [
                        {
                         'name': 'gardener.cloud/test-policy',
                         'value': True
                        }
                    ],
                    'name': 'job-image-1',
                    'relation': 'local',
                    'version': '1.2710.0',
                    'type': 'ociImage'
                },
                {
                    'access': {
                        'imageReference': 'bar',
                        'type': 'ociRegistry'
                    },
                    'labels': [
                        {
                         'name': 'gardener.cloud/test-policy',
                         'value': True
                        }
                    ],
                    'name': 'job-image-2',
                    'relation': 'local',
                    'version': '1.2710.0',
                    'type': 'ociImage'
                },
                {
                    'access': {
                        'imageReference': 'bar',
                        'type': 'ociRegistry'
                    },
                    'labels': [
                        {
                         'name': 'gardener.cloud/test-policy',
                         'value': False
                        }
                    ],
                    'name': 'job-image-3',
                    'relation': 'external',
                    'version': '1.2710.0',
                    'type': 'helmChart/v1'
                },
            ],
            'sources': [],
            'version': '1.2710.0'
        },
    'meta': {
        'schemaVersion': 'v2',
    }
}
    return dacite.from_dict(
        data=raw,
        data_class=ocm.ComponentDescriptor,
        config=dacite.Config(
            cast=[enum.Enum]
        )
    )


@pytest.fixture
def missing_test_result_finding_cfg() -> odg.findings.Finding:
    selector = odg.findings.TestResultFindingSelector(status=['.*'])

    categorisations = [
        odg.findings.FindingCategorisation(
            id='NONE',
            display_name='test exists and has no findings',
            value=0,
            allowed_processing_time=0,
            rescoring=None,
            selector=None,
        ),
        odg.findings.FindingCategorisation(
            id='BLOCKER',
            display_name='Test result is missing',
            value=16,
            allowed_processing_time=0,
            rescoring=None,
            selector=selector,
        ),
    ]

    return odg.findings.Finding(
        type=odg.model.Datatype.TEST_RESULT_FINDING,
        categorisations=categorisations,
        filter=None,
        rescoring_ruleset=None
    )


def test_artefact_test_results_filter(
    component_descriptor: ocm.ComponentDescriptor,
    missing_test_result_finding_cfg: odg.findings.Finding
):

    resources_req_tests = test_results.iter_artefacts_requiring_tests(
        component=component_descriptor)

    test_resources = test_results.find_test_artefacts(
        component=component_descriptor)

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

    assert test_coverage == None

# let's remove the test results
    component_descriptor.component.resources = [
        resource
        for resource in component_descriptor.component.resources
        if not resource.name == 'job-image-test-2' and not resource.name == 'job-image-test-1'
    ]

    test_resources = test_results.find_test_artefacts(
        component=component_descriptor)

    assert len(resources_req_tests) != len(test_resources)
