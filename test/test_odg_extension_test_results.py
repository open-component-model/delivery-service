import pytest

import ocm

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
                        'mediaType': 'application/data',                                                                                                                   'referenceName': None,
                        'type': 'localBlob/v1'
                    },
                    'labels': [
                        {
                            'name': 'gardener.cloud/purposes',
                            'signing': False,
                            'value': ['test'],
                            'version': None
                        }
                    ],
                    'name': 'test-results',
                    'relation': 'local',
                    'type': 'application/gzip',
                    'version': '1.2710.0'
                },
                {
                    'access': {
                        'imageReference': 'foo',
                        'type': 'ociRegistry'
                    },
                    'name': 'job-image',
                    'version': '1.2710.0',
                    'type': 'ociImage',
                },
            ],
            'sources': [],
            'version': '1.2710.0'
        },
    'meta': {
        'schemaVersion': 'v2',
    }
}

    return ocm.ComponentDescriptor.from_dict(raw)

def test_artefact_test_results(
    component_descriptor: ocm.ComponentDescriptor,
):
    import pprint
    pprint.pprint(component_descriptor)
    assert True

    # artefacts_requiring_tests = test_results.foo()
    # artefacts_containing_tests = bar()

    # for artefact in artefacts_requiring_tests:
    #     if has_tests_for(
    #         artefact=artefact,
    #         test_artefacts=artefacts_containing_tests,
    #     ):
    #         print('no finding')
    #     else:
    #         print('finding')