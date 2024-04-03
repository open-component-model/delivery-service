import os

import pytest

import cnudie.util
import gci.componentmodel as cm

import dora
import test.resources.lookup_mocks as lookup_mocks

own_dir = os.path.dirname(__file__)
res_dir = os.path.join(own_dir, 'resources')

component_descriptors_file = os.path.join(
    res_dir,
    'component_descriptors_dependency_updates_in_time_span.yaml',
)


component_descriptor_lookup_mockup = lookup_mocks.component_descriptor_lookup_mockup_factory(
    component_descriptors_file,
)

versions_lookup_mockup = lookup_mocks.versions_lookup_mockup_factory(
    component_descriptors_file,
)


def test_get_next_older_descriptor():

    next_older_descriptor = dora.get_next_older_descriptor(
        cm.ComponentIdentity(
            "TestComponent_1",
            "v2.0.0",
        ),
        component_descriptor_lookup_mockup,
        versions_lookup_mockup,
    )

    assert next_older_descriptor.component.identity() == cm.ComponentIdentity(
        'TestComponent_1',
        'v1.0.0',
    )

    # if there is no older version
    next_older_descriptor = dora.get_next_older_descriptor(
        cm.ComponentIdentity(
            name="TestComponent_1",
            version="v1.0.0",
        ),
        component_descriptor_lookup_mockup,
        versions_lookup_mockup,
    )
    assert next_older_descriptor is None

    # if there input version does not exist
    with pytest.raises(ValueError):
        dora.get_next_older_descriptor(
            cm.ComponentIdentity(
                "TestComponent_1",
                "v1.0942.0",
            ),
            component_descriptor_lookup_mockup,
            versions_lookup_mockup,
        )


def test_dependency_changes_between_versions():
    component_diff = cnudie.util.ComponentDiff(
        cidentities_only_left=(),
        cidentities_only_right=(),
        cpairs_version_changed=(
            (cm.ComponentIdentity('c1', '1.0.0'), cm.ComponentIdentity('c1', '2.0.0')),
            (cm.ComponentIdentity('c2', '1.0.0'), cm.ComponentIdentity('c2', '2.0.0')),
            (cm.ComponentIdentity('c3', '1.0.0'), cm.ComponentIdentity('c3', '2.0.0')),
            (cm.ComponentIdentity('c4', '1.0.0'), cm.ComponentIdentity('c4', '1.0.0')), # no change
        ),
    )

    # without dependency Filter
    dependency_changes = dora.dependency_changes_between_versions(
        component_diff=component_diff,
    )
    assert len(dependency_changes) == 3 # three out of fource cversions changed

    # with dependency Filter -> specified dependency did not change
    dependency_changes = dora.dependency_changes_between_versions(
        component_diff=component_diff,
        dependency_name_filter=['c4'],
    )
    assert len(dependency_changes) == 0

    # with dependency Filter -> specifiied dependency did change
    dependency_changes = dora.dependency_changes_between_versions(
        component_diff=component_diff,
        dependency_name_filter=['c3'],
    )
    assert len(dependency_changes) == 1
