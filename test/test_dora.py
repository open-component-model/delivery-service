import os

import cnudie.util
import ocm

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


def test_dependency_changes_between_versions():
    component_diff = cnudie.util.ComponentDiff(
        cidentities_only_left=(),
        cidentities_only_right=(),
        cpairs_version_changed=(
            (ocm.ComponentIdentity('c1', '1.0.0'), ocm.ComponentIdentity('c1', '2.0.0')),
            (ocm.ComponentIdentity('c2', '1.0.0'), ocm.ComponentIdentity('c2', '2.0.0')),
            (ocm.ComponentIdentity('c3', '1.0.0'), ocm.ComponentIdentity('c3', '2.0.0')),
            (ocm.ComponentIdentity('c4', '1.0.0'), ocm.ComponentIdentity('c4', '1.0.0')), # no change
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
