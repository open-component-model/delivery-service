import datetime
import json
import os
import unittest.mock

import pytest

import odg.extensions_cfg
import odg.model
from sla_violations import (
    iter_version_sla_violations,
    iter_versions_for_component,
)


@pytest.fixture
def test_data():
    data_path = os.path.join(
        os.path.dirname(__file__),
        'resources',
        'sla_violations_test_data.json',
    )
    with open(data_path) as f:
        return json.load(f)


def test_no_violation_when_deadline_after_release(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_90d'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_violation_when_deadline_before_release(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[],
            release_date=release_date,
        ),
    )

    assert len(violations) == 1


def test_violation_when_rescoring_happens_after_deadline(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_after_deadline'])
    release_date = datetime.datetime(2025, 4, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring],
            release_date=release_date,
        ),
    )

    assert len(violations) == 1


def test_rescoring_filtered_out_when_created_after_release(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_after_deadline'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring],
            release_date=release_date,
        ),
    )

    assert len(violations) == 1


def test_no_violation_when_rescoring_removes_deadline(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_removes_deadline'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_no_violation_when_rescoring_extends_deadline(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_extends_deadline'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_violation_when_rescoring_extends_deadline_not_enough(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_extends_deadline'])
    release_date = datetime.datetime(2025, 8, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring],
            release_date=release_date,
        ),
    )

    assert len(violations) == 1


def test_no_violation_when_rescoring_sets_due_date(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_sets_due_date'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_violation_when_rescoring_due_date_before_release(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_sets_due_date'])
    release_date = datetime.datetime(2025, 8, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring],
            release_date=release_date,
        ),
    )

    assert len(violations) == 1


def test_finding_skipped_when_created_after_release(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    release_date = datetime.datetime(2024, 12, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_finding_not_skipped_when_created_at_release_date(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    release_date = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_no_violation_when_deadline_equals_release_date(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    release_date = datetime.datetime(2025, 1, 31, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_raises_error_when_finding_has_no_discovery_date(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_no_discovery_date'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    with pytest.raises(ValueError):
        list(
            iter_version_sla_violations(
                findings=[finding],
                rescorings=[],
                release_date=release_date,
            ),
        )


def test_finding_skipped_when_no_allowed_processing_time(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_no_allowed_processing_time'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_multiple_findings_only_violating_one_reported(test_data):
    finding_90d = odg.model.ArtefactMetadata.from_dict(test_data['finding_90d'])
    finding_30d = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding_90d, finding_30d],
            rescorings=[],
            release_date=release_date,
        ),
    )

    assert len(violations) == 1
    assert violations[0].finding.cve == 'CVE-2025-0002'


def test_multiple_rescorings_last_removes_deadline(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring_extends = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_extends_deadline'])
    rescoring_removes = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_removes_deadline'])
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring_extends, rescoring_removes],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_multiple_rescorings_last_restores_deadline(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring_removes = odg.model.ArtefactMetadata.from_dict(test_data['rescoring_removes_deadline'])
    rescoring_restores = odg.model.ArtefactMetadata.from_dict(
        test_data['rescoring_restores_deadline_30d'],
    )
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring_removes, rescoring_restores],
            release_date=release_date,
        ),
    )

    assert len(violations) == 1


def test_due_date_takes_priority_over_allowed_processing_time(test_data):
    finding = odg.model.ArtefactMetadata.from_dict(test_data['finding_30d'])
    rescoring = odg.model.ArtefactMetadata.from_dict(
        test_data['rescoring_due_date_and_allowed_time'],
    )
    release_date = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)

    violations = list(
        iter_version_sla_violations(
            findings=[finding],
            rescorings=[rescoring],
            release_date=release_date,
        ),
    )

    assert len(violations) == 0


def test_iter_versions_returns_resolved_version_when_set():
    component = odg.extensions_cfg.Component(
        component_name='example.org/foo',
        version='1.2.3',
        ocm_repo_url=None,
    )
    delivery_service_client = unittest.mock.MagicMock()

    versions = list(
        iter_versions_for_component(
            component=component,
            delivery_service_client=delivery_service_client,
        ),
    )

    assert versions == ['1.2.3']
    delivery_service_client.greatest_component_versions.assert_not_called()


def test_iter_versions_queries_greatest_versions_when_no_resolved_version():
    component = odg.extensions_cfg.Component(
        component_name='example.org/foo',
        version=None,
        ocm_repo_url='ocm.example.org/repo',
        max_versions_limit=3,
    )
    delivery_service_client = unittest.mock.MagicMock()
    delivery_service_client.greatest_component_versions.return_value = ['1.0.0', '1.1.0', '1.2.0']

    versions = list(
        iter_versions_for_component(
            component=component,
            delivery_service_client=delivery_service_client,
        ),
    )

    assert versions == ['1.0.0', '1.1.0', '1.2.0']
    delivery_service_client.greatest_component_versions.assert_called_once_with(
        component_name='example.org/foo',
        max_versions=3,
        ocm_repo=component.ocm_repo,
        start_date=None,
        end_date=None,
    )


def test_iter_versions_passes_time_range_dates():
    time_range = odg.extensions_cfg.TimeRange(days_from=-30, days_to=0)
    component = odg.extensions_cfg.Component(
        component_name='example.org/foo',
        version=None,
        ocm_repo_url='ocm.example.org/repo',
        max_versions_limit=5,
        time_range=time_range,
    )
    delivery_service_client = unittest.mock.MagicMock()
    delivery_service_client.greatest_component_versions.return_value = ['2.0.0']

    versions = list(
        iter_versions_for_component(
            component=component,
            delivery_service_client=delivery_service_client,
        ),
    )

    assert versions == ['2.0.0']
    delivery_service_client.greatest_component_versions.assert_called_once_with(
        component_name='example.org/foo',
        max_versions=5,
        ocm_repo=component.ocm_repo,
        start_date=time_range.start_date,
        end_date=time_range.end_date,
    )
