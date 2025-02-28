import datetime

import pytest

import dso.model

import consts
import odg.findings
import rescore.model
import rescore.utility


@pytest.fixture
def cve_rescoring_ruleset() -> dict:
    return {
        'name': 'my-cve-rescoring',
        'description': 'this is a very good description',
        'operations': {
            'reduce': {
                'order': ['CRITICAL', 'MEDIUM', 'NONE'],
            },
            'not-exploitable': f'{consts.RESCORING_OPERATOR_SET_TO_PREFIX}NONE',
        },
        'rules': [
            {
                'category_value': 'network_exposure:public',
                'name': 'network-exposure-public',
                'rules': [
                    {
                        'cve_values': ['AV:A'],
                        'operation': 'reduce',
                    },
                    {
                        'cve_values': ['AV:L', 'AV:P'],
                        'operation': 'not-exploitable',
                    },
                ]
            }
        ],
    }


@pytest.fixture
def vulnerability_finding_cfg(
    cve_rescoring_ruleset: dict,
) -> odg.findings.Finding:
    return odg.findings.Finding.from_dict(
        findings_raw=[{
            'type': odg.findings.FindingType.VULNERABILITY,
            'categorisations': [{
                'id': 'NONE',
                'display_name': 'NONE display name',
                'value': 0,
            }, {
                'id': 'MEDIUM',
                'display_name': 'MEDIUM display name',
                'value': 2,
                'allowed_processing_time': 90,
                'selector': {
                    'cve_score_range': {
                        'min': 4.0,
                        'max': 6.9,
                    },
                },
            }, {
                'id': 'CRITICAL',
                'display_name': 'CRITICAL display name',
                'value': 8,
                'allowed_processing_time': 30,
                'selector': {
                    'cve_score_range': {
                        'min': 9.0,
                        'max': 10.0,
                    },
                },
            }],
            'rescoring_ruleset': cve_rescoring_ruleset,
        }],
        finding_type=odg.findings.FindingType.VULNERABILITY,
    )


@pytest.fixture
def sast_rescoring_ruleset() -> dict:
    return {
        'name': 'my-sast-rescoring',
        'rules': [
            {
                'name': 'local-linting-is-optional-for-internal-components',
                'match': [{'component_name': 'github.internal/.*'}],
                'sub_types': ['local-linting'],
                'sast_status': 'no-linter',
                'operation': f'{consts.RESCORING_OPERATOR_SET_TO_PREFIX}no-linter-required',
            },
            {
                'name': 'central-linting-is-optional-for-external-components',
                'match': [{'component_name': 'github.com/.*'}],
                'sub_types': ['central-linting'],
                'sast_status': 'no-linter',
                'operation': f'{consts.RESCORING_OPERATOR_SET_TO_PREFIX}no-linter-required',
            },
        ],
    }


@pytest.fixture
def sast_finding_cfg(
    sast_rescoring_ruleset: dict,
) -> odg.findings.Finding:
    return odg.findings.Finding.from_dict(
        findings_raw=[{
            'type': odg.findings.FindingType.SAST,
            'categorisations': [{
                'id': 'no-findings',
                'display_name': 'scan exists and has no findings',
                'value': 0,
                'rescoring': 'manual',
            }, {
                'id': 'no-linter-required',
                'display_name': 'linting is optional for this component',
                'value': 0,
            }, {
                'id': 'missing-scan',
                'display_name': 'missing sast scan',
                'value': 16,
                'allowed_processing_time': 0,
                'rescoring': 'automatic',
                'selector': {
                    'sub_types': ['.*'],
                },
            }],
            'rescoring_ruleset': sast_rescoring_ruleset,
        }],
        finding_type=odg.findings.FindingType.SAST,
    )


def test_deserialise_cve_rescoring_ruleset(
    cve_rescoring_ruleset: dict,
):
    rescoring_ruleset = rescore.model.CveRescoringRuleSet.from_dict(cve_rescoring_ruleset)

    assert len(rescoring_ruleset.rules) == 2

    rule1, rule2 = rescoring_ruleset.rules
    assert rule1.operation == 'reduce'
    assert rule2.operation == 'not-exploitable'


def test_deserialise_sast_rescoring_ruleset(
    sast_rescoring_ruleset: dict,
):
    rescoring_ruleset = rescore.model.SastRescoringRuleSet.from_dict(sast_rescoring_ruleset)

    assert len(rescoring_ruleset.rules) == 2

    rule1, rule2 = rescoring_ruleset.rules
    assert rule1.operation == f'{consts.RESCORING_OPERATOR_SET_TO_PREFIX}no-linter-required'
    assert rule2.operation == f'{consts.RESCORING_OPERATOR_SET_TO_PREFIX}no-linter-required'


def test_deserialise_with_extra_attributes(
    cve_rescoring_ruleset: dict,
    sast_rescoring_ruleset: dict
):
    cve_rescoring_ruleset['extra_attribute'] = 'extra_value'
    sast_rescoring_ruleset['extra_attribute'] = 'extra_value'

    test_deserialise_cve_rescoring_ruleset(cve_rescoring_ruleset)
    test_deserialise_sast_rescoring_ruleset(sast_rescoring_ruleset)


@pytest.fixture
def sast_categorisation(
    sast_finding_cfg: odg.findings.Finding,
) -> odg.findings.FindingCategorisation | None:
    sub_type = dso.model.SastSubType.CENTRAL_LINTING

    return odg.findings.categorise_finding(
        finding_cfg=sast_finding_cfg,
        finding_property=sub_type,
    )


@pytest.fixture
def sast_finding_public(
    sast_categorisation: odg.findings.FindingCategorisation,
) -> dso.model.ArtefactMetadata | None:
    if not sast_categorisation:
        return None

    return dso.model.ArtefactMetadata(
        artefact=dso.model.ComponentArtefactId(
            component_name='github.com/public-component',
            component_version='1.0.0',
            artefact=dso.model.LocalArtefactId(
                artefact_name=None,
                artefact_type=None,
            )
        ),
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.SAST,
            type=odg.findings.FindingType.SAST,
            creation_date=datetime.datetime.now(),
            last_update=datetime.datetime.now(),
        ),
        data=dso.model.SastFinding(
            sub_type=dso.model.SastSubType.CENTRAL_LINTING,
            sast_status=dso.model.SastStatus.NO_LINTER,
            severity=sast_categorisation.id,
        )
    )


def test_generate_sast_rescorings(
    sast_finding_public: dso.model.ArtefactMetadata,
    sast_finding_cfg: odg.findings.Finding,
    sast_categorisation: odg.findings.FindingCategorisation,
):
    rescoring = rescore.utility.rescoring_for_sast_finding(
        finding=sast_finding_public,
        sast_finding_cfg=sast_finding_cfg,
        categorisation=sast_categorisation,
        user=dso.model.User(
            username="test_user",
        ),
        creation_timestamp=datetime.datetime.now(),
    )

    assert isinstance(rescoring.data, dso.model.CustomRescoring)
    assert rescoring.data.matching_rules == [
        'central-linting-is-optional-for-external-components'
    ]
    assert rescoring.data.severity == 'no-linter-required'
