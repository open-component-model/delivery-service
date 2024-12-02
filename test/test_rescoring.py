import pytest
import dacite
import datetime

import dso.model
import github.compliance.model
import rescore.model
import rescore.utility


@pytest.fixture
def rescoring_rules_raw() -> dict:
    return {
        'defaultRuleSetNames': [
            {
                'name': 'my-sast-rescoring',
                'type': 'sast',
            },
            {
                'name': 'my-cve-rescoring',
                'type': 'cve',
            },
        ],
        'rescoringRuleSets': [
            {
                'name': 'my-sast-rescoring',
                'type': 'sast',
                'rules': [
                    {
                        'name': 'public-no-linting',
                        'component_context': 'public',
                        'sast_status': 'no-linting',
                        'rescore': 'blocker'
                    },
                    {
                        'name': 'internal-local-linting',
                        'component_context': 'internal',
                        'sast_status': 'local-linting',
                        'rescore': 'to-none'
                    },
                    {
                        'name': 'internal-central-linting',
                        'component_context': 'internal',
                        'sast_status': 'central-linting',
                        'rescore': 'to-none'
                    },
                ],
            },
            {
                'name': 'my-cve-rescoring',
                'type': 'cve',
                'rules': [
                    {
                        'category_value': 'network_exposure:public',
                        'name': 'network-exposure-public',
                        'rules': [
                            {
                                'cve_values': ['AV:N'],
                                'rescore': 'no-change'
                            },
                            {
                                'cve_values': ['AV:A'],
                                'rescore': 'reduce'
                            },
                            {
                                'cve_values': ['AV:L', 'AV:P'],
                                'rescore': 'not-exploitable'
                            },
                        ]
                    }
                ],
            }
        ]
    }


def test_deserialise_rescoring_rule_sets(
    rescoring_rules_raw: dict,
):
    cve_rescoring_rule_sets = tuple(
        rescore.model.CveRescoringRuleSet(
            name=cve_rule_set_raw['name'],
            description=cve_rule_set_raw.get('description'),
            rules=list(
                rescore.model.cve_rescoring_rules_from_dicts(cve_rule_set_raw['rules'])
            )
        )
        for cve_rule_set_raw in rescoring_rules_raw['rescoringRuleSets']
        if cve_rule_set_raw['type'] == rescore.model.RuleSetType.CVE
    )

    assert isinstance(cve_rescoring_rule_sets[0], rescore.model.CveRescoringRuleSet)

    ruleset = cve_rescoring_rule_sets[0]
    assert len(ruleset.rules) == 3

    rule1, rule2, rule3 = ruleset.rules
    assert rule1.rescore is rescore.model.Rescore.NO_CHANGE
    assert rule2.rescore is rescore.model.Rescore.REDUCE
    assert rule3.rescore is rescore.model.Rescore.NOT_EXPLOITABLE


def test_deserialise_rescoring_rule_sets_default_rule_set_names(
    rescoring_rules_raw: dict,
):
    default_rule_sets = [
        dacite.from_dict(
            data_class=rescore.model.DefaultRuleSet,
            data=default_ruleset,
            config=dacite.Config(
                cast=[rescore.model.RuleSetType],
            )
        )
        for default_ruleset in rescoring_rules_raw['defaultRuleSetNames']
        if default_ruleset['type'] == rescore.model.RuleSetType.CVE
    ]

    cve_rescoring_rule_sets = tuple(
        rescore.model.CveRescoringRuleSet(
            name=cve_rule_set_raw['name'],
            description=cve_rule_set_raw.get('description'),
            rules=list(
                rescore.model.cve_rescoring_rules_from_dicts(cve_rule_set_raw['rules'])
            )
        )
        for cve_rule_set_raw in rescoring_rules_raw['rescoringRuleSets']
        if cve_rule_set_raw['type'] == rescore.model.RuleSetType.CVE
    )

    default_rule_set = rescore.model.find_default_rule_set_for_type_and_name(
        default_rule_set=rescore.model.find_default_rule_set_for_type(
            default_rule_sets=default_rule_sets,
            rule_set_type=rescore.model.RuleSetType.CVE,
        ),
        rule_sets=cve_rescoring_rule_sets,
    )

    assert default_rule_set is not None
    assert default_rule_set.name == "my-cve-rescoring"
    assert default_rule_set.type == rescore.model.RuleSetType.CVE


# deserialization with extra attributes
def test_deserialise_with_extra_attributes(
    rescoring_rules_raw: dict
):
    rescoring_rules_raw['rescoringRuleSets'][0]['extra_attribute'] = 'extra_value'

    cve_rescoring_rule_sets = tuple(
        rescore.model.CveRescoringRuleSet(
            name=cve_rule_set_raw['name'],
            description=cve_rule_set_raw.get('description'),
            type=cve_rule_set_raw['type'],
            rules=list(
                rescore.model.cve_rescoring_rules_from_dicts(cve_rule_set_raw['rules'])
            )
        )
        for cve_rule_set_raw in rescoring_rules_raw['rescoringRuleSets']
        if cve_rule_set_raw['type'] == rescore.model.RuleSetType.CVE
    )

    assert isinstance(cve_rescoring_rule_sets[0], rescore.model.CveRescoringRuleSet)
    assert len(cve_rescoring_rule_sets[0].rules) == 3


def test_deserialise_sast_rescoring_rule_sets(
    rescoring_rules_raw: dict,
):
    sast_rescoring_rule_sets = tuple(
        rescore.model.SastRescoringRuleSet(
            name=sast_rule_set_raw['name'],
            description=sast_rule_set_raw.get('description'),
            rules=list(
                rescore.model.sast_rescoring_rules_from_dict(sast_rule_set_raw['rules'])
            )
        )
        for sast_rule_set_raw in rescoring_rules_raw['rescoringRuleSets']
        if sast_rule_set_raw['type'] == rescore.model.RuleSetType.SAST
    )

    assert isinstance(sast_rescoring_rule_sets[0], rescore.model.SastRescoringRuleSet)

    ruleset = sast_rescoring_rule_sets[0]
    assert len(ruleset.rules) == 3

    rule1, rule2, rule3 = ruleset.rules
    assert rule1.rescore is rescore.model.Rescore.BLOCKER
    assert rule2.rescore is rescore.model.Rescore.TO_NONE
    assert rule3.rescore is rescore.model.Rescore.TO_NONE


def test_deserialise_sast_rescoring_rule_sets_default_rule_set_names(
    rescoring_rules_raw: dict,
):
    default_rule_sets = [
        dacite.from_dict(
            data_class=rescore.model.DefaultRuleSet,
            data=default_ruleset,
            config=dacite.Config(
                cast=[rescore.model.RuleSetType],
            )
        )
        for default_ruleset in rescoring_rules_raw['defaultRuleSetNames']
        if default_ruleset['type'] == rescore.model.RuleSetType.SAST
    ]

    sast_rescoring_rule_sets = tuple(
        rescore.model.SastRescoringRuleSet(
            name=sast_rule_set_raw['name'],
            description=sast_rule_set_raw.get('description'),
            rules=list(
                rescore.model.sast_rescoring_rules_from_dict(sast_rule_set_raw['rules'])
            )
        )
        for sast_rule_set_raw in rescoring_rules_raw['rescoringRuleSets']
        if sast_rule_set_raw['type'] == rescore.model.RuleSetType.SAST
    )

    default_rule_set = rescore.model.find_default_rule_set_for_type_and_name(
        default_rule_set=rescore.model.find_default_rule_set_for_type(
            default_rule_sets=default_rule_sets,
            rule_set_type=rescore.model.RuleSetType.SAST,
        ),
        rule_sets=sast_rescoring_rule_sets,
    )

    assert default_rule_set is not None
    assert default_rule_set.name == "my-sast-rescoring"
    assert default_rule_set.type == rescore.model.RuleSetType.SAST


@pytest.fixture
def sast_finding_public():
    return dso.model.ArtefactMetadata(
        artefact=dso.model.ComponentArtefactId(
            component_name='public-component',
            component_version='1.0.0',
            artefact=dso.model.LocalArtefactId(
                artefact_name=None,
                artefact_type=None,
            )
        ),
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.CM06,
            type=dso.model.Datatype.SAST_FINDING,
            creation_date=datetime.datetime.now(),
            last_update=datetime.datetime.now(),
        ),
        data=dso.model.SastFinding(
            component_context=dso.model.ComponentContext.INTERNAL.value,
            sast_statuses=rescore.model.SastStatus.CENTRAL_LINTING.value,
            severity=github.compliance.model.Severity.BLOCKER.value,
        )
    )


@pytest.fixture
def sast_finding_internal():
    return dso.model.ArtefactMetadata(
        artefact=dso.model.ComponentArtefactId(
            component_name='internal-component',
            component_version='1.0.0',
            artefact=dso.model.LocalArtefactId(
                artefact_name=None,
                artefact_type=None,
            )
        ),
        meta=dso.model.Metadata(
            datasource=dso.model.Datasource.CM06,
            type=dso.model.Datatype.SAST_FINDING,
            creation_date=datetime.datetime.now(),
            last_update=datetime.datetime.now(),
        ),
        data=dso.model.SastFinding(
            component_context=dso.model.ComponentContext.INTERNAL.value,
            sast_statuses=rescore.model.SastStatus.CENTRAL_LINTING.value,
            severity=github.compliance.model.Severity.BLOCKER.value,
        )
    )


def test_generate_sast_rescorings(
    rescoring_rules_raw: dict,
    sast_finding_public: dso.model.ArtefactMetadata,
):
    sast_rescoring_rule_sets = tuple(
        rescore.model.SastRescoringRuleSet(
            name=sast_rule_set_raw['name'],
            description=sast_rule_set_raw.get('description'),
            rules=list(
                rescore.model.sast_rescoring_rules_from_dict(sast_rule_set_raw['rules'])
            )
        )
        for sast_rule_set_raw in rescoring_rules_raw['rescoringRuleSets']
        if sast_rule_set_raw['type'] == rescore.model.RuleSetType.SAST
    )
    sast_rescoring_ruleset = sast_rescoring_rule_sets[0]

    # Convert the generator to a list for testing
    rescored_metadata = list(rescore.utility.generate_sast_rescorings(
        findings=[sast_finding_public],
        sast_rescoring_ruleset=sast_rescoring_ruleset,
        user=dso.model.User(
            username="test_user",
        ),
    ))

    rescored_intern = rescored_metadata[0]
    assert isinstance(rescored_intern.data, dso.model.CustomRescoring)
    assert rescored_intern.data.matching_rules == ['internal-central-linting']
    assert rescored_intern.data.user.username == 'test_user'
    assert rescored_intern.data.comment == 'Automatically rescored based on rules.'
    assert (
        rescored_intern.data.finding.component_context is dso.model.ComponentContext.INTERNAL.value
    )
    assert (
        rescored_intern.data.finding.sast_statuses is rescore.model.SastStatus.CENTRAL_LINTING.value
    )
