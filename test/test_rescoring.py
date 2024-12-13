import pytest
import dacite

import rescore.model


@pytest.fixture
def cve_rescoring_rules_raw() -> dict:
    return {
        'defaultRuleSetNames': [
            {
                'name': 'my-cve-rescoring',
                'type': 'cve',
            }
        ],
        'rescoringRuleSets': [
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
    cve_rescoring_rules_raw: dict,
):
    cve_rescoring_rule_sets = tuple(
        rescore.model.CveRescoringRuleSet(
            name=cve_rule_set_raw['name'],
            description=cve_rule_set_raw.get('description'),
            rules=list(
                rescore.model.cve_rescoring_rules_from_dicts(cve_rule_set_raw['rules'])
            )
        )
        for cve_rule_set_raw in cve_rescoring_rules_raw['rescoringRuleSets']
    )

    assert isinstance(cve_rescoring_rule_sets[0], rescore.model.CveRescoringRuleSet)

    ruleset = cve_rescoring_rule_sets[0]
    assert len(ruleset.rules) == 3

    rule1, rule2, rule3 = ruleset.rules
    assert rule1.rescore is rescore.model.Rescore.NO_CHANGE
    assert rule2.rescore is rescore.model.Rescore.REDUCE
    assert rule3.rescore is rescore.model.Rescore.NOT_EXPLOITABLE


# deserialization of default rule set names
def test_deserialise_rescoring_rule_sets_default_rule_set_names(
    cve_rescoring_rules_raw: dict,
):
    default_rule_sets = [
        dacite.from_dict(
            data_class=rescore.model.DefaultRuleSet,
            data=item,
            config=dacite.Config(
                cast=[rescore.model.RuleSetType],
            )
        )
        for item in cve_rescoring_rules_raw['defaultRuleSetNames']
    ]

    cve_rescoring_rule_sets = tuple(
        rescore.model.CveRescoringRuleSet(
            name=cve_rule_set_raw['name'],
            description=cve_rule_set_raw.get('description'),
            rules=list(
                rescore.model.cve_rescoring_rules_from_dicts(cve_rule_set_raw['rules'])
            )
        )
        for cve_rule_set_raw in cve_rescoring_rules_raw['rescoringRuleSets']
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
    cve_rescoring_rules_raw: dict
):
    cve_rescoring_rules_raw['rescoringRuleSets'][0]['extra_attribute'] = 'extra_value'

    cve_rescoring_rule_sets = tuple(
        rescore.model.CveRescoringRuleSet(
            name=cve_rule_set_raw['name'],
            description=cve_rule_set_raw.get('description'),
            type=cve_rule_set_raw['type'],
            rules=list(
                rescore.model.cve_rescoring_rules_from_dicts(cve_rule_set_raw['rules'])
            )
        )
        for cve_rule_set_raw in cve_rescoring_rules_raw['rescoringRuleSets']
    )

    assert isinstance(cve_rescoring_rule_sets[0], rescore.model.CveRescoringRuleSet)
    assert len(cve_rescoring_rule_sets[0].rules) == 3
