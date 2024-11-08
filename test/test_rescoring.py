import pytest

import rescore.model


@pytest.fixture
def cve_rescoring_rules_raw() -> dict:
    return {
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
            type=cve_rule_set_raw['type'],
            rules=list(
                rescore.model.cve_rescoring_rules_from_dicts(cve_rule_set_raw['rules'])
            )
        )
        for cve_rule_set_raw in cve_rescoring_rules_raw['rescoringRuleSets']
    )
    assert isinstance(cve_rescoring_rule_sets, tuple)
    assert len(cve_rescoring_rule_sets) == 1
    assert isinstance(cve_rescoring_rule_sets[0], rescore.model.CveRescoringRuleSet)
