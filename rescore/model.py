import collections
import collections.abc
import dataclasses
import enum
import typing

import dacite
import yaml

import dso.cvss


class Rescore(enum.Enum):
    REDUCE = 'reduce'
    NOT_EXPLOITABLE = 'not-exploitable'
    NO_CHANGE = 'no-change'


class RuleSetType(enum.StrEnum):
    CVE = 'cve'


@dataclasses.dataclass(frozen=True)
class Rule:
    name: str
    rescore: Rescore


@dataclasses.dataclass(frozen=True)
class CveRescoringRule(Rule):
    '''
    a CVE rescoring rule intended to be used when re-scoring a CVE (see `CVSSV3` type) for an
    artefact that has a `CveCategorisation`.

    category_value is expected of form <CveCategorisation-attrname>:<value> (see CveCategorisation
    for allowed values)
    cve_values is expected as a list of <CVSSV3-attrname>:<value> entries (see CVSSV3 for allowed
    values)
    rescore indicates the rescoring that should be done, if the rule matches.

    A rescoring rule matches iff the artefact's categorisation-value exactly matches the rule's
    category_value attr AND the CVE's values are included in the rule's `cve_values`.

    CVE-Attributes for which a rule does not specify any value are not considered for matching.
    '''
    category_value: str
    cve_values: list[str]

    @property
    def category_attr(self):
        return self.category_value.split(':')[0]

    @property
    def category_type(self):
        attr = self.category_attr
        annotations = typing.get_type_hints(dso.cvss.CveCategorisation)

        if not attr in annotations:
            raise ValueError(f'invalid category-name: {attr=}')

        attr = annotations[attr]
        if typing.get_origin(attr) == typing.Union:
            args = [a for a in typing.get_args(attr) if not isinstance(None, a)]
            if len(args) != 1:
                # indicate programming error (CveCategorisation attrs must either be
                # simple types, or optionals.
                raise ValueError(f'only typing.Optional | Union with None is allowed {args=}')

            return args[0]

        return annotations[attr]

    @property
    def parsed_category_value(self):
        category_type = self.category_type
        value = self.category_value.split(':', 1)[-1]

        # special-case for bool
        if category_type == bool:
            parsed = yaml.safe_load(value)
            if not isinstance(parsed, bool):
                raise ValueError(f'failed to parse {value=} into boolean (using yaml.parsing)')
            return parsed

        return category_type(value)

    @property
    def parsed_cve_values(self) -> dict[str, set[object]]:
        attr_values = collections.defaultdict(set)

        for cve_value in self.cve_values:
            attr, value = cve_value.split(':', 1)
            attr = dso.cvss.CVSSV3.attr_name_from_CVSS(attr)

            if not attr in (annotations := typing.get_type_hints(dso.cvss.CVSSV3)):
                raise ValueError(f'{attr=} is not an allowed cve-attrname')

            attr_type = annotations[attr]
            attr_values[attr].add(attr_type(value))

        return attr_values

    def matches_cvss(self, cvss: dso.cvss.CVSSV3 | dict) -> bool:
        '''
        returns a boolean indicating whether this rule matches the given CVSS.

        Only CVSS-Attributes that are specified by this rule w/ at least one value are checked.
        If more than one value for the same attribute is specified, matching will be assumed if
        the given CVSS's attr-value is contained in the rule's values.
        '''
        cve_values = self.parsed_cve_values
        if not type(cvss) is dict:
            cvss = dataclasses.asdict(cvss)
        for attr, value in cvss.items():
            if not attr in cve_values:
                continue

            # if cvss is of type dict, the values have to be compared to the values of the enums
            if not value in [
                v if isinstance(value, enum.Enum) else v.value
                for v in cve_values[attr]
            ]:
                return False

        return True

    def matches_categorisation(self, categorisation: dso.cvss.CveCategorisation) -> bool:
        attr = self.category_attr
        value = self.parsed_category_value

        return value == getattr(categorisation, attr)


@dataclasses.dataclass
class RuleSet[T: Rule]:
    name: str
    rules: list[T]
    type: RuleSetType
    description: str | None = None


@dataclasses.dataclass
class CveRescoringRuleSet(RuleSet[CveRescoringRule]):
    type: RuleSetType = RuleSetType.CVE


@dataclasses.dataclass(frozen=True)
class DefaultRuleSet:
    name: str
    type: RuleSetType


def find_default_rule_set_for_type_and_name(
    default_rule_set: DefaultRuleSet,
    rule_sets: tuple[RuleSet],
) -> RuleSet:
    for ruleset in rule_sets:
        if (
            ruleset.name == default_rule_set.name
            and ruleset.type is default_rule_set.type
        ):
            return ruleset

    raise ValueError(f'No default rule_set found for the {ruleset.type}.')


def find_default_rule_set_for_type(
    default_rule_sets: list[DefaultRuleSet],
    rule_set_type: RuleSetType,
) -> DefaultRuleSet:
    for default_rule_set in default_rule_sets:
        if default_rule_set.type is rule_set_type:
            return default_rule_set

    raise ValueError(f'No default rule_set_name found for {default_rule_set.type}.')


def cve_rescoring_rules_from_dicts(
    rules: list[dict]
) -> typing.Generator[CveRescoringRule, None, None]:
    '''
    deserialises cve_rescoring rules. Each dict is expected to have the following form:

    category_value: <CveCategorisation-attr>:<value>
    name: <str> (optional)
    rules:
      - cve_values:
        - <CVSSV3-attr>: <value>
        rescore: <Rescore>
    '''
    for rule in rules:
        category_value = rule['category_value']
        name = rule.get('name')

        for subrule in rule['rules']:
            cve_values = subrule['cve_values']
            rescore = subrule['rescore']

            yield dacite.from_dict(
                data_class=CveRescoringRule,
                data={
                    'category_value': category_value,
                    'cve_values': cve_values,
                    'rescore': rescore,
                    'name': name,
                },
                config=dacite.Config(
                    cast=(enum.Enum, tuple),
                )
            )
