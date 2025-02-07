import dataclasses
import enum
import os
import re
import typing

import dacite
import yaml

import dso.model

import rescore.model as rm


own_dir = os.path.abspath(os.path.dirname(__file__))
defaults_file_path = os.path.join(own_dir, 'defaults.yaml')


class ModelValidationError(ValueError):
    pass


class FindingType(enum.StrEnum):
    CHECKMARX = 'codechecks/aggregated'
    DIKI = 'finding/diki'
    LICENSE = 'finding/license'
    MALWARE = 'finding/malware'
    OS_IDS = 'os_ids'
    SAST = 'finding/sast'
    VULNERABILITY = 'finding/vulnerability'


@dataclasses.dataclass
class MinMaxRange:
    min: float
    max: float


@dataclasses.dataclass
class LicenseFindingSelector:
    '''
    :param list[str] license_names:
        List of regexes to determine matching licenses.
    '''
    license_names: list[str]


@dataclasses.dataclass
class MalwareFindingSelector:
    '''
    :param list[str] malware_names:
        List of regexes to determine matching malware.
    '''
    malware_names: list[str]


@dataclasses.dataclass
class SASTFindingSelector:
    '''
    :param list[str] sub_types:
        List of regexes to determine matching missing linter findings.
    '''
    sub_types: list[str]


@dataclasses.dataclass
class VulnerabilityFindingSelector:
    '''
    :param MinMaxRange cve_score_range:
        Min (including) and max (including) cve score to determine matching CVEs.
    '''
    cve_score_range: MinMaxRange


@dataclasses.dataclass
class FindingCategorisation:
    '''
    :param str id:
        Stable identifier for the category (must not change as it will be written into findings as
        well).
    :param str display_name:
        Human-friendly name of the category (will be displayed to the user).
    :param int value:
        Finding type independent scala to determine the actual severity of the category, e.g. to
        be able to sort by severity or to determine appropriate colours. Only values between 0 and
        100 are allowed. Note: There must be exactly one category per finding which defines value as
        0 to express that a finding is not relevant anymore.
    :param int allowed_processing_time:
        The days after which a finding must have been assessed at the latest.
    :param Selector selector:
        Used to determine findings which should be assigned to this category.
    :param bool automatic_rescoring:
        If set and a rescoring ruleset is available, findings of this category are automatically
        rescored according to the configured ruleset.
    '''
    id: str
    display_name: str
    value: int
    allowed_processing_time: int | None
    selector: (
        LicenseFindingSelector
        | MalwareFindingSelector
        | SASTFindingSelector
        | VulnerabilityFindingSelector
        | None
    )
    automatic_rescoring: bool = False


@dataclasses.dataclass
class FindingIssues:
    '''
    :param str template:
        Template to use for the created GitHub issues. See `issue_replicator.github` for available
        substitues.
    :param bool enable_issues:
        If disabled, no GitHub issues will be created/updated for the specified finding type.
    :param bool enable_assignees:
        If set, determined responsibles will be automatically assigned to their respective issues.
    :param bool enable_per_finding:
        If set, GitHub issues will be created per finding for a specific artefact as opposed to a
        single issue with all findings.
    '''
    template: str = '{summary}'
    enable_issues: bool = True
    enable_assignees: bool = True
    enable_per_finding: bool = False


class FindingFilterSemantics(enum.StrEnum):
    INCLUDE = 'include'
    EXCLUDE = 'exclude'


@dataclasses.dataclass
class FindingFilter:
    '''
    The filter can be used to stop detection of the specified findings for certain components. If
    only "include" filters are configured, all other components will be ignored. If only "exclude"
    filters are configured, all other components will be considered. If a combination of "include"
    and "exclude" filters is configured, all included components which are not specifically excluded
    as well will be considered.

    Note: All properties, except `artefact_kind` and `artefact_extra_id`, will be compared as
    regexes. The `name` parameter is only used for informational purposes, such as logging.
    '''
    semantics: FindingFilterSemantics
    name: str | None
    component_name: list[str] | str | None
    component_version: list[str] | str | None
    artefact_kind: list[dso.model.ArtefactKind] | dso.model.ArtefactKind | None
    artefact_name: list[str] | str | None
    artefact_version: list[str] | str | None
    artefact_type: list[str] | str | None
    artefact_extra_id: list[dict] | dict | None

    def __post_init__(self):
        if isinstance(self.component_name, str):
            self.component_name = [self.component_name]
        if isinstance(self.component_version, str):
            self.component_version = [self.component_version]
        if isinstance(self.artefact_kind, dso.model.ArtefactKind):
            self.artefact_kind = [self.artefact_kind]
        if isinstance(self.artefact_name, str):
            self.artefact_name = [self.artefact_name]
        if isinstance(self.artefact_version, str):
            self.artefact_version = [self.artefact_version]
        if isinstance(self.artefact_type, str):
            self.artefact_type = [self.artefact_type]
        if isinstance(self.artefact_extra_id, dict):
            self.artefact_extra_id = [self.artefact_extra_id]

        self.artefact_extra_id = [
            dso.model.normalise_artefact_extra_id(artefact_extra_id)
            for artefact_extra_id in self.artefact_extra_id or []
        ]

    def matches(self, artefact: dso.model.ComponentArtefactId) -> bool:
        def match_regexes(patterns: list[str], string: str) -> bool:
            if not patterns:
                return True
            if not string:
                # considering the case there is only an "exclude" filter, then artefacts whose
                # property is empty should not be filtered-out although the pattern would match;
                # in contrast, when there is an "include" filter, then artefacts whose property is
                # empty should also be included
                return self.semantics is FindingFilterSemantics.INCLUDE
            return any(re.fullmatch(pattern, string, re.IGNORECASE) for pattern in patterns)

        if not match_regexes(self.component_name, artefact.component_name):
            return False
        if not match_regexes(self.component_version, artefact.component_version):
            return False
        if self.artefact_kind and artefact.artefact_kind not in self.artefact_kind:
            return False
        if not match_regexes(self.artefact_name, artefact.artefact.artefact_name):
            return False
        if not match_regexes(self.artefact_version, artefact.artefact.artefact_version):
            return False
        if not match_regexes(self.artefact_type, artefact.artefact.artefact_type):
            return False
        if (
            self.artefact_extra_id
            and artefact.artefact.normalised_artefact_extra_id not in self.artefact_extra_id
        ):
            return False

        return True


@dataclasses.dataclass
class Finding:
    '''
    :param FindingType type
    :param list[FindingCategorisation] categorisation:
        The available categories for this type of findings and information on how to assign the
        findings to one of these categories. If a string is given, the corresponding standard
        categorisations are automatically set after instantiation of this class.
    :param list[FindingFilter] filter:
        An optional filter to restrict detection of findings to certain artefacts.
    :param RuleSet ruleset:
        Based on the finding type, there might be a ruleset available to automatically suggest/do
        rescorings. If a string is given, the corresponding standard ruleset is automatically set
        after instantiation of this class.
    :param FindingIssues issues:
        Configuration whether and if yes, how, GitHub tracking issues should be created/updated.
    '''
    type: FindingType
    categorisations: list[FindingCategorisation] | str
    filter: list[FindingFilter] | None
    rescoring_ruleset: dict | str | None
    issues: FindingIssues = dataclasses.field(default_factory=FindingIssues)

    @staticmethod
    def from_dict(
        findings_raw: list[dict],
        finding_type: FindingType | None=None,
    ) -> list[typing.Self] | typing.Self | None:
        if not finding_type:
            return [
                dacite.from_dict(
                    data_class=Finding,
                    data=finding_raw,
                    config=dacite.Config(
                        cast=[enum.Enum],
                    ),
                ) for finding_raw in findings_raw
            ]

        for finding_raw in findings_raw:
            if FindingType(finding_raw['type']) is finding_type:
                break
        else:
            return None

        return dacite.from_dict(
            data_class=Finding,
            data=finding_raw,
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        )

    @staticmethod
    def from_file(
        path: str,
        finding_type: FindingType | None=None,
    ) -> list[typing.Self] | typing.Self | None:
        with open(path) as file:
            findings_raw = yaml.safe_load(file) or []

        return Finding.from_dict(
            findings_raw=findings_raw,
            finding_type=finding_type,
        )

    def __post_init__(self):
        if isinstance(self.categorisations, str):
            self.categorisations = default_finding_categorisations(
                finding_type=self.type,
                name=self.categorisations,
            )

        if isinstance(self.rescoring_ruleset, str):
            self.rescoring_ruleset = default_rescoring_ruleset(
                finding_type=self.type,
                name=self.rescoring_ruleset,
            )

        if isinstance(self.rescoring_ruleset, dict):
            if self.type is FindingType.SAST:
                self.rescoring_ruleset = rm.SastRescoringRuleSet( # noqa: E1123
                    name=self.rescoring_ruleset['name'],
                    rules=list(
                        rm.sast_rescoring_rules_from_dict(self.rescoring_ruleset['rules'])
                    ),
                    description=self.rescoring_ruleset.get('description'),
                )

            elif self.type is FindingType.VULNERABILITY:
                self.rescoring_ruleset = rm.CveRescoringRuleSet( # noqa: E1123
                    name=self.rescoring_ruleset['name'],
                    rules=list(
                        rm.cve_rescoring_rules_from_dicts(self.rescoring_ruleset['rules'])
                    ),
                    description=self.rescoring_ruleset.get('description'),
                )

        self._validate()

    def _validate(self):
        match self.type:
            case FindingType.DIKI:
                self._validate_diki()
            case FindingType.LICENSE:
                self._validate_license()
            case FindingType.MALWARE:
                self._validate_malware()
            case FindingType.SAST:
                self._validate_sast()
            case FindingType.VULNERABILITY:
                self._validate_vulnerabilty()
            case _:
                pass

    def _validate_diki(self):
        violations = []

        for categorisation in self.categorisations:
            if categorisation.selector:
                violations.append(
                    'selectors are not supported by diki, the diki extension takes care of '
                    'categorisation itself'
                )

        if not self.none_categorisation:
            violations.append(
                'there must be at least one categorisation with "value=0" to express that a '
                'finding is not relevant anymore'
            )

        if not violations:
            return

        e = ModelValidationError('diki finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_license(self):
        violations = []

        for categorisation in self.categorisations:
            selector = categorisation.selector
            if selector and not isinstance(selector, LicenseFindingSelector):
                violations.append(f'selector must be of type {LicenseFindingSelector}')

        if not self.none_categorisation:
            violations.append(
                'there must be at least one categorisation with "value=0" to express that a '
                'finding is not relevant anymore'
            )

        if not violations:
            return

        e = ModelValidationError('license finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_malware(self):
        violations = []

        for categorisation in self.categorisations:
            selector = categorisation.selector
            if selector and not isinstance(selector, MalwareFindingSelector):
                violations.append(f'selector must be of type {MalwareFindingSelector}')

        if not self.none_categorisation:
            violations.append(
                'there must be at least one categorisation with "value=0" to express that a '
                'finding is not relevant anymore'
            )

        if not violations:
            return

        e = ModelValidationError('malware finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_sast(self):
        violations = []

        for categorisation in self.categorisations:
            selector = categorisation.selector
            if selector and not isinstance(selector, SASTFindingSelector):
                violations.append(f'selector must be of type {SASTFindingSelector}')

        if not self.none_categorisation:
            violations.append(
                'there must be at least one categorisation with "value=0" to express that a '
                'finding is not relevant anymore'
            )

        if (
            self.rescoring_ruleset
            and not isinstance(self.rescoring_ruleset, rm.SastRescoringRuleSet)
        ):
            violations.append(f'rescoring rule set must be of type {rm.SastRescoringRuleSet}')

        if not violations:
            return

        e = ModelValidationError('sast finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_vulnerabilty(self):
        violations = []

        for categorisation in self.categorisations:
            selector = categorisation.selector
            if selector and not isinstance(selector, VulnerabilityFindingSelector):
                violations.append(f'selector must be of type {VulnerabilityFindingSelector}')

        if not self.none_categorisation:
            violations.append(
                'there must be at least one categorisation with "value=0" to express that a '
                'finding is not relevant anymore'
            )

        if (
            self.rescoring_ruleset
            and not isinstance(self.rescoring_ruleset, rm.CveRescoringRuleSet)
        ):
            violations.append(f'rescoring rule set must be of type {rm.CveRescoringRuleSet}')

        if not violations:
            return

        e = ModelValidationError('vulnerability finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    @property
    def none_categorisation(self) -> FindingCategorisation | None:
        '''
        Returns the category which marks a finding as "not relevant anymore", e.g. if it is assessed
        as a false-positive.
        '''
        for categorisation in self.categorisations:
            if categorisation.value == 0:
                return categorisation

    def categorisation_by_id(self, id: str) -> FindingCategorisation | None:
        for categorisation in self.categorisations:
            if categorisation.id == id:
                return categorisation

    def matches(self, artefact: dso.model.ComponentArtefactId) -> bool:
        if not self.filter:
            return True

        # we need to check whether there is at least one "include" filter because if there is none,
        # all not explicitly excluded artefacts are automatically included
        is_include_filter = FindingFilterSemantics.INCLUDE in (f.semantics for f in self.filter)

        is_included = False
        is_excluded = False

        for filter in self.filter:
            if filter.semantics is FindingFilterSemantics.INCLUDE and filter.matches(artefact):
                is_included = True
            elif filter.semantics is FindingFilterSemantics.EXCLUDE and filter.matches(artefact):
                is_excluded = True

        return not is_excluded and (not is_include_filter or is_included)


def default_finding_categorisations(
    finding_type: FindingType,
    name: str,
) -> list[FindingCategorisation]:
    with open(defaults_file_path) as file:
        categorisations_raw = yaml.safe_load(file).get('categorisations', [])

    for categorisation_raw in categorisations_raw:
        if FindingType(categorisation_raw['type']) is finding_type:
            break
    else:
        raise ValueError(f'did not find default categorisation for {finding_type=}')

    if not name in categorisation_raw:
        raise ValueError(f'did not find default categorisation for {finding_type=} and {name=}')

    return [
        dacite.from_dict(
            data_class=FindingCategorisation,
            data=categorisation,
        ) for categorisation in categorisation_raw[name]
    ]


def default_rescoring_ruleset(
    finding_type: FindingType,
    name: str,
) -> dict:
    with open(defaults_file_path) as file:
        rescoring_rulesets_raw = yaml.safe_load(file).get('rescoring_rulesets', [])

    for rescoring_ruleset_raw in rescoring_rulesets_raw:
        if FindingType(rescoring_ruleset_raw['type']) is finding_type:
            break
    else:
        raise ValueError(f'did not find default rescoring ruleset for {finding_type=}')

    if not name in rescoring_ruleset_raw:
        raise ValueError(f'did not find default rescoring ruleset for {finding_type=} and {name=}')

    return rescoring_ruleset_raw[name]


def categorise_finding(
    finding_cfg: Finding,
    finding_property,
) -> FindingCategorisation | None:
    '''
    Used to find the categorisation a finding belongs to according to the passed `finding_property`.
    '''
    for categorisation in finding_cfg.categorisations:
        if not (selector := categorisation.selector):
            continue

        if isinstance(selector, LicenseFindingSelector):
            for license_name in selector.license_names:
                if re.fullmatch(license_name, finding_property, re.IGNORECASE):
                    return categorisation

        elif isinstance(selector, MalwareFindingSelector):
            for malware_name in selector.malware_names:
                if re.fullmatch(malware_name, finding_property, re.IGNORECASE):
                    return categorisation

        elif isinstance(selector, SASTFindingSelector):
            for selector_sub_type in selector.sub_types:
                if re.fullmatch(selector_sub_type, finding_property, re.IGNORECASE):
                    return categorisation

        elif isinstance(selector, VulnerabilityFindingSelector):
            if (
                finding_property >= selector.cve_score_range.min
                and finding_property <= selector.cve_score_range.max
            ):
                return categorisation
