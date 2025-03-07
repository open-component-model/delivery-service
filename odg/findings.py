import dataclasses
import datetime
import enum
import hashlib
import re
import typing

import dacite
import yaml

import dso.model

import consts
import odg.shared_cfg
import rescore.model as rm
import util


class ModelValidationError(ValueError):
    pass


class RescoringSpecificity(enum.Enum):
    GLOBAL = 'global'
    COMPONENT = 'component'
    ARTEFACT = 'artefact'
    SINGLE = 'single'

    def _asint(self, rescoring_scopes):
        if rescoring_scopes is self.GLOBAL:
            return 0
        elif rescoring_scopes is self.COMPONENT:
            return 1
        elif rescoring_scopes is self.ARTEFACT:
            return 2
        elif rescoring_scopes is self.SINGLE:
            return 3
        else:
            raise ValueError(f'unknown {rescoring_scopes=}')

    def __lt__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._asint(self) < self._asint(other)

    def __le__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._asint(self) <= self._asint(other)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._asint(self) == self._asint(other)

    def __ne__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._asint(self) != self._asint(other)

    def __gt__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._asint(self) > self._asint(other)

    def __ge__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._asint(self) >= self._asint(other)


class FindingType(enum.StrEnum):
    CHECKMARX = 'codechecks/aggregated'
    CRYPTO = 'finding/crypto'
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
class CryptoFindingSelector:
    '''
    :param list[str] ratings:
        List of regexes to determine matching crypto findings based on their rating.
    '''
    ratings: list[str]


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


class RescoringModes(enum.StrEnum):
    MANUAL = 'manual'
    AUTOMATIC = 'automatic'


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
    :param str allowed_processing_time:
        The time after which a finding must have been assessed at the latest. Known units:
            - seconds: s, sec
            - minutes: m, min
            - hours: h, hr
            - days: d (default)
            - weeks: w
            - years: a
    :param RescoringModes rescoring:
        Specifies whether the categorisation is applicable to user rescoring (-> `manual`) and/or to
        full-automatic rescorings (-> `automatic`). Note that the latter requires a respective
        rescoring ruleset to be available.
    :param Selector selector:
        Used to determine findings which should be assigned to this category.
    '''
    id: str
    display_name: str
    value: int
    allowed_processing_time: str | int | None
    rescoring: RescoringModes | list[RescoringModes] | None
    selector: (
        CryptoFindingSelector
        | LicenseFindingSelector
        | MalwareFindingSelector
        | SASTFindingSelector
        | VulnerabilityFindingSelector
        | None
    )

    def __post_init__(self):
        if self.allowed_processing_time is not None:
            self.allowed_processing_time = util.convert_to_timedelta(self.allowed_processing_time)

        if isinstance(self.rescoring, RescoringModes):
            self.rescoring = [self.rescoring]

    @property
    def automatic_rescoring(self) -> bool:
        if not self.rescoring:
            return False

        if isinstance(self.rescoring, list):
            return RescoringModes.AUTOMATIC in self.rescoring

        return self.rescoring is RescoringModes.AUTOMATIC


@dataclasses.dataclass
class FindingIssues:
    '''
    :param str template:
        Template to use for the created GitHub issues. See `issue_replicator.github` for available
        substitues.
    :param str title_template:
        Template to use for the title of the created GitHub issues. Available substituates are
        `artefact`, `meta` and `data` (derived from the respective finding of type
        `dso.model.ArtefactMetadata`).
    :param bool enable_issues:
        If disabled, no GitHub issues will be created/updated for the specified finding type.
    :param bool enable_assignees:
        If set, determined responsibles will be automatically assigned to their respective issues.
    :param bool enable_per_finding:
        If set, GitHub issues will be created per finding for a specific artefact as opposed to a
        single issue with all findings.
    :param list[str] labels:
        List of labels that should be added to the created GitHub issues.
    :param list[str] attrs_to_group_by:
        Allows a custom configuration of those attributes, which should be used to group artefacts
        for a reporting in a shared GitHub issue. If not set, it defaults to the initial behaviour
        which uses `component_name`, `artefact_kind`, `artefact.artefact_name` and
        `artefact.artefact_type` for grouping. Nested attributes are expected to be separated using
        a dot `.`. Note: The order of the specified attributes is significant as they are
        concatenated in the order they were specified to create a stable issue id.
    '''
    template: str = '{summary}'
    title_template: str = '[{meta.type}] - {artefact.component_name}:{artefact.artefact.artefact_name}' # noqa: E501
    enable_issues: bool = True
    enable_assignees: bool = True
    enable_per_finding: bool = False
    labels: list[str] = dataclasses.field(default_factory=list)
    attrs_to_group_by: list[str] = dataclasses.field(default_factory=lambda: [
        'component_name',
        'artefact_kind',
        'artefact.artefact_name',
        'artefact.artefact_type',
    ])

    def group_id_for_artefact(
        self,
        artefact: dso.model.ComponentArtefactId,
    ) -> str:
        '''
        Creates a stable representation of the grouping relevant attributes of the `artefact`.
        '''
        artefact_raw = dataclasses.asdict(artefact)

        def resolve_attr_ref(attr_ref: str) -> str:
            prop = artefact_raw
            for attr_ref_part in attr_ref.split('.'):
                prop = prop.get(attr_ref_part, {})

            if isinstance(prop, dict):
                return dso.model.normalise_artefact_extra_id(prop)

            return prop

        return ''.join(
            resolve_attr_ref(attr_ref)
            for attr_ref in self.attrs_to_group_by
        )

    def issue_id(
        self,
        artefact: dso.model.ComponentArtefactId,
        latest_processing_date: datetime.date,
        version: str='v1',
    ) -> str:
        '''
        The issue-id (fka. correlation-id) is built from the grouping relevant properties of the
        `artefact` as well as the `latest_processing_date`. It is intended to be used to reference a
        GitHub issue to distinguish between issues "managed" by the Open-Delivery-Gear vs. those
        manually "managed". Also, a version prefix is added to be able to differentiate issue-ids in
        case their calculation changes in the future.
        '''
        group_id = self.group_id_for_artefact(artefact)
        digest_str = group_id + latest_processing_date.isoformat()
        digest = hashlib.shake_128(digest_str.encode()).hexdigest(length=23)

        return f'{version}/{digest}'

    def issue_title(
        self,
        finding: dso.model.ArtefactMetadata,
    ) -> str:
        return self.title_template.format(
            artefact=finding.artefact,
            meta=finding.meta,
            data=finding.data,
        )

    def strip_artefact(
        self,
        artefact: dso.model.ComponentArtefactId,
        keep_group_attributes: bool=True,
    ) -> dso.model.ComponentArtefactId:
        '''
        Based on `keep_group_attributes`, either returns an artefact which only contains the
        attributes which are used for grouping, or the opposite.
        '''
        def include_attribute(attr_ref: str) -> bool:
            is_group_attribute = attr_ref in self.attrs_to_group_by
            return is_group_attribute == keep_group_attributes

        return dso.model.ComponentArtefactId(
            component_name=artefact.component_name if include_attribute('component_name') else None, # noqa: E501
            component_version=artefact.component_version if include_attribute('component_version') else None, # noqa: E501
            artefact_kind=artefact.artefact_kind if include_attribute('artefact_kind') else None,
            artefact=dso.model.LocalArtefactId(
                artefact_name=artefact.artefact.artefact_name if include_attribute('artefact.artefact_name') else None, # noqa: E501
                artefact_version=artefact.artefact.artefact_version if include_attribute('artefact.artefact_version') else None, # noqa: E501
                artefact_type=artefact.artefact.artefact_type if include_attribute('artefact.artefact_type') else None, # noqa: E501
                artefact_extra_id=artefact.artefact.artefact_extra_id if include_attribute('artefact.artefact_extra_id') else dict(), # noqa: E501
            ),
        )


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
class SharedCfgReference:
    cfg_name: str
    ref: (
        odg.shared_cfg.SharedCfgGitHubReference
        | odg.shared_cfg.SharedCfgLocalReference
        | odg.shared_cfg.SharedCfgOCMReference
    )


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
    :param RescoringScope default_scope
        Default scope selection to be used for rescoring via the Delivery-Dashboard.
    '''
    type: FindingType
    categorisations: SharedCfgReference | list[FindingCategorisation]
    filter: list[FindingFilter] | None
    rescoring_ruleset: SharedCfgReference | dict | None
    issues: FindingIssues = dataclasses.field(default_factory=FindingIssues)
    default_scope: RescoringSpecificity = dataclasses.field(
        default_factory=lambda: RescoringSpecificity.ARTEFACT
    )

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
        shared_cfg_lookup = odg.shared_cfg.shared_cfg_lookup()

        if isinstance(self.categorisations, SharedCfgReference):
            default_cfg = shared_cfg_lookup(self.categorisations.ref)

            self.categorisations = default_finding_categorisations(
                categorisations_raw=default_cfg.get('categorisations', []),
                finding_type=self.type,
                name=self.categorisations.cfg_name,
            )

        if isinstance(self.rescoring_ruleset, SharedCfgReference):
            default_cfg = shared_cfg_lookup(self.rescoring_ruleset.ref)

            self.rescoring_ruleset = default_rescoring_ruleset(
                rescoring_rulesets_raw=default_cfg.get('rescoring_rulesets', []),
                finding_type=self.type,
                name=self.rescoring_ruleset.cfg_name,
            )

        if isinstance(self.rescoring_ruleset, dict):
            if self.type is FindingType.SAST:
                self.rescoring_ruleset = rm.SastRescoringRuleSet.from_dict(self.rescoring_ruleset)

            elif self.type is FindingType.VULNERABILITY:
                self.rescoring_ruleset = rm.CveRescoringRuleSet.from_dict(self.rescoring_ruleset)

        self._validate()

    def _validate(self):
        match self.type:
            case FindingType.CRYPTO:
                self._validate_crypto()
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

    def _validate_crypto(self):
        violations = self._validate_categorisations(
            expected_selector=CryptoFindingSelector,
        )

        if not violations:
            return

        e = ModelValidationError('crypto finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_diki(self):
        violations = self._validate_categorisations()

        if not violations:
            return

        e = ModelValidationError('diki finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_license(self):
        violations = self._validate_categorisations(
            expected_selector=LicenseFindingSelector,
        )

        if not violations:
            return

        e = ModelValidationError('license finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_malware(self):
        violations = self._validate_categorisations(
            expected_selector=MalwareFindingSelector,
        )

        if not violations:
            return

        e = ModelValidationError('malware finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_sast(self):
        violations = self._validate_categorisations(
            expected_selector=SASTFindingSelector,
        )

        if self.rescoring_ruleset:
            if not isinstance(self.rescoring_ruleset, rm.SastRescoringRuleSet):
                violations.append(f'rescoring rule set must be of type {rm.SastRescoringRuleSet}')

            else:
                violations.extend(self._validate_rescoring_ruleset())

        if not violations:
            return

        e = ModelValidationError('sast finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_vulnerabilty(self):
        violations = self._validate_categorisations(
            expected_selector=VulnerabilityFindingSelector,
        )

        if self.rescoring_ruleset:
            if not isinstance(self.rescoring_ruleset, rm.CveRescoringRuleSet):
                violations.append(f'rescoring rule set must be of type {rm.CveRescoringRuleSet}')

            else:
                violations.extend(self._validate_rescoring_ruleset())

        if not violations:
            return

        e = ModelValidationError('vulnerability finding model violations found:')
        e.add_note('\n'.join(violations))
        raise e

    def _validate_categorisations(
        self,
        expected_selector: object | None=None,
    ) -> list[str]:
        violations = []

        for categorisation in self.categorisations:
            selector = categorisation.selector
            if selector and expected_selector and not isinstance(selector, expected_selector):
                violations.append(f'selector must be of type {expected_selector}')

            if categorisation.id.startswith(consts.RESCORING_OPERATOR_SET_TO_PREFIX):
                violations.append(
                    f'the prefix "{consts.RESCORING_OPERATOR_SET_TO_PREFIX}" is reserved for '
                    'operations defined in the rescoring ruleset'
                )

        if not self.none_categorisation:
            violations.append(
                'there must be at least one categorisation with "value=0" to express that a '
                'finding is not relevant anymore'
            )

        return violations

    def _validate_rescoring_ruleset(self) -> list[str]:
        violations = []

        if self.rescoring_ruleset.operations:
            for operation in self.rescoring_ruleset.operations.values():
                violations.extend(self._validate_rescoring_ruleset_operation(operation))

        for rule in self.rescoring_ruleset.rules:
            violations.extend(self._validate_rescoring_ruleset_operation(
                operation=rule.operation,
                operations=self.rescoring_ruleset.operations,
            ))

        return violations

    def _validate_rescoring_ruleset_operation(
        self,
        operation: rm.Operation | str,
        operations: dict[str, rm.Operation | str] | None=None,
    ) -> list[str]:
        if not operations:
            operations = dict()

        if isinstance(operation, str):
            if operation in operations:
                return []

            if (
                operation.startswith(consts.RESCORING_OPERATOR_SET_TO_PREFIX)
                and self.categorisation_by_id(
                    id=operation.removeprefix(consts.RESCORING_OPERATOR_SET_TO_PREFIX),
                    absent_ok=True,
                )
            ):
                return []

            return [f'no categorisation matches operator "{operation}"']

        violations = []

        for op in operation.order:
            if (
                not op in operations
                and not self.categorisation_by_id(id=op, absent_ok=True)
            ):
                violations.append(f'no categorisation matches operator "{op}" in "{operation}"')

        return violations

    @property
    def none_categorisation(self) -> FindingCategorisation:
        '''
        Returns the category which marks a finding as "not relevant anymore", e.g. if it is assessed
        as a false-positive.
        '''
        for categorisation in self.categorisations:
            if categorisation.value == 0:
                return categorisation

        raise RuntimeError(
            'did not find any categorisation with value=0, this is probably a bug as initial '
            'validation should have checked that at least one such categorisation exists'
        )

    def categorisation_by_id(
        self,
        id: str,
        absent_ok: bool=False,
    ) -> FindingCategorisation | None:
        for categorisation in self.categorisations:
            if categorisation.id == id:
                return categorisation

        if absent_ok:
            return None

        raise ValueError(f'did not find categorisation with {id=} for type "{self.type}"')

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
    categorisations_raw: list[dict],
    finding_type: FindingType,
    name: str,
) -> list[FindingCategorisation]:
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
            config=dacite.Config(
                cast=[enum.Enum],
            ),
        ) for categorisation in categorisation_raw[name]
    ]


def default_rescoring_ruleset(
    rescoring_rulesets_raw: list[dict],
    finding_type: FindingType,
    name: str,
) -> dict:
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

        if isinstance(selector, CryptoFindingSelector):
            for rating in selector.ratings:
                if re.fullmatch(rating, finding_property, re.IGNORECASE):
                    return categorisation

        elif isinstance(selector, LicenseFindingSelector):
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
