import dataclasses
import enum
import re

import odg.model


class FilterSemantics(enum.StrEnum):
    INCLUDE = 'include'
    EXCLUDE = 'exclude'


@dataclasses.dataclass
class ComponentArtefactFilter:
    semantics: FilterSemantics
    name: str | None

    component_name: list[str] | str | None
    component_version: list[str] | str | None

    artefact_kind: list[odg.model.ArtefactKind] | odg.model.ArtefactKind | None
    artefact_name: list[str] | str | None
    artefact_version: list[str] | str | None
    artefact_type: list[str] | str | None
    artefact_extra_id: list[dict] | dict | None

    def __post_init__(self):
        if isinstance(self.component_name, str):
            self.component_name = [self.component_name]
        if isinstance(self.component_version, str):
            self.component_version = [self.component_version]
        if isinstance(self.artefact_kind, odg.model.ArtefactKind):
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
            odg.model.normalise_artefact_extra_id(artefact_extra_id)
            for artefact_extra_id in self.artefact_extra_id or []
        ]

    def matches(self, artefact: odg.model.ComponentArtefactId) -> bool:
        def match_regexes(patterns: list[str], value: str | None) -> bool:
            if not patterns:
                return True
            if not value:
                # considering the case there is only an 'exclude' filter, then artefacts whose
                # property is empty should not be filtered-out although the pattern would match;
                # in contrast, when there is an 'include' filter, then artefacts whose property is
                # empty should also be included
                return self.semantics is FilterSemantics.INCLUDE
            return any(re.fullmatch(p, value, re.IGNORECASE) for p in patterns)

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
class ComponentArtefactRuleSet:
    rules: list[ComponentArtefactFilter]

    def allows(self, artefact: odg.model.ComponentArtefactId) -> bool:
        includes = [r for r in self.rules if r.semantics is FilterSemantics.INCLUDE]
        excludes = [r for r in self.rules if r.semantics is FilterSemantics.EXCLUDE]

        is_included = True if not includes else any(r.matches(artefact) for r in includes)
        is_excluded = any(r.matches(artefact) for r in excludes)

        return is_included and not is_excluded
