import dataclasses
import enum
import typing

import reutil

import odg.model


class FilterTypes(enum.StrEnum):
    ARTEFACT_FILTER = 'artefact-filter'
    COMPONENT_FILTER = 'component-filter'
    DATATYPE_FILTER = 'datatype-filter'
    MATCH_ALL = 'match-all'


@dataclasses.dataclass
class FilterBase:
    type: FilterTypes

    def matches(
        self,
        artefact: odg.model.ComponentArtefactId,
        datatype: odg.model.Datatype,
    ) -> bool:
        raise NotImplementedError('must be implemented by its subclasses')


@dataclasses.dataclass
class ArtefactFilter(FilterBase):
    type: typing.Literal[FilterTypes.ARTEFACT_FILTER]
    include_artefact_names: list[str] = dataclasses.field(default_factory=list)
    exclude_artefact_names: list[str] = dataclasses.field(default_factory=list)
    include_artefact_types: list[str] = dataclasses.field(default_factory=list)
    exclude_artefact_types: list[str] = dataclasses.field(default_factory=list)
    include_artefact_kinds: list[str] = dataclasses.field(default_factory=list)
    exclude_artefact_kinds: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        self._artefact_name_filter = reutil.re_filter(
            include_regexes=self.include_artefact_names,
            exclude_regexes=self.exclude_artefact_names,
            value_transformation=lambda artefact: artefact.artefact.artefact_name or '',
        )
        self._artefact_type_filter = reutil.re_filter(
            include_regexes=self.include_artefact_types,
            exclude_regexes=self.exclude_artefact_types,
            value_transformation=lambda artefact: artefact.artefact.artefact_type or '',
        )
        self._artefact_kind_filter = reutil.re_filter(
            include_regexes=self.include_artefact_kinds,
            exclude_regexes=self.exclude_artefact_kinds,
            value_transformation=lambda artefact: artefact.artefact_kind or '',
        )

    def matches(
        self,
        artefact: odg.model.ComponentArtefactId,
        datatype: odg.model.Datatype,
    ) -> bool:
        return all((
            self._artefact_name_filter(artefact),
            self._artefact_type_filter(artefact),
            self._artefact_kind_filter(artefact),
        ))


@dataclasses.dataclass
class ComponentFilter(FilterBase):
    type: typing.Literal[FilterTypes.COMPONENT_FILTER]
    include_component_names: list[str] = dataclasses.field(default_factory=list)
    exclude_component_names: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        self._comp_name_filter = reutil.re_filter(
            include_regexes=self.include_component_names,
            exclude_regexes=self.exclude_component_names,
            value_transformation=lambda artefact: artefact.component_name or '',
        )

    def matches(
        self,
        artefact: odg.model.ComponentArtefactId,
        datatype: odg.model.Datatype,
    ) -> bool:
        return self._comp_name_filter(artefact)


@dataclasses.dataclass
class DatatypeFilter(FilterBase):
    type: typing.Literal[FilterTypes.DATATYPE_FILTER]
    include_types: list[str] = dataclasses.field(default_factory=list)
    exclude_types: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        self._datatype_filter = reutil.re_filter(
            include_regexes=self.include_types,
            exclude_regexes=self.exclude_types,
        )

    def matches(
        self,
        artefact: odg.model.ComponentArtefactId,
        datatype: odg.model.Datatype,
    ) -> bool:
        return self._datatype_filter(datatype)


@dataclasses.dataclass
class MatchAllFilter(FilterBase):
    type: typing.Literal[FilterTypes.MATCH_ALL]

    def matches(
        self,
        artefact: odg.model.ComponentArtefactId,
        datatype: odg.model.Datatype,
    ) -> bool:
        return True
