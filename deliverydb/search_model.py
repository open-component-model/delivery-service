import collections.abc
import dataclasses
import enum
import typing

import aiohttp.web


class CriteriaType(enum.StrEnum):
    OCM = 'ocm'
    ARTEFACT_METADATA = 'artefact-metadata'
    FULLTEXT = 'fulltext'


class Mode(enum.StrEnum):
    INCLUDE = 'include'
    EXCLUDE = 'exclude'


class ArtefactMetadataOp(enum.StrEnum):
    EQ = 'eq'
    IN = 'in'
    RANGE = 'range'
    CMP = 'cmp'


class SortOrder(enum.StrEnum):
    ASC = 'asc'
    DESC = 'desc'


@dataclasses.dataclass
class Criterion:
    mode: Mode = dataclasses.field(default=Mode.INCLUDE, kw_only=True)

    @staticmethod
    def _parse_mode(entry: dict) -> Mode:
        mode_raw = entry.get('mode')
        if mode_raw is None or mode_raw == '':
            return Mode.INCLUDE
        try:
            return Mode(str(mode_raw).lower())
        except Exception:
            raise aiohttp.web.HTTPBadRequest(text=f'invalid {mode_raw=}')


@dataclasses.dataclass
class OcmCriterion(Criterion):
    value: str
    type: CriteriaType = dataclasses.field(default=CriteriaType.OCM, init=False)

    @classmethod
    def from_dict(cls, entry: dict) -> typing.Self:
        value = entry.get('value')
        if not value:
            raise aiohttp.web.HTTPBadRequest(text='ocm entry missing value')
        return cls(
            value=str(value),
            mode=cls._parse_mode(entry),
        )


@dataclasses.dataclass
class ArtefactMetadataCriterion(Criterion):
    '''
    filter criterion for a single artefact-metadata attribute.

    fields:
      - attr:
          attribute name to filter on (e.g. "type", "data.cve", "meta.creation_date").
      - op:
          operation to apply. Determines which of the value-fields below are used.
          supported:
            - EQ:    exact match (or LIKE if value contains '*')
            - IN:    any-of matching (OR semantics within the same attr)
            - RANGE: datetime range query (inclusive)
            - CMP:   comparison operator (>, >=, <, <=, !=, ==) mainly used for severity etc.
      - mode:
          INCLUDE (default) keeps matching rows, EXCLUDE negates the predicate.

    value fields (depending on op):
      - op=EQ:
          - value: single value to match against.
      - op=IN:
          - values: list of values to match against (any-of).
      - op=RANGE:
          - gte / lte: ISO8601 datetimes (open range allowed by omitting either side).
      - op=CMP:
          - cmp: comparison operator string (e.g. ">=")
          - value: right-hand side value used for the comparison.
    '''
    attr: str
    op: ArtefactMetadataOp = ArtefactMetadataOp.EQ

    # op=eq
    value: str | None = None

    # op=in
    values: list[str] | None = None

    # op=range
    gte: str | None = None
    lte: str | None = None

    # op=cmp
    cmp: str | None = None

    type: CriteriaType = dataclasses.field(default=CriteriaType.ARTEFACT_METADATA, init=False)

    @classmethod
    def from_dict(cls, entry: dict) -> typing.Self:
        attr = entry.get('attr')
        if not attr:
            raise aiohttp.web.HTTPBadRequest(text='artefact-metadata entry missing attr')

        op_raw = entry.get('op') or ArtefactMetadataOp.EQ.value
        try:
            op = ArtefactMetadataOp(str(op_raw).lower())
        except Exception:
            raise aiohttp.web.HTTPBadRequest(text=f'unsupported {op_raw=} for {attr=}')

        mode = cls._parse_mode(entry)

        if op is ArtefactMetadataOp.EQ:
            if not (value := entry.get('value')):
                raise aiohttp.web.HTTPBadRequest(text=f'missing value for {attr=}')
            return cls(
                attr=str(attr),
                op=op,
                value=str(value),
                mode=mode,
            )

        if op is ArtefactMetadataOp.IN:
            raw_values = entry.get('values')
            if not isinstance(raw_values, list) or not raw_values:
                raise aiohttp.web.HTTPBadRequest(text=f'op=in requires non-empty values for {attr}')
            return cls(
                attr=str(attr),
                op=op,
                values=[str(v) for v in raw_values],
                mode=mode,
            )

        if op is ArtefactMetadataOp.RANGE:
            # allow open ranges (gte/lte may be missing)
            return cls(
                attr=str(attr),
                op=op,
                gte=entry.get('gte'),
                lte=entry.get('lte'),
                mode=mode,
            )

        if op is ArtefactMetadataOp.CMP:
            if not (cmp_op := entry.get('cmp')):
                raise aiohttp.web.HTTPBadRequest(text=f'op=cmp requires cmp for {attr}')

            if not (value := entry.get('value')):
                raise aiohttp.web.HTTPBadRequest(text=f'op=cmp requires value for {attr}')

            return cls(
                attr=str(attr),
                op=op,
                cmp=str(cmp_op),
                value=str(value),
                mode=mode,
            )

        raise aiohttp.web.HTTPBadRequest(text=f'unsupported op {op_raw} for {attr=}')


@dataclasses.dataclass
class FulltextCriterion(Criterion):
    value: str
    fields: list[str] | None = None
    type: CriteriaType = dataclasses.field(default=CriteriaType.FULLTEXT, init=False)

    @classmethod
    def from_dict(cls, entry: dict) -> typing.Self:
        value = entry.get('value')
        if not value:
            raise aiohttp.web.HTTPBadRequest(text='fulltext entry missing value')

        fields = entry.get('fields', None)
        if fields is not None:
            if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
                raise aiohttp.web.HTTPBadRequest(text='fulltext fields must be a list of strings')

        return cls(
            value=str(value),
            fields=fields,
            mode=cls._parse_mode(entry),
        )


CriterionType = OcmCriterion | ArtefactMetadataCriterion | FulltextCriterion


def parse_criterion(entry: dict) -> CriterionType:
    if not isinstance(entry, dict):
        raise aiohttp.web.HTTPBadRequest(text='each criteria entry must be an dict')

    type_raw = entry.get('type')
    if not type_raw:
        raise aiohttp.web.HTTPBadRequest(text='criteria entry missing type')

    try:
        criteria_type = CriteriaType(str(type_raw))
    except Exception:
        raise aiohttp.web.HTTPBadRequest(text=f'unsupported criteria {type_raw=}')

    factories: dict[CriteriaType, collections.abc.Callable[[dict], CriterionType]] = {
        CriteriaType.OCM: OcmCriterion.from_dict,
        CriteriaType.FULLTEXT: FulltextCriterion.from_dict,
        CriteriaType.ARTEFACT_METADATA: ArtefactMetadataCriterion.from_dict,
    }

    return factories[criteria_type](entry)


@dataclasses.dataclass
class SortSpec:
    field: str
    order: SortOrder = SortOrder.ASC

    @classmethod
    def from_dict(cls, entry: dict) -> typing.Self:
        if not isinstance(entry, dict):
            raise aiohttp.web.HTTPBadRequest(text='each sort entry must be an dict')

        field = entry.get('field')
        if not field:
            raise aiohttp.web.HTTPBadRequest(text='sort entry missing field')

        order_raw = entry.get('order') or SortOrder.ASC.value
        try:
            order = SortOrder(str(order_raw).lower())
        except Exception:
            raise aiohttp.web.HTTPBadRequest(text=f'invalid sort {order_raw=}')

        return cls(field=str(field), order=order)


@dataclasses.dataclass
class SearchRunRequest:
    criteria: list[CriterionType] = dataclasses.field(default_factory=list)
    limit: int = 50
    sort: list[SortSpec] = dataclasses.field(default_factory=list)
    cursor: dict | None = None

    @staticmethod
    def from_dict(body: dict) -> typing.Self:
        if not isinstance(body, dict):
            raise aiohttp.web.HTTPBadRequest(text='request body must be an dict')

        raw_criteria = body.get('criteria') or []
        if not isinstance(raw_criteria, list):
            raise aiohttp.web.HTTPBadRequest(text='criteria must be a list')

        criteria = [parse_criterion(entry) for entry in raw_criteria]

        limit_raw = body.get('limit', 50)
        try:
            limit = int(limit_raw)
        except Exception:
            raise aiohttp.web.HTTPBadRequest(text='limit must be an integer')

        raw_sort = body.get('sort') or []
        if raw_sort and not isinstance(raw_sort, list):
            raise aiohttp.web.HTTPBadRequest(text='sort must be a list')
        sort = [SortSpec.from_dict(entry) for entry in raw_sort]

        cursor = body.get('cursor')
        if cursor is not None and not isinstance(cursor, dict):
            raise aiohttp.web.HTTPBadRequest(text='cursor must be an dict')

        return SearchRunRequest(
            criteria=criteria,
            limit=limit,
            sort=sort,
            cursor=cursor,
        )
