import collections.abc
import datetime
import http
import typing

import aiohttp.web
import dacite
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync

import ocm

import consts
import deliverydb.cache as dc
import deliverydb.model as dm
import deliverydb.search_model as sm
import deliverydb.util as du
import deliverydb_cache.model as dcm
import features
import middleware.cors
import odg.findings
import odg.model
import util


_FIELD_TO_COL = {
    'id': dm.ArtefactMetaData.id,
    'type': dm.ArtefactMetaData.type,
    'datasource': dm.ArtefactMetaData.datasource,
    'artefact_kind': dm.ArtefactMetaData.artefact_kind,
    'artefact_name': dm.ArtefactMetaData.artefact_name,
    'artefact_version': dm.ArtefactMetaData.artefact_version,
    'artefact_type': dm.ArtefactMetaData.artefact_type,
    'component_name': dm.ArtefactMetaData.component_name,
    'component_version': dm.ArtefactMetaData.component_version,
    'data_key': dm.ArtefactMetaData.data_key,

    'ocm.name': dm.ArtefactMetaData.component_name,
    'ocm.version': dm.ArtefactMetaData.component_version,
    'artefact.name': dm.ArtefactMetaData.artefact_name,
    'artefact.version': dm.ArtefactMetaData.artefact_version,
    'artefact.type': dm.ArtefactMetaData.artefact_type,
}

_DEFAULT_SEARCH_FIELDS = [
    'data.summary',
    'data.cve',
    'data.package_name',
    'data.package_version',
    'artefact.name',
    'ocm.name',
]


_SORT_FOR_COL = {
    'meta.creation_date': lambda: sa.cast(
        dm.ArtefactMetaData.meta.op('->>')('creation_date'),
        sa.DateTime(timezone=True),
    ),
    'meta.last_update': lambda: sa.cast(
        dm.ArtefactMetaData.meta.op('->>')('last_update'),
        sa.DateTime(timezone=True),
    ),
    'ocm.name': lambda: dm.ArtefactMetaData.component_name,
    'ocm.version': lambda: dm.ArtefactMetaData.component_version,
    'type': lambda: dm.ArtefactMetaData.type,
    'id': lambda: dm.ArtefactMetaData.id,
}


def _json_text(
    col: sa.sql.ClauseElement,
    dotted: str
):
    parts = dotted.split('.')
    expr = col
    for part in parts[:-1]:
        expr = expr.op('->')(part)
    return expr.op('->>')(parts[-1])


def _categorisation_value_case(
    finding_cfgs: collections.abc.Iterable[odg.findings.Finding]
) -> sa.sql.ClauseElement:
    severity_id_expr = sa.func.upper(sa.cast(_expr_for_attr('data.severity'), sa.Text))
    type_expr = sa.cast(dm.ArtefactMetaData.type, sa.Text)

    whens: list[tuple[sa.sql.ClauseElement, int]] = []
    for cfg in finding_cfgs:
        for cat in cfg.categorisations:
            whens.append((
                sa.and_(type_expr == cfg.type, severity_id_expr == cat.id),
                cat.value,
            ))

    return sa.case(*whens, else_=0)


def _expr_for_attr(attr: str):
    '''
    supports:
      - meta.<key>  -> JSONB meta as TEXT
      - data.<path> -> JSONB data (nested) as TEXT
      - top-level known columns (e.g. type, datasource, artefact_kind)
      - known aliases from _FIELD_TO_COL
    '''
    if attr.startswith('meta.'):
        key = attr.split('.', 1)[1]
        return dm.ArtefactMetaData.meta.op('->>')(key)

    if attr.startswith('data.'):
        dotted = attr.split('.', 1)[1]
        return _json_text(dm.ArtefactMetaData.data, dotted)

    if attr in _FIELD_TO_COL:
        return _FIELD_TO_COL[attr]

    raise aiohttp.web.HTTPBadRequest(
        text=f'unknown {attr=}',
    )


def _escape_like_literal(raw: str) -> str:
    return (
        raw.replace('\\', '\\\\')
           .replace('%', r'\%')
           .replace('_', r'\_')
    )


def _like_pattern(
    value: str,
    wrap_contains: bool
) -> str:
    raw = str(value)
    esc = _escape_like_literal(raw)
    esc = esc.replace('*', '%')

    if wrap_contains:
        if not esc.startswith('%'):
            esc = '%' + esc
        if not esc.endswith('%'):
            esc = esc + '%'

    return esc


def _pred_like(
    attr: str,
    user_pattern: str,
    wrap_contains: bool = False
):
    expr = sa.cast(
        expression=_expr_for_attr(attr),
        type_=sa.Text
    )
    pat = _like_pattern(
        value=user_pattern,
        wrap_contains=wrap_contains
    )
    return sa.func.lower(expr).like(sa.func.lower(sa.literal(pat)), escape='\\')


def _datetime_or_none(raw: str):
    try:
        return datetime.datetime.fromisoformat(str(raw).replace('Z', '+00:00'))
    except Exception:
        return None


def _split_ocm(component_id: str) -> tuple[str, str | None]:
    raw_value = str(component_id).strip()
    if ':' in raw_value:
        name, version = raw_value.split(':', 1)
        name = name.strip()
        version = version.strip()
        return name, (version or None)
    return raw_value, None


def _pred_ocm(value: str):
    name, ver = _split_ocm(value)
    if not name:
        raise aiohttp.web.HTTPBadRequest(
            text='ocm component name is required',
        )

    component_name_col = dm.ArtefactMetaData.component_name
    component_version_col = dm.ArtefactMetaData.component_version
    return sa.and_(
        component_name_col == name,
        component_version_col == ver
    ) if ver else (component_name_col == name)


def _pred_eq(
    attr: str,
    value: typing.Any
):
    if isinstance(value, str) and '*' in value:
        return _pred_like(attr, value, wrap_contains=False)
    return sa.cast(expression=_expr_for_attr(attr), type_=sa.Text) == str(value)


def _pred_in(
    attr: str,
    values: list[typing.Any]
):
    expr = sa.cast(
        expression=_expr_for_attr(attr),
        type_=sa.Text
    )
    return expr.in_([str(v) for v in values])


def _pred_range(
    attr: str,
    gte: str | None,
    lte: str | None
):
    expr_text = sa.cast(
        expression=_expr_for_attr(attr),
        type_=sa.Text
    )
    clauses = []

    if gte is not None:
        gte_dt = _datetime_or_none(gte)
        if gte_dt is None:
            raise aiohttp.web.HTTPBadRequest(
                text=f'invalid gte for {attr}: {gte}',
            )
        clauses.append(sa.cast(expr_text, sa.DateTime(timezone=True)) >= gte_dt)

    if lte is not None:
        lte_dt = _datetime_or_none(lte)
        if lte_dt is None:
            raise aiohttp.web.HTTPBadRequest(
                text=f'invalid lte for {attr}: {lte}',
            )
        clauses.append(sa.cast(expr_text, sa.DateTime(timezone=True)) <= lte_dt)

    return sa.and_(*clauses) if clauses else sa.true()


def _pred_cmp(
    attr: str,
    op: str,
    value: typing.Any,
    severity_case: sa.sql.ClauseElement | None = None,
) -> sa.sql.ClauseElement:
    if attr == 'finding.severity':
        attr = 'data.severity'

    if attr == 'data.severity':
        if severity_case is None:
            raise aiohttp.web.HTTPBadRequest(text='severity comparisons require finding cfgs')

        try:
            right = int(value)
        except Exception:
            raise aiohttp.web.HTTPBadRequest(
                text=f'data.severity comparisons require an integer threshold (got {value=})'
            )

        left = severity_case
    else:
        left = sa.cast(_expr_for_attr(attr), sa.Text)
        right = str(value)

    if op == '>=': return left >= right
    if op == '>':  return left >  right
    if op == '<=': return left <= right
    if op == '<':  return left <  right
    if op == '!=': return left != right
    if op in ('==', '='): return left == right

    raise aiohttp.web.HTTPBadRequest(text=f'unsupported cmp {op=}')


def _pred_for_artefact_metadata(
    criterion: sm.ArtefactMetadataCriterion,
    severity_case: sa.sql.ClauseElement | None = None,
) -> sa.sql.ClauseElement:
    attr = criterion.attr
    op = criterion.op

    if op is sm.ArtefactMetadataOp.EQ:
        if criterion.value is None:
            raise aiohttp.web.HTTPBadRequest(text=f'missing value for {attr=}')
        return _pred_eq(
            attr=attr,
            value=criterion.value
        )

    if op is sm.ArtefactMetadataOp.IN:
        if not criterion.values:
            raise aiohttp.web.HTTPBadRequest(text=f'op=in requires non-empty values for {attr=}')
        return _pred_in(
            attr=attr,
            values=criterion.values
        )

    if op is sm.ArtefactMetadataOp.RANGE:
        return _pred_range(
            attr=attr,
            gte=criterion.gte,
            lte=criterion.lte
        )

    if op is sm.ArtefactMetadataOp.CMP:
        if not criterion.cmp or criterion.value is None:
            raise aiohttp.web.HTTPBadRequest(text=f'op=cmp requires cmp and value for {attr=}')
        return _pred_cmp(
            attr=attr,
            op=criterion.cmp,
            value=criterion.value,
            severity_case=severity_case,
        )

    raise aiohttp.web.HTTPBadRequest(text=f'unsupported {op=} for {attr=}')


def _translate_criteria(
    criteria: list[sm.CriterionType],
    default_search_fields: list[str] | None = None,
    severity_case: sa.sql.ClauseElement | None = None,
) -> sa.sql.ClauseElement:
    '''
    translates criteria list into SQLAlchemy WHERE clause.

    semantics:
      - all criteria types are AND'ed together.
      - for `type: ocm`:
          include entries are OR'ed (cn==name [AND cv==ver])
          exclude entries are NOT(OR(...))
      - for `type: artefact-metadata`:
          grouped by attr:
            include: AND over attrs, each attr is OR over values/ops
            exclude: AND over attrs, each attr is NOT(OR(...))
      - for `type: fulltext`:
          each token -> OR across configured fields (contains-like)
          multiple tokens are AND'ed (i.e. all tokens must match somewhere)
          excludes are AND'ed as NOT(OR(...)) per token

    supported entry shapes:
      - {type:'ocm', value:'acme.org/x:1.2.3', mode:'exclude'?}
      - {type:'artefact-metadata', attr:'data.cve', op:'eq|in|cmp|range', ... , mode:'exclude'?}
      - {type:'fulltext', value:'kerberos', mode:'exclude'?, fields:[... optional ...]}
    '''
    if not criteria:
        return sa.true()

    default_fields = default_search_fields or _DEFAULT_SEARCH_FIELDS
    ands: list[sa.sql.ClauseElement] = []

    ocm_inc: list[sa.sql.ClauseElement] = []
    ocm_exc: list[sa.sql.ClauseElement] = []
    for criterion in criteria:
        if isinstance(criterion, sm.OcmCriterion):
            pred = _pred_ocm(criterion.value)
            (ocm_exc if criterion.mode is sm.Mode.EXCLUDE else ocm_inc).append(pred)

    if ocm_inc:
        ands.append(sa.or_(*ocm_inc))
    if ocm_exc:
        ands.append(sa.not_(sa.or_(*ocm_exc)))

    by_attr_inc: dict[str, list[sa.sql.ClauseElement]] = collections.defaultdict(list)
    by_attr_exc: dict[str, list[sa.sql.ClauseElement]] = collections.defaultdict(list)

    for criterion in criteria:
        if isinstance(criterion, sm.ArtefactMetadataCriterion):
            pred = _pred_for_artefact_metadata(
                criterion=criterion,
                severity_case=severity_case,
            )
            target = by_attr_exc if criterion.mode is sm.Mode.EXCLUDE else by_attr_inc
            target[criterion.attr].append(pred)

    for preds in by_attr_inc.values():
        if preds:
            ands.append(sa.or_(*preds))
    for preds in by_attr_exc.values():
        if preds:
            ands.append(sa.not_(sa.or_(*preds)))

    def _pred_fulltext(token: str, fields: list[str]) -> sa.sql.ClauseElement:
        tok = str(token or '').strip()
        if not tok:
            return sa.true()
        return sa.or_(*[_pred_like(f, tok, wrap_contains=True) for f in fields])

    full_inc: list[sa.sql.ClauseElement] = []
    full_exc: list[sa.sql.ClauseElement] = []
    for criterion in criteria:
        if isinstance(criterion, sm.FulltextCriterion):
            fields = criterion.fields if criterion.fields is not None else default_fields
            pred = _pred_fulltext(criterion.value, fields)
            (full_exc if criterion.mode is sm.Mode.EXCLUDE else full_inc).append(pred)

    if full_inc:
        ands.append(sa.and_(*full_inc))
    if full_exc:
        ands.append(sa.and_(*[sa.not_(p) for p in full_exc]))

    return sa.and_(*ands) if ands else sa.true()


def _translate_sort(sort_spec: list[sm.SortSpec] | None):
    order_by = []
    for sort_entry in (sort_spec or []):
        field = sort_entry.field
        if field not in _SORT_FOR_COL:
            raise aiohttp.web.HTTPBadRequest(text=f'invalid sort field: {field}')
        col = _SORT_FOR_COL[field]()
        order_by.append(col.desc() if sort_entry.order is sm.SortOrder.DESC else col.asc())
    return order_by


def _parse_cursor_value(
    field: str,
    raw
):
    if raw is None:
        return None
    if field in ('meta.creation_date', 'meta.last_update'):
        dt = _datetime_or_none(raw)
        if dt is None:
            raise aiohttp.web.HTTPBadRequest(
                text=f'invalid cursor datetime for {field}: {raw}',
            )
        return dt
    return str(raw)


def _cursor_clause(
    sort_spec: list[sm.SortSpec],
    cursor: dict | None,
):
    if not cursor:
        return sa.true()

    cols = []
    vals = []

    for sort_entry in sort_spec:
        field = sort_entry.field
        if field not in _SORT_FOR_COL:
            raise aiohttp.web.HTTPBadRequest(text=f'invalid sort field: {field}')
        if field not in cursor:
            raise aiohttp.web.HTTPBadRequest(text=f'cursor missing field "{field}"')

        cols.append(_SORT_FOR_COL[field]())
        vals.append(_parse_cursor_value(field=field, raw=cursor[field]))

    left = sa.tuple_(*cols)
    right = sa.tuple_(*vals)

    # direction depends on FIRST sort key
    return (left < right) if sort_spec[0].order is sm.SortOrder.DESC else (left > right)


def _make_next_cursor(
    sort_spec: list[sm.SortSpec],
    obj: dm.ArtefactMetaData,
) -> dict:
    out = {}
    for s in sort_spec:
        field = s.field

        if field == 'id':
            out['id'] = str(obj.id)
        elif field == 'meta.creation_date':
            out['meta.creation_date'] = (obj.meta or {}).get('creation_date')
        elif field == 'meta.last_update':
            out['meta.last_update'] = (obj.meta or {}).get('last_update')
        elif field == 'type':
            out['type'] = str(obj.type)
        elif field == 'ocm.name':
            out['ocm.name'] = str(obj.component_name)
        elif field == 'ocm.version':
            out['ocm.version'] = (
                None if obj.component_version is None else str(obj.component_version)
            )
        else:
            out[field] = None
    return out


class ArtefactMetadataSearchFields(aiohttp.web.View):
    async def options(self):
        return aiohttp.web.Response()

    async def get(self):
        '''
        ---
        description:
          Returns supported query fields for artefact-metadata search, including their types and
          supported operators. Also returns `defaultSearchFields` used for free-text search.
        tags:
        - Artefact metadata
        produces:
        - application/json
        responses:
          "200":
            description: OK
        '''
        fields = [
            {'name': 'ocm', 'type': 'string', 'ops': ['eq']},

            {'name': 'type', 'type': 'string', 'ops': ['eq', 'in']},
            {'name': 'datasource', 'type': 'string', 'ops': ['eq', 'in']},
            {'name': 'artefact_kind', 'type': 'string', 'ops': ['eq', 'in']},

            {'name': 'artefact.name', 'type': 'string', 'ops': ['eq', 'in']},
            {'name': 'artefact.version', 'type': 'string', 'ops': ['eq', 'in']},
            {'name': 'artefact.type', 'type': 'string', 'ops': ['eq', 'in']},

            {'name': 'meta.creation_date', 'type': 'datetime', 'ops': ['range', 'eq']},
            {'name': 'meta.last_update', 'type': 'datetime', 'ops': ['range', 'eq']},

            {'name': 'data.cve', 'type': 'string', 'ops': ['eq', 'in']},
            {'name': 'data.package_name', 'type': 'string', 'ops': ['eq', 'in']},
            {'name': 'data.package_version', 'type': 'string', 'ops': ['eq', 'in']},
            {'name': 'data.osid.NAME', 'type': 'string', 'ops': ['eq', 'in']},
            {'name': 'data.severity', 'type': 'string', 'ops': ['cmp', 'eq', 'in']},
            {'name': 'data.summary', 'type': 'string', 'ops': ['eq']},
        ]

        default_search_fields = _DEFAULT_SEARCH_FIELDS

        return aiohttp.web.json_response({
            'fields': fields,
            'defaultSearchFields': default_search_fields,
        })


class ArtefactMetadataSearchRun(aiohttp.web.View):
    async def options(self):
        return aiohttp.web.Response()

    async def post(self):
        '''
        ---
        description:
          Executes an artefact-metadata search query.
          Supports criteria types `ocm`, `artefact-metadata`, and `fulltext`.
          Results are returned in a stable order and can be paged using cursor-based pagination.
        tags:
        - Artefacts
        consumes:
        - application/json
        produces:
        - application/json
        parameters:
        - in: body
          name: body
          required: true
          schema:
            type: object
            required:
            - criteria
            properties:
              criteria:
                type: array
                description: List of filter criteria (AND across types; OR within same field/attr).
                items:
                  type: object
              limit:
                type: integer
                required: false
                default: 50
                description: Page size (capped server-side).
              sort:
                type: array
                required: false
                description: Sort specification.
                items:
                  type: object
              cursor:
                type: object
                required: false
                description: Cursor for next page (seek pagination); must contain all sort fields.
        responses:
          "200":
            description: OK
          "400":
            description: Bad Request (invalid criteria / cursor / sort)
          "401":
            description: Unauthorized
        '''
        body = await self.request.json()
        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
        finding_cfgs = self.request.app[consts.APP_FINDING_CFGS]

        req = sm.SearchRunRequest.from_dict(body)

        page_size = max(1, min(req.limit, 200))  # hard cap per page

        sort = req.sort or [
            sm.SortSpec(field='meta.creation_date', order=sm.SortOrder.DESC),
        ]

        if not any(s.field == 'id' for s in sort):
            sort = [*sort, sm.SortSpec(field='id', order=sort[0].order)]

        if sort and any(s.order != sort[0].order for s in sort):
            raise aiohttp.web.HTTPBadRequest(text='mixed sort orders are not supported')

        cursor = req.cursor

        severity_case = _categorisation_value_case(finding_cfgs)
        base_where = _translate_criteria(
            criteria=req.criteria,
            severity_case=severity_case
        )
        order_by = _translate_sort(sort)

        # overfetch so we can still fill a page after cfg-filtering
        RAW_BATCH = min(2000, page_size * 10)
        MAX_ROUNDS = 10

        items: list[dict] = []
        next_cursor = None

        scan_cursor = cursor
        done = False

        for _ in range(MAX_ROUNDS):
            stmt = (
                sa.select(dm.ArtefactMetaData)
                .where(base_where)
                .where(_cursor_clause(sort, scan_cursor))
                .order_by(*order_by)
                .limit(RAW_BATCH)
            )

            result = await db_session.execute(stmt)
            rows = list(result.scalars().all())

            if not rows:
                # no more data
                done = True
                next_cursor = None
                break

            # walk rows in order, collect up to limit accepted
            for obj in rows:
                dso = du.db_artefact_metadata_row_to_dso((obj,))

                for cfg in finding_cfgs:
                    if cfg.type == dso.meta.type and not cfg.matches(dso.artefact):
                        break
                else:
                    items.append(util.dict_serialisation(dso))
                    if len(items) >= page_size:
                        # next page should continue after LAST RETURNED object
                        next_cursor = _make_next_cursor(sort, obj)
                        done = True
                        break

            if done:
                break

            # we didn't fill the page yet -> continue scanning after the last scanned DB row
            scan_cursor = _make_next_cursor(sort, rows[-1])

        # If we hit MAX_ROUNDS without filling page, still return what we have.
        # next_cursor in that case: continue after last scanned cursor (best effort)
        if not done and scan_cursor is not None:
            next_cursor = scan_cursor if items else None

        return aiohttp.web.json_response({
            'items': items,
            'nextCursor': next_cursor,
        })


class ArtefactMetadataQuery(aiohttp.web.View):
    required_features = (features.FeatureDeliveryDB,)

    async def options(self):
        return aiohttp.web.Response()

    async def post(self):
        '''
        ---
        description: Query artefact-metadata from delivery-db.
        tags:
        - Artefact metadata
        produces:
        - application/json
        parameters:
        - in: query
          name: type
          schema:
            $ref: '#/definitions/Datatype'
          required: false
          description:
            The metadata types to retrieve. Can be given multiple times. If no type is
            given, all relevant metadata will be returned. Check odg/model.py `Datatype` model class
            for a list of possible values.
        - in: query
          name: referenced_type
          schema:
            $ref: '#/definitions/Datatype'
          required: false
          description:
            The referenced types to retrieve (only applicable for metadata of type
            `rescorings`). Can be given multiple times. If no referenced type is given, all relevant
            metadata will be returned. Check odg/model.py `Datatype` model class for a list of
            possible values.
        - in: body
          name: body
          required: false
          schema:
            type: object
            properties:
              entries:
                type: array
                items:
                  $ref: '#/definitions/ComponentArtefactId'
        responses:
          "200":
            description: Successful operation.
            schema:
              type: array
              items:
                $ref: '#/definitions/ArtefactMetadata'
        '''
        component_descriptor_lookup = self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP]
        params = self.request.rel_url.query

        body = await self.request.json()
        entries: list[dict] = body.get('entries', [])

        type_filter = params.getall('type', [])
        referenced_type_filter = params.getall('referenced_type', [])

        artefact_refs = [
            dacite.from_dict(
                data_class=odg.model.ComponentArtefactId,
                data=entry,
                config=dacite.Config(
                    cast=[odg.model.ArtefactKind],
                ),
            ) for entry in entries
        ]

        async def artefact_queries(artefact_ref: odg.model.ComponentArtefactId):
            # when filtering for metadata of type `rescorings`, entries without a component
            # name or version should also be considered a "match" (caused by different rescoring
            # scopes)
            none_ok = not type_filter or odg.model.Datatype.RESCORING in type_filter

            async for query in du.ArtefactMetadataQueries.component_queries(
                components=[ocm.ComponentIdentity(
                    name=artefact_ref.component_name,
                    version=artefact_ref.component_version,
                )],
                none_ok=none_ok,
                component_descriptor_lookup=component_descriptor_lookup,
            ):
                yield query

            if artefact_ref.artefact_kind:
                yield dm.ArtefactMetaData.artefact_kind == artefact_ref.artefact_kind

            if not artefact_ref.artefact:
                return

            if artefact_name := artefact_ref.artefact.artefact_name:
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_name == None,
                    ),
                    dm.ArtefactMetaData.artefact_name == artefact_name,
                )

            if artefact_version := artefact_ref.artefact.artefact_version:
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_version == None,
                    ),
                    dm.ArtefactMetaData.artefact_version == artefact_version,
                )

            if artefact_type := artefact_ref.artefact.artefact_type:
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_type == None,
                    ),
                    dm.ArtefactMetaData.artefact_type == artefact_type,
                )

            if artefact_extra_id := artefact_ref.artefact.normalised_artefact_extra_id:
                yield sa.or_(
                    sa.and_(
                        none_ok,
                        dm.ArtefactMetaData.artefact_extra_id_normalised == '',
                    ),
                    dm.ArtefactMetaData.artefact_extra_id_normalised == artefact_extra_id,
                )

        async def artefact_refs_queries(artefact_refs: list[odg.model.ComponentArtefactId]):
            for artefact_ref in artefact_refs:
                yield sa.and_(*[
                    query async for query
                    in artefact_queries(artefact_ref=artefact_ref)
                ])

        db_statement = sa.select(dm.ArtefactMetaData)

        if type_filter:
            db_statement = db_statement.where(
                dm.ArtefactMetaData.type.in_(type_filter),
            )

        if referenced_type_filter:
            db_statement = db_statement.where(
                dm.ArtefactMetaData.referenced_type.in_(referenced_type_filter),
            )

        if artefact_refs:
            db_statement = db_statement.where(
                sa.or_(*[
                    query async for query
                    in artefact_refs_queries(artefact_refs=artefact_refs)
                ]),
            )

        async def serialise_and_enrich_finding(
            finding: odg.model.ArtefactMetadata,
        ) -> dict:
            def result_dict(
                finding: odg.model.ArtefactMetadata,
                meta: dict=None,
            ) -> dict:
                finding_dict = util.dict_serialisation(finding)

                if meta:
                    finding_dict['meta'] = meta

                return finding_dict

            return result_dict(finding)

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
        db_stream = await db_session.stream(db_statement)

        finding_cfgs = self.request.app[consts.APP_FINDING_CFGS]

        artefact_metadata = []
        async for partition in db_stream.partitions(size=50):
            for row in partition:
                artefact_metadatum = du.db_artefact_metadata_row_to_dso(row)

                # only yield findings which were not explicitly filtered-out by central finding-cfg
                for finding_cfg in finding_cfgs:
                    if (
                        finding_cfg.type == artefact_metadatum.meta.type
                        and not finding_cfg.matches(artefact_metadatum.artefact)
                    ):
                        # artefact metadatum is filtered-out, do not include it
                        break
                else:
                    # artefact metadatum was not explicitly filtered-out by central finding-cfg
                    artefact_metadata.append(await serialise_and_enrich_finding(artefact_metadatum))

        data = util.dict_to_json_factory(artefact_metadata)

        response = aiohttp.web.StreamResponse(
            headers={
                'Content-Type': 'application/json',
                # cors must be set here already because `response.prepare` already sends header
                **middleware.cors.cors_headers(self.request),
            },
        )
        response.enable_compression()
        await response.prepare(self.request)
        await response.write(data.encode('utf-8'))
        await response.write_eof()

        return response


class ArtefactMetadata(aiohttp.web.View):
    async def put(self):
        '''
        ---
        description: Update artefact-metadata in delivery-db.
        tags:
        - Artefact metadata
        parameters:
        - in: body
          name: body
          required: false
          schema:
            type: object
            properties:
              entries:
                type: array
                items:
                  $ref: '#/definitions/ArtefactMetadata'
        responses:
          "200":
            description: No entries were provided and no operation was performed.
          "201":
            description: Successful operation.
        '''
        body = await self.request.json()
        entries: list[dict] = body.get('entries')

        if not entries:
            return aiohttp.web.Response()

        artefact_metadata = [
            odg.model.ArtefactMetadata.from_dict(_fill_default_values(entry))
            for entry in entries
        ]

        # determine all artefact/type combinations to query them at once afterwards
        artefacts = dict()
        for artefact_metadatum in artefact_metadata:
            key = (artefact_metadatum.artefact, artefact_metadatum.meta.type)
            if key not in artefacts:
                artefacts[key] = artefact_metadatum

        artefacts = artefacts.values()

        def artefact_queries(artefacts: collections.abc.Iterable[odg.model.ArtefactMetadata]):
            for artefact in artefacts:
                yield du.ArtefactMetadataFilters.by_name_and_type(
                    artefact_metadata=dm.ArtefactMetaData(
                        component_name=artefact.artefact.component_name,
                        artefact_name=artefact.artefact.artefact.artefact_name,
                        type=artefact.meta.type,
                        datasource=artefact.meta.datasource,
                    ),
                )

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
        db_statement = sa.select(dm.ArtefactMetaData).where(
            sa.or_(artefact_queries(artefacts=artefacts)),
        )
        db_stream = await db_session.stream(db_statement)

        # order entries to increase chances to find matching existing entry as soon as possible
        existing_entries = sorted(
            [
                entry[0]
                async for partition in db_stream.partitions(size=50)
                for entry in partition
            ],
            key=lambda entry: entry.meta.get(
                'last_update',
                datetime.datetime.fromtimestamp(0, datetime.UTC).isoformat(),
            ),
            reverse=True,
        )

        existing_artefact_versions = {
            existing_entry.artefact_version for existing_entry in existing_entries
        }

        created_artefacts: list[dm.ArtefactMetaData] = []

        finding_cfgs = self.request.app[consts.APP_FINDING_CFGS]

        def find_entry_and_discovery_date(
            existing_entry: dm.ArtefactMetaData,
            new_entry: dm.ArtefactMetaData,
            reuse_discovery_date: odg.findings.ReuseDiscoveryDate,
        ) -> tuple[dm.ArtefactMetaData | None, datetime.date | None]:
            if (
                existing_entry.type != new_entry.type
                or existing_entry.component_name != new_entry.component_name
                or existing_entry.artefact_kind != new_entry.artefact_kind
                or existing_entry.artefact_name != new_entry.artefact_name
                or existing_entry.artefact_type != new_entry.artefact_type
            ):
                return None, None

            reusable_discovery_date = reuse_discovery_date_if_possible(
                old_metadata=existing_entry,
                new_metadata=metadata_entry,
                reuse_discovery_date=reuse_discovery_date,
            )

            if existing_entry.id != metadata_entry.id:
                return None, reusable_discovery_date

            return existing_entry, reusable_discovery_date

        try:
            for artefact_metadatum in artefact_metadata:
                metadata_entry = du.to_db_artefact_metadata(
                    artefact_metadata=artefact_metadatum,
                )

                for finding_cfg in finding_cfgs:
                    if finding_cfg.type == metadata_entry.type:
                        reuse_discovery_date = finding_cfg.reuse_discovery_date
                        break
                else:
                    reuse_discovery_date = odg.findings.ReuseDiscoveryDate()

                found = None
                discovery_date = None

                for existing_entry in created_artefacts:
                    found, reusable_discovery_date = find_entry_and_discovery_date(
                        existing_entry=existing_entry,
                        new_entry=metadata_entry,
                        reuse_discovery_date=reuse_discovery_date,
                    )

                    if not discovery_date:
                        discovery_date = reusable_discovery_date

                    if found:
                        break

                if not found:
                    for existing_entry in existing_entries:
                        if (
                            discovery_date
                            and metadata_entry.artefact_version not in existing_artefact_versions
                        ):
                            # there is no need to search any further -> we won't find any existing
                            # entry with the same artefact version and we don't have to find any
                            # reusable discovery date (anymore)
                            break

                        found, reusable_discovery_date = find_entry_and_discovery_date(
                            existing_entry=existing_entry,
                            new_entry=metadata_entry,
                            reuse_discovery_date=reuse_discovery_date,
                        )

                        if not discovery_date:
                            discovery_date = reusable_discovery_date

                        if found:
                            break

                await _mark_compliance_summary_cache_for_deletion(
                    db_session=db_session,
                    artefact_metadata=metadata_entry,
                )

                if not found:
                    # did not find existing database entry that matches the supplied metadata entry
                    # -> create new entry (and re-use discovery date if possible)
                    if discovery_date:
                        metadata_entry.discovery_date = discovery_date

                    db_session.add(metadata_entry)
                    created_artefacts.append(metadata_entry)
                    continue

                # update actual payload
                existing_entry.data = metadata_entry.data

                # create new dict instead of patching it, otherwise it won't be updated in the db
                del existing_entry.meta['last_update']
                if 'responsibles' in existing_entry.meta:
                    del existing_entry.meta['responsibles']
                if 'assignee_mode' in existing_entry.meta:
                    del existing_entry.meta['assignee_mode']
                existing_entry.meta = dict(
                    **existing_entry.meta,
                    last_update=metadata_entry.meta['last_update'],
                    responsibles=metadata_entry.meta.get('responsibles'),
                    assignee_mode=metadata_entry.meta.get('assignee_mode'),
                )

            await db_session.commit()
        except:
            await db_session.rollback()
            raise

        return aiohttp.web.Response(
            status=http.HTTPStatus.CREATED,
        )

    async def delete(self):
        '''
        ---
        description: Delete artefact-metadata from delivery-db.
        tags:
        - Artefact metadata
        parameters:
        - in: body
          name: body
          required: true
          schema:
            type: object
            properties:
              entries:
                type: array
                items:
                  $ref: '#/definitions/ArtefactMetadata'
        responses:
          "204":
            description: Successful operation.
        '''
        body = await self.request.json()
        entries: list[dict] = body.get('entries')

        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]

        try:
            for entry in entries:
                entry = _fill_default_values(entry)

                artefact_metadata = du.to_db_artefact_metadata(
                    artefact_metadata=odg.model.ArtefactMetadata.from_dict(entry),
                )

                await db_session.execute(sa.delete(dm.ArtefactMetaData).where(
                    dm.ArtefactMetaData.id == artefact_metadata.id,
                ))

                await _mark_compliance_summary_cache_for_deletion(
                    db_session=db_session,
                    artefact_metadata=artefact_metadata,
                )

            await db_session.commit()
        except:
            await db_session.rollback()
            raise

        return aiohttp.web.Response(
            status=http.HTTPStatus.NO_CONTENT,
        )


def reuse_discovery_date_if_possible(
    old_metadata: dm.ArtefactMetaData,
    new_metadata: dm.ArtefactMetaData,
    reuse_discovery_date: odg.findings.ReuseDiscoveryDate,
) -> datetime.date | None:
    if not reuse_discovery_date.enabled:
        return None

    if reuse_discovery_date.max_reuse_time:
        last_update = datetime.datetime.fromisoformat(old_metadata.meta.get('last_update'))
        if last_update + reuse_discovery_date.max_reuse_time < datetime.datetime.now():
            return None

    if new_metadata.type == odg.model.Datatype.VULNERABILITY_FINDING:
        if (
            new_metadata.data.get('package_name') == old_metadata.data.get('package_name')
            and new_metadata.data.get('cve') == old_metadata.data.get('cve')
        ):
            # found the same cve in existing entry, independent of the component-/
            # resource-/package-version, so we must re-use its discovery date
            return old_metadata.discovery_date

    elif new_metadata.type == odg.model.Datatype.LICENSE_FINDING:
        if (
            new_metadata.data.get('package_name') == old_metadata.data.get('package_name')
            and new_metadata.data.get('license').get('name')
                == old_metadata.data.get('license').get('name')
        ):
            # found the same license in existing entry, independent of the component-/
            # resource-/package-version, so we must re-use its discovery date
            return old_metadata.discovery_date

    elif new_metadata.type == odg.model.Datatype.IP_FINDING:
        if (
            new_metadata.data.get('package_name') == old_metadata.data.get('package_name')
            and new_metadata.data.get('license').get('name')
                == old_metadata.data.get('license').get('name')
            and sorted(new_metadata.data.get('labels'))
                == sorted(old_metadata.data.get('labels'))
            and new_metadata.data.get('policy_violation').get('name')
                == old_metadata.data.get('policy_violation').get('name')
        ):
            # found the same license in existing entry, independent of the component-/
            # resource-/package-version, so we must re-use its discovery date
            return old_metadata.discovery_date

    elif new_metadata.type == odg.model.Datatype.OSID_FINDING:
        if (
            new_metadata.data.get('osid').get('VERSION_ID')
                == old_metadata.data.get('osid').get('VERSION_ID')
            and new_metadata.data.get('osid').get('NAME')
                == old_metadata.data.get('osid').get('NAME')
        ):
            # found the same version and name in existing entry, so we must re-use its discovery date
            return old_metadata.discovery_date

    elif new_metadata.data_key == old_metadata.data_key:
        # found the same finding in existing entry, so we must re-use its discovery date
        return old_metadata.discovery_date

    return None


def _fill_default_values(
    raw: dict,
) -> dict:
    meta = raw['meta']
    if not meta.get('last_update'):
        meta['last_update'] = datetime.datetime.now().isoformat()

    if not meta.get('creation_date'):
        meta['creation_date'] = datetime.datetime.now().isoformat()

    return raw


async def _mark_compliance_summary_cache_for_deletion(
    db_session: sqlasync.session.AsyncSession,
    artefact_metadata: dm.ArtefactMetaData,
):
    if not (
        artefact_metadata.component_name and artefact_metadata.component_version
        and artefact_metadata.type and artefact_metadata.datasource
    ):
        # If one of these properties is not set, the cache id cannot be calculated properly.
        # Currently, this is only the case for BDBA findings where the component version is left
        # empty. In that case, the cache is invalidated upon successful finish of the scan.
        return

    component = ocm.ComponentIdentity(
        name=artefact_metadata.component_name,
        version=artefact_metadata.component_version,
    )

    if artefact_metadata.type == odg.model.Datatype.ARTEFACT_SCAN_INFO:
        # If the artefact scan info changes, the compliance summary for all datatypes related to
        # this datasource has to be updated, because it may has changed from
        # UNKNOWN -> CLEAN/FINDINGS
        datatypes = odg.model.Datasource(artefact_metadata.datasource).datatypes()
    else:
        datatypes = (artefact_metadata.type,)

    for datatype in datatypes:
        try:
            finding_type = odg.model.Datatype(datatype)
        except ValueError:
            continue

        await dc.mark_function_cache_for_deletion(
            encoding_format=dcm.EncodingFormat.PICKLE,
            function='compliance_summary.component_datatype_summaries',
            db_session=db_session,
            defer_db_commit=True, # only commit at the end of the query
            component=component,
            finding_type=finding_type,
            datasource=artefact_metadata.datasource,
        )
