import collections
import datetime
import json
import typing
import zlib

import aiohttp.web
import sqlalchemy as sa
import sqlalchemy.ext.asyncio as sqlasync

import oci.model
import ocm

import consts
import deliverydb.model as dm
import deliverydb.util as du
import lookups
import util


_FIELD_COL = {
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


_SEV_ORDER = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1
}


_SORT_COL = {
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


def _jsonb_text(
    col,
    dotted: str
):
    parts = dotted.split('.')
    expr = col
    for p in parts[:-1]:
        expr = expr.op('->')(p)
    return expr.op('->>')(parts[-1])


def _expr_for_attr(attr: str):
    '''
    supports:
      - meta.<key>  -> JSONB meta as TEXT
      - data.<path> -> JSONB data (nested) as TEXT
      - top-level known columns (e.g. type, datasource, artefact_kind)
      - known aliases from _FIELD_COL
    '''
    if attr.startswith('meta.'):
        key = attr.split('.', 1)[1]
        return dm.ArtefactMetaData.meta.op('->>')(key)

    if attr.startswith('data.'):
        dotted = attr.split('.', 1)[1]
        return _jsonb_text(dm.ArtefactMetaData.data, dotted)

    if attr in _FIELD_COL:
        return _FIELD_COL[attr]

    raise aiohttp.web.HTTPBadRequest(
        text=json.dumps({'error': f'unknown {attr=}'}),
        content_type='application/json',
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
    expr = sa.cast(_expr_for_attr(attr), sa.Text)
    pat = _like_pattern(user_pattern, wrap_contains=wrap_contains)
    return sa.func.lower(expr).like(sa.func.lower(sa.literal(pat)), escape='\\')


def _parse_datetime_maybe(s: str):
    try:
        return datetime.datetime.fromisoformat(str(s).replace('Z', '+00:00'))
    except Exception:
        return None


def _split_ocm(value: str) -> tuple[str, str | None]:
    s = str(value).strip()
    if ':' in s:
        name, ver = s.split(':', 1)
        name = name.strip()
        ver = ver.strip()
        return name, (ver or None)
    return s, None


def _pred_ocm(value: str):
    name, ver = _split_ocm(value)
    if not name:
        raise aiohttp.web.HTTPBadRequest(
            text=json.dumps({'error': 'invalid ocm value'}),
            content_type='application/json',
        )

    cn = dm.ArtefactMetaData.component_name
    cv = dm.ArtefactMetaData.component_version
    return sa.and_(cn == name, cv == ver) if ver else (cn == name)


def _severity_rank_case(attr: str):
    expr = sa.func.upper(sa.cast(_expr_for_attr(attr), sa.Text))
    return sa.case(
        (expr == 'CRITICAL', 4),
        (expr == 'HIGH', 3),
        (expr == 'MEDIUM', 2),
        (expr == 'LOW', 1),
        else_=0,
    )


def _pred_eq(
    attr: str,
    value: typing.Any
):
    if isinstance(value, str) and '*' in value:
        return _pred_like(attr, value, wrap_contains=False)
    return sa.cast(_expr_for_attr(attr), sa.Text) == str(value)


def _pred_in(
    attr: str,
    values: list[typing.Any]
):
    expr = sa.cast(_expr_for_attr(attr), sa.Text)
    return expr.in_([str(v) for v in values])


def _pred_range(
    attr: str,
    gte: str | None,
    lte: str | None
):
    expr_text = sa.cast(_expr_for_attr(attr), sa.Text)
    clauses = []

    if gte is not None:
        d1 = _parse_datetime_maybe(gte)
        if d1 is None:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'invalid gte for {attr}: {gte}'}),
                content_type='application/json',
            )
        clauses.append(sa.cast(expr_text, sa.DateTime(timezone=True)) >= d1)

    if lte is not None:
        d2 = _parse_datetime_maybe(lte)
        if d2 is None:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'invalid lte for {attr}: {lte}'}),
                content_type='application/json',
            )
        clauses.append(sa.cast(expr_text, sa.DateTime(timezone=True)) <= d2)

    return sa.and_(*clauses) if clauses else sa.true()


def _pred_cmp(
    attr: str,
    op: str,
    value: typing.Any
):
    if attr == 'finding.severity':
        attr = 'data.severity'

    if attr == 'data.severity':
        left = _severity_rank_case(attr)
        key = str(value).upper()
        if key not in _SEV_ORDER:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'unknown severity {value=}'}),
                content_type='application/json',
            )
        right = _SEV_ORDER[key]
    else:
        left = sa.cast(_expr_for_attr(attr), sa.Text)
        right = str(value)

    if op == '>=': return left >= right
    if op == '>':  return left >  right
    if op == '<=': return left <= right
    if op == '<':  return left <  right
    if op == '!=': return left != right
    if op in ('==', '='): return left == right

    raise aiohttp.web.HTTPBadRequest(
        text=json.dumps({'error': f'unsupported cmp {op=}'}),
        content_type='application/json',
    )


def _pred_for_artefact_metadata(e: dict) -> sa.sql.ClauseElement:
    '''
    entry example:
      {type:'artefact-metadata', attr:'type', value:'finding/vulnerability'}
      {type:'artefact-metadata', attr:'data.cve', value:'CVE-2024-*'}
      {type:'artefact-metadata', attr:'meta.creation_date', op:'range', gte:'..', lte:'..'}
      {type:'artefact-metadata', attr:'data.severity', op:'cmp', cmp:'>=', value:'MEDIUM'}
      {type:'artefact-metadata', attr:'data.cve', op:'in', values:['CVE-1','CVE-2']}
    '''
    attr = e.get('attr')
    if not attr:
        raise aiohttp.web.HTTPBadRequest(
            text=json.dumps({'error': 'artefact-metadata missing "attr"'}),
            content_type='application/json',
        )

    op = (e.get('op') or 'eq').lower()

    if op == 'eq':
        if 'value' not in e:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'missing value for attr {attr=}'}),
                content_type='application/json',
            )
        return _pred_eq(attr, e['value'])

    if op == 'in':
        vals = e.get('values')
        if not isinstance(vals, list) or not vals:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'op=in requires non-empty values for {attr=}'}),
                content_type='application/json',
            )
        return _pred_in(attr, vals)

    if op == 'range':
        return _pred_range(attr, e.get('gte'), e.get('lte'))

    if op == 'cmp':
        cmp_op = e.get('cmp')
        if not cmp_op or 'value' not in e:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'op=cmp requires cmp and value for {attr=}'}),
                content_type='application/json',
            )
        return _pred_cmp(attr, cmp_op, e['value'])

    raise aiohttp.web.HTTPBadRequest(
        text=json.dumps({'error': f'unsupported {op=} for {attr=}'}),
        content_type='application/json',
    )


def _is_exclude(e: dict) -> bool:
    return str(e.get('mode') or '').lower() == 'exclude'


def _translate_criteria(
    criteria: list[dict],
    default_search_fields: list[str] | None = None,
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

    Supported entry shapes:
      - {type:'ocm', value:'acme.org/x:1.2.3', mode:'exclude'?}
      - {type:'artefact-metadata', attr:'data.cve', op:'eq|in|cmp|range', ... , mode:'exclude'?}
      - {type:'fulltext', value:'kerberos', mode:'exclude'?, fields:[... optional ...]}
    '''
    if not criteria:
        return sa.true()

    if not isinstance(criteria, list):
        raise aiohttp.web.HTTPBadRequest(
            text=json.dumps({'error': '"criteria" must be a list'}),
            content_type='application/json',
        )

    default_fields = default_search_fields or _DEFAULT_SEARCH_FIELDS

    ands: list[sa.sql.ClauseElement] = []

    ocm_inc: list[sa.sql.ClauseElement] = []
    ocm_exc: list[sa.sql.ClauseElement] = []

    for e in criteria:
        if not isinstance(e, dict):
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': 'each criteria entry must be an object'}),
                content_type='application/json',
            )

        if e.get('type') != 'ocm':
            continue

        if 'value' not in e:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': 'ocm entry missing "value"'}),
                content_type='application/json',
            )

        pred = _pred_ocm(e['value'])
        (ocm_exc if _is_exclude(e) else ocm_inc).append(pred)

    if ocm_inc:
        ands.append(sa.or_(*ocm_inc))
    if ocm_exc:
        ands.append(sa.not_(sa.or_(*ocm_exc)))

    by_attr_inc: dict[str, list[sa.sql.ClauseElement]] = collections.defaultdict(list)
    by_attr_exc: dict[str, list[sa.sql.ClauseElement]] = collections.defaultdict(list)

    for e in criteria:
        if e.get('type') != 'artefact-metadata':
            continue

        attr = e.get('attr')
        if not attr:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': 'artefact-metadata entry missing "attr"'}),
                content_type='application/json',
            )

        pred = _pred_for_artefact_metadata(e)
        (by_attr_exc if _is_exclude(e) else by_attr_inc)[attr].append(pred)

    # includes: AND over attrs, each attr is OR over values
    for attr, preds in by_attr_inc.items():
        if preds:
            ands.append(sa.or_(*preds))

    # excludes: AND over attrs, each attr is NOT(OR over values)
    for attr, preds in by_attr_exc.items():
        if preds:
            ands.append(sa.not_(sa.or_(*preds)))

    def _pred_fulltext(token: str, fields: list[str]) -> sa.sql.ClauseElement:
        tok = str(token or '').strip()
        if not tok:
            # ignore empty tokens
            return sa.true()

        # validate fields early (unknown field -> 400 via _expr_for_attr)
        preds = [_pred_like(f, tok, wrap_contains=True) for f in fields]
        return sa.or_(*preds) if preds else sa.true()

    full_inc: list[sa.sql.ClauseElement] = []
    full_exc: list[sa.sql.ClauseElement] = []

    for e in criteria:
        if e.get('type') != 'fulltext':
            continue

        if 'value' not in e:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': 'fulltext entry missing "value"'}),
                content_type='application/json',
            )

        fields = e.get('fields')
        if fields is None:
            fields = default_fields
        if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': 'fulltext "fields" must be a list of strings'}),
                content_type='application/json',
            )

        pred = _pred_fulltext(e['value'], fields)
        (full_exc if _is_exclude(e) else full_inc).append(pred)

    if full_inc:
        ands.append(sa.and_(*full_inc))

    if full_exc:
        ands.append(sa.and_(*[sa.not_(p) for p in full_exc]))

    for e in criteria:
        t = e.get('type')
        if t not in ('ocm', 'artefact-metadata', 'fulltext'):
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'unsupported criteria type "{t}"'}),
                content_type='application/json',
            )

    return sa.and_(*ands) if ands else sa.true()


def _translate_sort(sort_spec):
    order_by = []
    for s in (sort_spec or []):
        field = s.get('field')
        order = (s.get('order') or 'asc').lower()
        if field not in _SORT_COL:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'invalid sort {field=}'}),
                content_type='application/json',
            )
        col = _SORT_COL[field]()
        order_by.append(col.desc() if order == 'desc' else col.asc())
    return order_by


def _parse_cursor_value(
    field: str,
    raw
):
    if raw is None:
        return None
    if field in ('meta.creation_date', 'meta.last_update'):
        dt = _parse_datetime_maybe(raw)
        if dt is None:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'invalid cursor datetime for {field}: {raw}'}),
                content_type='application/json',
            )
        return dt
    return str(raw)


def _cursor_clause(
    sort_spec: list[dict],
    cursor: dict | None
):
    if not cursor:
        return sa.true()

    cols = []
    vals = []

    for s in sort_spec:
        field = s.get('field')
        if field not in _SORT_COL:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'invalid sort {field=}'}),
                content_type='application/json',
            )
        if field not in cursor:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': f'cursor missing field "{field}"'}),
                content_type='application/json',
            )
        cols.append(_SORT_COL[field]())
        vals.append(_parse_cursor_value(
            field=field,
            raw=cursor[field])
        )

    order = (sort_spec[0].get('order') or 'asc').lower()
    left = sa.tuple_(*cols)
    right = sa.tuple_(*vals)

    return (left < right) if order == 'desc' else (left > right)


def _make_next_cursor(
    sort_spec: list[dict],
    obj: dm.ArtefactMetaData
) -> dict:
    out = {}
    for s in sort_spec:
        field = s.get('field')
        if field == 'id':
            out['id'] = str(obj.id)
        elif field == 'meta.creation_date':
            v = None
            try:
                v = (obj.meta or {}).get('creation_date')
            except Exception:
                v = None
            out['meta.creation_date'] = v
        elif field == 'meta.last_update':
            v = None
            try:
                v = (obj.meta or {}).get('last_update')
            except Exception:
                v = None
            out['meta.last_update'] = v
        elif field == 'type':
            out['type'] = str(obj.type)
        elif field == 'ocm.name':
            out['ocm.name'] = str(obj.component_name)
        elif field == 'ocm.version':
            out['ocm.version'] = str(obj.component_version)
        else:
            out[field] = None
    return out


class ArtefactMetadataSearchFields(aiohttp.web.View):
    async def options(self):
        return aiohttp.web.Response()

    async def get(self):
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

        default_search_fields = [
            'data.summary',
            'data.cve',
            'data.package_name',
            'data.package_version',
            'artefact.name',
            'ocm.name',
        ]

        return aiohttp.web.json_response({
            'fields': fields,
            'defaultSearchFields': default_search_fields,
        })


class ArtefactMetadataSearchRun(aiohttp.web.View):
    async def options(self):
        return aiohttp.web.Response()

    async def post(self):
        '''
        POST /artefacts/metadata/search-run

        Body:{
          'criteria': [
            {'type':'ocm','value':'acme.org/my-component:v1.2'},
            {'type':'ocm','value':'acme.org/another-component'},
            {'type':'ocm','value':'acme.org/another-component:unwanted','mode':'exclude'},

            {'type':'artefact-metadata','attr':'type','value':'finding/vulnerability'},
            {'type':'artefact-metadata','attr':'data.cve','value':'CVE-2024-*'},
            {'type':'artefact-metadata','attr':'data.severity','op':'cmp','cmp':'>=','value':'MEDIUM'}
        ],
            'limit': 50,
            "sort": [{"field":"meta.creation_date","order":"desc"},{"field":"id","order":"desc"}],
            "cursor": {"meta.creation_date":"2025-11-03T12:34:56Z","id":"..."}
        }
        '''
        body = await self.request.json()
        db_session: sqlasync.session.AsyncSession = self.request[consts.REQUEST_DB_SESSION]
        finding_cfgs = self.request.app[consts.APP_FINDING_CFGS]

        if 'offset' in body:
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': 'offset/paging is not supported (use cursor + limit)'}),
                content_type='application/json',
            )

        criteria = body.get('criteria') or []
        if not isinstance(criteria, list):
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': '"criteria" must be a list'}),
                content_type='application/json',
            )

        # page size (50 default)
        limit = int(body.get('limit', 50))
        limit = max(1, min(limit, 200))  # hard cap per page

        sort = body.get('sort') or [{'field': 'meta.creation_date', 'order': 'desc'}]

        # stable ordering: always add id as tie-breaker
        if not any((s.get('field') == 'id') for s in sort):
            sort = [*sort, {'field': 'id', 'order': (sort[0].get('order') or 'desc')}]

        cursor = body.get('cursor')  # may be None
        if cursor is not None and not isinstance(cursor, dict):
            raise aiohttp.web.HTTPBadRequest(
                text=json.dumps({'error': '"cursor" must be an object'}),
                content_type='application/json',
            )

        base_where = _translate_criteria(criteria)
        order_by = _translate_sort(sort)

        # overfetch so we can still fill a page after cfg-filtering
        RAW_BATCH = min(2000, limit * 10)
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
                    if len(items) >= limit:
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


class ArtefactBlob(aiohttp.web.View):
    async def get(self):
        '''
        ---
        description:
          Returns a requested artefact (from a OCM Component) as an octet-stream. This route is
          limited to artefacts with `localBlob` as access-type. If artefact is not specified
          unambiguously, the first match will be used.
        tags:
        - Artefacts
        produces:
        - application/octet-stream
        parameters:
        - in: query
          name: component
          type: string
          required: true
          description: component-name:component-version
        - in: query
          name: artefact
          type: string
          required: true
          description: |
            has two forms:
            1. str - interpreted as `name` attribute
            2. json (object) - str-to-str mapping for attributes
        - in: query
          name: ocm_repository
          type: string
          required: false
          description: ocm-repository-url
        - in: query
          name: unzip
          type: boolean
          required: false
          default: true
          description:
            if true and artefact's access is gzipped, returned content will be unzipped (for
            convenience)
        '''
        params = self.request.rel_url.query

        component_id = util.param(params, 'component', required=True)
        if component_id.count(':') != 1:
            raise aiohttp.web.HTTPBadRequest(text='Malformed component-id')

        artefact = util.param(params, 'artefact', required=True).strip()
        if artefact.startswith('{'):
            artefact = json.loads(artefact)

            # special-handling for name/version (should refactor in ocm)
            artefact_name = artefact.pop('name', None)
            artefact_version = artefact.pop('version', None)
        elif artefact.startswith('['):
            raise aiohttp.web.HTTPBadRequest(
                text='Bad artefact: Either name or json-object is allowed',
            )
        else:
            artefact_name = artefact
            artefact = {}
            artefact_version = None

        ocm_repository = util.param(params, 'ocm_repository')
        unzip = util.param_as_bool(params, 'unzip', default=True)

        component_descriptor_lookup = self.request.app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP]

        try:
            component_descriptor = await component_descriptor_lookup(
                component_id,
                ocm_repository_lookup=lookups.init_ocm_repository_lookup(ocm_repository),
            )
            component = component_descriptor.component
        except oci.model.OciImageNotFoundException:
            raise aiohttp.web.HTTPBadRequest(text=f'Did not find {component_id=}')

        def matches(a: ocm.Artifact):
            if artefact_name and artefact_name != a.name:
                return False
            if artefact_version and artefact_version != a.version:
                return False

            for attr, value in artefact.items():
                if a.extraIdentity.get(attr) != value:
                    return False

            return True

        for a in component.iter_artefacts():
            if matches(a):
                break
        else:
            raise aiohttp.web.HTTPBadRequest(text='Did not find requested artefact')

        artefact = a
        access = artefact.access

        if not isinstance(access, ocm.LocalBlobAccess):
            raise aiohttp.web.HTTPBadRequest(
                text=f'{artefact.name=} has {access.type=}; only localBlobAccess is supported',
            )

        access: ocm.LocalBlobAccess
        digest = access.globalAccess.digest if access.globalAccess else access.localReference

        oci_client = self.request.app[consts.APP_OCI_CLIENT]
        blob = await oci_client.blob(
            image_reference=component.current_ocm_repo.component_oci_ref(component),
            digest=digest,
            absent_ok=True,
        )

        if access.mediaType == 'application/pdf':
            file_ending = '.pdf'
        elif access.mediaType == 'application/tar+gzip':
            file_ending = '.tar.gz'
        elif access.mediaType == 'application/tar':
            file_ending = '.tar'
        else:
            file_ending = ''

        fname = f'{component.name}_{component.version}_{artefact.name}{file_ending}'

        if unzip and access.mediaType == 'application/gzip':
            response = aiohttp.web.StreamResponse(
                headers={
                    'Content-Type': artefact.type,
                    'Content-Disposition': f'attachment; filename="{fname}"',
                },
            )
            await response.prepare(self.request)

            decompressor = zlib.decompressobj(wbits=31)
            async for chunk in blob.content.iter_chunked(4096):
                await response.write(decompressor.decompress(chunk))
            await response.write(decompressor.flush())
        else:
            response = aiohttp.web.StreamResponse(
                headers={
                    'Content-Type': access.mediaType,
                    'Content-Disposition': f'attachment; filename="{fname}"',
                },
            )
            await response.prepare(self.request)

            async for chunk in blob.content.iter_chunked(4096):
                await response.write(chunk)

        await response.write_eof()
        return response
