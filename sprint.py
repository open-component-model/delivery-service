import datetime

import aiohttp.web
import dateutil.parser

import consts
import features
import util
import yp


def current_sprint(
    sprints: list[yp.Sprint],
    offset: int=0,
    ref_date: datetime.datetime=None,
):
    '''
    returns the "current sprint" from the given list of sprints. The list of sprints is
    assumed to be ordered chronologically, with the newest one being at the beginning.
    the current sprint is determined as the one precedeeding the newest sprint whose
    end-date is in the past (compared to "today" according to system-time or passed-in
    reference-date). If the end-date of a sprint is identical to "today" (or reference-date), it
    is considered to still be the current sprint.

    if offset is set, the sprint returned is calculated relative (in full sprints) to the current
    one. For example, an offset of +1 will return the next sprint, whereas -1 will return the
    previous one.

    note that date-operations are not timezone-aware, which is believed to be "good enough"
    '''
    if not ref_date:
        ref_date = datetime.datetime.today()

    if offset: # need to invert offset, as sprints are ordered chronologically
        offset = - offset

    for idx, sprint in enumerate(sprints):
        if sprint.end_date.date() > ref_date.date():
            continue
        if sprint.end_date.date() == ref_date.date():
            return sprint
        # if this line is reached, current sprint has already ended, so its predecessor is the
        # current one (edge-case: there is no such sprint)
        if idx == 0:
            raise aiohttp.web.HTTPBadRequest(
                reason='No sprint found',
                text=f'All sprints ended before {ref_date.date()=}',
            )

        return sprints[idx - 1 + offset]
    raise aiohttp.web.HTTPBadRequest(
        reason='No sprint found',
        text=f'All sprints started after {ref_date=}',
    )


class SprintInfos(aiohttp.web.View):
    required_features = (features.FeatureSprints,)

    async def get(self):
        '''
        ---
        tags:
        - Sprints
        produces:
        - application/json
        responses:
          "200":
            description: Successful operation.
            schema:
              type: object
              required:
              - sprints
              properties:
                sprints:
                  type: array
                  items:
                    $ref: '#/definitions/Sprint'
        '''
        sprints_metadata = self.request.app[consts.APP_SPRINTS_METADATA]
        sprints = self.request.app[consts.APP_SPRINTS]

        return aiohttp.web.json_response(
            data={
                'sprints': [
                    sprint.asdict(meta=sprints_metadata)
                    for sprint in sprints
                ],
            },
            dumps=util.dict_to_json_factory,
        )


class SprintInfosCurrent(aiohttp.web.View):
    required_features = (features.FeatureSprints,)

    async def get(self):
        '''
        ---
        description:
          Returns the "current" sprint infos, optionally considering passed query-params. The
          current sprint is (by default, i.e. no arguments) the sprint whose end_date is either the
          current day, or the nearest day (in chronological sense) from today, considering only
          future sprints. If both `offset` and `before` are given, offset is applied after
          calculating "current" sprint.
        tags:
        - Sprints
        produces:
        - application/json
        parameters:
        - in: query
          name: offset
          type: integer
          required: false
          default: 0
          description:
            If set, the returned sprint is offset by given amount of sprints (positive value will
            yield future sprints, while negative numbers will yield past ones).
        - in: query
          name: before
          type: string
          required: false
          description:
            If set, the returned sprint is calculated setting "today" to the specified date.
        responses:
          "200":
            description: Successful operation.
            schema:
              $ref: '#/definitions/Sprint'
        '''
        params = self.request.rel_url.query

        offset = int(util.param(params, 'offset', default=0))
        before = util.param(params, 'before')
        if before:
            try:
                before = dateutil.parser.isoparse(before)
            except ValueError:
                raise aiohttp.web.HTTPBadRequest(text='Invalid date format')

        sprints_metadata = self.request.app[consts.APP_SPRINTS_METADATA]
        sprints = self.request.app[consts.APP_SPRINTS]

        current = current_sprint(
            sprints=sprints,
            offset=offset,
            ref_date=before,
        )

        return aiohttp.web.json_response(
            data=current.asdict(meta=sprints_metadata),
            dumps=util.dict_to_json_factory,
        )
