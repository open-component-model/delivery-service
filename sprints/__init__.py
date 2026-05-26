import datetime

import aiohttp.web
import dateutil.parser

import consts
import sprints.util as su
import util as utility


class SprintInfos(aiohttp.web.View):
    async def get(self):
        """
        ---
        tags:
        - Sprints
        responses:
          "200":
            description: Successful operation.
            content:
              application/json:
                schema:
                  type: object
                  required:
                  - sprints
                  properties:
                    sprints:
                      type: array
                      items:
                        $ref: '#/components/schemas/Sprint'
        """
        sprints_configuration = self.request.app[consts.APP_SPRINTS_CONFIGURATION]

        return aiohttp.web.json_response(
            data={
                'sprints': sprints_configuration.sprints if sprints_configuration else [],
            },
            dumps=utility.dict_to_json_factory,
        )


class SprintInfosCurrent(aiohttp.web.View):
    async def get(self):
        """
        ---
        description:
          Returns the "current" sprint infos, optionally considering passed query-params. The
          current sprint is (by default, i.e. no arguments) the sprint whose end_date is either the
          current day, or the nearest day (in chronological sense) from today, considering only
          future sprints. If both `offset` and `before` are given, offset is applied after
          calculating "current" sprint.
        tags:
        - Sprints
        parameters:
        - in: query
          name: offset
          required: false
          schema:
            type: integer
            default: 0
          description:
            If set, the returned sprint is offset by given amount of sprints (positive value will
            yield future sprints, while negative numbers will yield past ones).
        - in: query
          name: before
          required: false
          schema:
            type: string
          description:
            If set, the returned sprint is calculated setting "today" to the specified date.
        responses:
          "200":
            description: Successful operation.
            content:
              application/json:
                schema:
                  $ref: '#/components/schemas/Sprint'
        """
        params = self.request.rel_url.query

        try:
            offset = int(utility.param(params, 'offset', default=0))
        except (TypeError, ValueError):
            raise aiohttp.web.HTTPBadRequest(text='Invalid offset')

        if ref_date_raw := utility.param(params, 'before'):
            try:
                ref_date = dateutil.parser.isoparse(ref_date_raw).date()
            except ValueError:
                raise aiohttp.web.HTTPBadRequest(text='Invalid date format')
        else:
            ref_date = datetime.date.today()

        sprints_configuration = self.request.app[consts.APP_SPRINTS_CONFIGURATION]

        current_sprint = su.find_sprint_for_ref_date(
            ref_date=ref_date,
            sprints=sprints_configuration.sprints if sprints_configuration else None,
            sprint_assignment_offset=offset,
        )

        if not current_sprint:
            raise aiohttp.web.HTTPBadRequest(
                reason='No sprint found',
                text=f'No sprint found for {ref_date=}',
            )

        return aiohttp.web.json_response(
            data=current_sprint,
            dumps=utility.dict_to_json_factory,
        )
