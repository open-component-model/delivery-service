import datetime
import dateutil.parser

import falcon

import features
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
            # pylint: disable=E1101
            raise falcon.HTTPBadRequest(
                title='no sprint found',
                description=f'all sprints ended before {ref_date.date()=}',
            )

        return sprints[idx - 1 + offset]
    # pylint: disable=E1101
    raise falcon.HTTPBadRequest(
        title='no sprint found',
        description=f'all sprints started after {ref_date=}',
    )


class SprintInfos:
    required_features = (features.FeatureSprints,)

    def __init__(
        self,
        sprints_repo_callback,
        sprints_relpath_callback,
        sprint_date_display_name_callback,
    ):
        self.sprints_repo_callback = sprints_repo_callback
        self.sprints_relpath_callback = sprints_relpath_callback
        self.sprint_date_display_name_callback = sprint_date_display_name_callback

    def on_get(self, req, resp):
        sprints = yp._sprints(
            repo=self.sprints_repo_callback(),
            sprints_file_relpath=self.sprints_relpath_callback(),
        )
        sprints_meta = yp._sprints_metadata(
            repo=self.sprints_repo_callback(),
            sprints_file_relpath=self.sprints_relpath_callback(),
        )

        resp.media = {
            'sprints': [
                sprint.asdict(
                    sprint_date_display_name_callback=self.sprint_date_display_name_callback,
                    meta=sprints_meta,
                )
                for sprint in sprints
            ]
        }

    def on_get_current(self, req: falcon.Request, resp):
        '''
        returns the "current" sprint infos, optionally considering passed query-params.

        The current sprint is (by default, i.e. no arguments) the sprint whose end_date is either
        the current day, or the nearest day (in chronological sense) from today, considering only
        future sprints.

        **expected query parameters:**

            offset: <int>; if set, the returned sprint is offset by given amount of sprints \n
                    (positive value will yield future sprints, while negative numbers will yield \n
                    past ones) \n
            before: <str(iso8601-date)>; if set, the returned sprint is calculated setting "today" \n
                    to the specified date

        If both `offset` and `before` are given, offset is applied after calculating "current"
        sprint.

        **response:**

            name: <str> e.g. "2304b" \n
            dates: \n
            - name: <str> e.g. "rtc" \n
              display_name: <str> e.g. "Release To Customer" \n
              value: <iso8601-date-str> \n
        '''
        sprints = yp._sprints(
            repo=self.sprints_repo_callback(),
            sprints_file_relpath=self.sprints_relpath_callback(),
        )
        sprints_meta = yp._sprints_metadata(
            repo=self.sprints_repo_callback(),
            sprints_file_relpath=self.sprints_relpath_callback(),
        )

        offset = req.get_param_as_int('offset', default=0)
        before = req.get_param('before')
        if before:
            try:
                before = dateutil.parser.isoparse(before)
            except ValueError:
                # pylint: disable=E1101
                raise falcon.HTTPBadRequest(title='invalid date format')

        current = current_sprint(
            sprints=sprints,
            offset=offset,
            ref_date=before,
        )

        resp.media = current.asdict(
            sprint_date_display_name_callback=self.sprint_date_display_name_callback,
            meta=sprints_meta,
        )
