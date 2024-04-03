import typing

import features


class ShortcutRoutesWithUnavailableFeatures:
    '''
    Used to catch requests that require features which are unavailable. Returns a
    response with status code 400 and a list of the missing features.
    '''
    def __init__(
        self,
        unavailable_features: typing.Iterable[features.FeatureBase],
    ):
        self.unavailable_features = self.getFeatureNameSet(unavailable_features)

    @staticmethod
    def getFeatureNameSet(
        feature_list: typing.Iterable[features.FeatureBase],
    ) -> set[str]:
        return set([f.name for f in feature_list])

    def process_resource(self, req, resp, resource, params):
        if not (required_features := getattr(resource, 'required_features', False)):
            # no features required
            return

        if req.method == 'OPTIONS':
            return

        if (missing_features := self.getFeatureNameSet(required_features)
            & self.unavailable_features):
            resp.complete = True
            resp.status = 400
            resp.media = {
                'error_id': 'feature-inactive',
                'missing_features': list(missing_features)
            }
