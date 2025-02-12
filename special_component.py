import aiohttp.web

import consts
import features
import util


class CurrentDependencies(aiohttp.web.View):
    required_features = (features.FeatureSpecialComponents,)

    async def get(self):
        '''
        ---
        tags:
        - Components
        produces:
        - application/json
        parameters:
        - in: query
          name: id
          type: string
          required: true
        '''
        params = self.request.rel_url.query

        id = util.param(params, 'id', required=True)

        component_cfg = self.request.app[consts.APP_SPECIAL_COMPONENT_CALLBACK](id)

        if not component_cfg:
            return aiohttp.web.json_response(
                data={},
            )

        github_api_lookup = self.request.app[consts.APP_GITHUB_API_LOOKUP]

        resolved_dependencies = [
            {
                'name': dependency.name,
                'displayName': dependency.displayName,
                'version': (
                    dependency.currentVersion.retrieve(github_api_lookup)
                    if dependency.currentVersion
                    else None
                ),
            } for dependency in component_cfg.dependencies
        ]

        return aiohttp.web.json_response(
            data={
                'displayName': component_cfg.displayName,
                'componentDependencies': resolved_dependencies,
                'version': (
                    component_cfg.currentVersion.retrieve(github_api_lookup)
                    if component_cfg.currentVersion
                    else None
                ),
            },
        )
