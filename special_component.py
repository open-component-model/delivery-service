import aiohttp.web

import consts
import deliverydb.cache
import features
import util


class CurrentDependencies(aiohttp.web.View):
    required_features = (features.FeatureSpecialComponents,)

    @deliverydb.cache.dbcached_route()
    async def get(self):
        '''
        ---
        tags:
        - Components
        produces:
        - application/json
        parameters:
        - in: query
          name: component_name
          type: string
          required: true
        '''
        params = self.request.rel_url.query

        component_name = util.param(params, 'component_name', required=True)
        component_cfg = self.request.app[consts.APP_SPECIAL_COMPONENT_CALLBACK](
            component_name=component_name,
        )

        if not component_cfg:
            return aiohttp.web.json_response(
                data={},
            )

        github_api_lookup = self.request.app[consts.APP_GITHUB_API_LOOKUP]

        resolved_dependencies = []
        for dependency in component_cfg.dependencies or []:
            resolved_dependency = {
                'name': dependency.name,
                'displayName': dependency.displayName,
            }
            if (dependency.currentVersion):
                resolved_dependency['version'] = dependency.currentVersion.retrieve(
                    github_api_lookup=github_api_lookup,
                )
            resolved_dependencies.append(resolved_dependency)

        resp_media = {
            'displayName': component_cfg.displayName,
            'component_dependencies': resolved_dependencies
        }
        if component_cfg.currentVersion:
            resp_media['version'] = component_cfg.currentVersion.retrieve(
                github_api_lookup=github_api_lookup,
            )

        return aiohttp.web.json_response(
            data=resp_media,
        )
