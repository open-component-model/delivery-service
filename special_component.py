import aiohttp.web

import consts
import features
import util


class CurrentDependencies(aiohttp.web.View):
    required_features = (features.FeatureSpecialComponents,)

    async def get(self):
        """
        ---
        tags:
        - Components
        parameters:
        - in: query
          name: id
          required: true
          schema:
            type: string
        responses:
          "200":
            description: Success
            content:
              application/json:
                schema:
                  type: object
        """
        params = self.request.rel_url.query

        id = util.param(params, 'id', required=True)

        component_cfg = self.request.app[consts.APP_SPECIAL_COMPONENT_CALLBACK](id)

        if not component_cfg:
            return aiohttp.web.json_response(
                data={},
            )

        resolved_dependencies = [
            {
                'name': dependency.name,
                'displayName': dependency.displayName,
                'version': (
                    dependency.currentVersion.retrieve() if dependency.currentVersion else None
                ),
            }
            for dependency in component_cfg.dependencies
        ]

        return aiohttp.web.json_response(
            data={
                'displayName': component_cfg.displayName,
                'componentDependencies': resolved_dependencies,
                'version': (
                    component_cfg.currentVersion.retrieve() if component_cfg.currentVersion else None
                ),
            },
        )
