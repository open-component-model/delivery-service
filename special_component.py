import falcon

import features


class CurrentDependencies():
    required_features = (features.FeatureSpecialComponents,)

    def __init__(
        self,
        special_component_callback,
        github_api_lookup,
    ):
        self.special_component_callback = special_component_callback
        self.github_api_lookup = github_api_lookup

    def on_get(self, req: falcon.Request, resp: falcon.Response):
        component_name = req.get_param('component_name', True)
        component_cfg = self.special_component_callback(component_name=component_name)

        if not component_cfg:
            resp.media = {}
            return

        resolved_dependencies = []
        for dependency in component_cfg.dependencies or []:
            resolved_dependency = {
                'name': dependency.name,
                'displayName': dependency.displayName,
            }
            if (dependency.currentVersion):
                resolved_dependency['version'] = dependency.currentVersion.retrieve(
                    github_api_lookup=self.github_api_lookup,
                )
            resolved_dependencies.append(resolved_dependency)

        resp_media = {
            'displayName': component_cfg.displayName,
            'component_dependencies': resolved_dependencies
        }
        if component_cfg.currentVersion:
            resp_media['version'] = component_cfg.currentVersion.retrieve(
                github_api_lookup=self.github_api_lookup,
            )
        resp.media = resp_media
