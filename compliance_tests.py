import logging
import falcon

import zipfile
import io

import features
import lookups
import ci.log


ci.log.configure_default_logging()
logger = logging.getLogger(__name__)


class DownloadTestResults:
    required_features = (features.FeatureTests,)

    def __init__(
        self,
        component_with_tests_callback,
        github_api_lookup,
    ):
        self.component_with_tests_callback = component_with_tests_callback
        self.github_api_lookup = github_api_lookup

    def on_get(
        self,
        req: falcon.Request,
        resp: falcon.Response,
    ):
        """
        Downloads the zipped test results for the specified component release
        """

        component_name: str = req.get_param('componentName', required=True)
        component_version: str = req.get_param('componentVersion', required=True)

        github_repo_lookup = lookups.github_repo_lookup(self.github_api_lookup)

        # todo: lookup repository in component-descriptor
        gh_api = self.github_api_lookup(
            component_name,
        )
        repo = github_repo_lookup(component_name)

        release = repo.release_from_tag(component_version)
        assets = release.assets()

        # todo: use streaming
        zip_buffer = io.BytesIO()
        zipf = zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED)

        component_with_tests = self.component_with_tests_callback(component_name)

        if not component_with_tests:
            raise falcon.HTTPBadRequest()

        for asset in assets:
            # only add test assets that are prefixed like configured in the features config
            if not asset.name.startswith(tuple(component_with_tests.assetNamePrefixes)):
                continue

            logger.debug(f'add test file {asset.name}')
            with gh_api._get(
                asset.download_url,
                headers={
                    'Accept': 'application/octet-stream',
                },
                allow_redirects=True,
            ) as assetResp:

                if assetResp.headers['Content-Type'] not in ['application/octet-stream']:
                    content_type = assetResp.headers['Content-Type']
                    logger.debug(f'unknown content type {content_type} for asset {asset.name}')
                    continue

                zipf.writestr(
                    data=assetResp.content,
                    zinfo_or_arcname=asset.name,
                )

        zipf.close()
        resp.content_type = 'application/zip'
        resp.downloadable_as = f'{component_with_tests.downloadableName}_{component_version}.zip'
        resp.data = zip_buffer.getvalue()
