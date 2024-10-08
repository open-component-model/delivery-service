import io
import logging
import zipfile

import aiohttp.web

import ci.log

import consts
import features
import util


ci.log.configure_default_logging()
logger = logging.getLogger(__name__)


class DownloadTestResults(aiohttp.web.View):
    required_features = (features.FeatureTests,)

    async def get(self):
        '''
        ---
        description: Downloads the zipped test results for the specified component release.
        tags:
        - Components
        produces:
        - application/zip
        parameters:
        - in: query
          name: componentName
          type: string
          required: true
        - in: query
          name: componentVersion
          type: string
          required: true
        '''
        params = self.request.rel_url.query

        component_name = util.param(params, 'componentName', required=True)
        component_version = util.param(params, 'componentVersion', required=True)

        # todo: lookup repository in component-descriptor
        gh_api = self.request.app[consts.APP_GITHUB_API_LOOKUP](component_name)
        repo = self.request.app[consts.APP_GITHUB_REPO_LOOKUP](component_name)

        release = repo.release_from_tag(component_version)
        assets = release.assets()

        # todo: use streaming
        zip_buffer = io.BytesIO()
        zipf = zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED)

        component_with_tests_callback = self.request.app[consts.APP_COMPONENT_WITH_TESTS_CALLBACK]
        component_with_tests = component_with_tests_callback(component_name)

        if not component_with_tests:
            raise aiohttp.web.HTTPBadRequest

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

        response = aiohttp.web.Response(
            body=zip_buffer.getvalue(),
            content_type='application/zip',
        )

        fname = f'{component_with_tests.downloadableName}_{component_version}.zip'
        response.headers.add('Content-Disposition', f'attachment; filename="{fname}"')

        return response
