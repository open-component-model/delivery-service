#!/usr/bin/env python3
import argparse
import asyncio
import concurrent.futures
import logging
import os

import aiohttp.web
import aiohttp_swagger
import yaml

import ci.log
import ci.util

import artefacts
import compliance_tests
import compliance_summary as cs
import components
import consts
import ctx_util
import deliverydb.cache
import dora
import eol
import features
import k8s.util
import lookups
import metadata
import middleware.auth
import middleware.cors
import middleware.errors
import middleware.prometheus
import middleware.route_feature_check as rfc
import osinfo
import paths
import rescore.artefacts
import rescore.model as rm
import secret_mgmt
import service_extensions
import special_component
import sprint


ci.log.configure_default_logging(print_thread_id=True)
logger = logging.getLogger(__name__)

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--productive', action='store_true', default=False)
    parser.add_argument('--port', default=5000, type=int)
    parser.add_argument('--max-workers', default=4, type=int)
    parser.add_argument('--shortcut-auth', action='store_true', default=False)
    parser.add_argument('--delivery-db-cfg', default='internal')
    parser.add_argument('--delivery-db-url', default=None)
    parser.add_argument('--cache-dir', default=default_cache_dir)
    parser.add_argument(
        '--invalid-semver-ok',
        action='store_true',
        default=False,
        help='whether to raise on invalid (semver) version when resolving greatest version',
    )
    parser.add_argument(
        '--k8s-cfg-name',
        help='specify kubernetes cluster to interact with extensions (and logs)',
    )
    parser.add_argument(
        '--kubeconfig',
        help='''
            specify kubernetes cluster to interact with extensions (and logs); if both
            `k8s-cfg-name` and `kubeconfig` are set, `k8s-cfg-name` takes precedence
        ''',
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with extensions (and logs)',
    )

    return parser.parse_args()


def get_base_url(
    is_productive: bool,
    kubernetes_api: k8s.util.KubernetesApi | None=None,
    namespace: str | None=None,
    port: int | None=None,
) -> str:
    if not is_productive:
        return f'http://localhost:{port}'

    ingress = kubernetes_api.networking_kubernetes_api.read_namespaced_ingress(
        name='delivery-service',
        namespace=namespace,
    )
    host = ingress.spec.rules[0].host

    return f'https://{host}'


def add_app_context_vars(
    app: aiohttp.web.Application,
    secret_factory: secret_mgmt.SecretFactory,
    parsed_arguments,
) -> aiohttp.web.Application:
    oci_client = lookups.semver_sanitising_oci_client_async(secret_factory)

    version_lookup = lookups.init_version_lookup_async(
        oci_client=oci_client,
        default_absent_ok=True,
    )

    delivery_db_feature = features.get_feature(features.FeatureDeliveryDB)
    if delivery_db_feature.state is features.FeatureStates.AVAILABLE:
        delivery_db_feature: features.FeatureDeliveryDB
        db_url = delivery_db_feature.db_url
    else:
        db_url = None

    component_descriptor_lookup = lookups.init_component_descriptor_lookup_async(
        cache_dir=parsed_arguments.cache_dir,
        db_url=db_url,
        oci_client=oci_client,
    )

    github_api_lookup = lookups.github_api_lookup(secret_factory)
    github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)

    addressbook_feature = features.get_feature(features.FeatureAddressbook)
    if addressbook_feature.state is features.FeatureStates.AVAILABLE:
        addressbook_feature: features.FeatureAddressbook

        addressbook_entries = addressbook_feature.get_addressbook_entries()
        addressbook_github_mappings = addressbook_feature.get_github_mappings()
        addressbook_source = addressbook_feature.get_source()
    else:
        addressbook_entries = []
        addressbook_github_mappings = []
        addressbook_source = None

    artefact_metadata_cfg_by_type = cs.artefact_metadata_cfg_by_type(
        artefact_metadata_cfg=ci.util.parse_yaml_file(
            paths.artefact_metadata_cfg,
        ),
    )

    component_with_tests_callback = features.get_feature(
        features.FeatureTests,
    ).get_component_with_tests

    finding_cfgs = features.get_feature(features.FeatureFindingConfigurations).finding_cfgs
    scan_cfg = features.get_feature(features.FeatureScanConfiguration).scan_cfg

    rescoring_feature = features.get_feature(features.FeatureRescoring)
    rescoring_rule_set_lookup = rescoring_feature.find_rule_set
    default_rule_set_for_type_callback = lambda rule_set_type: (
        rm.find_default_rule_set_for_type_and_name(
            default_rule_set_ref=rm.find_default_rule_set_for_type(
                default_rule_sets=rescoring_feature.default_rule_sets,
                rule_set_type=rule_set_type,
            ),
            rule_sets=rescoring_feature.rescoring_rule_sets,
        )
    )

    service_extensions_feature = features.get_feature(features.FeatureServiceExtensions)
    kubernetes_api_callback = service_extensions_feature.get_kubernetes_api
    namespace_callback = service_extensions_feature.get_namespace

    special_component_callback = features.get_feature(
        features.FeatureSpecialComponents,
    ).get_special_component

    sprints_feature = features.get_feature(features.FeatureSprints)
    if sprints_feature.state is features.FeatureStates.AVAILABLE:
        sprints_feature: features.FeatureSprints

        sprint_date_display_name_callback = sprints_feature.get_sprint_date_display_name
        sprints = sprints_feature.get_sprints()
        sprints_metadata = sprints_feature.get_sprints_metadata()
    else:
        sprint_date_display_name_callback = None
        sprints = []
        sprints_metadata = None

    upr_regex_callback = features.get_feature(features.FeatureUpgradePRs).get_regex

    version_filter_callback = features.get_feature(
        feature_type=features.FeatureVersionFilter,
    ).get_version_filter

    base_url = get_base_url(
        is_productive=parsed_arguments.productive,
        kubernetes_api=kubernetes_api_callback(),
        namespace=namespace_callback(),
        port=parsed_arguments.port,
    )

    app[consts.APP_ADDRESSBOOK_ENTRIES] = addressbook_entries
    app[consts.APP_ADDRESSBOOK_GITHUB_MAPPINGS] = addressbook_github_mappings
    app[consts.APP_ADDRESSBOOK_SOURCE] = addressbook_source
    app[consts.APP_ARTEFACT_METADATA_CFG] = artefact_metadata_cfg_by_type
    app[consts.APP_BASE_URL] = base_url
    app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP] = component_descriptor_lookup
    app[consts.APP_COMPONENT_WITH_TESTS_CALLBACK] = component_with_tests_callback
    app[consts.APP_RESCORING_RULE_SET_LOOKUP] = rescoring_rule_set_lookup
    app[consts.APP_DEFAULT_RULE_SET_FOR_TYPE_CALLBACK] = default_rule_set_for_type_callback
    app[consts.APP_EOL_CLIENT] = eol.EolClient()
    app[consts.APP_FINDING_CFGS] = finding_cfgs
    app[consts.APP_GITHUB_API_LOOKUP] = github_api_lookup
    app[consts.APP_GITHUB_REPO_LOOKUP] = github_repo_lookup
    app[consts.APP_INVALID_SEMVER_OK] = parsed_arguments.invalid_semver_ok
    app[consts.APP_KUBERNETES_API_CALLBACK] = kubernetes_api_callback
    app[consts.APP_NAMESPACE_CALLBACK] = namespace_callback
    app[consts.APP_OCI_CLIENT] = oci_client
    app[consts.APP_SCAN_CFG] = scan_cfg
    app[consts.APP_SECRET_FACTORY] = secret_factory
    app[consts.APP_SPECIAL_COMPONENT_CALLBACK] = special_component_callback
    app[consts.APP_SPRINT_DATE_DISPLAY_NAME_CALLBACK] = sprint_date_display_name_callback
    app[consts.APP_SPRINTS] = sprints
    app[consts.APP_SPRINTS_METADATA] = sprints_metadata
    app[consts.APP_UPR_REGEX_CALLBACK] = upr_regex_callback
    app[consts.APP_VERSION_FILTER_CALLBACK] = version_filter_callback
    app[consts.APP_VERSION_LOOKUP] = version_lookup

    return app


@middleware.auth.noauth
class Ready(aiohttp.web.View):
    async def get(self):
        '''
        ---
        description: This endpoint allows to test that the service is up and running.
        tags:
        - Health check
        responses:
          "200":
            description: Service is up and running
        '''
        return aiohttp.web.Response()


def add_routes(
    app: aiohttp.web.Application,
) -> aiohttp.web.Application:
    app.router.add_view(
        path='/ready',
        handler=Ready,
    )

    app.router.add_view(
        path='/features',
        handler=features.Features,
    )

    app.router.add_view(
        path='/ocm/artefacts/blob',
        handler=artefacts.ArtefactBlob,
    )

    app.router.add_view(
        path='/artefacts/metadata',
        handler=metadata.ArtefactMetadata,
    )
    app.router.add_view(
        path='/artefacts/metadata/query',
        handler=metadata.ArtefactMetadataQuery,
    )

    app.router.add_view(
        path='/components/upgrade-prs',
        handler=components.UpgradePRs,
    )

    app.router.add_view(
        path='/components/diff',
        handler=components.ComponentDescriptorDiff,
    )

    app.router.add_view(
        path='/special-component/current-dependencies',
        handler=special_component.CurrentDependencies,
    )

    app.router.add_view(
        path='/components/tests',
        handler=compliance_tests.DownloadTestResults,
    )

    app.router.add_view(
        path='/components/compliance-summary',
        handler=components.ComplianceSummary,
    )

    app.router.add_view(
        path='/components/metadata',
        handler=components.ComponentMetadata,
    )

    app.router.add_view(
        path='/delivery/sprint-infos',
        handler=sprint.SprintInfos,
    )
    app.router.add_view(
        path='/delivery/sprint-infos/current',
        handler=sprint.SprintInfosCurrent,
    )

    app.router.add_view(
        path='/auth',
        handler=middleware.auth.OAuthLogin,
    )
    app.router.add_view(
        path='/auth/logout',
        handler=middleware.auth.OAuthLogout,
    )
    app.router.add_view(
        path='/auth/configs',
        handler=middleware.auth.OAuthCfgs,
    )

    # endpoint according to OpenID provider configuration request
    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
    app.router.add_view(
        path='/.well-known/openid-configuration',
        handler=middleware.auth.OpenIDCfg,
    )
    app.router.add_view(
        path='/openid/v1/jwks',
        handler=middleware.auth.OpenIDJwks,
    )

    app.router.add_view(
        path='/ocm/component',
        handler=components.Component,
    )
    app.router.add_view(
        path='/ocm/component/versions',
        handler=components.GreatestComponentVersions,
    )
    app.router.add_view(
        path='/ocm/component/dependencies',
        handler=components.ComponentDependencies,
    )
    app.router.add_view(
        path='/ocm/component/responsibles',
        handler=components.ComponentResponsibles,
    )
    app.router.add_view(
        path='/os/{os_id}/branches',
        handler=osinfo.OsInfoRoutes,
    )
    app.router.add_view(
        path='/rescore',
        handler=rescore.artefacts.Rescore,
    )

    app.router.add_view(
        path='/service-extensions',
        handler=service_extensions.ServiceExtensions,
    )
    app.router.add_view(
        path='/service-extensions/log-collections',
        handler=service_extensions.LogCollections,
    )
    app.router.add_view(
        path='/service-extensions/container-statuses',
        handler=service_extensions.ContainerStatuses,
    )
    app.router.add_view(
        path='/service-extensions/scan-configurations',
        handler=service_extensions.ScanConfigurations,
    )
    app.router.add_view(
        path='/service-extensions/backlog-items',
        handler=service_extensions.BacklogItems,
    )
    app.router.add_view(
        path='/service-extensions/runtime-artefacts',
        handler=service_extensions.RuntimeArtefacts,
    )
    app.router.add_view(
        path='/dora/dora-metrics',
        handler=dora.DoraMetrics,
    )
    app.router.add_view(
        path='/metrics',
        handler=middleware.prometheus.Metrics,
    )
    app.router.add_view(
        path='/cache',
        handler=deliverydb.cache.DeliveryDBCache,
    )

    return app


async def initialise_app():
    parsed_arguments = parse_args()

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=parsed_arguments.max_workers)
    loop = asyncio.get_running_loop()
    loop.set_default_executor(executor)

    secret_factory = ctx_util.secret_factory()

    middlewares = [
        middleware.cors.cors_middleware(),
        middleware.errors.errors_middleware(),
    ]

    middlewares = await features.init_features(
        parsed_arguments=parsed_arguments,
        secret_factory=secret_factory,
        middlewares=middlewares,
    )

    if (unavailable_features := tuple(
        f for f in features.feature_cfgs
        if f.state is features.FeatureStates.UNAVAILABLE
    )):
        logger.info(
            f'The following feature{"s are" if len(unavailable_features) != 1 else " is"} '
            f'inactive: {", ".join(f.name for f in unavailable_features)}'
        )
        middlewares.append(rfc.feature_check_middleware(unavailable_features))

    app = aiohttp.web.Application(
        middlewares=middlewares,
        client_max_size=0, # max request body size is already configured via ingress
    )

    app = middleware.prometheus.add_prometheus_middleware(app=app)

    app = add_app_context_vars(
        app=app,
        secret_factory=secret_factory,
        parsed_arguments=parsed_arguments,
    )

    app = add_routes(
        app=app,
    )

    api_definitions = yaml.safe_load(open(paths.swagger_path)).get('definitions')

    aiohttp_swagger.setup_swagger(
        app=app,
        swagger_url='/api/v1/doc',
        description='API definition',
        title='Delivery-Service by Gardener CICD',
        definitions=api_definitions,
    )

    return app


async def run_app():
    parsed_arguments = parse_args()

    port = parsed_arguments.port

    app = await initialise_app()

    if parsed_arguments.productive:
        host = '0.0.0.0'

    else:
        host = '127.0.0.1'
        print('running in development mode')
        print()
        print(f'listening at {host}:{port}')
        print()

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    await aiohttp.web.TCPSite(
        runner=runner,
        host=host,
        port=port,
    ).start()

    await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(run_app())
else:
    app = initialise_app
