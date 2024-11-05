#!/usr/bin/env python3
import argparse
import asyncio
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
import dora
import eol
import features
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
import service_extensions
import special_component
import sprint
import util


ci.log.configure_default_logging(print_thread_id=True)
logger = logging.getLogger(__name__)

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--productive', action='store_true', default=False)
    parser.add_argument('--port', default=5000, type=int)
    parser.add_argument('--shortcut-auth', action='store_true', default=False)
    parser.add_argument('--delivery-cfg', default='internal')
    parser.add_argument('--delivery-db-cfg', default='internal')
    parser.add_argument('--delivery-endpoints', default='internal')
    parser.add_argument('--delivery-db-url', default=None)
    parser.add_argument('--cache-dir', default=default_cache_dir)
    parser.add_argument('--es-config-name', default='sap_internal')
    parser.add_argument(
        '--invalid-semver-ok',
        action='store_true',
        default=False,
        help='whether to raise on invalid (semver) version when resolving greatest version',
    )
    parser.add_argument('--service-extensions', nargs='*')
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
    delivery_endpoints: str,
    port: int,
    cfg_factory=None,
) -> str:
    if is_productive:
        if not cfg_factory:
            cfg_factory = ctx_util.cfg_factory()

        endpoints = cfg_factory.delivery_endpoints(delivery_endpoints)
        base_url = f'https://{endpoints.service_host()}'
    else:
        base_url = f'http://localhost:{port}'

    return base_url


def add_app_context_vars(
    app: aiohttp.web.Application,
    cfg_factory,
    parsed_arguments,
    base_url: str,
) -> aiohttp.web.Application:
    oci_client = lookups.semver_sanitised_oci_client_async(cfg_factory)

    version_lookup = lookups.init_version_lookup_async(
        oci_client=oci_client,
        default_absent_ok=True,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup_async(
        cache_dir=parsed_arguments.cache_dir,
        oci_client=oci_client,
    )

    github_api_lookup = lookups.github_api_lookup(cfg_factory)
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

    cve_rescoring_rule_set_lookup = features.get_feature(
        features.FeatureRescoring,
    ).find_rule_set_by_name
    default_rule_set_callback = features.get_feature(features.FeatureRescoring).default_rule_set

    issue_repo_callback = features.get_feature(features.FeatureIssues).get_issue_repo

    kubernetes_api_callback = features.get_feature(
        features.FeatureServiceExtensions,
    ).get_kubernetes_api

    namespace_callback = features.get_feature(
        features.FeatureServiceExtensions,
    ).get_namespace

    service_extensions_callback = features.get_feature(
        features.FeatureServiceExtensions,
    ).get_services

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

    app[consts.APP_ADDRESSBOOK_ENTRIES] = addressbook_entries
    app[consts.APP_ADDRESSBOOK_GITHUB_MAPPINGS] = addressbook_github_mappings
    app[consts.APP_ADDRESSBOOK_SOURCE] = addressbook_source
    app[consts.APP_ARTEFACT_METADATA_CFG] = artefact_metadata_cfg_by_type
    app[consts.APP_BASE_URL] = base_url
    app[consts.APP_CFG_FACTORY] = cfg_factory
    app[consts.APP_COMPONENT_DESCRIPTOR_LOOKUP] = component_descriptor_lookup
    app[consts.APP_COMPONENT_WITH_TESTS_CALLBACK] = component_with_tests_callback
    app[consts.APP_CVE_RESCORING_RULE_SET_LOOKUP] = cve_rescoring_rule_set_lookup
    app[consts.APP_DEFAULT_RULE_SET_CALLBACK] = default_rule_set_callback
    app[consts.APP_DELIVERY_CFG] = parsed_arguments.delivery_cfg
    app[consts.APP_EOL_CLIENT] = eol.EolClient()
    app[consts.APP_GITHUB_API_LOOKUP] = github_api_lookup
    app[consts.APP_GITHUB_REPO_LOOKUP] = github_repo_lookup
    app[consts.APP_INVALID_SEMVER_OK] = parsed_arguments.invalid_semver_ok
    app[consts.APP_ISSUE_REPO_CALLBACK] = issue_repo_callback
    app[consts.APP_KUBERNETES_API_CALLBACK] = kubernetes_api_callback
    app[consts.APP_NAMESPACE_CALLBACK] = namespace_callback
    app[consts.APP_OCI_CLIENT] = oci_client
    app[consts.APP_SERVICE_EXTENSIONS_CALLBACK] = service_extensions_callback
    app[consts.APP_SPECIAL_COMPONENT_CALLBACK] = special_component_callback
    app[consts.APP_SPRINT_DATE_DISPLAY_NAME_CALLBACK] = sprint_date_display_name_callback
    app[consts.APP_SPRINTS] = sprints
    app[consts.APP_SPRINTS_METADATA] = sprints_metadata
    app[consts.APP_UPR_REGEX_CALLBACK] = upr_regex_callback
    app[consts.APP_VERSION_FILTER_CALLBACK] = version_filter_callback
    app[consts.APP_VERSION_LOOKUP] = version_lookup

    return app


def add_routes(
    app: aiohttp.web.Application,
) -> aiohttp.web.Application:
    app.router.add_view(
        path='/ready',
        handler=util.Ready,
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
        path='/components/issues',
        handler=components.Issues,
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

    return app


async def initialise_app():
    parsed_arguments = parse_args()

    cfg_factory = ctx_util.cfg_factory()

    middlewares = [
        middleware.cors.cors_middleware(),
    ]

    middlewares = await features.init_features(
        parsed_arguments=parsed_arguments,
        cfg_factory=cfg_factory,
        middlewares=middlewares,
    )

    es_client = features.get_feature(features.FeatureElasticSearch).get_es_client()
    middlewares.append(middleware.errors.errors_middleware(es_client))

    if (unavailable_features := tuple(
        f for f in features.feature_cfgs
        if f.state is features.FeatureStates.UNAVAILABLE
    )):
        logger.info(
            f'The following feature{"s are" if len(unavailable_features) != 1 else " is"} '
            f'inactive: {", ".join(f.name for f in unavailable_features)}'
        )
        middlewares.append(rfc.feature_check_middleware(unavailable_features))

    base_url = get_base_url(
        is_productive=parsed_arguments.productive,
        delivery_endpoints=parsed_arguments.delivery_endpoints,
        port=parsed_arguments.port,
        cfg_factory=cfg_factory,
    )

    app = aiohttp.web.Application(
        middlewares=middlewares,
        client_max_size=0, # max request body size is already configured via ingress
    )

    app = middleware.prometheus.add_prometheus_middleware(app=app)

    app = add_app_context_vars(
        app=app,
        cfg_factory=cfg_factory,
        parsed_arguments=parsed_arguments,
        base_url=base_url,
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
