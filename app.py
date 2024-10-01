#!/usr/bin/env python3
import argparse
import asyncio
import functools
import json
import logging
import os
import sys
import traceback

import aiohttp.web
import falcon
import falcon.media
import spectree

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
import metric
import middleware.auth
import middleware.decompressor
import middleware.json_translator
import middleware.route_feature_check as rfc
import osinfo
import paths
import rescore
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

    args = sys.argv
    if args[0].endswith('pytest'):
        # remove arguments passed to "pytest" from delivery-service arguments
        args = []
    else:
        args = args[1:]
    return parser.parse_args(args)


def init(parsed_arguments):
    cfg_factory = ctx_util.cfg_factory()

    base_url = get_base_url(
        is_productive=parsed_arguments.productive,
        delivery_endpoints=parsed_arguments.delivery_endpoints,
        cfg_factory=cfg_factory,
    )

    middlewares = features.init_features(
        parsed_arguments=parsed_arguments,
        cfg_factory=cfg_factory,
        base_url=base_url,
    )

    middlewares.extend([
        falcon.CORSMiddleware(allow_credentials='*', allow_origins='*'),
        middleware.decompressor.DecompressorMiddleware(),
    ])

    if (unavailable_features := tuple(
        f for f in features.feature_cfgs
        if f.state is features.FeatureStates.UNAVAILABLE
    )):
        logger.info(
            f'The following feature{"s are" if len(unavailable_features) != 1 else " is"} '
            f'inactive: {", ".join(f.name for f in unavailable_features)}'
        )
        middlewares.append(rfc.ShortcutRoutesWithUnavailableFeatures(unavailable_features))

    oci_client = lookups.semver_sanitised_oci_client(
        cfg_factory=cfg_factory,
    )

    version_lookup = lookups.init_version_lookup(
        oci_client=oci_client,
        default_absent_ok=True,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        oci_client=oci_client,
    )

    github_api_lookup = lookups.github_api_lookup(
        cfg_factory=cfg_factory,
    )

    app = init_app(
        component_descriptor_lookup=component_descriptor_lookup,
        github_api_lookup=github_api_lookup,
        oci_client=oci_client,
        version_lookup=version_lookup,
        middlewares=middlewares,
        parsed_arguments=parsed_arguments,
        base_url=base_url,
    )

    with open(paths.version_file, 'r') as f:
        version = f.readline()

    spec = spectree.SpecTree(
        backend_name='falcon',
        title='Delivery-Service by Gardener CICD',
        version=version,
    )
    spec.register(app)

    return app


def init_app(
    component_descriptor_lookup,
    github_api_lookup,
    oci_client,
    version_lookup,
    middlewares,
    parsed_arguments,
    base_url: str,
) -> falcon.App:
    es_client = features.get_feature(features.FeatureElasticSearch).get_es_client()
    cve_rescoring_rule_set_lookup = features.get_feature(
        features.FeatureRescoring,
    ).find_rule_set_by_name
    default_rule_set_callback = features.get_feature(features.FeatureRescoring).default_rule_set
    component_with_tests_callback = features.get_feature(
        features.FeatureTests,
    ).get_component_with_tests
    upr_regex_callback = features.get_feature(features.FeatureUpgradePRs).get_regex
    issue_repo_callback = features.get_feature(features.FeatureIssues).get_issue_repo
    special_component_callback = features.get_feature(
        features.FeatureSpecialComponents,
    ).get_special_component
    service_extensions_callback = features.get_feature(
        features.FeatureServiceExtensions,
    ).get_services
    namespace_callback = features.get_feature(
        features.FeatureServiceExtensions,
    ).get_namespace
    kubernetes_api_callback = features.get_feature(
        features.FeatureServiceExtensions,
    ).get_kubernetes_api
    version_filter_callback = features.get_feature(features.FeatureVersionFilter).get_version_filter
    invalid_semver_ok = parsed_arguments.invalid_semver_ok

    addressbook_feature = features.get_feature(features.FeatureAddressbook)
    if addressbook_feature.state is features.FeatureStates.AVAILABLE:
        addressbook_feature: features.FeatureAddressbook

        addressbook_source = addressbook_feature.get_source()
        addressbook_entries = addressbook_feature.get_addressbook_entries()
        addressbook_github_mappings = addressbook_feature.get_github_mappings()
    else:
        addressbook_source = None
        addressbook_entries = []
        addressbook_github_mappings = []

    sprints_feature = features.get_feature(features.FeatureSprints)
    if sprints_feature.state is features.FeatureStates.AVAILABLE:
        sprints_feature: features.FeatureSprints

        sprints_metadata = sprints_feature.get_sprints_metadata()
        sprints = sprints_feature.get_sprints()
        sprint_date_display_name_callback = sprints_feature.get_sprint_date_display_name
    else:
        sprints_metadata = None
        sprints = []
        sprint_date_display_name_callback = None

    def handle_exception(req, resp, ex, params, ws=None):
        stacktrace = traceback.format_exc()
        logger.error(stacktrace)
        if not es_client:
            raise falcon.HTTPInternalServerError
        try:
            body = req.media
        except:
            body = None

        exception_metric = metric.ExceptionMetric.create(
            service='delivery-service',
            stacktrace=stacktrace,
            request=body,
            params=req.params,
        )
        try:
            import ccc.elasticsearch
            ccc.elasticsearch.metric_to_es(
                es_client=es_client,
                metric=exception_metric,
                index_name=metric.index_name(exception_metric),
            )
        except:
            logger.warn('an exception occurred whilst trying to log to elasticsearch - will ignore')
            traceback.print_exc()

        # raise HTTP error to not leak logs to client
        raise falcon.HTTPInternalServerError

    artefact_metadata_cfg_by_type = cs.artefact_metadata_cfg_by_type(
        artefact_metadata_cfg=ci.util.parse_yaml_file(
            paths.artefact_metadata_cfg,
        )
    )

    eol_client = eol.EolClient()

    app = falcon.App(
        middleware=middlewares,
    )

    app.add_route(
        '/ready',
        util.Ready()
    )

    app.add_route(
        '/features',
        features.Features()
    )

    app.add_route(
      '/ocm/artefacts/blob',
      artefacts.ArtefactBlob(
          component_descriptor_lookup=component_descriptor_lookup,
          oci_client=oci_client,
      ),
    )

    app.add_route(
        '/artefacts/metadata',
        metadata.ArtefactMetadata(
            eol_client=eol_client,
            artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
            component_descriptor_lookup=component_descriptor_lookup,
        ),
    )
    app.add_route(
        '/artefacts/metadata/query',
        metadata.ArtefactMetadata(
            eol_client=eol_client,
            artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
            component_descriptor_lookup=component_descriptor_lookup,
        ),
        suffix='query',
    )

    app.add_route(
        '/components/upgrade-prs',
        components.UpgradePRs(
            upr_regex_callback=upr_regex_callback,
            component_descriptor_lookup=component_descriptor_lookup,
            github_api_lookup=github_api_lookup,
            version_lookup=version_lookup,
            version_filter_callback=version_filter_callback,
            invalid_semver_ok=invalid_semver_ok,
        ),
    )

    app.add_route(
        '/components/diff',
        components.ComponentDescriptorDiff(
            component_descriptor_lookup=component_descriptor_lookup,
        ),
    )

    app.add_route(
        '/components/issues',
        components.Issues(
            issue_repo_callback=issue_repo_callback,
            github_api_lookup=github_api_lookup,
        ),
    )

    app.add_route(
        '/special-component/current-dependencies',
        special_component.CurrentDependencies(
            special_component_callback=special_component_callback,
            github_api_lookup=github_api_lookup,
        ),
    )

    app.add_route(
        '/components/tests',
        compliance_tests.DownloadTestResults(
            component_with_tests_callback=component_with_tests_callback,
            github_api_lookup=github_api_lookup,
        ),
    )

    app.add_route(
        '/components/compliance-summary',
        components.ComplianceSummary(
            component_descriptor_lookup=component_descriptor_lookup,
            version_lookup=version_lookup,
            eol_client=eol_client,
            artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
            version_filter_callback=version_filter_callback,
            invalid_semver_ok=invalid_semver_ok,
        ),
    )

    app.add_route(
        '/components/metadata',
        components.ComponentMetadata(
            version_lookup=version_lookup,
            version_filter_callback=version_filter_callback,
            invalid_semver_ok=invalid_semver_ok,
        ),
    )

    app.add_route(
        '/delivery/sprint-infos',
        sprint.SprintInfos(
            sprints_metadata=sprints_metadata,
            sprints=sprints,
            sprint_date_display_name_callback=sprint_date_display_name_callback,
        ),
    )
    app.add_route(
        '/delivery/sprint-infos/current',
        sprint.SprintInfos(
            sprints_metadata=sprints_metadata,
            sprints=sprints,
            sprint_date_display_name_callback=sprint_date_display_name_callback,
        ),
        suffix='current',
    )

    app.add_route(
        '/auth',
        middleware.auth.OAuth(
            base_url=base_url,
            delivery_cfg=parsed_arguments.delivery_cfg,
        ),
    )
    app.add_route(
        '/auth/logout',
        middleware.auth.OAuth(
            base_url=base_url,
            delivery_cfg=parsed_arguments.delivery_cfg,
        ),
        suffix='logout',
    )
    app.add_route(
        '/auth/configs',
        middleware.auth.OAuth(
            base_url=base_url,
            delivery_cfg=parsed_arguments.delivery_cfg,
        ),
        suffix='cfgs',
    )

    # endpoint according to OpenID provider configuration request
    # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
    app.add_route(
        '/.well-known/openid-configuration',
        middleware.auth.OpenID(
            base_url=base_url,
            delivery_cfg=parsed_arguments.delivery_cfg,
        ),
        suffix='configuration',
    )
    app.add_route(
        '/openid/v1/jwks',
        middleware.auth.OpenID(
            base_url=base_url,
            delivery_cfg=parsed_arguments.delivery_cfg,
        ),
        suffix='jwks',
    )

    app.add_route(
        '/ocm/component',
        components.Component(
            component_descriptor_lookup=component_descriptor_lookup,
            version_lookup=version_lookup,
            version_filter_callback=version_filter_callback,
            invalid_semver_ok=invalid_semver_ok,
        ),
    )
    app.add_route(
        '/ocm/component/versions',
        components.GreatestComponentVersions(
            component_descriptor_lookup=component_descriptor_lookup,
            version_lookup=version_lookup,
            version_filter_callback=version_filter_callback,
            invalid_semver_ok=invalid_semver_ok,
        ),
    )
    app.add_route(
        '/ocm/component/dependencies',
        components.ComponentDependencies(
            component_descriptor_lookup=component_descriptor_lookup,
            version_lookup=version_lookup,
            version_filter_callback=version_filter_callback,
            invalid_semver_ok=invalid_semver_ok,
        ),
    )
    app.add_route(
        '/ocm/component/responsibles',
        components.ComponentResponsibles(
            component_descriptor_lookup=component_descriptor_lookup,
            version_lookup=version_lookup,
            github_api_lookup=github_api_lookup,
            addressbook_source=addressbook_source,
            addressbook_entries=addressbook_entries,
            addressbook_github_mappings=addressbook_github_mappings,
            version_filter_callback=version_filter_callback,
            invalid_semver_ok=invalid_semver_ok,
        ),
    )
    app.add_route(
        '/os/{os_id}/branches',
        osinfo.OsInfoRoutes(
            eol_client=eol_client,
        ),
        suffix='branches',
    )
    app.add_route(
        '/rescore',
        rescore.Rescore(
            cve_rescoring_rule_set_lookup=cve_rescoring_rule_set_lookup,
            default_rule_set_callback=default_rule_set_callback,
            component_descriptor_lookup=component_descriptor_lookup,
            namespace_callback=namespace_callback,
            kubernetes_api_callback=kubernetes_api_callback,
            sprints=sprints,
        ),
    )

    app.add_route(
        '/service-extensions',
        service_extensions.ServiceExtensions(
            service_extensions_callback=service_extensions_callback,
        ),
    )
    app.add_route(
        '/service-extensions/log-collections',
        service_extensions.LogCollections(
            service_extensions_callback=service_extensions_callback,
            namespace_callback=namespace_callback,
            kubernetes_api_callback=kubernetes_api_callback,
        ),
    )
    app.add_route(
        '/service-extensions/container-statuses',
        service_extensions.ContainerStatuses(
            service_extensions_callback=service_extensions_callback,
            namespace_callback=namespace_callback,
            kubernetes_api_callback=kubernetes_api_callback,
        ),
    )
    app.add_route(
        '/service-extensions/scan-configurations',
        service_extensions.ScanConfigurations(
            namespace_callback=namespace_callback,
            kubernetes_api_callback=kubernetes_api_callback,
        ),
    )
    app.add_route(
        '/service-extensions/backlog-items',
        service_extensions.BacklogItems(
            namespace_callback=namespace_callback,
            kubernetes_api_callback=kubernetes_api_callback,
        ),
    )
    app.add_route(
        '/service-extensions/runtime-artefacts',
        service_extensions.RuntimeArtefacts(
            namespace_callback=namespace_callback,
            kubernetes_api_callback=kubernetes_api_callback,
        ),
    )
    app.add_route(
        '/dora/dora-metrics',
        dora.DoraMetrics(
            component_descriptor_lookup=component_descriptor_lookup,
            component_version_lookup=version_lookup,
            github_api_lookup=github_api_lookup,
        ),
    )

    app.resp_options.media_handlers[falcon.MEDIA_JSON] = falcon.media.JSONHandler(
        dumps=functools.partial(json.dumps, default=middleware.json_translator.json_serializer),
    )

    app.add_error_handler(
        exception=Exception,
        handler=handle_exception,
    )

    return app


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
) -> aiohttp.web.Application:
    oci_client = lookups.semver_sanitised_oci_client(cfg_factory)

    version_lookup = lookups.init_version_lookup(
        oci_client=oci_client,
        default_absent_ok=True,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
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

    base_url = get_base_url(
        is_productive=parsed_arguments.productive,
        delivery_endpoints=parsed_arguments.delivery_endpoints,
        port=parsed_arguments.port,
        cfg_factory=cfg_factory,
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


async def initialise_app(parsed_arguments):
    cfg_factory = ctx_util.cfg_factory()

    app = aiohttp.web.Application()

    app = add_app_context_vars(
        app=app,
        cfg_factory=cfg_factory,
        parsed_arguments=parsed_arguments,
    )

    return app


async def run_app_locally():
    parsed_arguments = parse_args()

    port = parsed_arguments.port

    app = await initialise_app(parsed_arguments)

    print('running in development mode')
    print()
    print(f'listening at localhost:{port}')
    print()

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    await aiohttp.web.TCPSite(
        runner=runner,
        host='localhost',
        port=port,
    ).start()

    await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(run_app_locally())
else:
    # required for uWSGI setup
    global app

    parsed_arguments = parse_args()
    app = init(parsed_arguments)
