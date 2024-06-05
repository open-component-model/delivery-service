#!/usr/bin/env python3
import argparse
import functools
import json
import logging
import os
import traceback
import multiprocessing

import falcon
import falcon.media
import spectree

import ccc.oci
import ci.log
import ci.util

import artefacts
import compliance_tests
import compliance_summary as cs
import components
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
    parser.add_argument('--workers', type=int, default=12)
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
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with extensions (and logs)',
    )

    return parser.parse_args()


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

    oci_client = ccc.oci.oci_client(cfg_factory=cfg_factory)

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
    addressbook_repo_callback = features.get_feature(features.FeatureAddressbook).get_repo
    addressbook_relpath_callback = features.get_feature(
        features.FeatureAddressbook,
    ).get_addressbook_relpath
    github_mappings_relpath_callback = features.get_feature(
        features.FeatureAddressbook,
    ).get_github_mappings_relpath
    sprints_repo_callback = features.get_feature(features.FeatureSprints).get_repo
    sprints_relpath_callback = features.get_feature(features.FeatureSprints).get_sprints_relpath
    sprint_date_display_name_callback = features.get_feature(
        features.FeatureSprints,
    ).get_sprint_date_display_name
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
        ),
    )
    app.add_route(
        '/artefacts/metadata/query',
        metadata.ArtefactMetadata(
            eol_client=eol_client,
            artefact_metadata_cfg_by_type=artefact_metadata_cfg_by_type,
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
            sprints_repo_callback=sprints_repo_callback,
            sprints_relpath_callback=sprints_relpath_callback,
            sprint_date_display_name_callback=sprint_date_display_name_callback,
        ),
    )
    app.add_route(
        '/delivery/sprint-infos/current',
        sprint.SprintInfos(
            sprints_repo_callback=sprints_repo_callback,
            sprints_relpath_callback=sprints_relpath_callback,
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
            addressbook_repo_callback=addressbook_repo_callback,
            addressbook_relpath_callback=addressbook_relpath_callback,
            github_mappings_relpath_callback=github_mappings_relpath_callback,
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
            sprints_repo_callback=sprints_repo_callback,
            sprints_relpath_callback=sprints_relpath_callback,
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
    cfg_factory=None,
) -> str:
    if is_productive:
        if not cfg_factory:
            cfg_factory = ctx_util.cfg_factory()

        endpoints = cfg_factory.delivery_endpoints(delivery_endpoints)
        base_url = f'https://{endpoints.service_host()}'
    else:
        base_url = 'http://localhost:5000'

    return base_url


def run_app():
    parsed_arguments = parse_args()

    if parsed_arguments.productive:
        host = '0.0.0.0'
        workers = 4
    else:
        host = '127.0.0.1'
        workers = 2

    port = parsed_arguments.port

    app = init(parsed_arguments)

    if parsed_arguments.productive:
        # pylint: disable=E0401
        import bjoern

        def serve():
            bjoern.run(app, host, port, reuse_port=True)

        for _ in range(workers - 1):
            proc = multiprocessing.Process(target=serve)
            proc.start()
        serve()
    else:
        print('running in development mode')
        print()
        print(f'listening at localhost:{port}')
        print()
        # pylint: disable=E0401
        import werkzeug.serving
        werkzeug.serving.run_simple(
            hostname='localhost',
            port=port,
            application=app,
            use_reloader=True,
            use_debugger=True,
            extra_files=(), # might add cfg-files
        )


if __name__ == '__main__':
    run_app()
