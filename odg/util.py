import argparse
import atexit
import collections.abc
import dataclasses
import logging
import os
import signal
import sys
import time

import cnudie.retrieve
import delivery.client
import oci.client

import consts
import ctx_util
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups
import odg.extensions_cfg
import odg.model
import paths
import secret_mgmt


logger = logging.getLogger(__name__)

own_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(own_dir, os.pardir)
default_cache_dir = os.path.join(root_dir, '.cache')

ready_to_terminate = True
wants_to_terminate = False


class Arguments:
    K8S_CFG_NAME = {
        'name': '--k8s-cfg-name',
        'help': 'specify kubernetes cluster to interact with extensions (and logs)',
        'default': os.environ.get('K8S_CFG_NAME'),
    }
    KUBECONFIG = {
        'name': '--kubeconfig',
        'help': 'specify kubernetes cluster to interact with extensions (and logs); if both '
                '`k8s-cfg-name` and `kubeconfig` are set, `k8s-cfg-name` takes precedence',
    }
    K8S_NAMESPACE = {
        'name': '--k8s-namespace',
        'help': 'specify kubernetes cluster namespace to interact with extensions (and logs)',
        'default': os.environ.get('K8S_TARGET_NAMESPACE', 'delivery'),
    }
    EXTENSIONS_CFG_PATH = {
        'name': '--extensions-cfg-path',
        'help': 'custom path to the `extensions_cfg.yaml` file that should be used',
    }
    FINDINGS_CFG_PATH = {
        'name': '--findings-cfg-path',
        'help': 'custom path to the `findings.yaml` file that should be used',
    }
    DELIVERY_SERVICE_URL = {
        'name': '--delivery-service-url',
        'help': 'specify the url of the delivery service to use instead of the one configured in '
                'the respective extensions configuration',
    }
    CACHE_DIR = {
        'name': '--cache-dir',
        'default': default_cache_dir,
    }


scan_extension_arguments = [
    Arguments.K8S_CFG_NAME,
    Arguments.KUBECONFIG,
    Arguments.K8S_NAMESPACE,
    Arguments.EXTENSIONS_CFG_PATH,
    Arguments.FINDINGS_CFG_PATH,
    Arguments.DELIVERY_SERVICE_URL,
    Arguments.CACHE_DIR,
]


def parse_args(
    arguments: collections.abc.Iterable[dict]=scan_extension_arguments,
):
    parser = argparse.ArgumentParser()

    for argument in arguments:
        parser.add_argument(
            argument.pop('name'),
            **argument,
        )

    return parser.parse_args()


def kubernetes_api(
    parsed_arguments: argparse.Namespace,
    secret_factory: secret_mgmt.SecretFactory | None=None,
) -> k8s.util.KubernetesApi:
    if not parsed_arguments.k8s_cfg_name:
        return k8s.util.kubernetes_api(kubeconfig_path=parsed_arguments.kubeconfig)

    if not secret_factory:
        secret_factory = ctx_util.secret_factory()

    kubernetes_cfg = secret_factory.kubernetes(parsed_arguments.k8s_cfg_name)
    return k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)


def handle_termination_signal(*args):
    global wants_to_terminate

    # also terminate if > 1 termination signals were received
    if ready_to_terminate or wants_to_terminate:
        sys.exit(0)

    # grace period to finish current scan is defined in the replica set
    # after this period, the scan will be terminated anyways by k8s means
    logger.info('termination signal received, will try to finish current scan and then exit')
    wants_to_terminate = True


def process_backlog_items(
    parsed_arguments: argparse.Namespace,
    service: odg.extensions_cfg.Services,
    callback: collections.abc.Callable[[
        odg.model.ComponentArtefactId,
        object, # extension_cfg
        cnudie.retrieve.ComponentDescriptorLookupById,
        delivery.client.DeliveryServiceClient | None,
        oci.client.Client,
        secret_mgmt.SecretFactory,
    ], None],
    local_debug_artefact: odg.model.ComponentArtefactId | dict | None=None,
):
    '''
    Infinitely process backlog items until `SIGTERM` or `SIGINT` signal is retrieved, then try to
    finish processing of current backlog item. Processing is done by the passed-in `callback`, which
    pre-fills the following keyword-arguments for convenience:

        - `artefact`: odg.model.ComponentArtefactId
        - `extension_cfg`: object
        - `component_descriptor_lookup`: cnudie.retrieve.ComponentDescriptorLookup
        - `delivery_client`: delivery.client.DeliveryServiceClient
        - `oci_client`: oci.client.Client
        - `secret_factory`: secret_mgmt.SecretFactory

    Make sure the passed-in `callback` accepts all these arguments, even if they are not required for
    the specific use-case, for example by allowing `**kwargs`.

    Also, for convenience, this function will initialise loggers which will periodically write the
    logs to the Kubernetes custom resource `LogCollection` for monitoring via the Delivery-Dashboard.

    If a `local_debug_artefact` is passed, the interaction with backlog items from a Kubernetes
    cluster will be shortcut and instead the passed-in artefact will be used for a dummy backlog
    item. This is useful for local development scenarios.
    '''
    if not local_debug_artefact:
        signal.signal(signal.SIGTERM, handle_termination_signal)
        signal.signal(signal.SIGINT, handle_termination_signal)

    secret_factory = ctx_util.secret_factory()

    namespace = parsed_arguments.k8s_namespace

    if not local_debug_artefact:
        _kubernetes_api = kubernetes_api(parsed_arguments, secret_factory=secret_factory)

        k8s.logging.init_logging_thread(
            service=service,
            namespace=namespace,
            kubernetes_api=_kubernetes_api,
        )
        atexit.register(
            k8s.logging.log_to_crd,
            service=service,
            namespace=namespace,
            kubernetes_api=_kubernetes_api,
        )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    if not (extension_cfg := extensions_cfg.find_extension_cfg(service=service)):
        logger.warning(f'Did not find extension-cfg for {service=}, exiting...')
        return

    if not (delivery_service_url := parsed_arguments.delivery_service_url):
        if hasattr(extension_cfg, 'delivery_service_url'):
            delivery_service_url = extension_cfg.delivery_service_url

    if delivery_service_url:
        delivery_client = delivery.client.DeliveryServiceClient(
            routes=delivery.client.DeliveryServiceRoutes(
                base_url=delivery_service_url,
            ),
            auth_token_lookup=lookups.github_auth_token_lookup,
        )
    else:
        delivery_client = None

    oci_client = lookups.semver_sanitising_oci_client(
        secret_factory=secret_factory,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_client,
        oci_client=oci_client,
    )

    global ready_to_terminate
    while not wants_to_terminate:
        ready_to_terminate = False

        if local_debug_artefact:
            backlog_crd = {
                'metadata': {
                    'name': 'local-backlog-item-abcde',
                },
                'spec': {
                    'timestamp': '2025-01-01T00:00:00.000000',
                    'artefact': (
                        dataclasses.asdict(local_debug_artefact)
                        if dataclasses.is_dataclass(local_debug_artefact)
                        else local_debug_artefact
                    ),
                    'priority': 8,
                },
            }
        else:
            backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
                service=service,
                namespace=namespace,
                kubernetes_api=_kubernetes_api,
            )

        if not backlog_crd:
            ready_to_terminate = True
            sleep_interval_seconds = consts.BACKLOG_ITEM_SLEEP_INTERVAL_SECONDS
            logger.info(f'no open backlog item found, will sleep for {sleep_interval_seconds=}')
            time.sleep(sleep_interval_seconds)
            continue

        name = backlog_crd['metadata']['name']
        logger.info(f'processing backlog item {name}')

        backlog_item = k8s.backlog.BacklogItem.from_dict(
            backlog_item=backlog_crd['spec'],
        )

        callback(
            artefact=backlog_item.artefact,
            extension_cfg=extension_cfg,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            oci_client=oci_client,
            secret_factory=secret_factory,
        )

        if local_debug_artefact:
            logger.info(f'processed local backlog item {name}')
            return
        else:
            k8s.util.delete_custom_resource(
                crd=k8s.model.BacklogItemCrd,
                name=name,
                namespace=namespace,
                kubernetes_api=_kubernetes_api,
            )
            logger.info(f'processed and deleted backlog item {name}')
