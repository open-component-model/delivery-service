import argparse
import collections.abc
import os

import ctx_util
import k8s.util
import secret_mgmt


own_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(own_dir, os.pardir)
default_cache_dir = os.path.join(root_dir, '.cache')


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
    INVALID_SEMVER_OK = {
        'name': '--invalid-semver-ok',
        'action': 'store_true',
        'default': os.environ.get('INVALID_SEMVER_OK') or False,
        'help': 'whether to raise on invalid (semver) version when resolving greatest version',
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
