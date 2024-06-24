import collections.abc
import dataclasses
import functools
import http
import logging
import random
import re
import time
import yaml

import kubernetes.client as kc
import kubernetes.client.rest
import kubernetes.config
import urllib3.exceptions

import github.compliance.model as gcm
import model.kubernetes

import config
import ctx_util
import k8s.model


logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class KubernetesApi:
    api_client: kc.ApiClient
    core_kubernetes_api: kc.CoreV1Api
    custom_kubernetes_api: kc.CustomObjectsApi
    apps_kubernetes_api: kc.AppsV1Api


@functools.cache
def kubernetes_api(
    kubernetes_cfg: model.kubernetes.KubernetesConfig=None,
) -> KubernetesApi:
    if kubernetes_cfg:
        api_client = kubernetes.config.new_client_from_config_dict(kubernetes_cfg.kubeconfig())
    else:
        kubernetes.config.load_incluster_config()
        api_client = kc.ApiClient()

    return KubernetesApi(
        api_client=api_client,
        core_kubernetes_api=kc.CoreV1Api(api_client=api_client),
        custom_kubernetes_api=kc.CustomObjectsApi(api_client=api_client),
        apps_kubernetes_api=kc.AppsV1Api(api_client=api_client),
    )


def generate_kubernetes_suffix(
    prefix: str='',
    max_suffix_length: int=5,
) -> str:
    '''
    Generates a random name for a resource in the same way the kubernetes api would (appending
    a suffix of up to 5 random alphanumeric characters while ignoring vowels and 0, 1, 3 to
    reduce changes of "bad words" being formed).
    '''
    alphanums = 'bcdfghjklmnpqrstvwxyz2456789'
    # max kubernetes name length is 63
    suffix_length = min(max_suffix_length, 63 - len(prefix))
    return ''.join(random.choice(alphanums) for _ in range(suffix_length))


def generate_kubernetes_name(
    name_parts: tuple[str],
    generate_num_suffix: bool=True,
) -> str:
    def to_snake_case(s: str) -> str:
        return re.sub(r'([A-Z]{1})', r'_\1', s).lower()

    name_parts = tuple(
        to_snake_case(part.lower()).replace("_", "-")
        for part in name_parts
    )

    name = '-'.join(name_parts)

    if generate_num_suffix:
        name += f'-{generate_kubernetes_suffix(prefix=name)}'

    return name


def normalise_pod_label(pod_label: str) -> str:
    pod_label = pod_label.title().replace('-', '').replace('_', '')
    return pod_label[:1].lower() + pod_label[1:]


def create_label_selector(
    labels: dict[str, str],
) -> str:
    return ', '.join([f'{k}={v}' for k, v in labels.items()])


def label_is_true(label: str):
    is_true = yaml.safe_load(label)
    if not isinstance(is_true, bool):
        raise ValueError('cannot parse to boolean', label)
    return is_true


CrdName = str
EventType = str
CrdMetadata = dict
CrdSpec = dict
Namespace = str
CrdChangeCallback = collections.abc.Callable[
    [CrdName, EventType, CrdMetadata, CrdSpec, Namespace, KubernetesApi],
    None,
]


def watch_crd_changes(
    crd: k8s.model.Crd,
    on_change: CrdChangeCallback,
    namespace: str,
    kubernetes_api: KubernetesApi,
):
    resource_version = ''

    while True:
        try:
            for event in kubernetes.watch.Watch().stream(
                kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object,
                group=crd.DOMAIN,
                version=crd.VERSION,
                namespace=namespace,
                plural=crd.PLURAL_NAME,
                resource_version=resource_version,
                timeout_seconds=0,
            ):
                type = str(event['type'])
                object = event['object']
                metadata = object.get('metadata')
                resource_version = metadata['resourceVersion']
                name = metadata['name']
                spec = object.get('spec')

                logger.debug(f'identified modification {type=} of {crd.KIND} {name}')

                on_change(name, type, metadata, spec, namespace, kubernetes_api)
        except kubernetes.client.rest.ApiException as e:
            if e.status == http.HTTPStatus.GONE:
                resource_version = ''
                logger.info('API resource watching expired, will start new watch')
            else:
                raise e
        except urllib3.exceptions.ProtocolError:
            # this is a known error which has no impact on the functionality, thus rather be
            # degregated to a warning or even info
            # [ref](https://github.com/kiwigrid/k8s-sidecar/issues/233#issuecomment-1332358459)
            resource_version = ''
            logger.info('API resource watching received protocol error, will start new watch')


def scale_replica_set(
    service: config.Services,
    cfg_name: str,
    namespace: str,
    kubernetes_api: KubernetesApi,
    desired_replicas: int,
    max_retries: int=3,
    retry_count: int=0,
):
    name = generate_kubernetes_name(
        name_parts=(service, cfg_name),
        generate_num_suffix=False,
    )
    replica_set = kubernetes_api.apps_kubernetes_api.read_namespaced_replica_set(
        namespace=namespace,
        name=name,
    )

    current_replicas = replica_set.spec.replicas

    if current_replicas == desired_replicas:
        # nothing to do here
        return

    replica_set.spec.replicas = desired_replicas

    logger.info(
        f'attempting to scale replica set {name} in {namespace=} '
        f'from {current_replicas} to {desired_replicas}'
    )

    try:
        # use "replace" instead of "patch" here to allow running in a conflict
        # -> "patch" silently ignores conflicts and overrides the resource anyways
        kubernetes_api.apps_kubernetes_api.replace_namespaced_replica_set(
            namespace=namespace,
            name=name,
            body=replica_set,
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status != http.HTTPStatus.CONFLICT or retry_count >= max_retries:
            raise e

        retry_interval = (retry_count + 1) * 10
        logger.warning(
            f'scaling replica set {name} in {namespace=} from {current_replicas} to '
            f'{desired_replicas} resulted  in a conflict, will try to scale replica set '
            f'again in {retry_interval} sec...'
        )
        time.sleep(retry_interval)
        return scale_replica_set(
            service=service,
            cfg_name=cfg_name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            desired_replicas=desired_replicas,
            max_retries=max_retries,
            retry_count=retry_count + 1,
        )

    logger.info(
        f'scaled replica set {name} in {namespace=} from {current_replicas} to {desired_replicas}'
    )


@functools.lru_cache(maxsize=1)
def iter_scan_configurations(
    namespace: str,
    kubernetes_api: KubernetesApi,
) -> list[k8s.model.ScanConfiguration]:
    scan_configurations_raw = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.ScanConfigurationCrd.DOMAIN,
        version=k8s.model.ScanConfigurationCrd.VERSION,
        plural=k8s.model.ScanConfigurationCrd.PLURAL_NAME,
        namespace=namespace,
    ).get('items')

    scan_configurations = []
    for scan_configuration in scan_configurations_raw:
        spec = scan_configuration.get('spec')

        if bdba_config := spec.get('bdba'):
            # enrich bdba config with bdba url to be able to show bdba url in dashboard
            cfg_factory = ctx_util.cfg_factory()
            cfg_name = bdba_config.get('cfg_name')

            try:
                bdba_cfg = cfg_factory.bdba(cfg_name)
            except ValueError:
                # factory method 'bdba' does not exist, fallback to 'protecode'
                try:
                    bdba_cfg = cfg_factory.protecode(cfg_name)
                except ValueError:
                    pass

            if bdba_cfg:
                bdba_config['base_url'] = bdba_cfg.base_url()
        if issue_replicator_config := spec.get('issueReplicator'):
            # enrich issue replicator config with max processing days to be able to show
            # preview effects of rescorings on due date in dashboard
            if not 'max_processing_days' in issue_replicator_config:
                mpd = gcm.MaxProcessingTimesDays()
                issue_replicator_config['max_processing_days'] = dataclasses.asdict(mpd)

        scan_configurations.append(k8s.model.ScanConfiguration(
            name=scan_configuration.get('metadata').get('name'),
            config=spec,
        ))

    return scan_configurations
