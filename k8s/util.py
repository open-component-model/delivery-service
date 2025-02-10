import dataclasses
import http
import logging
import random
import re
import time

import kubernetes.client as kc
import kubernetes.client.rest
import kubernetes.config
import yaml

import cnudie.iter
import cnudie.retrieve
import dso.model
import ocm

import k8s.model
import odg.extensions_cfg
import secret_mgmt.kubernetes


logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class KubernetesApi:
    api_client: kc.ApiClient
    core_kubernetes_api: kc.CoreV1Api
    custom_kubernetes_api: kc.CustomObjectsApi
    apps_kubernetes_api: kc.AppsV1Api
    networking_kubernetes_api: kc.NetworkingV1Api


def kubernetes_api(
    kubernetes_cfg: secret_mgmt.kubernetes.Kubernetes | None=None,
    kubeconfig_path: str | None=None,
) -> KubernetesApi:
    if kubernetes_cfg:
        api_client = kubernetes.config.new_client_from_config_dict(kubernetes_cfg.kubeconfig)
    elif kubeconfig_path:
        kubeconfig = yaml.safe_load(open(kubeconfig_path))
        api_client = kubernetes.config.new_client_from_config_dict(kubeconfig)
    else:
        kubernetes.config.load_incluster_config()
        api_client = kc.ApiClient()

    return KubernetesApi(
        api_client=api_client,
        core_kubernetes_api=kc.CoreV1Api(api_client=api_client),
        custom_kubernetes_api=kc.CustomObjectsApi(api_client=api_client),
        apps_kubernetes_api=kc.AppsV1Api(api_client=api_client),
        networking_kubernetes_api=kc.NetworkingV1Api(api_client=api_client),
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


def scale_replica_set(
    service: odg.extensions_cfg.Services,
    namespace: str,
    kubernetes_api: KubernetesApi,
    desired_replicas: int,
    max_retries: int=3,
    retry_count: int=0,
):
    name = generate_kubernetes_name(
        name_parts=(service,),
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
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            desired_replicas=desired_replicas,
            max_retries=max_retries,
            retry_count=retry_count + 1,
        )

    logger.info(
        f'scaled replica set {name} in {namespace=} from {current_replicas} to {desired_replicas}'
    )


def get_ocm_node(
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    artefact: dso.model.ComponentArtefactId,
) -> cnudie.iter.ResourceNode | cnudie.iter.SourceNode | None:
    if not dso.model.is_ocm_artefact(artefact.artefact_kind):
        return None

    component: ocm.Component = component_descriptor_lookup(ocm.ComponentIdentity(
        name=artefact.component_name,
        version=artefact.component_version,
    )).component

    if artefact.artefact_kind is dso.model.ArtefactKind.RESOURCE:
        artefacts = component.resources
    elif artefact.artefact_kind is dso.model.ArtefactKind.SOURCE:
        artefacts = component.sources
    else:
        raise RuntimeError('this line should never be reached')

    for a in artefacts:
        if a.name != artefact.artefact.artefact_name:
            continue
        if a.version != artefact.artefact.artefact_version:
            continue
        if a.type != artefact.artefact.artefact_type:
            continue
        if (
            dso.model.normalise_artefact_extra_id(a.extraIdentity)
            != artefact.artefact.normalised_artefact_extra_id
        ):
            continue

        # found artefact of backlog item in component's artefacts
        if artefact.artefact_kind is dso.model.ArtefactKind.RESOURCE:
            return cnudie.iter.ResourceNode(
                path=(cnudie.iter.NodePathEntry(component),),
                resource=a,
            )
        elif artefact.artefact_kind is dso.model.ArtefactKind.SOURCE:
            return cnudie.iter.SourceNode(
                path=(cnudie.iter.NodePathEntry(component),),
                source=a,
            )
        else:
            raise RuntimeError('this line should never be reached')
    else:
        logger.error(f'could not find OCM node for {artefact=}')
        raise ValueError(artefact)


def delete_custom_resource(
    crd: k8s.model.Crd,
    name: str,
    namespace: str,
    kubernetes_api: KubernetesApi,
):
    try:
        kubernetes_api.custom_kubernetes_api.delete_namespaced_custom_object(
            group=crd.DOMAIN,
            version=crd.VERSION,
            plural=crd.PLURAL_NAME,
            namespace=namespace,
            name=name,
        )
    except kubernetes.client.rest.ApiException as e:
        # if the http status is 404 it is fine because the resource should be deleted anyway
        if e.status != http.HTTPStatus.NOT_FOUND:
            raise e
