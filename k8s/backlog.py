import collections.abc
import dataclasses
import datetime
import dateutil.parser
import enum
import http
import logging
import os
import pytz
import time

import dacite
import kubernetes.client.rest

import ci.util
import cnudie.iter
import dso.model
import gci.componentmodel as cm

import config
import k8s.model
import k8s.util


logger = logging.getLogger(__name__)

LABEL_CLAIMED = f'{k8s.model.BacklogItemCrd.DOMAIN}/claimed'
ANNOTATION_CLAIMED_BY = f'{k8s.model.BacklogItemCrd.DOMAIN}/claimed-by'
ANNOTATION_CLAIMED_AT = f'{k8s.model.BacklogItemCrd.DOMAIN}/claimed-at'


class BacklogPriorities(enum.IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 4
    CRITICAL = 8


@dataclasses.dataclass(frozen=True)
class BacklogItem:
    timestamp: datetime.datetime
    artefact: dso.model.ComponentArtefactId
    priority: BacklogPriorities

    def as_dict(self) -> dict:
        return dataclasses.asdict(
            obj=self,
            dict_factory=ci.util.dict_to_json_factory,
        )

    @staticmethod
    def from_dict(backlog_item: dict) -> 'BacklogItem':
        type_hooks = {
            datetime.datetime: lambda ts: dateutil.parser.isoparse(ts) if ts else None,
        }

        return dacite.from_dict(
            data_class=BacklogItem,
            data=backlog_item,
            config=dacite.Config(
                type_hooks=type_hooks,
                cast=[
                    BacklogPriorities,
                    dso.model.ArtefactKind,
                ],
            ),
        )


def create_backlog_crd_body(
    service: str,
    cfg_name: str,
    name: str,
    namespace: str,
    backlog_item: BacklogItem,
) -> dict:
    return {
        'apiVersion': k8s.model.BacklogItemCrd.api_version(),
        'kind': k8s.model.BacklogItemCrd.KIND,
        'metadata': {
            'labels': {
                k8s.model.LABEL_SERVICE: service,
                k8s.model.LABEL_CFG_NAME: cfg_name,
            },
            'name': name,
            'namespace': namespace,
        },
        'spec': backlog_item.as_dict(),
    }


def iter_existing_backlog_items_for_artefact(
    service: config.Services,
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: dso.model.ComponentArtefactId,
) -> collections.abc.Generator[dict, None, None]:
    labels = {
        k8s.model.LABEL_SERVICE: service,
        k8s.model.LABEL_CFG_NAME: cfg_name,
    }
    label_selector = k8s.util.create_label_selector(labels=labels)
    label_selector += f', {LABEL_CLAIMED}!=True'

    backlog_crds = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.BacklogItemCrd.DOMAIN,
        version=k8s.model.BacklogItemCrd.VERSION,
        plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
        namespace=namespace,
        label_selector=label_selector,
    ).get('items')

    for backlog_crd in backlog_crds:
        crd_artefact = dacite.from_dict(
            data_class=dso.model.ComponentArtefactId,
            data=backlog_crd.get('spec').get('artefact'),
            config=dacite.Config(
                cast=[dso.model.ArtefactKind],
            ),
        )

        if service is config.Services.BDBA:
            if crd_artefact == artefact:
                yield backlog_crd
        elif service is config.Services.CLAMAV:
            if crd_artefact == artefact:
                yield backlog_crd
        elif service is config.Services.ISSUE_REPLICATOR:
            if (
                crd_artefact.artefact_kind == artefact.artefact_kind
                and crd_artefact.component_name == artefact.component_name
                and crd_artefact.artefact.artefact_name == artefact.artefact.artefact_name
                and crd_artefact.artefact.artefact_type == artefact.artefact.artefact_type
                # TODO-Extra-Id: uncomment below code once extraIdentities are handled properly
                # and crd_artefact.artefact.normalised_artefact_extra_id(
                #     remove_duplicate_version=True,
                # ) == artefact.artefact.normalised_artefact_extra_id(
                #     remove_duplicate_version=True,
                # )
            ):
                yield backlog_crd
        else:
            raise NotImplementedError(f'{service=} is not valid for a backlog item')


def create_backlog_item(
    service: config.Services,
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: dso.model.ComponentArtefactId,
    priority: BacklogPriorities=BacklogPriorities.LOW,
):
    name = k8s.util.generate_kubernetes_name(
        name_parts=(service, cfg_name, str(priority)),
    )

    backlog_item = BacklogItem(
        timestamp=datetime.datetime.now(),
        artefact=artefact,
        priority=priority,
    )

    body = create_backlog_crd_body(
        service=service,
        cfg_name=cfg_name,
        name=name,
        namespace=namespace,
        backlog_item=backlog_item,
    )

    kubernetes_api.custom_kubernetes_api.create_namespaced_custom_object(
        group=k8s.model.BacklogItemCrd.DOMAIN,
        version=k8s.model.BacklogItemCrd.VERSION,
        plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
        namespace=namespace,
        body=body,
    )


def create_unique_backlog_item(
    service: config.Services,
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: dso.model.ComponentArtefactId,
    priority: BacklogPriorities=BacklogPriorities.LOW,
) -> bool:
    '''
    creates a backlog item for the given `artefact` and `priority`. If there is
    already an existing backlog item which is semantically equal, the creation is
    skipped. However, if the priority of the existing backlog item is lower than
    `priority`, the old backlog item will be patched with the new priority.
    Returns `True` if a new backlog item was created, otherwise `False`.
    '''
    backlog_items = iter_existing_backlog_items_for_artefact(
        service=service,
        cfg_name=cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        artefact=artefact,
    )

    found_backlog_item = False
    for backlog_item in backlog_items:
        found_backlog_item = True
        metadata = backlog_item.get('metadata')
        crd_priority = backlog_item.get('spec').get('priority')

        if crd_priority < priority:
            backlog_item['spec']['priority'] = priority

            kubernetes_api.custom_kubernetes_api.patch_namespaced_custom_object(
                group=k8s.model.BacklogItemCrd.DOMAIN,
                version=k8s.model.BacklogItemCrd.VERSION,
                plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
                namespace=namespace,
                name=metadata.get('name'),
                body=backlog_item,
            )

    if found_backlog_item:
        return False

    create_backlog_item(
        service=service,
        cfg_name=cfg_name,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        artefact=artefact,
        priority=priority,
    )
    return True


def get_backlog_crd_and_claim(
    service: config.Services,
    cfg_name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    shortcut_claim: bool=False,
) -> dict | None:
    labels = {
        k8s.model.LABEL_SERVICE: service,
        k8s.model.LABEL_CFG_NAME: cfg_name,
    }
    label_selector = k8s.util.create_label_selector(labels=labels)
    label_selector += f', {LABEL_CLAIMED}!=True'

    backlog_crds = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.BacklogItemCrd.DOMAIN,
        version=k8s.model.BacklogItemCrd.VERSION,
        plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
        namespace=namespace,
        label_selector=label_selector,
    ).get('items')

    if not backlog_crds:
        return None

    backlog_crds.sort(
        key=lambda backlog_crd: BacklogPriorities(backlog_crd.get('spec').get('priority')),
        reverse=True,
    )

    backlog_crd = backlog_crds[0]

    if shortcut_claim:
        return backlog_crd

    metadata = backlog_crd.get('metadata')

    labels = metadata.get('labels')

    labels[LABEL_CLAIMED] = 'True'
    metadata['labels'] = labels

    annotations = metadata.get('annotations', dict())
    annotations[ANNOTATION_CLAIMED_BY] = os.environ.get('HOSTNAME', 'local')
    annotations[ANNOTATION_CLAIMED_AT] = datetime.datetime.now(tz=pytz.UTC)
    metadata['annotations'] = annotations

    try:
        # use "replace" instead of "patch" here to allow running in a conflict
        # -> "patch" silently ignores conflicts and overrides the resource anyways
        kubernetes_api.custom_kubernetes_api.replace_namespaced_custom_object(
            group=k8s.model.BacklogItemCrd.DOMAIN,
            version=k8s.model.BacklogItemCrd.VERSION,
            plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
            namespace=namespace,
            name=metadata.get('name'),
            body=backlog_crd,
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status != http.HTTPStatus.CONFLICT:
            raise e

        retry_interval = 10
        logger.warning(
            'trying to claim a new backlog item resulted in a conflict, '
            f'will try to claim a different backlog item in {retry_interval} sec...'
        )
        time.sleep(retry_interval)
        return get_backlog_crd_and_claim(
            service=service,
            cfg_name=cfg_name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )

    return backlog_crd


def remove_claim(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    backlog_crd: dict,
    max_retries: int=3,
    retry_count: int=0,
) -> dict | None:
    metadata = backlog_crd.get('metadata')
    name = metadata.get('name')

    labels = metadata.get('labels')
    labels[LABEL_CLAIMED] = 'False'
    metadata['labels'] = labels

    annotations = metadata.get('annotations')
    del annotations[ANNOTATION_CLAIMED_BY]
    del annotations[ANNOTATION_CLAIMED_AT]
    metadata['annotations'] = annotations

    logger.info(f'attempting to remove claim from backlog item {name} in {namespace=}')

    try:
        # use "replace" instead of "patch" here to allow running in a conflict
        # -> "patch" silently ignores conflicts and overrides the resource anyways
        kubernetes_api.custom_kubernetes_api.replace_namespaced_custom_object(
            group=k8s.model.BacklogItemCrd.DOMAIN,
            version=k8s.model.BacklogItemCrd.VERSION,
            plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
            body=backlog_crd,
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status != http.HTTPStatus.CONFLICT or retry_count >= max_retries:
            raise e

        retry_interval = (retry_count + 1) * 10
        logger.warning(
            f'trying to remove claim from backlog item {name} resulted in a conflict, '
            f'will try to remove claim again in {retry_interval} sec...'
        )
        time.sleep(retry_interval)
        return remove_claim(
            namespace=namespace,
            kubernetes_api=kubernetes_api,
            backlog_crd=backlog_crd,
            max_retries=max_retries,
            retry_count=retry_count + 1,
        )

    logger.info(f'removed claim from backlog item {name} in {namespace=}')


def update_backlog_crd(
    name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    backlog_item: BacklogItem,
):
    body = {
        'spec': backlog_item.as_dict(),
    }

    try:
        kubernetes_api.custom_kubernetes_api.patch_namespaced_custom_object(
            group=k8s.model.BacklogItemCrd.DOMAIN,
            version=k8s.model.BacklogItemCrd.VERSION,
            plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
            body=body,
        )
    except kubernetes.client.rest.ApiException as e:
        # if the http status is 404 it is fine because then it was already processed
        # and must not be updated anymore
        if e.status != http.HTTPStatus.NOT_FOUND:
            raise e


def delete_backlog_crd(
    name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
):
    try:
        kubernetes_api.custom_kubernetes_api.delete_namespaced_custom_object(
            group=k8s.model.BacklogItemCrd.DOMAIN,
            version=k8s.model.BacklogItemCrd.VERSION,
            plural=k8s.model.BacklogItemCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
        )
    except kubernetes.client.rest.ApiException as e:
        # if the http status is 404 it is fine because the object should be deleted anyway
        # this case can occur if two bdba worker processed the same backlog item (edge case)
        if e.status != http.HTTPStatus.NOT_FOUND:
            raise e


def get_resource_node(
    backlog_item: BacklogItem,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
) -> cnudie.iter.ResourceNode:
    component = component_descriptor_lookup(cm.ComponentIdentity(
        name=backlog_item.artefact.component_name,
        version=backlog_item.artefact.component_version,
    )).component

    for resource in component.resources:
        if resource.name != backlog_item.artefact.artefact.artefact_name:
            continue
        if resource.version != backlog_item.artefact.artefact.artefact_version:
            continue
        if resource.type != backlog_item.artefact.artefact.artefact_type:
            continue
        # currently, we do not set the extraIdentity in the backlog items
        # TODO-Extra-Id: uncomment below code once extraIdentities are handled properly
        # if dso.model.normalise_artefact_extra_id(
        #     artefact_extra_id=resource.extraIdentity,
        #     artefact_version=resource.version,
        # ) != backlog_item.artefact.artefact.normalised_artefact_extra_id(
        #     remove_duplicate_version=True,
        # ):
        #     continue
        break # found resource of backlog item in component's resources
    else:
        logger.error(
            f'could not find {backlog_item.artefact.artefact.artefact_name}:'
            f'{backlog_item.artefact.artefact.artefact_version} in resources of '
            f'{component.name}:{component.version}'
        )
        raise ValueError(resource)

    return cnudie.iter.ResourceNode(
        path=(cnudie.iter.NodePathEntry(component),),
        resource=resource,
    )
