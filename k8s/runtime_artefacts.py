'''
This module defines the data model of a runtime artefact and can be used to maintain the lifecycle
of runtime artefacts (e.g. creation/iteration).
'''
import dataclasses
import datetime
import typing

import dacite
import dateutil.parser

import dso.model

import k8s.model
import k8s.util
import util


@dataclasses.dataclass(frozen=True)
class RuntimeArtefact:
    '''
    Runtime artefacts depict the dynamic runtime view in contrast to the conceptual design-time view
    modelled by OCM. However, these runtime artefacts relate to one (or more) static OCM components
    or artefacts. This relation can be expressed by specifying certain `references` in the
    `artefact` property.
    '''
    creation_date: datetime.datetime
    artefact: dso.model.ComponentArtefactId

    def as_dict(self) -> dict:
        return util.dict_serialisation(self)

    @staticmethod
    def from_dict(runtime_artefact: dict) -> typing.Self:
        type_hooks = {
            datetime.datetime: lambda ts: dateutil.parser.isoparse(ts) if ts else None,
        }

        return dacite.from_dict(
            data_class=RuntimeArtefact,
            data=runtime_artefact,
            config=dacite.Config(
                type_hooks=type_hooks,
                cast=[dso.model.ArtefactKind],
            ),
        )


def create_runtime_artefact_crd_body(
    name: str,
    namespace: str,
    runtime_artefact: RuntimeArtefact,
    labels: dict[str, str]=None,
) -> dict:
    return {
        'apiVersion': k8s.model.RuntimeArtefactCrd.api_version(),
        'kind': k8s.model.RuntimeArtefactCrd.KIND,
        'metadata': {
            'name': name,
            'namespace': namespace,
            'labels': labels,
        },
        'spec': runtime_artefact.as_dict(),
    }


def iter_runtime_artefacts(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    labels: dict[str, str]=None,
) -> tuple[RuntimeArtefact]:
    if labels:
        label_selector = k8s.util.create_label_selector(labels=labels)
    else:
        label_selector = None

    runtime_artefact_crds = kubernetes_api.custom_kubernetes_api.list_namespaced_custom_object(
        group=k8s.model.RuntimeArtefactCrd.DOMAIN,
        version=k8s.model.RuntimeArtefactCrd.VERSION,
        plural=k8s.model.RuntimeArtefactCrd.PLURAL_NAME,
        namespace=namespace,
        label_selector=label_selector,
    ).get('items')

    return tuple(
        RuntimeArtefact.from_dict(runtime_artefact_crd.get('spec'))
        for runtime_artefact_crd in runtime_artefact_crds
    )


def create_runtime_artefact(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: dso.model.ComponentArtefactId,
    labels: dict[str, str]=None,
):
    name = k8s.util.generate_kubernetes_name(
        name_parts=('runtime-artefact',),
    )

    runtime_artefact = RuntimeArtefact(
        creation_date=datetime.datetime.now(tz=datetime.timezone.utc),
        artefact=artefact,
    )

    body = create_runtime_artefact_crd_body(
        name=name,
        namespace=namespace,
        runtime_artefact=runtime_artefact,
        labels=labels,
    )

    kubernetes_api.custom_kubernetes_api.create_namespaced_custom_object(
        group=k8s.model.RuntimeArtefactCrd.DOMAIN,
        version=k8s.model.RuntimeArtefactCrd.VERSION,
        plural=k8s.model.RuntimeArtefactCrd.PLURAL_NAME,
        namespace=namespace,
        body=body,
    )


def create_unique_runtime_artefact(
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
    artefact: dso.model.ComponentArtefactId,
    labels: dict[str, str]=None,
) -> bool:
    '''
    creates a runtime artefact for the given `artefact`. If there is already an existing runtime
    artefact which is semantically equal and contains `labels`, the creation is skipped. Returns
    `True` if a new runtime artefact was created, otherwise `False`.
    '''
    runtime_artefacts = iter_runtime_artefacts(
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        labels=labels,
    )

    for runtime_artefact in runtime_artefacts:
        if runtime_artefact.artefact == artefact:
            # artefact is already existing -> don't create a new one
            return False

    create_runtime_artefact(
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        artefact=artefact,
        labels=labels,
    )
    return True
