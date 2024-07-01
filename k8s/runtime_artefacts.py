import dataclasses
import datetime
import dateutil.parser
import http
import typing

import dacite
import kubernetes.client.rest

import ci.util
import dso.model

import k8s.model
import k8s.util


@dataclasses.dataclass(frozen=True)
class RuntimeArtefact:
    creation_date: datetime.datetime
    artefact: dso.model.ComponentArtefactId

    def as_dict(self) -> dict:
        return dataclasses.asdict(
            obj=self,
            dict_factory=ci.util.dict_to_json_factory,
        )

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
                cast=[
                    dso.model.ArtefactKind,
                ],
            ),
        )


def create_runtime_artefact_crd_body(
    name: str,
    namespace: str,
    runtime_artefact: RuntimeArtefact,
    labels: dict[str, str]={},
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
    labels: dict[str, str]={},
) -> tuple[RuntimeArtefact]:
    label_selector = k8s.util.create_label_selector(labels=labels)

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
    labels: dict[str, str]={},
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
    labels: dict[str, str]={},
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

    found_runtime_artefact = False
    for runtime_artefact in runtime_artefacts:
        if runtime_artefact.artefact == artefact:
            found_runtime_artefact = True
            break

    if found_runtime_artefact:
        return False

    create_runtime_artefact(
        namespace=namespace,
        kubernetes_api=kubernetes_api,
        artefact=artefact,
        labels=labels,
    )
    return True


def delete_runtime_artefact(
    name: str,
    namespace: str,
    kubernetes_api: k8s.util.KubernetesApi,
):
    try:
        kubernetes_api.custom_kubernetes_api.delete_namespaced_custom_object(
            group=k8s.model.RuntimeArtefactCrd.DOMAIN,
            version=k8s.model.RuntimeArtefactCrd.VERSION,
            plural=k8s.model.RuntimeArtefactCrd.PLURAL_NAME,
            namespace=namespace,
            name=name,
        )
    except kubernetes.client.rest.ApiException as e:
        # if the http status is 404 it is fine because the object should be deleted anyway
        if e.status != http.HTTPStatus.NOT_FOUND:
            raise e
