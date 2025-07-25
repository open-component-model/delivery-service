import collections.abc
import logging

import cnudie.iter
import cnudie.retrieve_async
import ioutil
import oci.client
import oci.model
import ocm

import odg.model


logger = logging.getLogger(__name__)


def local_blob_access_as_blob_descriptor(
    access: ocm.LocalBlobAccess,
    oci_client: oci.client.Client,
    image_reference: str=None,
) -> ioutil.BlobDescriptor:
    if access.globalAccess:
        image_reference = access.globalAccess.ref
        digest = access.globalAccess.digest
        size = access.globalAccess.size

    else:
        if not image_reference:
            raise ValueError('`image_reference` must not be empty to resolve local blob')

        digest = access.localReference.lower()
        size = access.size

    blob = oci_client.blob(
        image_reference=image_reference,
        digest=digest,
        stream=True,
    )

    if not size:
        manifest = oci_client.manifest(
            image_reference=image_reference,
            accept=oci.model.MimeTypes.prefer_multiarch,
        )

        if isinstance(manifest, oci.model.OciImageManifestList):
            raise ValueError('component-descriptor manifest must not be a manifest list')

        for layer in manifest.layers:
            if layer.digest == digest:
                size = layer.size
                break
        else:
            raise ValueError('`size` must not be empty to stream local blob')

    return ioutil.BlobDescriptor(
        content=blob.iter_content(chunk_size=4096),
        size=size,
        name=access.referenceName,
    )


async def find_artefact_node_async(
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    artefact: odg.model.ComponentArtefactId,
    absent_ok: bool=False,
) -> cnudie.iter.ResourceNode | cnudie.iter.SourceNode | None:
    if not odg.model.is_ocm_artefact(artefact.artefact_kind):
        return None

    component = (await component_descriptor_lookup(
        ocm.ComponentIdentity(
            name=artefact.component_name,
            version=artefact.component_version,
        ),
        absent_ok=absent_ok,
    )).component

    if not component:
        return None

    if artefact.artefact_kind is odg.model.ArtefactKind.RESOURCE:
        artefacts = component.resources
    elif artefact.artefact_kind is odg.model.ArtefactKind.SOURCE:
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
            odg.model.normalise_artefact_extra_id(a.extraIdentity)
            != artefact.artefact.normalised_artefact_extra_id
        ):
            continue

        # found artefact in component's artefacts
        if artefact.artefact_kind is odg.model.ArtefactKind.RESOURCE:
            return cnudie.iter.ResourceNode(
                path=(cnudie.iter.NodePathEntry(component),),
                resource=a,
            )
        elif artefact.artefact_kind is odg.model.ArtefactKind.SOURCE:
            return cnudie.iter.SourceNode(
                path=(cnudie.iter.NodePathEntry(component),),
                source=a,
            )
        else:
            raise RuntimeError('this line should never be reached')

    if not absent_ok:
        raise ValueError(f'could not find OCM node for {artefact=}')


def find_artefact_node(
    artefact_nodes: collections.abc.Sequence[cnudie.iter.ArtefactNode],
    artefact_name: str=None,
    artefact_version: str=None,
    artefact_type: str=None,
    artefact_extra_id: dict=None,
    absent_ok: bool=False,
) -> cnudie.iter.ArtefactNode | None:
    for artefact_node in artefact_nodes:

        if (
            artefact_name is not None
            and artefact_node.artefact.name != artefact_name
        ):
            continue

        if (
            artefact_version is not None
            and artefact_node.artefact.version != artefact_version
        ):
            continue

        if (
            artefact_type is not None
            and artefact_node.artefact.type != artefact_type
        ):
            continue

        if (
            artefact_extra_id is not None
            and odg.model.normalise_artefact_extra_id(artefact_node.artefact.extraIdentity) != odg.model.normalise_artefact_extra_id(artefact_extra_id) # noqa: E501
        ):
            continue

        return artefact_node

    else:
        if absent_ok:
            return None

        raise ValueError(f'no ocm node found for {artefact_name=} {artefact_version=} \
                         {artefact_type=} {artefact_extra_id=}')
