import collections.abc
import logging

import cnudie.iter
import cnudie.retrieve_async
import dso.model
import ioutil
import oci.client
import oci.model
import ocm
import tarutil


logger = logging.getLogger(__name__)


def iter_local_blob_content(
    access: ocm.LocalBlobAccess,
    oci_client: oci.client.Client,
    image_reference: str=None,
) -> collections.abc.Generator[bytes, None, None]:
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

    return tarutil.concat_blobs_as_tarstream(
        blobs=[
            ioutil.BlobDescriptor(
                content=blob.iter_content(chunk_size=4096),
                size=size,
                name=access.referenceName,
            )
        ],
    )


async def find_artefact_node(
    component_descriptor_lookup: cnudie.retrieve_async.ComponentDescriptorLookupById,
    artefact: dso.model.ComponentArtefactId,
    absent_ok: bool=False,
) -> cnudie.iter.ResourceNode | cnudie.iter.SourceNode | None:
    if not dso.model.is_ocm_artefact(artefact.artefact_kind):
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

        # found artefact in component's artefacts
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

    if not absent_ok:
        raise ValueError(f'could not find OCM node for {artefact=}')
