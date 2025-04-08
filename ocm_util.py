import collections.abc
import logging
import urllib.parse

import ci.util
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


async def find_artefact_node_async(
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


def to_absolute_oci_access(
    access: ocm.OciAccess | ocm.RelativeOciAccess,
    ocm_repo: ocm.OciOcmRepository=None,
) -> ocm.OciAccess:
    if access.type is ocm.AccessType.OCI_REGISTRY:
        return access

    if access.type is ocm.AccessType.RELATIVE_OCI_REFERENCE:
        if not '://' in ocm_repo.baseUrl:
            base_url = urllib.parse.urlparse(f'x://{ocm_repo.baseUrl}').netloc
        else:
            base_url = urllib.parse.urlparse(ocm_repo.baseUrl).netloc

        return ocm.OciAccess(
            imageReference=ci.util.urljoin(base_url, access.reference),
        )

    raise ValueError(f'{access.type=} is not supported for conversion to absolute oci access')


def find_artefact_node(
    artefact_node_sequence: collections.abc.Sequence[cnudie.iter.ArtefactNode],
    artefact_name: str=None,
    artefact_version: str=None,
    artefact_type: str=None,
    artefact_extra_id: dict=None,
    absent_ok: bool=False,
) -> cnudie.iter.ArtefactNode | None:
    for artefact_node in artefact_node_sequence:

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
            and artefact_node.artefact.extraIdentity != artefact_extra_id
        ):
            continue

        return artefact_node

    else:
        if absent_ok:
            return None

        raise ValueError(f'no ocm node found for {artefact_name=} {artefact_version=} \
                         {artefact_type=}')
