import collections.abc
import logging
import tarfile

import cnudie.access
import cnudie.retrieve_async
import ioutil
import oci.client
import oci.model
import ocm
import ocm.iter
import tarutil

import odg.model
import secret_mgmt
import secret_mgmt.aws


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
) -> ocm.iter.ResourceNode | ocm.iter.SourceNode | None:
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
        if (
            (a.name or artefact.artefact.artefact_name)
            and a.name != artefact.artefact.artefact_name
        ):
            continue
        if (
            (a.version or artefact.artefact.artefact_version)
            and a.version != artefact.artefact.artefact_version
        ):
            continue
        if (
            (a.type or artefact.artefact.artefact_type)
            and a.type != artefact.artefact.artefact_type
        ):
            continue
        if (
            odg.model.normalise_artefact_extra_id(a.extraIdentity)
            != artefact.artefact.normalised_artefact_extra_id
        ):
            continue

        # found artefact in component's artefacts
        if artefact.artefact_kind is odg.model.ArtefactKind.RESOURCE:
            return ocm.iter.ResourceNode(
                path=(ocm.iter.NodePathEntry(component),),
                resource=a,
            )
        elif artefact.artefact_kind is odg.model.ArtefactKind.SOURCE:
            return ocm.iter.SourceNode(
                path=(ocm.iter.NodePathEntry(component),),
                source=a,
            )
        else:
            raise RuntimeError('this line should never be reached')

    if not absent_ok:
        raise ValueError(f'could not find OCM node for {artefact=}')


def find_artefact_node(
    artefact_nodes: collections.abc.Sequence[ocm.iter.ArtefactNode],
    artefact_name: str=None,
    artefact_version: str=None,
    artefact_type: str=None,
    artefact_extra_id: dict=None,
    absent_ok: bool=False,
) -> ocm.iter.ArtefactNode | None:
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


def iter_content_for_resource_node(
    resource_node: ocm.iter.ResourceNode,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
    aws_secret_name: str | None = None,
) -> collections.abc.Iterator[bytes]:
    access = resource_node.resource.access

    if access.type is ocm.AccessType.OCI_REGISTRY:
        return image_layers_as_tarfile_generator(
            image_reference=access.imageReference,
            oci_client=oci_client,
            include_config_blob=False,
            fallback_to_first_subimage_if_index=True,
        )

    elif access.type is ocm.AccessType.S3:
        aws_secret = secret_mgmt.aws.find_cfg(
            secret_factory=secret_factory,
            secret_name=aws_secret_name,
        )
        s3_client = aws_secret.session.client('s3')

        return tarutil.concat_blobs_as_tarstream(
            blobs=[
                cnudie.access.s3_access_as_blob_descriptor(
                    s3_client=s3_client,
                    s3_access=access,
                ),
            ]
        )

    elif access.type is ocm.AccessType.LOCAL_BLOB:
        ocm_repo = resource_node.component.current_ocm_repo
        image_reference = ocm_repo.component_version_oci_ref(
            name=resource_node.component.name,
            version=resource_node.component.version,
        )

        return tarutil.concat_blobs_as_tarstream(
            blobs=[
                local_blob_access_as_blob_descriptor(
                    access=access,
                    oci_client=oci_client,
                    image_reference=image_reference,
                ),
            ]
        )

    else:
        raise RuntimeError(f'Unsupported access type: {access.type}')


def image_layers_as_tarfile_generator(
    image_reference: str,
    oci_client: oci.client.Client,
    chunk_size=tarfile.RECORDSIZE,
    include_config_blob=True,
    fallback_to_first_subimage_if_index=False,
) -> collections.abc.Generator[bytes, None, None]:
    '''
    returns a generator yielding a tar-archive with the passed oci-image's layer-blobs as
    members. This is somewhat similar to the result of a `docker save` with the notable difference
    that the cfg-blob is discarded.
    This function is useful to e.g. upload file system contents of an oci-container-image to some
    scanning-tool (provided it supports the extraction of tar-archives)
    If include_config_blob is set to False the config blob will be ignored.

    If fallback_to_first_subimage_if_index is set to True, in case of oci-image-manifest-list the
    first sub-manifest is taken.
    '''
    manifest = oci_client.manifest(
        image_reference=image_reference,
        accept=oci.model.MimeTypes.prefer_multiarch,
    )

    image_reference = oci.model.OciImageReference.to_image_ref(image_reference)

    if fallback_to_first_subimage_if_index and isinstance(manifest, oci.model.OciImageManifestList):
        logger.warn(
            f'image-index handling not fully implemented - will only scan first image, '
            f'{image_reference=}, {manifest.mediaType=}'
        )
        manifest_ref = manifest.manifests[0]
        manifest = oci_client.manifest(
            image_reference=f'{image_reference.ref_without_tag}@{manifest_ref.digest}',
        )

    blob_refs = manifest.blobs() if include_config_blob else manifest.layers

    if not include_config_blob:
        logger.debug('skipping config blob')

    def resolve_blob(
        blob_ref: oci.model.OciBlobRef,
        image_reference: str,
    ) -> ioutil.BlobDescriptor:
        content = oci_client.blob(
            image_reference=image_reference,
            digest=blob_ref.digest,
            stream=True,
        ).iter_content(chunk_size=chunk_size)

        return ioutil.BlobDescriptor(
            content=content,
            size=blob_ref.size,
            name=f'{blob_ref.digest}.tar',
        )

    return tarutil.concat_blobs_as_tarstream(
        blobs=(
            resolve_blob(
                blob_ref=blob_ref,
                image_reference=image_reference,
            )
            for blob_ref in blob_refs
        ),
    )
