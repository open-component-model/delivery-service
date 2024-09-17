import collections.abc

import dso.model
import ioutil
import oci.client
import ocm
import tarutil


def find_artefact_of_component_or_none(
    component: ocm.Component,
    artefact: dso.model.ComponentArtefactId,
) -> ocm.Resource | ocm.Source | None:
    if artefact.component_name and component.name != artefact.component_name:
        return None

    if artefact.component_version and component.version != artefact.component_version:
        return None

    if not artefact.artefact:
        return None

    local_artefact = artefact.artefact
    artefact_kind = artefact.artefact_kind

    for artefact in component.resources + component.sources:
        artefact: ocm.Resource | ocm.Source

        if local_artefact.artefact_name and artefact.name != local_artefact.artefact_name:
            continue

        if local_artefact.artefact_version and artefact.version != local_artefact.artefact_version:
            continue

        if local_artefact.artefact_type and artefact.type != local_artefact.artefact_type:
            continue

        if local_artefact.artefact_extra_id and dso.model.normalise_artefact_extra_id(
            artefact_extra_id=artefact.extraIdentity,
        ) != local_artefact.normalised_artefact_extra_id():
            continue

        if isinstance(artefact, ocm.Resource) and artefact_kind != dso.model.ArtefactKind.RESOURCE:
            continue

        if isinstance(artefact, ocm.Source) and artefact_kind != dso.model.ArtefactKind.SOURCE:
            continue

        # artefact is referenced in component
        break
    else:
        # artefact is not referenced in component
        artefact = None

    return artefact


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

    return tarutil.concat_blobs_as_tarstream(
        blobs=[
            ioutil.BlobDescriptor(
                content=blob.iter_content(chunk_size=4096),
                size=size,
                name=access.referenceName,
            )
        ],
    )
