import collections.abc

import ioutil
import oci.client
import ocm
import tarutil


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
