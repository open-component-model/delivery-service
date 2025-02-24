import json
import logging
import os
import subprocess
import tarfile
import tempfile

import oci.client
import ocm

import crypto_extension.sbom
import dockerutil
import odg.extensions_cfg
import secret_mgmt
import secret_mgmt.oci_registry


logger = logging.getLogger(__name__)

own_dir = os.path.abspath(os.path.dirname(__file__))


def create_cbom(
    image: str | None=None,
    dir: str | None=None,
    sbom_path: str | None=None,
) -> dict:
    '''
    Uses `cbomkit-theia` (https://github.com/IBM/cbomkit-theia) to create a CBOM document for the
    provided `image` OR local `dir`. If a path to a SBOM document is specified, the resulting CBOM
    will be an enriched version of this SBOM, otherwise it will be created from-scratch.
    '''
    if not (bool(image) ^ bool(dir)):
        raise ValueError(f'exactly one of {image=} and {dir=} must be set')

    if image:
        cbom_cmd = [
            'cbomkit-theia',
            'image',
            'get',
            image,
        ]
    else:
        cbom_cmd = [
            'cbomkit-theia',
            'dir',
            dir,
        ]

    if sbom_path:
        cbom_cmd.extend(['--bom', sbom_path])

    logger.info(f'run cmd "{' '.join(cbom_cmd)}"')
    try:
        cbom_raw = subprocess.run(cbom_cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        e.add_note(f'{e.stdout=}')
        e.add_note(f'{e.stderr=}')
        raise

    return json.loads(cbom_raw)


def find_cbom_or_create(
    component: ocm.Component,
    access: ocm.Access,
    mapping: odg.extensions_cfg.CryptoMapping,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
) -> dict:
    '''
    Looks up an existing CBOM document (to be implemented once it is aligned on target picture) or
    creates a CBOM ad-hoc using `syft` and `cbomkit-theia`.
    '''
    if access.type is ocm.AccessType.OCI_REGISTRY:
        oci_secret = secret_mgmt.oci_registry.find_cfg(
            secret_factory=secret_factory,
            image_reference=access.imageReference,
        )

        dockerutil.prepare_docker_cfg(
            image_reference=access.imageReference,
            username=oci_secret.username,
            password=oci_secret.password,
        )

        with tempfile.TemporaryDirectory(dir=own_dir) as tmp_dir:
            sbom_path = os.path.join(tmp_dir, 'sbom')

            crypto_extension.sbom.derive_sbom_for_source(
                source=access.imageReference,
                output_path=sbom_path,
            )

            cbom = create_cbom(
                image=access.imageReference,
                sbom_path=sbom_path,
            )

    elif access.type is ocm.AccessType.S3:
        if not mapping.aws_secret_name:
            raise ValueError('"aws_secret_name" must be configured for resources stored in S3')

        logger.info(f'using AWS secret element "{mapping.aws_secret_name}"')
        aws_secret = secret_factory.aws(mapping.aws_secret_name)
        s3_client = aws_secret.session.client('s3')

        fileobj = s3_client.get_object(Bucket=access.bucketName, Key=access.objectKey)['Body']

        def tar_filter(member: tarfile.TarInfo, dest_path: str) -> tarfile.TarInfo | None:
            if member.islnk() or member.issym():
                if os.path.isabs(member.linkname):
                    return None
            return member

        with tempfile.TemporaryDirectory(dir=own_dir) as tmp_dir:
            sbom_path = os.path.join(tmp_dir, 'sbom')
            s3_path = os.path.join(tmp_dir, 's3')

            with tarfile.open(fileobj=fileobj, mode='r|*') as tar:
                tar.extractall(
                    path=s3_path,
                    filter=tar_filter,
                )

            crypto_extension.sbom.derive_sbom_for_source(
                source=s3_path,
                output_path=sbom_path,
            )

            cbom = create_cbom(
                dir=s3_path,
                sbom_path=sbom_path,
            )

    elif access.type is ocm.AccessType.LOCAL_BLOB:
        if access.globalAccess:
            image_reference = access.globalAccess.ref
            digest = access.globalAccess.digest
        else:
            image_reference = component.current_ocm_repo.component_version_oci_ref(
                name=component.name,
                version=component.version,
            )
            digest = access.localReference

        blob = oci_client.blob(
            image_reference=image_reference,
            digest=digest,
            stream=True,
        )

        with tempfile.TemporaryDirectory(dir=own_dir) as tmp_dir:
            sbom_path = os.path.join(tmp_dir, 'sbom')
            local_blob_path = os.path.join(tmp_dir, 'local_blob')

            with open(local_blob_path, 'wb') as file:
                for chunk in blob.iter_content(chunk_size=4096):
                    file.write(chunk)

            crypto_extension.sbom.derive_sbom_for_source(
                source=local_blob_path,
                output_path=sbom_path,
            )

            cbom = create_cbom(
                dir=local_blob_path,
                sbom_path=sbom_path,
            )

    else:
        # we filtered supported access types already earlier
        raise RuntimeError('this is a bug, this line should never be reached')

    return cbom
