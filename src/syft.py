import enum
import logging
import os
import subprocess
import tarfile

import oci.client
import ocm

import dockerutil
import secret_mgmt.aws
import secret_mgmt.oci_registry


logger = logging.getLogger(__name__)
own_dir = os.path.abspath(os.path.dirname(__file__))


class SyftSbomFormat(enum.StrEnum):
    CYCLONEDX = 'cyclonedx-json'
    SPDX = 'spdx-json'


def run_syft(
    source: str,
    output_format: SyftSbomFormat = SyftSbomFormat.CYCLONEDX,
) -> str:
    """
    Runs `syft` (https://github.com/anchore/syft) to create a SBOM for the provided `source`.
    `source` might be any of the accepted inputs for `syft`, e.g. an image reference or a path
    to a directory, file, archive.

    Returns the raw SBOM output as a string.
    """
    sbom_cmd = (
        'syft',
        source,
        '--scope',
        'all-layers',
        '--output',
        output_format,
    )
    logger.info(f'run cmd "{" ".join(sbom_cmd)}"')
    try:
        sbom_raw = subprocess.run(sbom_cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        e.add_note(f'{e.stdout=}')
        e.add_note(f'{e.stderr=}')
        raise

    return sbom_raw


def generate_raw_sbom_for_artefact(
    component: ocm.Component,
    access: ocm.Access,
    secret_factory: secret_mgmt.SecretFactory,
    oci_client: oci.client.Client,
    file_path: str | None = None,
    aws_secret_name: str | None = None,
    sbom_output_format: SyftSbomFormat = SyftSbomFormat.CYCLONEDX,
) -> str:
    if (
        access.type
        in (
            ocm.AccessType.LOCAL_BLOB,
            ocm.AccessType.S3,
        )
        and not file_path
    ):
        raise ValueError(f'file_path must not be empty for {access.type=}')

    if access.type is ocm.AccessType.OCI_REGISTRY:
        access: ocm.OciAccess

        oci_secret = secret_mgmt.oci_registry.find_cfg(
            secret_factory=secret_factory,
            image_reference=access.imageReference,
        )

        if oci_secret:
            dockerutil.prepare_docker_cfg(
                image_reference=access.imageReference,
                username=oci_secret.username,
                password=oci_secret.password,
            )

        return run_syft(
            source=access.imageReference,
            output_format=sbom_output_format,
        )

    elif access.type is ocm.AccessType.S3:
        access: ocm.S3Access

        aws_secret = secret_mgmt.aws.find_cfg(
            secret_factory=secret_factory,
            secret_name=aws_secret_name,
        )
        s3_client = aws_secret.session.client('s3')

        if isinstance(access, ocm.LegacyS3Access):
            bucket = access.bucketName
            key = access.objectKey
        else:
            bucket = access.bucket
            key = access.key

        fileobj = s3_client.get_object(Bucket=bucket, Key=key)['Body']

        def tar_filter(member: tarfile.TarInfo, dest_path: str) -> tarfile.TarInfo | None:
            if member.islnk() or member.issym():
                if os.path.isabs(member.linkname):
                    return None
            return member

        with tarfile.open(fileobj=fileobj, mode='r|*') as tar:
            tar.extractall(
                path=file_path,
                filter=tar_filter,
            )

        return run_syft(
            source=file_path,
            output_format=sbom_output_format,
        )

    elif access.type is ocm.AccessType.LOCAL_BLOB:
        access: ocm.LocalBlobAccess | ocm.LocalBlobGlobalAccess

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

        with open(file_path, 'wb') as file:
            for chunk in blob.iter_content(chunk_size=4096):
                file.write(chunk)

        return run_syft(
            source=file_path,
            output_format=sbom_output_format,
        )

    else:
        raise ValueError(f'dont know how to handle {access.type=}')
