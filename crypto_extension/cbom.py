import json
import logging
import os
import subprocess
import tempfile

import oci.client
import ocm

import syft
import odg.extensions_cfg
import secret_mgmt


logger = logging.getLogger(__name__)

own_dir = os.path.abspath(os.path.dirname(__file__))


def create_cbom(
    image: str | None = None,
    dir: str | None = None,
    sbom_path: str | None = None,
) -> dict:
    """
    Uses `cbomkit-theia` (https://github.com/IBM/cbomkit-theia) to create a CBOM document for the
    provided `image` OR local `dir`. If a path to a SBOM document is specified, the resulting CBOM
    will be an enriched version of this SBOM, otherwise it will be created from-scratch.
    """
    if not (bool(image) ^ bool(dir)):
        raise ValueError(f'exactly one of {image=} and {dir=} must be set')

    if image:
        cbom_cmd = [
            'cbomkit-theia',
            'image',
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

    logger.info(f'run cmd "{" ".join(cbom_cmd)}"')
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
    """
    Looks up an existing CBOM document (to be implemented once it is aligned on target picture) or
    creates a CBOM ad-hoc using `syft` and `cbomkit-theia`.
    """
    with tempfile.TemporaryDirectory(dir=own_dir) as tmp_dir:
        filename_for_access_type = {
            ocm.AccessType.LOCAL_BLOB: 'local_blob',
            ocm.AccessType.S3: 's3',
        }

        file_path = None
        if filename := filename_for_access_type.get(access.type):
            file_path = os.path.join(tmp_dir, filename)

        sbom_raw = syft.generate_raw_sbom_for_artefact(
            component=component,
            access=access,
            secret_factory=secret_factory,
            oci_client=oci_client,
            aws_secret_name=mapping.aws_secret_name,
            file_path=file_path,
        )

        sbom_path = os.path.join(tmp_dir, 'sbom')
        with open(sbom_path, 'w') as file:
            file.write(sbom_raw)

        if access.type is ocm.AccessType.OCI_REGISTRY:
            cbom = create_cbom(
                image=access.imageReference,
                sbom_path=sbom_path,
            )

        else:
            cbom = create_cbom(
                dir=file_path,
                sbom_path=sbom_path,
            )

    return cbom
