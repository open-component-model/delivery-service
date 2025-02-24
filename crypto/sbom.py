import logging
import subprocess


logger = logging.getLogger(__name__)


def derive_sbom_for_source(
    source: str,
    output_path: str,
):
    '''
    Uses `syft` (https://github.com/anchore/syft) to create a SBOM document at `output_path` for the
    provided `source`. `source` might be any of the accepted inputs for `syft`, e.g. an image
    reference or a path to a directory, file, archive.
    '''
    sbom_cmd = (
        'syft',
        source,
        '--scope', 'all-layers',
        '--output', 'cyclonedx-json'
    )
    logger.info(f'run cmd "{' '.join(sbom_cmd)}"')
    try:
        sbom_raw = subprocess.run(sbom_cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        e.add_note(f'{e.stdout=}')
        e.add_note(f'{e.stderr=}')
        raise

    with open(output_path, 'w') as file:
        file.write(sbom_raw)
