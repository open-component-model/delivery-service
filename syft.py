import enum
import logging
import subprocess


logger = logging.getLogger(__name__)


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
