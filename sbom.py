import dataclasses
import enum

class SBomFormat(enum.StrEnum):
    CYCLONEDX = 'cyclonedx'
    SPDX = 'spdx'
    BDIO = 'bdio'


@dataclasses.dataclass
class SBOM:
    sbom_raw: dict
    sbom_format: SBomFormat
