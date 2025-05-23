import dataclasses
import enum
import functools
import inspect
import sys

import dacite

import ocm

import odg.cvss


@dataclasses.dataclass(frozen=True)
class PathRegexes:
    include_paths: list[str] = dataclasses.field(default_factory=list)
    exclude_paths: list[str] = dataclasses.field(default_factory=list)


class ScanPolicy(enum.Enum):
    SCAN = 'scan'
    SKIP = 'skip'


@dataclasses.dataclass(frozen=True)
class LabelValue:
    pass


@dataclasses.dataclass(frozen=True)
class Label:
    name: str
    value: LabelValue


@dataclasses.dataclass(frozen=True)
class ScanningHint(LabelValue):
    policy: ScanPolicy
    path_config: PathRegexes | None
    comment: str | None


@dataclasses.dataclass(frozen=True)
class BinaryIdScanLabel(Label):
    name = 'cloud.gardener.cnudie/dso/scanning-hints/binary_id/v1'
    value: ScanningHint


@dataclasses.dataclass(frozen=True)
class SourceScanLabel(Label):
    name = 'cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1'
    value: ScanningHint


@dataclasses.dataclass(frozen=True)
class PurposeLabel(Label):
    name = 'gardener.cloud/purposes'
    value: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class PackageVersionHint:
    name: str
    version: str


@dataclasses.dataclass(frozen=True)
class PackageVersionHintLabel(Label):
    name = 'cloud.gardener.cnudie/dso/scanning-hints/package-versions'
    value: tuple[PackageVersionHint, ...]


@dataclasses.dataclass(frozen=True)
class CveCategorisationLabel(Label):
    name = 'gardener.cloud/cve-categorisation'
    value: odg.cvss.CveCategorisation


@functools.cache
def _label_to_type() -> dict[str, Label]:
    own_module = sys.modules[__name__]
    types = tuple(t for entry
        in inspect.getmembers(own_module, inspect.isclass)
        if (t := entry[1]) != Label and issubclass(t, Label)
    )

    label_names_to_types = {}
    for t in types:
        label_names_to_types[t.name] = t

    return label_names_to_types


def deserialise_label(
    label: ocm.Label | dict,
):
    if isinstance(label, ocm.Label):
        label = {
            'name': label.name,
            'value': label.value,
        }

    if not (t := _label_to_type().get(label['name'])):
        raise ValueError(f"unknown {label['name']=}")

    return dacite.from_dict(
        data_class=t,
        data=label,
        config=dacite.Config(
            cast=[tuple, enum.Enum],
        ),
    )
