# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0


import collections.abc
import dataclasses
import datetime
import enum
import logging
import traceback

import dacite
import dateutil.parser

import ci.util
import dso.cvss
import dso.labels
import ocm


logger = logging.getLogger()


class VersionOverrideScope(enum.IntEnum):
    APP = 1
    GROUP = 2
    GLOBAL = 3


class ProcessingStatus(enum.StrEnum):
    BUSY = 'B'
    READY = 'R'
    FAILED = 'F'


class CVSSVersion(enum.StrEnum):
    V2 = 'CVSSv2'
    V3 = 'CVSSv3'


class TriageScope(enum.StrEnum):
    ACCOUNT_WIDE = 'CA'
    FILE_NAME = 'FN'
    FILE_HASH = 'FH'
    RESULT = 'R'
    GROUP = 'G'


class ProcessingMode(enum.StrEnum):
    RESCAN = 'rescan'
    FORCE_UPLOAD = 'force_upload'


@dataclasses.dataclass
class Product:
    product_id: int
    name: str
    custom_data: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class Triage:
    id: int
    vuln_id: str
    component: str
    version: str | None
    scope: TriageScope
    reason: str
    description: str | None
    modified: datetime.datetime
    user: dict = dataclasses.field(default_factory=dict)

    def __repr__(self):
        return (
            f'{self.__class__.__name__}: {self.id} ({self.component} {self.version}, '
            f'{self.vuln_id}, Scope: {self.scope})'
        )

    def __eq__(self, other):
        if not isinstance(other, Triage):
            return False
        if self.vuln_id != other.vuln_id:
            return False
        if self.component != other.component:
            return False
        if self.description != other.description:
            return False
        return True

    def __hash__(self):
        return hash((self.vuln_id, self.component, self.description))


@dataclasses.dataclass
class Vulnerability:
    vuln: dict
    exact: bool | None
    triage: list[Triage]

    @property
    def historical(self):
        return not self.exact

    @property
    def cve(self) -> str:
        return self.vuln.get('cve')

    def cve_severity(
        self,
        cvss_version: CVSSVersion=CVSSVersion.V3,
    ) -> float:
        if cvss_version is CVSSVersion.V3:
            return float(self.vuln.get('cvss3_score'))
        elif cvss_version is CVSSVersion.V2:
            return float(self.vuln.get('cvss'))
        else:
            raise ValueError(f'{cvss_version} not supported')

    @property
    def cvss(self) -> dso.cvss.CVSSV3 | None:
        # ignore cvss2_vector for now
        if not (cvss_vector := self.vuln.get('cvss3_vector')):
            return None

        return dso.cvss.CVSSV3.parse(cvss_vector)

    @property
    def summary(self) -> str:
        return self.vuln.get('summary')

    @property
    def has_triage(self) -> bool:
        return bool(self.triage)

    @property
    def triages(self) -> collections.abc.Generator[Triage, None, None]:
        if not self.has_triage:
            return

        yield from self.triage

    def __repr__(self):
        return f'{self.__class__.__name__}: {self.cve}'


@dataclasses.dataclass
class License:
    name: str
    type: str | None
    url: str | None


@dataclasses.dataclass
class ExtendedObject:
    name: str | None
    sha1: str | None
    extended_fullpath: list[dict]


@dataclasses.dataclass
class Component:
    lib: str
    version: str | None
    vulns: list[dict] | None
    license: License | None
    licenses: dict | None
    extended_objects: list[ExtendedObject] = dataclasses.field(default_factory=list)

    @property
    def name(self) -> str:
        return self.lib

    @property
    def vulnerabilities(self) -> collections.abc.Generator[Vulnerability, None, None]:
        for vuln in self.vulns or []:
            if vuln['vuln'].get('cve'):
                yield dacite.from_dict(
                    data_class=Vulnerability,
                    data=vuln,
                    config=dacite.Config(
                        type_hooks={
                            datetime.datetime: dateutil.parser.isoparse,
                        },
                        cast=[enum.Enum],
                    ),
                )

    @property
    def iter_licenses(self) -> collections.abc.Generator[License, None, None]:
        '''
        Wrapper to consume package's licenses and prefer those stored in the `licenses` property
        over the one in the `license` property. Rationale: BDBA is known to always store the
        greatest license version under `license`, and the "correct" one under `licenses`.
        '''
        if not self.licenses:
            if self.license:
                yield self.license
            return

        yield from [
            dacite.from_dict(
                data_class=License,
                data=license_raw,
            ) for license_raw in self.licenses.get('licenses')
        ]

    def __repr__(self):
        return f'{self.__class__.__name__}: {self.name} {self.version or "version not detected"}'


@dataclasses.dataclass
class Result:
    product_id: int
    report_url: str
    filename: str | None
    stale: bool | None
    rescan_possible: bool | None

    @property
    def base_url(self) -> str:
        parsed_url = ci.util.urlparse(self.report_url)
        return f'{parsed_url.scheme}://{parsed_url.netloc}'

    @property
    def display_name(self) -> str:
        return self.filename or '<None>'

    def __repr__(self):
        return f'{self.__class__.__name__}: {self.display_name} ({self.product_id})'


@dataclasses.dataclass
class AnalysisResult(Result):
    group_id: int
    status: ProcessingStatus
    name: str | None
    fail_reason: str | None
    components: list[Component] = dataclasses.field(default_factory=list)
    custom_data: dict[str, str] = dataclasses.field(default_factory=dict)


#############################################################################
## upload result model

class UploadStatus(enum.IntEnum):
    SKIPPED = 1
    PENDING = 2
    DONE = 4


@dataclasses.dataclass
class ScanRequest:
    '''
    a scan request of an artefact (referenced by component and artefact).

    if a previous scan result was found, its "product-id" is stored as `target_product_id`
    '''
    component: ocm.Component
    artefact: ocm.Artifact
    # The actual content to be scanned.
    scan_content: collections.abc.Generator[bytes, None, None]
    display_name: str
    target_product_id: int | None
    custom_metadata: dict

    def auto_triage_scan(self) -> bool:
        # hardcode auto-triage to be determined by artefact
        artefact = self.artefact

        # pylint: disable=E1101
        if not (label := artefact.find_label(name=dso.labels.BinaryIdScanLabel.name)):
            return False

        label: dso.labels.BinaryIdScanLabel = dso.labels.deserialise_label(label=label)

        return label.value.policy is dso.labels.ScanPolicy.SKIP

    def __str__(self):
        return (
            f"ScanRequest(name='{self.display_name}', target_product_id='{self.target_product_id}' "
            f"custom_metadata='{self.custom_metadata}')"
        )


class BdbaScanError(Exception):
    def __init__(
        self,
        scan_request: ScanRequest,
        component: ocm.Component,
        artefact: ocm.Artifact,
        exception=None,
        *args,
        **kwargs,
    ):
        self.scan_request = scan_request
        self.component = component
        self.artefact = artefact
        self.exception = exception

        super().__init__(*args, **kwargs)

    def print_stacktrace(self):
        c = self.component
        a = self.artefact
        name = f'{c.name}/{a.name}:{a.version}'

        if not self.exception:
            return name + ' - no exception available'

        return name + '\n' + ''.join(traceback.format_tb(self.exception.__traceback__))
