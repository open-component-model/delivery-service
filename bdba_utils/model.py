import collections.abc
import dataclasses
import traceback

import ocm

import odg.labels


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

    @property
    def skip_vulnerability_scan(self) -> bool:
        # hardcode skip-info to be determined by artefact
        artefact = self.artefact

        if not (label := artefact.find_label(name=odg.labels.BinaryIdScanLabel.name)):
            return False

        label: odg.labels.BinaryIdScanLabel = odg.labels.deserialise_label(label=label)
        return label.value.policy is odg.labels.ScanPolicy.SKIP

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
