import collections.abc

import bdba.client
import bdba.model as bm

import odg.labels


def upload_version_hints(
    scan_result: bm.AnalysisResult,
    hints: collections.abc.Iterable[odg.labels.PackageVersionHint],
    bdba_client: bdba.client.BDBAApi,
) -> bm.AnalysisResult:
    for component in scan_result.components:
        name = component.name
        version = component.version

        if version and version != 'unknown':
            # check if package is unique -> in that case we can overwrite the detected version
            if len([c for c in scan_result.components if c.name == name]) > 1:
                # not unique, so we cannot overwrite package version
                continue

        for hint in hints:
            if hint.name == name and hint.version != version:
                break
        else:
            continue

        digests = [eo.sha1 for eo in component.extended_objects]

        bdba_client.set_component_version(
            component_name=name,
            component_version=hint.version,
            objects=digests,
            app_id=scan_result.product_id,
        )

        # the bdba api does not properly react to multiple component versions being set in
        # a short period of time. This even stays true if all component versions are set
        # using one single api request. That's why, adding a small delay in case multiple
        # hints and thus possible version overrides exist by retrieving scan result again
        scan_result = bdba_client.wait_for_scan_result(
            product_id=scan_result.product_id,
            polling_interval_seconds=15, # re-scanning usually don't take a minute
        )

    return scan_result
