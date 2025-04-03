import logging

import awesomeversion

import unixutil.model as um

import osinfo.model


logger = logging.getLogger(__name__)


def find_branch_info(
    os_id: um.OperatingSystemId,
    os_infos: list[osinfo.model.OsReleaseInfo],
) -> osinfo.model.OsReleaseInfo | None:
    os_version = os_id.VERSION_ID

    def version_candidates():
        yield os_version
        yield f'v{os_version}'

        parts = os_version.split('.')

        if len(parts) == 1:
            return

        yield parts[0]
        yield 'v' + parts[0]

        yield '.'.join(parts[:2]) # strip parts after minor
        yield 'v' + '.'.join(parts[:2]) # strip parts after minor

    candidates = tuple(version_candidates() if os_version else ())

    for os_info in os_infos:
        for candidate in candidates:
            if os_info.name == candidate:
                return os_info

    logger.warning(f'did not find branch-info for {os_id=}')


def branch_reached_eol(
    os_id: um.OperatingSystemId,
    os_infos: list[osinfo.model.OsReleaseInfo],
) -> bool:
    if not os_id.ID:
        return False

    branch_info = find_branch_info(
        os_id=os_id,
        os_infos=os_infos,
    )

    return branch_info.reached_eol if branch_info else False


def update_available(
    os_id: um.OperatingSystemId,
    os_infos: list[osinfo.model.OsReleaseInfo],
    ignore_if_patchlevel_is_next_to_greatest=False,
) -> bool:
    if not os_id.ID:
        return False

    branch_info = find_branch_info(
        os_id=os_id,
        os_infos=os_infos,
    )
    if not branch_info:
        return False

    if not branch_info.greatest_version:
        return False

    version = awesomeversion.AwesomeVersion(os_id.VERSION_ID.replace('_', '-'))
    greatest_version = awesomeversion.AwesomeVersion(branch_info.greatest_version.replace('_', '-'))

    greater_version_available = greatest_version > version

    if not greater_version_available or not ignore_if_patchlevel_is_next_to_greatest:
        return greater_version_available

    # there is greated version; check whether difference is not more than one patchlevel
    # check whether both versions actually _have_ patchlevel
    if not greatest_version.patch or not version.patch:
        return greater_version_available

    patch_diff = int(greatest_version.patch) - int(version.patch)
    return patch_diff > 1
