import os


own_dir = os.path.abspath(os.path.dirname(__file__))

# Explicit allowlist of supported OS IDs with filesystem configs
# Maps os_id → config filename
SUPPORTED_OS_CONFIGS = {
    'alinux': 'alinux.yaml',
}


def for_os(os_id: str) -> str:
    """
    Returns the absolute path to the OS configuration file for the given os_id.

    Raises ValueError if os_id is not in the allowlist.
    """
    config_filename = SUPPORTED_OS_CONFIGS.get(os_id)

    if config_filename is None:
        raise ValueError(
            f"Unsupported os_id for filesystem lookup: '{os_id}'. "
            f'Supported IDs: {", ".join(sorted(SUPPORTED_OS_CONFIGS.keys()))}',
        )

    return os.path.join(own_dir, config_filename)
