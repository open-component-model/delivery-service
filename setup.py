import os

import semver


own_dir = os.path.abspath(os.path.dirname(__file__))


def finalize_version():
    with open(os.path.join(own_dir, 'VERSION')) as f:
        return semver.finalize_version(f.read().strip())
