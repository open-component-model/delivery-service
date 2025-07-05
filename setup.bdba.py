import os

import semver
import setuptools


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    with open(os.path.join(own_dir, 'requirements.bdba.txt')) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            yield line


def finalize_version():
    with open(os.path.join(own_dir, 'BDBA_VERSION')) as f:
        return semver.finalize_version(f.read().strip())


setuptools.setup(
    name='bdba',
    version=os.environ.get(
        'BDBA_PACKAGE_VERSION',
        finalize_version(),
    ),
    py_modules=[],
    packages=['bdba'],
    install_requires=list(requirements()),
)
