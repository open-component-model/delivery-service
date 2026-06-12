import os

import semver
import setuptools


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    with open(os.path.join(own_dir, 'requirements.bdba-client.txt')) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            yield line


def bump_version():
    with open(os.path.join(own_dir, 'BDBA_CLIENT_VERSION')) as f:
        return semver.Version.parse(f.read().strip()).bump_minor()


setuptools.setup(
    name='bdba-client',
    version=str(bump_version()),
    package_dir={'': 'src'},
    py_modules=[],
    packages=['bdba'],
    install_requires=list(requirements()),
)
