import os

import semver
import setuptools


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    with open(os.path.join(own_dir, 'requirements.odg-client.txt')) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            yield line


def bump_version():
    with open(os.path.join(own_dir, 'ODG_CLIENT_VERSION')) as f:
        return semver.Version.parse(f.read().strip()).bump_minor()


setuptools.setup(
    name='odg-client',
    version=bump_version(),
    description='Client library for the Open Delivery Gear',
    long_description='Client library for the Delivery Service (part of the Open Delivery Gear)',
    long_description_content_type='text/markdown',
    python_requires='>=3.11',
    py_modules=[],
    packages=['delivery'],
    install_requires=list(requirements()),
)
