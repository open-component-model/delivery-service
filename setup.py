import os

import semver
import setuptools
import setuptools.discovery


own_dir = os.path.abspath(os.path.dirname(__file__))
BDBA_CLIENT_VERSION_FILE = os.path.join(own_dir, 'BDBA_CLIENT_VERSION')
ODG_CLIENT_VERSION_FILE = os.path.join(own_dir, 'ODG_CLIENT_VERSION')


def read_version(file: str) -> str:
    with open(file) as f:
        return f.read().strip()


def finalize_version():
    with open(os.path.join(own_dir, 'VERSION')) as f:
        return semver.finalize_version(f.read().strip())


def requirements():
    yield f'bdba-client=={read_version(BDBA_CLIENT_VERSION_FILE)}'
    yield f'odg-client=={read_version(ODG_CLIENT_VERSION_FILE)}'

    with open(os.path.join(own_dir, 'requirements.txt')) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            yield line


def package_data():
    return {
        'features': ['*.yaml'],
        'freshclam': ['freshclam.conf'],
        'odg': ['*.yaml'],
        'osinfo': ['*.yaml'],
        'responsibles': ['*.yaml'],
        'schema': ['*.yaml'],
        'secret_mgmt': ['*.yaml'],
        'swagger': ['*.yaml'],
    }


setuptools.setup(
    name='odg-core-libs',
    version=os.environ.get('ODG_CORE_LIBS_VERSION', finalize_version()),
    package_dir={'': 'src'},
    py_modules=setuptools.discovery.ModuleFinder.find('src'),
    packages=setuptools.discovery.PackageFinder.find('src'),
    package_data=package_data(),
    install_requires=list(requirements()),
    description='Mandatory system internals for the Open Delivery Gear',
    url='https://github.com/open-component-model/open-delivery-gear',
)
