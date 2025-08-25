import os

import setuptools

import setup


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    with open(os.path.join(own_dir, 'requirements.utils.txt')) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            yield line


def modules():
    return [
        'caching',
        'consts',
        'crypto_extension.config',
        'ctx_util',
        'dockerutil',
        'eol',
        'lookups',
        'ocm_util',
        'paths',
        'rescore.model',
        'rescore.utility',
        'responsibles_extension.filters',
        'responsibles_extension.strategies',
        'util',
    ]


def packages():
    return [
        'deliverydb_cache',
        'k8s',
        'odg',
        'secret_mgmt',
        'osinfo',
        'bdba_utils',
    ]


def package_data():
    return {
        'odg': ['*.yaml'],
        'secret_mgmt': ['*.yaml'],
    }


setuptools.setup(
    name='delivery-gear-utils',
    version=os.environ.get(
        'ODG_UTILS_PACKAGE_VERSION',
        setup.finalize_version(),
    ),
    py_modules=modules(),
    packages=packages(),
    package_data=package_data(),
    install_requires=list(requirements()),
)
