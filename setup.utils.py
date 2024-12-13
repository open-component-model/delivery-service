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
        'config',
        'config_filter',
        'consts',
        'ctx_util',
        'lookups',
        'ocm_util',
        'paths',
        'rescore.utility',
    ]


def packages():
    return [
        'bdba',
        'deliverydb_cache',
        'k8s',
    ]


setuptools.setup(
    name='ocm-gear-utils',
    version=setup.finalize_version(),
    py_modules=modules(),
    packages=packages(),
    install_requires=list(requirements()),
)
