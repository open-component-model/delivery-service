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
        'ctx_util',
        'lookups',
        'paths',
        'rescoring_util',
    ]


def packages():
    return [
        'k8s',
    ]


setuptools.setup(
    name='ocm-gear-utils',
    version=setup.finalize_version(),
    py_modules=modules(),
    packages=packages(),
    install_requires=list(requirements()),
)
