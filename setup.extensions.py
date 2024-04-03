import os

import setuptools

import setup


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    yield 'ocm-gear-utils'

    with open(os.path.join(own_dir, 'requirements.extensions.txt')) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            yield line


def modules():
    return [
        'artefact_enumerator',
        'backlog_controller',
        'bdba',
        'delivery_db_backup',
    ]


def packages():
    return [
        'issue_replicator',
        'malware',
    ]


setuptools.setup(
    name='ocm-gear-extensions',
    version=setup.finalize_version(),
    py_modules=modules(),
    packages=packages(),
    install_requires=list(requirements()),
)
