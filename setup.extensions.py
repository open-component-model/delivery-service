import os

import setuptools

import setup


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    yield 'delivery-gear-utils'


def modules():
    return [
        'artefact_enumerator',
        'backlog_controller',
        'delivery_db_backup',
        'sast',
    ]


def packages():
    return [
        'bdba',
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
