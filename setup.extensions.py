import os

import setuptools

import setup


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    yield 'delivery-gear-utils'

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
        'delivery_db_backup',
        'sast',
        'ghas',
    ]


def packages():
    return [
        'bdba_extension',
        'crypto_extension',
        'issue_replicator',
        'malware',
        'osid_extension',
        'responsibles_extension',
    ]


def package_data():
    return {
        'crypto_extension': ['*.yaml'],
    }


setuptools.setup(
    name='ocm-gear-extensions',
    version=os.environ.get(
        'ODG_EXTENSIONS_PACKAGE_VERSION',
        setup.finalize_version(),
    ),
    py_modules=modules(),
    packages=packages(),
    package_data=package_data(),
    install_requires=list(requirements()),
)
