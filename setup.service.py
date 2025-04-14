import os

import setuptools

import setup


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    yield 'delivery-gear-utils'

    with open(os.path.join(own_dir, 'requirements.service.txt')) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            yield line


def modules():
    return [
        'app',
        'artefacts',
        'cache_manager',
        'compliance_tests',
        'components',
        'dora',
        'metadata',
        'metric',
        'service_extensions',
        'smoke_test',
        'special_component',
        'sprint',
        'yp',
    ]


def packages():
    return [
        'compliance_summary',
        'deliverydb',
        'features',
        'middleware',
        'rescore',
        'responsibles',
        'schema',
        'swagger',
    ]


def package_data():
    return {
        'compliance_summary': ['*.yaml'],
        'features': ['*.yaml'],
        'osinfo': ['*.yaml'],
        'responsibles': ['*.yaml'],
        'schema': ['*.yaml'],
        'swagger': ['*.yaml'],
    }


setuptools.setup(
    name='ocm-gear-service',
    version=os.environ.get(
        'ODG_SERVICE_PACKAGE_VERSION',
        setup.finalize_version(),
    ),
    py_modules=modules(),
    packages=packages(),
    package_data=package_data(),
    install_requires=list(requirements()),
)
