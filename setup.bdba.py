import os

import setuptools

import setup


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    with open(os.path.join(own_dir, 'requirements.bdba.txt')) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            yield line


setuptools.setup(
    name='bdba',
    version=setup.finalize_version(),
    py_modules=[],
    packages=['bdba'],
    install_requires=list(requirements()),
)
