===================================
Setup Local Development Environment
===================================
In order to start with the set-up first clone the `delivery-service repository <https://github.com/open-component-model/delivery-service>`_.

.. note::
   This guide focuses on running the delivery-service (+ database) and one
   extension locally, possibly with interacting with a remote Kubernetes
   cluster. This might be used during the process of developing a new or
   updating an existing extension. To run a full Open Delivery Gear locally,
   i.e. containing multiple extensions and a local Kubernetes cluster, please
   refer to the `Local Setup
   <https://github.com/open-component-model/delivery-service/blob/master/local-setup/local-setup.md>`_
   guide instead.

Prerequisites
=============
The following software should be installed on your local machine:

- `Python 3.12` or greater (qualification is always done using the Python3
  version from `alpine:edge`)
- `Docker` (only if running a local PostgreSQL container)
- `SQLite3` (only if running a local SQLite3 database)

Running the Delivery-Database
=============================

For the local development, currently, **SQLite3** and **PostgreSQL 16** are
supported, so either of them can be chosen. For production environments, the
usage of PostgreSQL is recommended (the Helm charts do not support SQLite3).

SQLite3
^^^^^^^

Valid SQLite3 URL forms are:

.. code-block::

    sqlite+aiosqlite:///:memory:
    sqlite+aiosqlite:///relative/path/to/file.db
    sqlite+aiosqlite:////absolute/path/to/file.db

PostgreSQL
^^^^^^^^^^

Instantiate a local PostgreSQL 16 database, e.g. as OCI container:

.. code-block::

    docker run -dit \
      --name postgres \
      -e POSTGRES_USER=postgres \
      -e POSTGRES_PASSWORD=MyPassword \
      -p 5432:5432 \
      postgres:16

Running the Delivery-Service
============================

Requirements
^^^^^^^^^^^^

#. (Optional) Create a new `virtual env
   <https://docs.python.org/3/library/venv.html>`_ in your local delivery-service repository and activate it:

   .. code-block:: bash

      python3 -m venv venv
      source venv/bin/activate

#. Install development dependencies

   .. code-block:: bash

      pip3 install --upgrade -r <path-to-local-delivery-service-repo>/requirements-dev.txt

Secrets
^^^^^^^

For the local setup, the delivery-service retrieves its secrets from a config
repository. Therefore, a local copy of the config repository must be available
and specified via env var `CC_CONFIG_DIR=/path/to/config.d` (see `Gardener's
configuration management <https://github.com/gardener/cc-utils/tree/master>`_ for more details) (more comprehensive documentation on
how to obtain secrets TBD). In short: please add `export CC_CONFIG_DIR='<path-to-local-cc-config-repo>/cc-config` 
to your .zshrc file.

Certificates
^^^^^^^^^^^^

In the context of local development, interaction with endpoints with either
self-signed certificates, or certificates signed by CAs not included in the
default trust-bundles might be required. Therefore, it is necessary to include
them into Python's trust store (Python does by default not honour system's
CA-bundle).

As an example, the following script can be used to add SAP's CAs to Python's
trust store.

.. code-block:: bash

   #!/usr/bin/env bash

   set -eu

   ca_bundle_path=$(python3 -m certifi)
   echo "appending certs to ${ca_bundle_path}"

   urls=(
       "https://aia.pki.co.sap.com/aia/SAP%20Global%20Root%20CA.crt"
       "https://aia.pki.co.sap.com/aia/SAPNetCA_G2_2.crt"
   )

   for url in ${urls[@]}; do
     curl $url >> $ca_bundle_path
   done

Start-Up
^^^^^^^^

.. code-block:: bash

    # Running with PostgreSQL
    python3 <path-to-local-delivery-service-repo>/app.py --delivery-db-url postgresql+psycopg://postgres:MyPassword@127.0.0.1:5432

    # Running with SQLite3
    python3 <path-to-local-delivery-service-repo>/app.py --delivery-db-url sqlite+aiosqlite:///filename.db

Start-up with useful development tooling (e.g. hot-reloading or enhanced
request information upon errors):

.. code-block:: bash

    # Running with PostgreSQL
    adev runserver --port 5000 <path-to-local-delivery-service-repo> -- --delivery-db-url postgresql+psycopg://postgres:MyPassword@127.0.0.1:5432

    # Running with SQLite3
    adev runserver --port 5000 <path-to-local-delivery-service-repo> -- --delivery-db-url sqlite+aiosqlite:///filename.db

Running the Extension
=====================

Configuration
^^^^^^^^^^^^^

The configuration required for the extension can be added locally to the
`odg/extensions_cfg.yaml` file as well as to the `odg/findings_cfg.yaml` file
respectively. Those will be picked-up automatically if using the
`paths.extensions_cfg_path()` and `paths.findings_cfg_path` utility functions.

Start-Up
^^^^^^^^

To run the extension locally, the Kubernetes cluster and the delivery-service
to interact with have to be specified via additional argument:

.. code-block:: bash

    python3 -m <path-to-extension> \
      --k8s-cfg-name ocm_gear_dev \
      --k8s-namespace delivery \
      --delivery-service-url http://localhost:5000
