==========================
Contribute a new Extension
==========================

Setup Local Development Environment
===================================
For instructions on how to setup a local development environment, please refer
to :doc:`/local_setup`.

Model
=====
For information on the `ArtefactMetadata` model and how to extend it, please
refer to :doc:`/model`.

.. _extensions-configuration:

Extensions Configuration
========================

Configuration for each extension should be provided via the interface defined
in the `odg.extensions_cfg` module
(`ref <https://github.com/open-component-model/delivery-service/blob/master/odg/extensions.py>`_).
A minimal set of configuration parameters is defined by the required base class
`ExtensionCfgMixins`. In case the extension is expected to be working with
backlog items (more on that topic in :ref:`extension-triggers` and
:ref:`artefact-enumerator`), the `BacklogItemMixins` base class must be used
instead. Usually, an extension will also require the `delivery_service_url` to
be defined to be able to access the delivery-service and an `interval` or
`schedule`.

Once a suitable dataclass for the extension is defined, it must be added to the
`ExtensionsConfiguration` class as optional property as well. Such an
`ExtensionsConfiguration` will be available to the workload in the cluster via
a mounted ConfigMap (more on that topic in :ref:`helm-chart`).

.. note::
   See `open-component-model/delivery-service@b635470
   <https://github.com/open-component-model/delivery-service/commit/b6354706c7545eacd571271472807c95aa2525da>`_
   as an example for this chapter.

.. _findings-configuration:

Findings Configuration
======================

If the extension emits findings (see :doc:`/model` for information on the
supported datatypes), it will also be necessary to add the new finding type to
the findings configuration (see `odg.findings_cfg` module for the model
definition and `odg/findings_cfg.yaml` for the example used for the local
development). The most important part are the `categorisations` which define
the supported "severities" with extra information like for example the
`allowed_processing_time`. Also, if the findings should be reported as GitHub
issues, the `issues` property has to be configured accordingly too (see
:ref:`issue-replicator` as well).

.. note::
   See `open-component-model/delivery-service@15dabcf
   <https://github.com/open-component-model/delivery-service/commit/15dabcf1b9f439b0d4eff6b60aa7f7310819bd09>`_
   as an example for this chapter.

Anatomy of an ODG Extension
===========================

When adding an extension to the Open Delivery Gear, different flavours
specifying the level of integration are supported:

* **Fully Integrated / Running In-Cluster**

   If an extension is fully integrated into the ODG, it is part of the ODG
   deployment and running within the same Kubernetes cluster. In this case,
   the steps in :ref:`helm-chart`, :ref:`oci-image` and :ref:`python-package`
   can be followed and then the new extension will be automatically part of the
   ODG deployment (in case it is enabled via configuration). When running fully
   integrated, it also has to be considered *when* the extension should run
   (e.g. regularly as a cronjob, triggered by artefact updates or both) (see
   :ref:`extension-triggers`).

* **Lightly Integrated / Running Out-Of-Cluster**

   In the lightly integrated variant, the extension is running standalone and
   only uploads `ArtefactMetadata` via the delivery-service API to make use of
   the reporting capabilities of the ODG. In that case, the extension must take
   care of deployment and triggering on its own, hence the chapters
   :ref:`extension-triggers`, :ref:`helm-chart`, :ref:`oci-image` and
   :ref:`python-package` can be skipped.

.. _extension-triggers:

Extension Triggers
^^^^^^^^^^^^^^^^^^

The Open Delivery Gear currently features two kinds of triggers:

#. *Kubernetes Cronjob*

   As the title already states, an extension can be modelled as regular
   Kubernetes Cronjob with a well-defined `schedule`. If running as a Cronjob,
   the extension might has to be able to retrieve the information for which
   artefacts it should run. This is relevant as the
   :doc:`/model` requires the data to be always correlated to a certain
   `artefact`. This information should be passed to the extension using the
   :ref:`extensions-configuration`.

#. *Artefact-Enumerator*

   Another common trigger is the artefact-enumerator (see
   :doc:`artefact-enumerator extension </extensions/artefact_enumerator>`). The
   artefact-enumerator itself is a Kubernetes Cronjob as described before which
   retrieves a list of artefacts via the :ref:`extensions-configuration`. For
   these artefacts, it periodically checks if there are any updates or the
   `interval` for a certain extension has passed, and if that is the case, it
   creates a `BacklogItem` custom resource. The backlog-controller extension
   itself reconciles these resources and scales the Kubernetes Deployment of
   the affected extension accordingly. This means, if the new extension uses
   this trigger, it should be designed to always process the `artefact` defined
   by one `BacklogItem` at a time. For that, the `process_backlog_items`
   utility function, defined in the `odg.util` module
   (`ref <https://github.com/open-component-model/delivery-service/blob/master/odg/util.py>`_),
   should be used.

.. note::
   The `already existing extensions <https://github.com/open-component-model/delivery-service/tree/master/charts/extensions/charts>`_
   and their respective implementations can be always used as a reference how
   either a Kubernetes Cronjob or a `BacklogItem` based approach via the
   artefact-enumerator might look like.

General Flow
^^^^^^^^^^^^

The general flow for extensions which are intended to submit
:doc:`/model` via the delivery-service API is usually very similar. In case of
findings, there is a well-defined overview of the supported states of a finding
(see Fig. 1).

.. figure:: /res/finding-states.svg
   :figwidth: 50%
   :align: center

   Fig. 1: Finding State Machine

If the extension is written in Python, the `delivery-service-client
<https://github.com/gardener/cc-utils/blob/master/delivery/client.py>`_ should
be used which already contains functionality for the below described points:

#. Fetch existing `ArtefactMetadata` entries

   As a first step, the existing `ArtefactMetadata` entries for the current
   `artefact` should be queried using the `POST /artefacts/metadata/query`
   endpoint of the delivery-service. This is required to be able to delete the
   obsolete entries afterwards in step (3).

#. Submit new entries and update existing ones

   The new or updated entries must be submitted using the
   `PUT /artefacts/metadata` endpoint. This will upload new entries to the
   delivery-db or update existing entries in case the defined `key` matches.
   Apart from the entries containing the findings, an extra entry of type
   `meta/artefact_scan_info` must be submitted for each `artefact`. This info
   object is used to store information about the last execution and that an
   `artefact` has been scanned in general.

#. Delete obsolete entries

   At last, entries which were fetched in step (1) but not submitted anymore in
   step (2) have to be deleted using the `DELETE /artefacts/metadata` endpoint.
   This is required to ensure that outdated findings or informational entries
   are not reported anymore.

.. _artefact-enumerator:

Artefact-Enumerator
===================

If the artefact-enumerator was chosen as trigger in :ref:`extension-triggers`,
it is necessary to inform the artefact-enumerator about this extension and that
it should create `BacklogItems` for it. Therefore, a minor change must be added
to the artefact-enumerator (see `open-component-model/delivery-service@68d6f5b
<https://github.com/open-component-model/delivery-service/commit/68d6f5bd322bd018a67e54784804d65dde3f2a38>`_).

.. note::
   In the future, it is planned that this must not be explicitly defined
   anymore but the artefact-enumerator should instead automatically detect
   which extensions require `BacklogItems` to be created.

.. _issue-replicator:

Issue-Replicator
================

In order to enable the
:doc:`issue-replicator extension </extensions/issue_replicator>` to also report
findings for the new extension, it must be defined how the findings should be
templated into a GitHub issue. Therefore, a minor change must be added to the
issue-replicator (see `open-component-model/delivery-service@adb7239
<https://github.com/open-component-model/delivery-service/commit/adb723957c2f6ec115ac702463f94802b35ed6df>`_).
Also, the `issues` property of the :ref:`findings-configuration` must be
configured accordingly.

.. _helm-chart:

Helm Chart
==========

If the extension should be deployed as part of the Open Delivery Gear
deployment, it must be added as subchart to the `extensions` Helm chart
(`ref <https://github.com/open-component-model/delivery-service/tree/master/charts/extensions/charts>`_).
Based on the trigger (see :ref:`extension-triggers`), either a Kubernetes
Deployment or Cronjob should be used. In all cases, it can be assumed that
an `extensions-cfg` and a `findings-cfg` ConfigMap exists which may be mounted
as volume. Also, in case an OCM lookup is required, the `ocm-repo-mappings`
ConfigMap should be used. If any secrets are required by the extension, those
can be mounted as well by referencing the Secrets
`secret-factory-<SECRET_TYPE>`.

.. note::
   It might be very helpful to use the `already existing extensions
   <https://github.com/open-component-model/delivery-service/tree/master/charts/extensions/charts>`_
   as reference and adjust them accordingly.

.. _oci-image:

OCI Image
=========

In case the extension does not require any additional installations, the
general purpose extensions OCI image can be re-used (`ref
<https://github.com/open-component-model/delivery-service/blob/master/Dockerfile.extensions>`_).
Otherwise, a new Dockerfile `Dockerfile.extensions.<EXTENSION_NAME>` must be
created and added to the `build
<https://github.com/open-component-model/delivery-service/blob/master/.github/workflows/build.yaml>`_.
In both cases, a Helm chart mapping must be added to the `build
<https://github.com/open-component-model/delivery-service/blob/master/.github/workflows/build.yaml>`_
as well.

.. _python-package:

Python Package
==============

The default extensions image built from `Dockerfile.extensions` installs the
Python package `ocm-gear-extensions` which contains the sources of all Python
extensions. In case this image is re-used, the module(s) of the new extension
must be included in the Python package (`ref
<https://github.com/open-component-model/delivery-service/blob/master/setup.extensions.py>`_).
