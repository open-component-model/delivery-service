==========================
Contribute a new Extension
==========================

.. note::
   In case the extension is planned to be "loosely coupled", meaning it will
   not run as part of the Open Delivery Gear deployment but standalone and only
   reporting data via the delivery-service API, the steps
   :ref:`extensions-configuration`, :ref:`helm-chart`, :ref:`oci-image` and
   :ref:`python-package` might be skipped.

Setup Local Development Environment
===================================
For instructions on how to setup a local development environment, please refer
to :doc:`/contribute/local_setup`.

Model
=====
As a first step, a new data model must be defined which is used by the
extension for its emitted data objects. These models are defined in the
`odg.model` module of the delivery-service
(`ref <https://github.com/open-component-model/delivery-service/blob/master/odg/model.py>`_).

Therefore, the new extension must be defined as additional `Datasource`
(usually just the name of the extension) and at least one additional
`Datatype`. There are three kinds of datatypes:

.. _meta-types:

#. *Meta Types*

   Those datatypes are not directly related to any type of finding or a single
   extension, but rather used internally by the Open Delivery Gear. Most
   presumably the new extension does not have to define any of those datatypes.

#. *Finding Types*

   Finding types are those which can be assigned a certain "severity", meaning
   that the desired state is not met and it should be processed "somehow".

#. *Informational Types*

.. _informational-types:

   The informational types are used to store information without any
   "severity". Those might be used to enrich the findings or just to provide
   information on certain artefacts.

To create a mapping between the `Datasource` and the `Datatypes` it emits (and
vice-versa), the respective util functions `datasource()` and `datatypes()`
must be updated as well.

After that, the actual **schema** of the just added `Datatypes` must be
defined. This schema must be adhered to when uploading data via the API.
Therefore, it is necessary to add a new dataclass with the desired structure
for each `Datatype`. Afterwards, this new dataclass must be added to the list
of allowed types for the `data` property of the `ArtefactMetadata` class.

.. _artefact-metadata:

Artefact Metadata
^^^^^^^^^^^^^^^^^

The model defined by the `ArtefactMetadata` class is the structure which is
expected by the delivery-service API for CRUD operations of data. It contains
an `artefact`, which identifies the OCM reference the data belongs to. The
`meta` field is used to store the information of the before described
`Datasource` and `Datatype`. Also, it might contain responsibles that should be
used later on for the reporting via GitHub issues (see
:doc:`issue-replicator extension </extensions/issue_replicator>`). Last but not
least, the `discovery_date` and `allowed_processing_time` are used to determine
the due-date of findings. This means it is not required for data which is
purely informational (see :ref:`meta types <meta-types>` or
:ref:`informational types <informational-types>`).

.. _key:

Key
^^^

To be able to uniquely identify already existing database entries, it is
required for each `ArtefactMetadata` instance to define a unique `key`
property. This `key` always consists of the `artefact`, `Datasource`,
`Datatype` as well as the `key` defined by the `data` class (if there is any).
This means, in case it is expected that there may be multiple entries per tuple
of `artefact`, `Datasource` and `Datatype`, the new class must define a unique
`key` property as well.

.. note::
   See `gardener/cc-utils#1166 <https://github.com/gardener/cc-utils/pull/1166/files>`_
   as an example for this chapter. Please note that the `dso.model` module in
   the pull request has been replaced by the `odg.model` module in the
   delivery-service.

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

If the extension emits findings, it will also be necessary to add the new
finding type to the findings configuration (see `odg.findings_cfg` module for
the model definition and `odg/findings_cfg.yaml` for the example used for the
local development). The most important part are the `categorisations` which
define the supported "severities" with extra information like for example the
`allowed_processing_time`. Also, if the findings should be reported as GitHub
issues, the `issues` property has to be configured accordingly too (see
:ref:`issue-replicator` as well).

.. note::
   See `open-component-model/delivery-service@15dabcf
   <https://github.com/open-component-model/delivery-service/commit/15dabcf1b9f439b0d4eff6b60aa7f7310819bd09>`_
   as an example for this chapter.

Actual Extension
================

When implementing the actual extension, it has to be considered *where* it
should run (as part of the Open Delivery Gear deployment vs. standalone) and
*when* it should run (i.e. regularly as a cronjob, triggered by artefact
updates or both). In case the extension is expected to be run standalone, you
might want to skip the section :ref:`extension-triggers` as a standalone
running extension must take care of triggering on its own.

.. _extension-triggers:

Extension Triggers
^^^^^^^^^^^^^^^^^^

The Open Delivery Gear currently features two kinds of triggers:

#. *Kubernetes Cronjob*

   As the title already states, an extension can be modelled as regular
   Kubernetes Cronjob with a well-defined `schedule`. If running as a Cronjob,
   the extension might has to be able to retrieve the information for which
   artefacts it should run. This is relevant as the :ref:`artefact-metadata`
   requires the data to be always correlated to a certain `artefact`. This
   information should be passed to the extension using the
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

The general flow for extensions which are intended to submit `ArtefactMetadata`
via the delivery-service API is usually very similar. If the extension is
written in Python, the `delivery-client
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
   delivery-db or update existing entries in case the :ref:`key` matches.
   Also, if enabled (see :ref:`discovery-date`), existing entries may be used
   to lookup the initial `discovery_date` of a finding and use it for the newly
   submitted ones as well in order to ensure correctness of the actual
   `discovery_date`. Otherwise, updating the `artefact` to a new version would
   always reset the `discovery_date`.
   Apart from the entries containing the findings, an extra entry of type
   `meta/artefact_scan_info` must be submitted for each `artefact`. This info
   object is used to store information about the last execution and that an
   `artefact` has been scanned in general (see
   :ref:`example <artefact-scan-info>`).

#. Delete obsolete entries

   At last, entries which were fetched in step (1) but not submitted anymore in
   step (2) may be deleted using the `DELETE /artefacts/metadata` endpoint.
   This is required to ensure that outdated findings or informational entries
   are not reported anymore.

.. _discovery-date:

Discovery Date
==============

In case the extension emits data objects which are findings, it is relevant to
store the first `discovery_date` to be able to determine the actual due-date.
Therefore, the `discovery_date` is part of the `ArtefactMetadata` model. To
re-use the initial `discovery_date` of a finding, and don't reset it as part of
every new scan, it must be defined when a finding is to be interpreted as equal
so that the `discovery_date` must be re-used. In the most trivial example, this
is the case when the `data` key is equal. However, there might be cases where
this is not enough, for example for vulnerability findings, the
`discovery_date` must be re-used in case the CVE and the package is the same,
even if the package-version (which is part of the `data` key) changes.
Therefore, the behaviour must be defined in the `PUT /artefacts/metadata` route
(see `open-component-model/delivery-service@6697e50
<https://github.com/open-component-model/delivery-service/commit/6697e5045d080d72c70b2ccaa214ffcaa8d0e244>`_
as an example how to define this behaviour). In case it is not defined, the
`discovery_date` will be always consumed as it is defined in the new
`ArtefactMetadata` entry.

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

Examples
========

.. _artefact-scan-info:

Artefact Scan Info
^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

  artefact:
    component_name: example.org/my-component
    component_version: 0.1.0
    artefact_kind: resource
    artefact:
      artefact_name: my-resource
      artefact_version: 0.1.0
      artefact_type: ociImage
      artefact_extra_id:
        version: 0.1.0
  meta:
    type: meta/artefact_scan_info
    datasource: <NEW_EXTENSION>
  data: {} # optional properties describing the scan
