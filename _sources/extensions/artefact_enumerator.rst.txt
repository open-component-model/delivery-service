===================
Artefact-Enumerator
===================

Purpose
=======

The artefact-enumerator extension periodically checks the configured
:ref:`OCM artefacts <ocm-components>` and available
:ref:`runtime artefacts <runtime-artefacts>` and takes care of the lifecycle of
their :ref:`compliance snapshots <compliance-snapshots>`
(create/update/delete). Based on the status information in the compliance
snapshots, the artefact-enumerator evaluates whether it must create backlog
items for certain extensions or not.

How it works
============

.. _artefacts:

Artefacts
^^^^^^^^^

It is required to specify a set of **artefacts "of interest"** which should be
periodically being processed by the available extensions (e.g. scanned,
reported, etc.). Apart from these periodical triggers initiated by the
artefact-enumerator, certain extensions might be triggered manually by creating
a respective **backlog item** for the desired extension and `artefact` (see
:ref:`example <example-backlog-item>`), for example via delivery-dashboard or
directly via delivery-service or cluster API. In general, creating backlog
items is the same trigger as used by the artefact-enumerator, however, certain
extensions might require the artefacts to be configured here in order to
process them (e.g.
:doc:`issue-replicator extension </extensions/issue_replicator>`). Artefacts
may be configured in two different ways, as referenced
:ref:`OCM components <ocm-components>` or as
:ref:`runtime artefacts <runtime-artefacts>`.

.. _ocm-components:

OCM Components
**************

OCM components are configured using the `components` property in the extensions
configuration. The configured components and their dependencies are retrieved
**recursively** and each of their dependencies is subject of being processed.
As the Open Delivery Gear generally works on the granularity of
`ComponentArtefactIds`, each `resource` and `source` of the OCM components is
parsed into such a `ComponentArtefactId` and tracked individually.

.. _runtime-artefacts:

Runtime Artefacts
*****************

To be also able to process artefacts which are not (yet) subject of being
modelled via OCM, i.e. volatile **runtime artefacts**, those can be added to
the list of artefacts "of interest" by creating respective `RuntimeArtefact`
custom resources, either via delivery-service or via cluster API (see
:ref:`example <example-runtime-artefact>`). Note that, because these artefacts
are not modelled via OCM, the artefact-enumerator is not able to resolve any
dependencies and thus each artefact must be specified via a dedicated runtime
artefact. Those runtime artefacts also contain a `ComponentArtefactId` and are
later processed equally as the before mentioned OCM resources and sources.

.. _compliance-snapshots:

Compliance Snapshots
^^^^^^^^^^^^^^^^^^^^

Compliance snapshots are used as internal state for the configured
:ref:`artefacts <artefacts>`, e.g. to store information on the last execution
time by a extension or to keep track of artefacts which should be reported
before but, by now, they are not "of interest" anymore, and thus, for example,
remaining open GitHub issues must be closed. Therefore, for each artefact, a
respective compliance snapshot is being created. Already existing compliance
snapshots of artefacts which are not "of interest" anymore are kept for an
extra grace period to allow other extensions (e.g. the
:doc:`issue-replicator </extensions/issue_replicator>`) to react upon those
changes (e.g. to close related GitHub issues).

Examples
========

Configuration
^^^^^^^^^^^^^

.. code-block:: yaml

  artefact_enumerator:
    components:
      - component_name: example.org/my-component
        ocm_repo_url: europe-docker.pkgk.dev/gardener-project/releases
        version: greatest
        version_filter: releases_only
        max_versions_limit: 1

.. _example-backlog-item:

Backlog Item
^^^^^^^^^^^^

.. code-block:: yaml

  apiVersion: delivery-gear.gardener.cloud/v1
  kind: BacklogItem
  metadata:
    name: issuereplicator-8-abcde
    namespace: delivery
    labels:
      delivery-gear.gardener.cloud/service: issueReplicator
  spec:
    artefact:
      component_name: example.org/my-component
      component_version: 0.1.0
      artefact_kind: runtime
      artefact:
        artefact_name: my-runtime-resource
        artefact_version: 0.1.0
        artefact_type: virtual-machine
        artefact_extra_id:
          version: 0.1.0
          hyperscaler: my-hyperscaler
    priority: 8
    timestamp: '2025-01-01T12:00:00.000000+00:00'

.. _example-runtime-artefact:

Runtime Artefact
^^^^^^^^^^^^^^^^

.. code-block:: yaml

  apiVersion: delivery-gear.gardener.cloud/v1
  kind: RuntimeArtefact
  metadata:
    name: runtime-artefact-abcde
    namespace: delivery
  spec:
    artefact:
      component_name: example.org/my-component
      component_version: 0.1.0
      artefact_kind: runtime
      artefact:
        artefact_name: my-runtime-resource
        artefact_version: 0.1.0
        artefact_type: virtual-machine
        artefact_extra_id:
          version: 0.1.0
          hyperscaler: my-hyperscaler
    creation_date: '2025-01-01T12:00:00.000000+00:00'
