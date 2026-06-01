================
SBOM-Generator
================

The SBOM-Generator extension generates Software Bill of Materials (SBoM)
documents for the OCM resources of your components. It processes backlog items,
resolves component descriptors from OCM repositories, and produces SBoM
documents in the configured format. Generated SBoMs are stored in the
delivery-service blob storage and can be downloaded directly from the ODG
Dashboard, or via API.

SBoM generation uses `Syft <https://github.com/anchore/syft>`_ to scan
artefacts directly.

Supported output formats are **CycloneDX** and **SPDX**. Once generated, the SBoM is uploaded to blob storage and its
digest, size, and format are recorded as ``ArtefactMetadata`` of type
``artefact_scan_info``, allowing the dashboard to track readiness and offer the
download.


Users
=========

How do I download SBoM documents for my product or its sub-components?
-----------------------------------------------------------------------

1. Add your product to the ODG Dashboard.

2. Open your product page.

3. To download the SBoM for your **product**, click the ``DOWNLOAD SBOM`` button.
   
   .. image:: ../res/download-sbom-button.svg
      :alt: Download SBOM button

   This opens the SBoM popover, where all sub-components are grouped into three
   sections: **Ready**, **Not ready**, and **Unsupported**. 
   
   .. image:: ../res/download-sbom-popover.svg
      :alt: Download SBOM Popover

   The popover also shows the configured generation mode and output format, and displays the access type
   and artefact type for each sub-component so you can see at a glance what will
   be scanned and what will be skipped.

   .. hint::
      The popover updates in real time. No manual refresh is needed.

4. To download the SBoM for a specific **sub-component**, open the sub-component
   first, then click the ``DOWNLOAD SBOM`` button.


How can I manually request SBoMs for a given OCM component?
-----------------------------------------------------------

Open the ``DOWNLOAD SBOM`` popover for your component. Any sub-components whose
SBoM has not been generated yet will appear in the **Not ready** section. When
there are pending sub-components, a ``Trigger SBOM generation`` button is shown.
Clicking it schedules SBoM generation for all of them immediately. The popover
updates in real time, and completed SBoMs move from the **Not ready** section to
the **Ready** section as they finish.


Operators
=========

How do I know if there is a problem generating an SBoM?
-------------------------------------------------------

If SBoM generation fails, check the **SBOM-Generator** section in the ODG
Dashboard sidebar. The logs show the status of each run, including errors,
warnings, and timestamps, making it straightforward to identify and diagnose
issues.


Developers
==========

How does the SBoM generation work under the hood?
-------------------------------------------------

When a backlog item is picked up for a given OCM component, the SBOM-Generator
resolves the component descriptor from the configured OCM repositories and
retrieves the matching ``Resource`` and scans it.

For supported resources, the generation proceeds according to the configured
mode:

- In **syft** mode, the Syft CLI binary is invoked via subprocess. For
  ``ociRegistry``, the image reference is passed directly to the CLI. For
  ``localBlob/v1``, the blob is downloaded to a temp file first. For ``s3``,
  the tar archive is downloaded and extracted to a temp directory before
  scanning.

Once the SBoM is produced, it is serialised to JSON, hashed (SHA-256), and
uploaded to the delivery-service blob storage. The digest, file size, and output
format are then recorded as ``ArtefactMetadata`` of type ``artefact_scan_info``
for that resource, which is what the dashboard queries to determine whether an
SBoM is ready for download.

.. image:: ../res/sbom-generator-overview.svg
   :alt: SBOM Generation Overview
