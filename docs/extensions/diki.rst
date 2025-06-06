====
Diki
====

This document shows the required requests needed to be sent for `Diki` findings
to be created as GitHub issues via delivery-service.

.. note::
   The endpoints listed in this document were extracted from the
   `REST-API-documentation
   <https://github.com/open-component-model/delivery-service?tab=readme-ov-file#rest-api-documentation>`_.

Creating Diki compliance issues
===============================

To have `Diki` issues generated by the issue-replicato, the `Diki` findings
need to be uploaded to the delivery-database and a specific `CR` has to be
created in the Open Delivery Gear Kubernetes cluster.

To push `Diki` findings, a `PUT` request to the `/artefacts/metadata` endpoint
of the delivery-service has to be made. The request body must contain a list of
`entries`, one of which should be of type `meta/artefact_scan_info`. `Diki`
findings are separated by rule in `finding/diki` type:

.. code-block:: json

   {
     "entries": [
       {
         "artefact": {
           "component_name": "<component_name>",
           "component_version": "<component_version>",
           "artefact_kind": "runtime",
           "artefact": {
             "artefact_name": "<artefact_name>",
             "artefact_version": "diki",
             "artefact_type": "dikiReport"
           }
         },
         "meta": {
           "type": "meta/artefact_scan_info",
           "datasource": "diki"
         },
         "data": {}
       },
       {
         "artefact": {
           "component_name": "<component_name>",
           "component_version": "<component_version>",
           "artefact_kind": "runtime",
           "artefact": {
             "artefact_name": "<artefact_name>",
             "artefact_version": "diki",
             "artefact_type": "dikiReport"
           }
         },
         "meta": {
           "type": "finding/diki",
           "datasource": "diki"
         },
         "discovery_date": "<YYYY-MM-DD>",
         "data": {
           "severity": "<severity>",
           "provider_id": "<provider_id>",
           "ruleset_id": "<ruleset_id>",
           "ruleset_version": "<ruleset_version>",
           "rule_id": "<rule_id>",
           "checks": [
             {
               "message": "<message>",
               "targets": {} // List of targets, if the findings are from multiple instances this field can be presented as a map, where the keys are the names of the checked instances and the values are their targets
             }
           ]
         }
       }
       // list all other diki findings
     ]
   }

To create the required `runtimeartefact` `CR` in the Open Delivery Gear
Kubernetes cluster, a `PUT` request to the
`/service-extensions/runtime-artefacts` endpoint of the delivery-service must
be made. The request body should look like:

.. code-block:: json

   {
     "artefacts": [
       {
         "component_name": "<component_name>",
         "component_version": "<component_version>",
         "artefact_kind": "runtime",
         "artefact": {
           "artefact_name": "<artefact_name>",
           "artefact_version": "diki",
           "artefact_type": "dikiReport"
         }
       }
     ]
   }

Cleanup
=======

It is advised to remove old `Diki` findings from the delivery-database and
their `runtimeartefact` `CR`. To remove `Diki` findings from the
delivery-database, a `DELETE` request to the `/artefacts/metadata` endpoint of
the delivery-service must be made. The request body should contain the entries
we want to delete. To remove the `runtimeartefact` `CR` in the cluster, a
`DELETE` request to the `/service-extensions/runtime-artefacts` endpoint of the
delivery-service must be made. To specify which `runtimeartefact` to remove, it
has to be specified in the request via the query argument `name`.
