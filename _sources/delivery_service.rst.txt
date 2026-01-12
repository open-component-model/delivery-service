===================================
Using the delivery-service HTTP API
===================================

Overview
========

The delivery-service is an HTTP API that provides OCM and ODG related functionalities.

**Authentication**: The delivery-service uses authentication based on GitHub API tokens. Users authenticate by providing their GitHub personal access tokens, which are then used to verify access permissions and generate bearer tokens.

**Documentation**: Complete API documentation is available as an OpenAPI specification document at: ``https://{DELIVERY_SERVICE_URL}/api/v1/doc``

cURL
====

1. Authenticate

.. code-block:: bash

  export DELIVERY_SERVICE_URL='https://<my-delivery-service>'
  export GITHUB_TOKEN='ghp_XXX'
  export GITHUB_API_URL='https://api.github.com'
  DELIVERY_SERVICE_API_TOKEN=$(curl -c - "${DELIVERY_SERVICE_URL}/auth?api_url=${GITHUB_API_URL}&access_token=${GITHUB_TOKEN}" | awk '/bearer_token/ {print $NF}')

2. Make requests

.. code-block:: bash

  curl -v -k -H "Authorization: Bearer ${DELIVERY_SERVICE_API_TOKEN}" "${DELIVERY_SERVICE_URL}/ocm/component?component_name=github.com/gardener/gardener&version=greatest"


Python Package
==============

A Python client implementation for the delivery-service is available at:

`delivery/client.py <https://github.com/gardener/cc-utils/blob/f3bf7a0c5610b9148719de691cf99e52f51a147a/delivery/client.py#L128>`_

This client provides comprehensive functionality including:

- **Authentication**: Automatic authentication handling with the delivery-service
- **Session refresh**: Automatic token refresh to maintain active sessions
- **Multiple endpoints**: Support for most delivery-service API endpoints
