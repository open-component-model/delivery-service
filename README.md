# Open Delivery Gear Core

[![REUSE status](https://api.reuse.software/badge/github.com/open-component-model/odg-core)](https://api.reuse.software/info/github.com/open-component-model/odg-core)

![tests](https://github.com/open-component-model/odg-core/actions/workflows/non-release.yaml/badge.svg)
![release](https://github.com/open-component-model/odg-core/actions/workflows/release.yaml/badge.svg)

This repository is used for developing the `Delivery-Service` + Extensions, which are part of the
Open Delivery Gear. It exposes a RESTful API useful for delivery- and compliance-related tasks
for OCM-based software deliveries.

Both Delivery-Service and (optional) Extensions are intended to be deployed into a common Kubernetes
cluster.

# Local Development

Delivery-Service and Extensions require a Python runtime environment (see `setup.py` for details) to
run. Typically, the Python3 version from greatest released version of
[Alpine](https://endoflife.date/alpine) Linux is used/tested (see `Dockerfile`). Greater or smaller
versions _may_ work, but are typically untested.

For Delivery-Service, use `src/app.py` as entry point. Check online-help (`app.py --help`) for further
instructions. Note that most features of Delivery-Service are optional (features are disabled by
default unless explicitly enabled through additional configuration).

Please refer to [this guide](https://open-component-model.github.io/odg-core/local_setup.html)
for a step-by-step description on how to setup the Delivery-Service (and an extension if desired).

## Getting Started using Kind
If you wish to deploy the Open Delivery Gear (Delivery-Service, Delivery-Dashboard, Delivery-DB,
Extensions) in a local Kubernetes cluster using Kind, please refer to
[this guide](https://github.com/open-component-model/odg-core/blob/master/local-setup/local-setup.md).

# REST-API-Documentation

Delivery-Service exposes generated documentation through the following route: `/api/v1/doc`

> [!NOTE]  
> For a full (-> still WIP) documentation, please visit https://open-component-model.github.io/odg-core.

<p align="center"><img alt="Bundesministerium für Wirtschaft und Energie (BMWE)-EU funding logo" src="https://apeirora.eu/assets/img/BMWK-EU.png" width="400"/></p>
