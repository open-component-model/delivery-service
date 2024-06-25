# Delivery-Service

[![REUSE status](https://api.reuse.software/badge/github.com/open-component-model/delivery-service)](https://api.reuse.software/info/github.com/open-component-model/delivery-service)

This repository is used for developing the `Delivery Service` + Extensions, which are part of the
OCM (Delivery) Gear. It exposes a RESTful API useful for delivery- and compliance-related tasks
for OCM-based software deliveries.

Both delivery service and (optional) extensions are intended to be deployed into a common kubernetes
cluster.

# Local Development

Delivery Service and Extensions require a python runtime environment (see setup*.py for details) to
run. Typically, the python3 version from greatest released version of
[alpine](https://endoflife.date/alpine) linux is used/tested (see Dockerfile.*). Greater or smaller
versions _may_ work, but are typically untested.

For delivery-service, use `app.py` as entry point. Check online-help (app.py --help) for further
instructions. Note that most features of delivery-service are optional (features are disabled by
default unless explicitly enabled through additional configuration).

## Getting Started using Kind
If you wish to deploy the OCM-Gear (Delivery-Service, Delivery-Dashboard, Delivery-DB, Extensions)
in a local kubernetes cluster using kind, please refer to
[this guide](https://github.com/open-component-model/delivery-service/blob/master/local-setup/local-setup.md).

## Getting Started
1. Install development dependencies
```
pip3 install -r requirements-dev.txt --upgrade --break-system-packages
```

2. Obtain secrets and configuration (tbd)

3. Start delivery-service with (delivery) database
    - with [local](#db-local) database
    - with [remote](#db-remote) database


<a id="db-local"></a>
## Run with local database

Currently `SQLite3` and `PostgreSQL 16` are support.

### SQLite3

```
python3 app.py --delivery-db-url sqlite:///test.db
```

#### SQLite3 hints

```
Valid SQLite URL forms are:
  sqlite:///:memory: (or, sqlite://)
  sqlite:///relative/path/to/file.db
  sqlite:////absolute/path/to/file.db
```
> Note: _Four_ slashes for abs-path.

### PostgreSQL

Instantiate a local PostgreSQL 16 database, e.g. as OCI Container.

```
docker run -dit  \
    --name postgres \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=MyPassword \
    -p 5432:5432 postgres:16
```

Start the delivery-service

```
python3 app.py --delivery-db-url postgresql+psycopg://postgres:MyPassword@127.0.0.1:5432
```

<a id="db-remote"></a>
## Run with remote database

### Kubernetes
Port-forward the delivery-db service


```
kubectl port-forward service/delivery-db --namespace=database 5431:5432
```

Start the delivery-service

```
python3 app.py --delivery-db-url postgresql+psycopg://postgres:MyPassword@127.0.0.1:5431
```


## Hint: Enable caching

Optionally enable caching using the `--cache-dir` parameter.

# REST-API-Documentation

Delivery-Service exposes generated documentation through the following routes:

- `/apidoc/swagger`
- `/apidoc/redoc`
