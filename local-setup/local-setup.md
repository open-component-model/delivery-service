# Deploying the OCM-Gear locally

This guide will help you deploy a custom OCM-Gear on your local machine using
[kind](https://kind.sigs.k8s.io/). If you encounter any problems, please feel
free to [open an issue](https://github.com/open-component-model/delivery-service/issues/new?assignees=&labels=kind%2Fenhancement&projects=&template=enhancement_request.md)
so that we can improve this process or documentation.

## Prerequisites
To get started, you first of all need to install the required toolchain:
- [kubectl](https://kubernetes.io/docs/tasks/tools)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- [helm](https://helm.sh/docs/intro/install)
- [ocm cli](https://github.com/open-component-model/ocm-cli) (only required if
no specific version is set using the environment variable `OCM_GEAR_VERSION`)
- Gardener CI/CD utilities `pip3 install gardener-cicd-dso`

## Configuration
To customize the OCM-Gear according to your needs, you have to adjust the
configuration templates [here](https://github.com/open-component-model/delivery-service/tree/master/local-setup/cfg).
There are already reasonable defaults set for most entries, however, following
entries must still be provided:
- GitHub credentials to ensure repository access ([ref](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/github.yaml))
- OCI registry credentials to access desired component descriptors and resources
([ref](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/container_registry.yaml))
- If you want to add more than one account for either GitHub or the OCI registry,
you have to add them [here](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/configs.yaml)
as well
- GitHub App credentials to allow OAuth  
    (1) Go to your GitHub organization's settings  
    (2) Developer settings -> GitHub Apps -> New GitHub App  
    (3) Fill in the form ("Callback URL" -> `http://localhost`, "Request user
    authorization (OAuth) during installation" -> `True`, other checkboxes -> `False`)  
    (4) Fill in `client_id` and `client_secret` [here](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/delivery.yaml)  
    (5) Generate a RSA key pair and store it also [here](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/delivery.yaml)
    -> `ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key && openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub`

## Start-Up
To create a local Kubernetes cluster and deploy the OCM-Gear, you have to run
`make kind-up`. If you want to deploy a specific version of the OCM-Gear, you
have to set the enviroment variable `OCM_GEAR_VERSION`. Otherwise, the ocm cli
is used to retrieve the greatest version. Upon execution, this command will
create `<REPO_ROOT>/local-setup/kind/kubeconfig` which can be used to interact
with the OCM-Gear cluster. Also, it will forward the delivery-service to
`http://localhost:5000`.

## Configuration Update
To update the OCM-Gear deployment in case your local configuration has changed,
just run the `make kind-update` command. This will upgrade the existing helm
charts and re-apply your configuration settings without the need to re-create
your kind cluster.

## Termination
If you wish to stop the OCM-Gear and delete the kind cluster, you have to run
`make kind-down`. However, this will _not_ delete the delivery-db storage since
it is permanently stored on the host machine. To also clear the delivery-db
storage, you have to delete the `/var/delivery-db` directory.

## Extensions
OCM-Gear extensions can be dynamically added to your installation. However, some
extensions require the presence of another extension or extra configuration to
work properly. The basic configuration of the extensions is done via the
[`values-delivery-gear-extensions.yaml`](https://github.com/open-component-model/delivery-service/blob/master/local-setup/kind/cluster/values-delivery-gear-extensions.yaml).

### Artefact Enumerator
> Requires: -

To set up the artefact enumerator, you need to set the
`artefact-enumerator.enabled` flag. Also, you'll need to add extra configuration
via `configuration.scanConfigurations.[].spec.artefactEnumerator`. Basically, this
is to specify which OCM components should be processed by the other OCM-Gear
extensions in a regular manner.

### Backlog Controller
> Requires: -

To set up the backlog controller, you just need to set the
`backlog-controller.enabled` flag. That's it.

### BDBA
> Requires: Artefact Enumerator, Backlog Controller

To set up the BDBA scanner, you first of all need to add correspondig BDBA
credentials [here](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/bdba.yaml).
To include these credentials, you'll also have to uncomment the bdba block in the
[`configs.yaml`](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/configs.yaml).
After that, you must reference these credentials in the
`configuration.scanConfigurations.[].spec.bdba` section.

### ClamAV
> Requires: Artefact Enumerator, Backlog Controller

To set up the ClamAV scanner, you need to set the `freshclam.enabled` flag and add
configuration via `configuration.scanConfigurations.[].spec.clamav`.

### Delivery-DB Backup
> Requires: -

To enable the delivery-db backup extension, you have to set the
`delivery-db-backup.enabled` flag and add configuration via
`configuration.scanConfigurations.[].spec.deliveryDbBackup`. You have to make sure
you have OCI registry credentials provided in your
[`container_registry.yaml`](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/container_registry.yaml)
file and referenced in the [`configs.yaml`](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/configs.yaml),
which have write permissions to the OCI registry the backup component should be
published to.

### GitHub Issues
> Requires: Artefact Enumerator, Backlog Controller

To set up the GitHub issues extension, you need to add the configuration via
`configuration.scanConfigurations.[].spec.issueReplicator`. Also, you have to make
sure you have GitHub credentials provided in your
[`github.yaml`](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/github.yaml)
file and referenced in the [`configs.yaml`](https://github.com/open-component-model/delivery-service/blob/master/local-setup/cfg/configs.yaml),
which have write permissions to the repository specified under
`configuration.scanConfigurations.[].spec.issueReplicator.github_issues_target_repository_url`.
