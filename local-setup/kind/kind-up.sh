#!/usr/bin/env bash

set -euo pipefail

CLUSTER_NAME=""
CHART=""
HELM_REPO=""
REPO_ROOT=""

parse_flags() {
  while test $# -gt 0; do
    case "$1" in
    --cluster-name)
      shift; CLUSTER_NAME="$1"
      ;;
    --path-cluster-chart)
      shift; CHART="$1"
      ;;
    --helm-repo)
      shift; HELM_REPO="$1"
      ;;
    --repo-root)
      shift; REPO_ROOT="$1"
      ;;
    esac

    shift
  done
}

parse_flags "$@"

kind create cluster \
  --name "$CLUSTER_NAME" \
  --config <(helm template $CHART)

NAMESPACE="${NAMESPACE:-delivery}"

kubectl create ns ingress-nginx
kubectl create ns $NAMESPACE
kubectl config set-context --current --namespace=ingress-nginx

OCM_GEAR_VERSION="${OCM_GEAR_VERSION:-$(ocm show versions europe-docker.pkg.dev/gardener-project/releases//ocm.software/ocm-gear | tail -1)}"
echo "Installing OCM-Gear with version $OCM_GEAR_VERSION"

# Install ingress nginx controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
echo "Waiting for ingress nginx controller to become ready, this can take up to 3 minutes..."
kubectl wait \
    --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=90s

kubectl config set-context --current --namespace=$NAMESPACE

# Install delivery-db
# First, install custom pv and pvc to allow re-usage of host's filesystem mount
kubectl apply -f "${CHART}/delivery-db-pv" --namespace $NAMESPACE
helm install delivery-db oci://${HELM_REPO}/postgresql \
    --namespace $NAMESPACE \
    --version $POSTGRES_VERSION \
    --values ${CHART}/values-delivery-db.yaml

# Install delivery-service
python3 ${REPO_ROOT}/local-setup/cfg/serialise_cfg.py
python3 ${CHART}/delivery-service-mounts/render_sprints.py
kubectl apply -f "${CHART}/delivery-service-mounts/addressbook.yaml" --namespace $NAMESPACE
kubectl apply -f "${CHART}/delivery-service-mounts/github_mappings.yaml" --namespace $NAMESPACE
kubectl apply -f "${CHART}/delivery-service-mounts/sprints.yaml" --namespace $NAMESPACE
helm install delivery-service oci://${HELM_REPO}/delivery-service \
    --namespace $NAMESPACE \
    --version $OCM_GEAR_VERSION \
    --values ${CHART}/values-delivery-service.yaml
rm ${CHART}/values-delivery-service.yaml ${CHART}/delivery-service-mounts/sprints.yaml # are created every time from base file
echo "Waiting for delivery-service to become ready, this can take up to 3 minutes..."
kubectl wait \
    --namespace $NAMESPACE \
    --for=condition=ready pod \
    --selector=app=delivery-service \
    --timeout=180s

# Install delivery-dashboard
helm install delivery-dashboard oci://${HELM_REPO}/delivery-dashboard \
    --namespace $NAMESPACE \
    --version $OCM_GEAR_VERSION \
    --values ${CHART}/values-delivery-dashboard.yaml

# Install extensions
helm install extensions oci://${HELM_REPO}/extensions \
    --namespace $NAMESPACE \
    --version $OCM_GEAR_VERSION \
    --values ${CHART}/values-extensions.yaml

kubectl port-forward service/delivery-service 5000:8080 > /dev/null &
