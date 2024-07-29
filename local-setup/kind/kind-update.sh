#!/usr/bin/env bash

set -euo pipefail

CHART=""
HELM_REPO=""
REPO_ROOT=""

parse_flags() {
  while test $# -gt 0; do
    case "$1" in
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

NAMESPACE="${NAMESPACE:-delivery}"

kubectl config set-context --current --namespace=ingress-nginx

OCM_GEAR_VERSION="${OCM_GEAR_VERSION:-$(ocm show versions europe-docker.pkg.dev/gardener-project/releases//ocm.software/delivery-gear | tail -1)}"
echo "Installing delivery-gear with version $OCM_GEAR_VERSION"

kubectl config set-context --current --namespace=$NAMESPACE

# Upgrade delivery-db
# First, install custom pv and pvc to allow re-usage of host's filesystem mount
kubectl apply -f "${CHART}/delivery-db-pv" --namespace $NAMESPACE
helm upgrade delivery-db oci://europe-docker.pkg.dev/gardener-project/releases/delivery-gear/delivery-charts/postgresql \
    --namespace $NAMESPACE \
    --version $POSTGRES_VERSION \
    --values ${CHART}/values-delivery-db.yaml

# Upgrade delivery-service
python3 ${REPO_ROOT}/local-setup/cfg/serialise_cfg.py
python3 ${CHART}/delivery-service-mounts/render_sprints.py
kubectl apply -f "${CHART}/delivery-service-mounts/addressbook.yaml" --namespace $NAMESPACE
kubectl apply -f "${CHART}/delivery-service-mounts/github_mappings.yaml" --namespace $NAMESPACE
kubectl apply -f "${CHART}/delivery-service-mounts/sprints.yaml" --namespace $NAMESPACE
helm upgrade delivery-service oci://${HELM_REPO}/delivery-service \
    --namespace $NAMESPACE \
    --version $OCM_GEAR_VERSION \
    --values ${CHART}/values-delivery-service.yaml
rm ${CHART}/values-delivery-service.yaml ${CHART}/delivery-service-mounts/sprints.yaml # are created every time from base file
kubectl rollout restart deployment delivery-service # required to use updated configuration
kubectl rollout status deployment delivery-service

# Upgrade delivery-dashboard
helm upgrade delivery-dashboard oci://${HELM_REPO}/delivery-dashboard \
    --namespace $NAMESPACE \
    --version $OCM_GEAR_VERSION \
    --values ${CHART}/values-delivery-dashboard.yaml

# Upgrade extensions
helm upgrade delivery-gear-extensions oci://${HELM_REPO}/delivery-gear-extensions \
    --namespace $NAMESPACE \
    --version $OCM_GEAR_VERSION \
    --values ${CHART}/values-delivery-gear-extensions.yaml

# port-forward to the new delivery-service pods
lsof -i tcp:5000 | grep kubectl | awk 'NR!=1 {print $2}' | xargs kill
kubectl port-forward service/delivery-service 5000:8080 > /dev/null &
