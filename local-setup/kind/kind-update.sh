#!/usr/bin/env bash

set -euo pipefail

CHART=""
REPO_ROOT=""

parse_flags() {
  while test $# -gt 0; do
    case "$1" in
    --path-cluster-chart)
      shift; CHART="$1"
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

OCM_GEAR_COMPONENT_REF="europe-docker.pkg.dev/gardener-project/releases//ocm.software/ocm-gear"
OCM_GEAR_VERSION="${OCM_GEAR_VERSION:-$(ocm show versions ${OCM_GEAR_COMPONENT_REF} | tail -1)}"
COMPONENT_DESCRIPTORS=$(ocm get cv ${OCM_GEAR_COMPONENT_REF}:${OCM_GEAR_VERSION} -o yaml -r)
echo "Installing OCM-Gear with version $OCM_GEAR_VERSION"

BOOTSTRAPPING_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "bootstrapping" and .type | test("helmChart")) | .access.imageReference')
DELIVERY_SERVICE_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "delivery-service" and .type | test("helmChart")) | .access.imageReference')
DELIVERY_DASHBOARD_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "delivery-dashboard" and .type | test("helmChart")) | .access.imageReference')
EXTENSIONS_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "extensions" and .type | test("helmChart")) | .access.imageReference')
DELIVERY_DATABASE_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "postgresql" and .type | test("helmChart")) | .access.imageReference')

kubectl config set-context --current --namespace=$NAMESPACE

echo ">>> Installing bootstrapping chart from ${BOOTSTRAPPING_CHART}"
helm upgrade -i bootstrapping oci://${BOOTSTRAPPING_CHART%:*} \
  --namespace ${NAMESPACE} \
  --version ${BOOTSTRAPPING_CHART#*:} \
  --values ${CHART}/values-bootstrapping.yaml

echo ">>> Installing delivery-database from ${DELIVERY_DATABASE_CHART}"
# First, install custom pv and pvc to allow re-usage of host's filesystem mount
kubectl apply -f "${CHART}/delivery-db-pv" --namespace $NAMESPACE
helm upgrade -i delivery-db oci://${DELIVERY_DATABASE_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${DELIVERY_DATABASE_CHART#*:} \
    --values ${CHART}/values-delivery-db.yaml

echo ">>> Installing delivery-service from ${DELIVERY_SERVICE_CHART}"
python3 ${CHART}/delivery-service-mounts/render_sprints.py
kubectl apply -f "${CHART}/delivery-service-mounts/sprints.yaml" --namespace $NAMESPACE
helm upgrade -i delivery-service oci://${DELIVERY_SERVICE_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${DELIVERY_SERVICE_CHART#*:} \
    --values ${CHART}/values-delivery-service.yaml
rm ${CHART}/delivery-service-mounts/sprints.yaml # is created every time from base file
kubectl rollout restart deployment delivery-service # required to use updated configuration
echo "Waiting for delivery-service to become ready, this can take up to 3 minutes..."
kubectl rollout status deployment delivery-service \
    --namespace $NAMESPACE \
    --timeout=180s

echo ">>> Installing delivery-dashboard from ${DELIVERY_DASHBOARD_CHART}"
helm upgrade -i delivery-dashboard oci://${DELIVERY_DASHBOARD_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${DELIVERY_DASHBOARD_CHART#*:} \
    --values ${CHART}/values-delivery-dashboard.yaml

echo ">>> Installing extensions from ${EXTENSIONS_CHART}"
helm upgrade -i extensions oci://${EXTENSIONS_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${EXTENSIONS_CHART#*:} \
    --values ${CHART}/values-extensions.yaml

# port-forward to the new delivery-service pods
lsof -i tcp:5000 | grep kubectl | awk 'NR!=1 {print $2}' | xargs kill
kubectl port-forward service/delivery-service 5000:8080 > /dev/null &
