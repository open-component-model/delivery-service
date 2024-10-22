#!/usr/bin/env bash

set -euo pipefail

CLUSTER_NAME=""
CHART=""
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

OCM_GEAR_COMPONENT_REF="europe-docker.pkg.dev/gardener-project/releases//ocm.software/ocm-gear"
OCM_GEAR_VERSION="${OCM_GEAR_VERSION:-$(ocm show versions ${OCM_GEAR_COMPONENT_REF} | tail -1)}"
COMPONENT_DESCRIPTORS=$(ocm get cv ${OCM_GEAR_COMPONENT_REF}:${OCM_GEAR_VERSION} -o yaml -r)
echo "Installing OCM-Gear with version $OCM_GEAR_VERSION"

DELIVERY_SERVICE_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "delivery-service" and .type | test("helmChart")) | .access.imageReference')
DELIVERY_DASHBOARD_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "delivery-dashboard" and .type | test("helmChart")) | .access.imageReference')
EXTENSIONS_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "extensions" and .type | test("helmChart")) | .access.imageReference')
DELIVERY_DATABASE_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "postgresql" and .type | test("helmChart")) | .access.imageReference')
PROMETHEUS_CHART=$(echo "${COMPONENT_DESCRIPTORS}" | yq eval '.component.resources.[] | select(.name == "prometheus" and .type | test("helmChart")) | .access.imageReference')

# Install ingress nginx controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
echo "Waiting for ingress nginx controller to become ready, this can take up to 3 minutes..."
kubectl wait \
    --namespace ingress-nginx \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/component=controller \
    --timeout=90s

kubectl config set-context --current --namespace=$NAMESPACE

echo ">>> Installing delivery-database from ${DELIVERY_DATABASE_CHART}"
# First, install custom pv and pvc to allow re-usage of host's filesystem mount
kubectl apply -f "${CHART}/delivery-db-pv" --namespace $NAMESPACE
helm install delivery-db oci://${DELIVERY_DATABASE_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${DELIVERY_DATABASE_CHART#*:} \
    --values ${CHART}/values-delivery-db.yaml

echo ">>> Installing delivery-service from ${DELIVERY_SERVICE_CHART}"
python3 ${REPO_ROOT}/local-setup/cfg/serialise_cfg.py
python3 ${CHART}/delivery-service-mounts/render_sprints.py
kubectl apply -f "${CHART}/delivery-service-mounts/addressbook.yaml" --namespace $NAMESPACE
kubectl apply -f "${CHART}/delivery-service-mounts/github_mappings.yaml" --namespace $NAMESPACE
kubectl apply -f "${CHART}/delivery-service-mounts/sprints.yaml" --namespace $NAMESPACE
helm install delivery-service oci://${DELIVERY_SERVICE_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${DELIVERY_SERVICE_CHART#*:} \
    --values ${CHART}/values-delivery-service.yaml
rm ${CHART}/values-delivery-service.yaml ${CHART}/delivery-service-mounts/sprints.yaml # are created every time from base file
echo "Waiting for delivery-service to become ready, this can take up to 3 minutes..."
kubectl rollout status deployment delivery-service \
    --namespace $NAMESPACE \
    --timeout=180s

echo ">>> Installing delivery-dashboard from ${DELIVERY_DASHBOARD_CHART}"
helm install delivery-dashboard oci://${DELIVERY_DASHBOARD_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${DELIVERY_DASHBOARD_CHART#*:} \
    --values ${CHART}/values-delivery-dashboard.yaml

echo ">>> Installing extensions from ${EXTENSIONS_CHART}"
helm install extensions oci://${EXTENSIONS_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${EXTENSIONS_CHART#*:} \
    --values ${CHART}/values-extensions.yaml

echo ">>> Installing prometheus from ${PROMETHEUS_CHART}"
helm install prometheus oci://${PROMETHEUS_CHART%:*} \
    --namespace $NAMESPACE \
    --version ${PROMETHEUS_CHART#*:} \
    --values ${CHART}/values-prometheus.yaml

kubectl port-forward service/delivery-service 5000:8080 > /dev/null &
kubectl port-forward service/prometheus 9090:8080 > /dev/null &
