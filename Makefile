REPO_ROOT := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

kind-up kind-down: export CLUSTER_NAME = ocm-gear-local
kind-up kind-update: export KUBECONFIG = $(REPO_ROOT)/local-setup/kind/kubeconfig
kind-up kind-update: export PATH_CLUSTER_CHART = $(REPO_ROOT)/local-setup/kind/cluster

kind-up: $(KIND) $(KUBECTL) $(HELM) $(OCM)
	./local-setup/kind/kind-up.sh \
		--cluster-name $(CLUSTER_NAME) \
		--path-cluster-chart $(PATH_CLUSTER_CHART) \
		--repo-root $(REPO_ROOT)
kind-update: $(KIND) $(KUBECTL) $(HELM) $(OCM)
	./local-setup/kind/kind-update.sh \
		--path-cluster-chart $(PATH_CLUSTER_CHART) \
		--repo-root $(REPO_ROOT)
kind-down: $(KIND)
	./local-setup/kind/kind-down.sh \
		--cluster-name $(CLUSTER_NAME)
