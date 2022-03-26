
# Image URL to use all building/pushing image targets
IMG ?= acm-sync-manager:latest
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.22

KUSTOMIZE = kustomize

SHELL = bash
.SHELLFLAGS = -ec -o pipefail
.DELETE_ON_ERROR:
.SUFFIXES:
.ONESHELL:

.DEFAULT_GOAL := help

.PHONY: all
all: build

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: test
test: ## Run tests.
	cargo test

##@ Build

.PHONY: build
build: generate fmt vet ## Build manager binary.
	cargo build

.PHONY: run
run: ## Run a controller from your host.
	cargo run

.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	docker build -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push $(IMG)

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=$(IMG)
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

##@ E2E testing

CONTROLLER_NAME := acm-sync-manager
K8S_CLUSTER_NAME := $(CONTROLLER_NAME)
CERT_MANAGER_VERSION ?= 1.6.1
HELM_RELEASE_NAME := $(CONTROLLER_NAME)

REGISTRY_NAME := "kind-registry"
REGISTRY_PORT := 5000
LOCAL_IMAGE := "localhost:$(REGISTRY_PORT)/$(CONTROLLER_NAME)"
NAMESPACE := $(CONTROLLER_NAME)
SERVICE_ACCOUNT := $(NAMESPACE)-sa
export TEST_KUBECONFIG_LOCATION := /tmp/acm_sync_manager_kubeconfig

AWS_ACCOUNT := $(shell aws sts get-caller-identity | jq '.Account' -Mr)
ifndef AWS_ACCOUNT
$(error AWS account could not be retrieved)
endif

OIDC_ACM_SYNC_MANAGER_IAM_ROLE := arn:aws:iam::$(AWS_ACCOUNT):role/$(CONTROLLER_NAME)

.PHONY: setup-aws
setup-aws: ## setup AWS for IRSA
	@if [[ -z "$$OIDC_S3_BUCKET_NAME" ]]; then
		echo "OIDC_S3_BUCKET_NAME variable must be set"
		exit 1
	fi
	./e2e/aws_config/setup.sh $$OIDC_S3_BUCKET_NAME

.PHONY: cleanup-aws
cleanup-aws: ## cleanup AWS for IRSA
	if [[ -z "$$OIDC_S3_BUCKET_NAME" ]]; then
		echo "OIDC_S3_BUCKET_NAME variable must be set"
		exit 1
	fi
	./e2e/aws_config/cleanup.sh $$OIDC_S3_BUCKET_NAME

create-local-registry:
	RUNNING=$$(docker inspect -f '{{.State.Running}}' $(REGISTRY_NAME) 2>/dev/null || true); \
	if [ "$$RUNNING" != 'true' ]; then \
		docker run -d --restart=always -p "127.0.0.1:$(REGISTRY_PORT):5000" --name $(REGISTRY_NAME) registry:2; \
	fi; \
	sleep 15

docker-push-local:
	docker tag $(IMG) $(LOCAL_IMAGE)
	docker push $(LOCAL_IMAGE)

.PHONY: kind-cluster
kind-cluster: ## Use Kind to create a Kubernetes cluster for E2E tests
	if [[ -z "$$OIDC_S3_BUCKET_NAME" ]]; then \
		echo "OIDC_S3_BUCKET_NAME variable not set"; \
		exit 1; \
	fi; \
	if [[ -z "$$AWS_REGION" ]]; then \
		echo "AWS_REGION variable not set"; \
		exit 1; \
	fi; \

	cat e2e/kind_config/config.yaml | sed "s/S3_BUCKET_NAME_PLACEHOLDER/$$OIDC_S3_BUCKET_NAME/g" \
		| sed "s/AWS_REGION_PLACEHOLDER/$$AWS_REGION/g" > /tmp/config.yaml; \
	kind get clusters | grep $(K8S_CLUSTER_NAME) || \
	kind create cluster --name $(K8S_CLUSTER_NAME) --config=/tmp/config.yaml
	kind get kubeconfig --name $(K8S_CLUSTER_NAME) > $(TEST_KUBECONFIG_LOCATION)
	docker network connect "kind" $(REGISTRY_NAME) || true
	kubectl apply -f e2e/kind_config/registry_configmap.yaml --kubeconfig=$(TEST_KUBECONFIG_LOCATION)

.PHONY: setup-eks-webhook
setup-eks-webhook:
	#Ensure that there is a OIDC role and S3 bucket available
	if [[ -z "$$OIDC_S3_BUCKET_NAME" ]]; then \
		echo "OIDC_S3_BUCKET_NAME env var is not set"; \
		exit 1; \
	fi;
	#Get open id configuration from API server
	 kubectl apply -f e2e/kind_config/unauth_role.yaml --kubeconfig=$(TEST_KUBECONFIG_LOCATION);
	 APISERVER=$$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' --kubeconfig=$(TEST_KUBECONFIG_LOCATION));
	 TOKEN=$$(kubectl get secret $$(kubectl get serviceaccount default -o jsonpath='{.secrets[0].name}' --kubeconfig=$(TEST_KUBECONFIG_LOCATION)) \
	-o jsonpath='{.data.token}' --kubeconfig=$(TEST_KUBECONFIG_LOCATION) | base64 --decode );
	curl $$APISERVER/.well-known/openid-configuration --header "Authorization: Bearer $$TOKEN" --insecure -o openid-configuration;
	curl $$APISERVER/openid/v1/jwks --header "Authorization: Bearer $$TOKEN" --insecure -o jwks;
	#Put idP configuration in public S3 bucket
	aws s3 cp --acl public-read jwks s3://$$OIDC_S3_BUCKET_NAME/cluster/acm-sync-cluster/openid/v1/jwks;
	aws s3 cp --acl public-read openid-configuration s3://$$OIDC_S3_BUCKET_NAME/cluster/acm-sync-cluster/.well-known/openid-configuration;
	sleep 60;
	envsubst -no-empty -i e2e/kind_config/install_eks.yaml | kubectl apply -f - --kubeconfig=$(TEST_KUBECONFIG_LOCATION);
	kubectl wait --for=condition=Available --timeout 300s deployment pod-identity-webhook --kubeconfig=$(TEST_KUBECONFIG_LOCATION);

.PHONY: kind-cluster-delete
kind-cluster-delete:
	kind delete cluster --name $(K8S_CLUSTER_NAME)

.PHONY: kind-export-logs
kind-export-logs:
	kind export logs --name $(K8S_CLUSTER_NAME) $(E2E_ARTIFACTS_DIRECTORY)

.PHONY: deploy-cert-manager
deploy-cert-manager: ## Deploy cert-manager in the configured K8s cluster
	kubectl apply --filename=https://github.com/jetstack/cert-manager/releases/download/v$(CERT_MANAGER_VERSION)/cert-manager.yaml --kubeconfig=$(TEST_KUBECONFIG_LOCATION)
	kubectl wait --for=condition=Available --timeout=300s apiservice v1.cert-manager.io --kubeconfig=$(TEST_KUBECONFIG_LOCATION)
	kubectl wait --for=condition=Available --timeout=300s deployment cert-manager-webhook --namespace cert-manager --kubeconfig=$(TEST_KUBECONFIG_LOCATION)
	kubectl apply -f ./e2e/config/cert-manager-issuer.yaml

.PHONY: install-local
install-local: docker-build docker-push-local
	#install plugin from local docker repo
	sleep 15
	#Create namespace and service account
	kubectl get namespace $(NAMESPACE) --kubeconfig=$(TEST_KUBECONFIG_LOCATION) || \
	kubectl create namespace $(NAMESPACE) --kubeconfig=$(TEST_KUBECONFIG_LOCATION)

	helm install $(HELM_RELEASE_NAME) ./charts/$(CONTROLLER_NAME) -n $(NAMESPACE) \
	--set serviceAccount.name=$(SERVICE_ACCOUNT) \
	--set image.repository=$(LOCAL_IMAGE) \
	--set image.tag=latest --set image.pullPolicy=Always \
	--set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="$(OIDC_ACM_SYNC_MANAGER_IAM_ROLE)"

.PHONY: uninstall-local
uninstall-local:
	helm uninstall $(HELM_RELEASE_NAME) -n $(NAMESPACE)

.PHONY: upgrade-local
upgrade-local: uninstall-local install-local

.PHONY: cluster
cluster: create-local-registry kind-cluster deploy-cert-manager setup-eks-webhook ## Sets up a kind cluster using the latest commit on the current branch

