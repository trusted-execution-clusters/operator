# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: all build build-tools crds-rs generate manifests cluster-up cluster-down image push install-trustee install clean fmt-check clippy lint test test-release release-tarball

NAMESPACE ?= trusted-execution-clusters
PLATFORM ?= kind

KUBECTL=kubectl
INTEGRATION_TEST_THREADS ?= 1

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_TOOLS_VERSION ?= $(shell go list -m -f '{{.Version}}' sigs.k8s.io/controller-tools)
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen-$(CONTROLLER_TOOLS_VERSION)
YQ_VERSION ?= $(shell go list -m -f '{{.Version}}' github.com/mikefarah/yq/v4)
YQ ?= $(LOCALBIN)/yq-$(YQ_VERSION)
KOPIUM_VERSION ?= $(shell cargo metadata --format-version 1 | jq -r '.resolve.nodes[] | select(.deps[]?.name == "kopium") | .deps[] | select(.name == "kopium") | .pkg | split("@")[1]')
KOPIUM ?= $(LOCALBIN)/kopium-$(KOPIUM_VERSION)

REGISTRY ?= quay.io/trusted-execution-clusters
TAG ?= latest
PUSH_FLAGS ?=
OPERATOR_IMAGE=$(REGISTRY)/trusted-cluster-operator:$(TAG)
COMPUTE_PCRS_IMAGE=$(REGISTRY)/compute-pcrs:$(TAG)
REG_SERVER_IMAGE=$(REGISTRY)/registration-server:$(TAG)
ATTESTATION_KEY_REGISTER_IMAGE=$(REGISTRY)/attestation-key-register:$(TAG)
TRUSTEE_IMAGE ?= quay.io/trusted-execution-clusters/key-broker-service:v0.17.0
TEST_IMAGE ?= quay.io/trusted-execution-clusters/fedora-coreos-kubevirt:clevis-attest-reg
# tagged as 42.20251012.2.0
APPROVED_IMAGE ?= quay.io/trusted-execution-clusters/fedora-coreos@sha256:6997f51fd27d1be1b5fc2e6cc3ebf16c17eb94d819b5d44ea8d6cf5f826ee773

BUILD_TYPE ?= release
IMAGE_BUILD_OPTION ?=
IMAGE_BUILD_OPTIONS=--build-arg build_type=$(BUILD_TYPE) $(IMAGE_BUILD_OPTION)

all: build trusted-cluster-gen reg-server attestation-key-register

build: crds-rs
	cargo build -p compute-pcrs
	cargo build -p operator

reg-server: crds-rs
	cargo build -p register-server

attestation-key-register: crds-rs
	cargo build -p attestation-key-register

CRD_YAML_PATH = config/crd
CRD_WORK_PATH = config/crd/tmp
RBAC_YAML_PATH = config/rbac
API_PATH = api/v1alpha1
generate: $(CONTROLLER_GEN)
	$(call controller-gen,./...,*)
	$(call controller-gen,github.com/openshift/api/route/v1,*)
	$(call controller-gen,github.com/openshift/api/config/v1,*_ingresses.yaml)

RS_LIB_PATH = lib/src
CRD_RS_PATH = $(RS_LIB_PATH)/kopium
$(CRD_RS_PATH):
	mkdir $(CRD_RS_PATH)

$(CRD_RS_PATH)/%.rs: $(CRD_YAML_PATH)/*_%.yaml $(KOPIUM) $(CRD_RS_PATH)
	$(KOPIUM) -f $< > $@
	rustfmt $@

crds-rs: generate $(KOPIUM) $(CRD_RS_PATH)
	$(MAKE) $(shell find $(CRD_YAML_PATH) -type f \
		| sed -E 's|$(CRD_YAML_PATH)/.*_(.*)\.yaml|$(CRD_RS_PATH)/\1.rs|')

trusted-cluster-gen: api/trusted-cluster-gen.go
	go build -o $@ $<

DEPLOY_PATH = config/deploy
manifests: trusted-cluster-gen generate
	./trusted-cluster-gen -output-dir $(DEPLOY_PATH) \
		-namespace $(NAMESPACE) \
		-image $(OPERATOR_IMAGE) \
		-trustee-image $(TRUSTEE_IMAGE) \
		-pcrs-compute-image $(COMPUTE_PCRS_IMAGE) \
		-register-server-image $(REG_SERVER_IMAGE) \
		-attestation-key-register-image $(ATTESTATION_KEY_REGISTER_IMAGE) \
		-approved-image $(APPROVED_IMAGE)

cluster-up:
	RUNTIME=$(RUNTIME) scripts/create-cluster-kind.sh

cluster-cleanup:
	$(KUBECTL) delete -f $(DEPLOY_PATH)/trusted_execution_cluster_cr.yaml
	$(KUBECTL) delete -f $(CRD_YAML_PATH)/trusted-execution-clusters.io_trustedexecutionclusters.yaml
	$(KUBECTL) delete -f $(DEPLOY_PATH)/operator.yaml


cluster-down:
	RUNTIME=$(RUNTIME) scripts/delete-cluster-kind.sh

CONTAINER_CLI ?= podman
RUNTIME ?= podman

image:
	$(CONTAINER_CLI) build $(IMAGE_BUILD_OPTIONS) -t $(OPERATOR_IMAGE) -f Containerfile .
	$(CONTAINER_CLI) build $(IMAGE_BUILD_OPTIONS) -t $(COMPUTE_PCRS_IMAGE) -f compute-pcrs/Containerfile .
	$(CONTAINER_CLI) build $(IMAGE_BUILD_OPTIONS) -t $(REG_SERVER_IMAGE) -f register-server/Containerfile .
	$(CONTAINER_CLI) build $(IMAGE_BUILD_OPTIONS) -t $(ATTESTATION_KEY_REGISTER_IMAGE) -f attestation-key-register/Containerfile .

push: image
	$(CONTAINER_CLI) push $(OPERATOR_IMAGE) $(PUSH_FLAGS)
	$(CONTAINER_CLI) push $(COMPUTE_PCRS_IMAGE) $(PUSH_FLAGS)
	$(CONTAINER_CLI) push $(REG_SERVER_IMAGE) $(PUSH_FLAGS)
	$(CONTAINER_CLI) push $(ATTESTATION_KEY_REGISTER_IMAGE) $(PUSH_FLAGS)

release-tarball: manifests
	tar -cf trusted-execution-operator-$(TAG).tar config

# OLM Bundle related variables
BUNDLE_DIR := bundle
BUNDLE_IMAGE := $(REGISTRY)/trusted-cluster-operator-bundle:$(TAG)
PREVIOUS_CSV ?= ""  # optional previous CSV for OLM upgrades

.PHONY: bundle bundle-image push-bundle

bundle: manifests
	@echo "Generating OLM bundle..."
	@OPERATOR_IMAGE=$(OPERATOR_IMAGE) \
	COMPUTE_PCRS_IMAGE=$(COMPUTE_PCRS_IMAGE) \
	REG_SERVER_IMAGE=$(REG_SERVER_IMAGE) \
	ATTESTATION_KEY_REGISTER_IMAGE=$(ATTESTATION_KEY_REGISTER_IMAGE) \
	TRUSTEE_IMAGE=$(TRUSTEE_IMAGE) \
	scripts/generate-bundle-prod.sh -v $(TAG) -n $(NAMESPACE) $(if $(PREVIOUS_CSV),-p $(PREVIOUS_CSV))

bundle-image: bundle
	@echo "Building OLM bundle image..."
	$(CONTAINER_CLI) build -f $(BUNDLE_DIR)/Containerfile -t $(BUNDLE_IMAGE) $(BUNDLE_DIR)/

push-bundle: bundle-image
	@echo "Pushing OLM bundle image..."
	$(CONTAINER_CLI) push $(BUNDLE_IMAGE) $(PUSH_FLAGS)

push-all: push push-bundle ## Pushes all operator and bundle images

install: $(YQ)
ifndef TRUSTEE_ADDR
	$(error TRUSTEE_ADDR is undefined)
endif
ifndef AK_REGISTRATION_ADDR
	$(error AK_REGISTRATION_ADDR is undefined)
endif
	scripts/clean-cluster-kind.sh $(OPERATOR_IMAGE) $(COMPUTE_PCRS_IMAGE) $(REG_SERVER_IMAGE) $(ATTESTATION_KEY_REGISTER_IMAGE)
	$(YQ) '.spec.publicTrusteeAddr = "$(TRUSTEE_ADDR):8080"' \
		-i $(DEPLOY_PATH)/trusted_execution_cluster_cr.yaml
	$(YQ) '.spec.publicAttestationKeyRegisterAddr = "http://$(AK_REGISTRATION_ADDR):8001/register-ak"' \
		-i $(DEPLOY_PATH)/trusted_execution_cluster_cr.yaml
	sed "s/NAMESPACE/$(NAMESPACE)/g" config/rbac/kustomization.yaml.in > config/rbac/kustomization.yaml
	$(KUBECTL) apply -f $(DEPLOY_PATH)/operator.yaml
	$(KUBECTL) apply -f config/crd
	$(KUBECTL) apply -k config/rbac
	@if [ "$(PLATFORM)" = "openshift" ]; then \
		sed 's/<NAMESPACE>/$(NAMESPACE)/g' config/openshift/scc.yaml | $(KUBECTL) apply -f -; \
	else \
		sed 's/<NAMESPACE>/$(NAMESPACE)/g' kind/ak-register-forward.yaml | $(KUBECTL) apply -f -; \
		sed 's/<NAMESPACE>/$(NAMESPACE)/g' kind/register-forward.yaml | $(KUBECTL) apply -f -; \
		sed 's/<NAMESPACE>/$(NAMESPACE)/g' kind/kbs-forward.yaml | $(KUBECTL) apply -f -; \
	fi
	$(KUBECTL) apply -f $(DEPLOY_PATH)/trusted_execution_cluster_cr.yaml
	$(KUBECTL) apply -f $(DEPLOY_PATH)/approved_image_cr.yaml

install-kubevirt:
	scripts/install-kubevirt.sh

pre-pull-images:
	APPROVED_IMAGE=$(APPROVED_IMAGE) \
	TRUSTEE_IMAGE=$(TRUSTEE_IMAGE) \
	TEST_IMAGE=$(TEST_IMAGE) \
		scripts/pre-pull-images.sh

clean:
	cargo clean
	rm -rf bin manifests $(CRD_YAML_PATH) $(CRD_RS_PATH)
	rm -f trusted-cluster-gen config/rbac/role.yaml .crates.toml .crates2.json

fmt-check:
	cargo fmt -- --check
	if [ "$$(gofmt -l .)" ]; then exit 1; fi

clippy: crds-rs
	cargo clippy --all-targets --all-features -- -D warnings

vet:
	go vet ./...

equal-conditions:
	cargo test --test equal_conditions

lint: fmt-check clippy vet equal-conditions

test: crds-rs
	cargo test --workspace --bins

test-release: crds-rs
	cargo test --workspace --bins --release

integration-tests: generate trusted-cluster-gen crds-rs
	RUST_LOG=info REGISTRY=$(REGISTRY) TAG=$(TAG) \
		TRUSTEE_IMAGE=$(TRUSTEE_IMAGE) APPROVED_IMAGE=$(APPROVED_IMAGE) TEST_IMAGE=$(TEST_IMAGE) \
		cargo test --test trusted_execution_cluster --test attestation \
		--features virtualization -- --nocapture --test-threads=$(INTEGRATION_TEST_THREADS)

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),controller-gen,sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

$(YQ): $(LOCALBIN)
	$(call go-install-tool,$(YQ),yq,github.com/mikefarah/yq/v4,$(YQ_VERSION))

$(KOPIUM): $(LOCALBIN)
	$(call cargo-install-tool,$(KOPIUM),kopium,$(KOPIUM_VERSION))

build-tools: $(CONTROLLER_GEN) $(KOPIUM)

define go-install-tool
[ -f "$(1)" ] || { \
	set -e; \
	package=$(3)@$(4) ;\
	GOBIN="$(LOCALBIN)" go install $(3)@$(4) ;\
	mv "$$(dirname $(1))/$(2)" $(1) ;\
}
endef

define cargo-install-tool
[ -f "$(1)" ] || { \
	set -e; \
	cargo install --locked --version $(3) --root "$(LOCALBIN)/.." $(2) ;\
	mv "$$(dirname $(1))/$(2)" $(1) ;\
}
endef

define controller-gen
mkdir -p $(CRD_WORK_PATH)
$(CONTROLLER_GEN) rbac:roleName=trusted-cluster-operator-role crd webhook paths=$(1) \
	output:crd:artifacts:config=$(CRD_WORK_PATH) \
	output:rbac:artifacts:config=$(RBAC_YAML_PATH)
mv $(CRD_WORK_PATH)/$(2) $(CRD_YAML_PATH)/
rm -rf $(CRD_WORK_PATH)
endef
