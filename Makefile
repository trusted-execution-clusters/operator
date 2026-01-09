# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: all build build-tools crds-rs generate manifests cluster-up cluster-down image push install-trustee install clean fmt-check clippy lint test test-release release-tarball

NAMESPACE ?= trusted-execution-clusters
PLATFORM ?= kind

KUBECTL=kubectl

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_TOOLS_VERSION ?= v0.19.0
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen-$(CONTROLLER_TOOLS_VERSION)
YQ_VERSION ?= v4.48.1
YQ ?= $(LOCALBIN)/yq-$(YQ_VERSION)
# tracking k8s v1.33, sync with Cargo.toml
KOPIUM_VERSION ?= 0.21.3
KOPIUM ?= $(LOCALBIN)/kopium-$(KOPIUM_VERSION)

REGISTRY ?= quay.io/trusted-execution-clusters
TAG ?= latest
PUSH_FLAGS ?=
OPERATOR_IMAGE=$(REGISTRY)/trusted-cluster-operator:$(TAG)
COMPUTE_PCRS_IMAGE=$(REGISTRY)/compute-pcrs:$(TAG)
REG_SERVER_IMAGE=$(REGISTRY)/registration-server:$(TAG)
# TODO add support for TPM AK verification, then move to a KBS with implemented verifier
TRUSTEE_IMAGE ?= quay.io/trusted-execution-clusters/key-broker-service:tpm-verifier-built-in-as-20250711
# tagged as 42.20250705.3.0
APPROVED_IMAGE ?= quay.io/trusted-execution-clusters/fedora-coreos@sha256:e71dad00aa0e3d70540e726a0c66407e3004d96e045ab6c253186e327a2419e5

BUILD_TYPE ?= release

all: build trusted-cluster-gen reg-server

build: crds-rs
	cargo build -p compute-pcrs
	cargo build -p operator

reg-server: crds-rs
	cargo build -p register-server

CRD_YAML_PATH = config/crd
RBAC_YAML_PATH = config/rbac/base
API_PATH = api/v1alpha1
generate: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) rbac:roleName=trusted-cluster-operator-role crd webhook paths="./..." \
		output:crd:artifacts:config=$(CRD_YAML_PATH) \
		output:rbac:artifacts:config=$(RBAC_YAML_PATH)

RS_LIB_PATH = lib/src
CRD_RS_PATH = $(RS_LIB_PATH)/kopium
$(CRD_RS_PATH):
	mkdir $(CRD_RS_PATH)

YAML_PREFIX = trusted-execution-clusters.io_
$(CRD_RS_PATH)/%.rs: $(CRD_YAML_PATH)/$(YAML_PREFIX)%.yaml $(KOPIUM) $(CRD_RS_PATH)
	$(KOPIUM) -f $< > $@
	rustfmt $@

crds-rs: generate
	$(MAKE) $(shell find $(CRD_YAML_PATH) -type f \
		| sed -E 's|$(CRD_YAML_PATH)/$(YAML_PREFIX)(.*)\.yaml|$(CRD_RS_PATH)/\1.rs|')

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
	$(CONTAINER_CLI) build --build-arg build_type=$(BUILD_TYPE) -t $(OPERATOR_IMAGE) -f Containerfile .
	$(CONTAINER_CLI) build --build-arg build_type=$(BUILD_TYPE) -t $(COMPUTE_PCRS_IMAGE) -f compute-pcrs/Containerfile .
	$(CONTAINER_CLI) build --build-arg build_type=$(BUILD_TYPE) -t $(REG_SERVER_IMAGE) -f register-server/Containerfile .

push: image
	$(CONTAINER_CLI) push $(OPERATOR_IMAGE) $(PUSH_FLAGS)
	$(CONTAINER_CLI) push $(COMPUTE_PCRS_IMAGE) $(PUSH_FLAGS)
	$(CONTAINER_CLI) push $(REG_SERVER_IMAGE) $(PUSH_FLAGS)

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
	scripts/clean-cluster-kind.sh $(OPERATOR_IMAGE) $(COMPUTE_PCRS_IMAGE) $(REG_SERVER_IMAGE)
	$(YQ) '.spec.publicTrusteeAddr = "$(TRUSTEE_ADDR):8080"' \
		-i $(DEPLOY_PATH)/trusted_execution_cluster_cr.yaml
	$(YQ) '.namespace = "$(NAMESPACE)"' -i config/rbac/base/kustomization.yaml
	$(YQ) '.patches[0].patch = "- op: replace\n  path: /metadata/name\n  value: $(NAMESPACE)-manager-rolebinding"' -i config/rbac/base/kustomization.yaml
	$(YQ) '.patches[1].patch = "- op: replace\n  path: /metadata/name\n  value: $(NAMESPACE)-metrics-auth-rolebinding"' -i config/rbac/base/kustomization.yaml
	@if [ "$(PLATFORM)" = "openshift" ]; then \
		$(YQ) '.patches[0].patch = "- op: replace\n  path: /metadata/name\n  value: $(NAMESPACE)-trusted-cluster-scc\n- op: replace\n  path: /users/0\n  value: system:serviceaccount:$(NAMESPACE):trusted-cluster-operator"' -i config/rbac/overlays/openshift/kustomization.yaml; \
	fi
	$(KUBECTL) apply -f $(DEPLOY_PATH)/operator.yaml
	$(KUBECTL) apply -f config/crd
	$(KUBECTL) apply -k config/rbac/overlays/$(PLATFORM)
	$(KUBECTL) apply -f $(DEPLOY_PATH)/trusted_execution_cluster_cr.yaml
	$(KUBECTL) apply -f $(DEPLOY_PATH)/approved_image_cr.yaml
	$(KUBECTL) apply -f kind/register-forward.yaml
	$(KUBECTL) apply -f kind/kbs-forward.yaml

install-kubevirt:
	scripts/install-kubevirt.sh

clean:
	cargo clean
	rm -rf bin manifests $(CRD_YAML_PATH) $(CRD_RS_PATH)
	rm -f trusted-cluster-gen config/rbac/base/role.yaml .crates.toml .crates2.json

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
	RUST_LOG=info cargo test --test trusted_execution_cluster --test attestation \
		--features virtualization -- --no-capture  --test-threads=3

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
