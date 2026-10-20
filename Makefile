# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: all build build-tools crds-rs generate manifests cluster-up cluster-down \
	install-trustee install clean fmt-check clippy lint test test-release release-tarball prepare-release \
	operator-image compute-pcrs-image reg-server-image attestation-key-register-image image \
	push-operator push-compute-pcrs push-reg-server push-attestation-key-register push \

SHELL := /bin/bash

# Define directory of this Makefile so it can be `include`d from
# elsewhere without variables breaking, e.g. for use of controller-gen
# & kopium from this directory's LOCALBIN.
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

NAMESPACE ?= trusted-execution-clusters
PLATFORM ?= kind

KUBECTL=kubectl
INTEGRATION_TEST_THREADS ?= 1

LOCALBIN ?= $(MAKEFILE_DIR)/bin
# either linux or darwin
OS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
# either x86_64/amd64 or aarch64/arm64
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')

# Kopium architecture detection: supports only Linux and macOS.
# Rust target triples use x86_64/aarch64, but macOS uname -m returns arm64.
KOPIUM_RUST_ARCH := $(shell uname -m | sed 's/arm64/aarch64/')
ifeq ($(OS),linux)
  KOPIUM_TARGET := $(KOPIUM_RUST_ARCH)-unknown-linux-gnu
else ifeq ($(OS),darwin)
  KOPIUM_TARGET := $(KOPIUM_RUST_ARCH)-apple-darwin
endif

CONTROLLER_TOOLS_VERSION ?= $(shell cd $(MAKEFILE_DIR) && go list -m -f '{{.Version}}' sigs.k8s.io/controller-tools)
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen-$(CONTROLLER_TOOLS_VERSION)
YQ_VERSION ?= $(shell cd $(MAKEFILE_DIR) && go list -m -f '{{.Version}}' github.com/mikefarah/yq/v4)
YQ ?= $(LOCALBIN)/yq-$(YQ_VERSION)
KOPIUM_VERSION ?= $(shell cd $(MAKEFILE_DIR) && cargo metadata --format-version 1 | jq -r '.resolve.nodes[] | select(.deps[]?.name == "kopium") | .deps[] | select(.name == "kopium") | .pkg | split("@")[1]')
KOPIUM ?= $(LOCALBIN)/kopium-$(KOPIUM_VERSION)

REGISTRY ?= quay.io/trusted-execution-clusters
TAG ?= latest
# Image tags may use a leading v (e.g. v0.2.1); OLM requires bare semver, without 'v' prefix.
OLM_VERSION ?= $(patsubst v%,%,$(TAG))
PUSH_FLAGS ?=
DELETE_AFTER_PUSH ?= false
OPERATOR_IMAGE ?= $(REGISTRY)/trusted-cluster-operator:$(TAG)
COMPUTE_PCRS_IMAGE=$(REGISTRY)/compute-pcrs:$(TAG)
REG_SERVER_IMAGE=$(REGISTRY)/registration-server:$(TAG)
ATTESTATION_KEY_REGISTER_IMAGE=$(REGISTRY)/attestation-key-register:$(TAG)

TRUSTEE_IMAGE ?= quay.io/trusted-execution-clusters/key-broker-service:v0.20.0

# Upgrade tests: released versions to upgrade from (always on quay.io)
UPGRADE_OLD_REGISTRY ?= quay.io/trusted-execution-clusters
UPGRADE_OLD_TAG ?= v0.2.2
UPGRADE_OLD_TRUSTEE_TAG ?= v0.17.0

TEST_IMAGE ?= quay.io/trusted-execution-clusters/fedora-coreos-kubevirt:20260831
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
	$(call controller-gen,./api/...,*)
	$(call controller-gen,github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1,*)

RS_LIB_PATH = lib/src
CRD_RS_PATH = $(RS_LIB_PATH)/kopium
$(CRD_RS_PATH):
	mkdir $(CRD_RS_PATH)

$(CRD_RS_PATH)/%.rs: $(CRD_YAML_PATH)/*_%.yaml $(KOPIUM) $(CRD_RS_PATH)
	$(KOPIUM) -f $< $$(grep -Eq '(certificates|issuers)' <<< $< && echo --derive Default) > $@
	sed -i 'N; s/, Default)\]\n\(pub struct CertificateAdditionalOutputFormats\)/)]\n\1/; P; D' $@
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
		-approved-image coreos,$(APPROVED_IMAGE)

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

operator-image:
	$(CONTAINER_CLI) build $(IMAGE_BUILD_OPTIONS) --target operator -t $(OPERATOR_IMAGE) -f Containerfile .
compute-pcrs-image:
	$(CONTAINER_CLI) build $(IMAGE_BUILD_OPTIONS) --target compute-pcrs -t $(COMPUTE_PCRS_IMAGE) -f Containerfile .
reg-server-image:
	$(CONTAINER_CLI) build $(IMAGE_BUILD_OPTIONS) --target register-server -t $(REG_SERVER_IMAGE) -f Containerfile .
attestation-key-register-image:
	$(CONTAINER_CLI) build $(IMAGE_BUILD_OPTIONS) --target attestation-key-register -t $(ATTESTATION_KEY_REGISTER_IMAGE) -f Containerfile .

image: operator-image compute-pcrs-image reg-server-image attestation-key-register-image

define push-image
$(CONTAINER_CLI) push $(1) $(PUSH_FLAGS)
$(if $(filter true,$(DELETE_AFTER_PUSH)),$(CONTAINER_CLI) rmi $(1))
endef

push-operator: operator-image
	$(call push-image,$(OPERATOR_IMAGE))
push-compute-pcrs: compute-pcrs-image
	$(call push-image,$(COMPUTE_PCRS_IMAGE))
push-reg-server: reg-server-image
	$(call push-image,$(REG_SERVER_IMAGE))
push-attestation-key-register: attestation-key-register-image
	$(call push-image,$(ATTESTATION_KEY_REGISTER_IMAGE))

push: push-operator push-compute-pcrs push-reg-server push-attestation-key-register

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
	scripts/generate-bundle-prod.sh -v $(OLM_VERSION) -n $(NAMESPACE) $(if $(PREVIOUS_CSV),-p $(PREVIOUS_CSV))

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
	$(YQ) '.spec.publicAttestationKeyRegisterAddr = "$(AK_REGISTRATION_ADDR):8001"' \
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
	$(KUBECTL) apply -f '$(DEPLOY_PATH)/approved_image_cr_*.yaml'

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
	$(CONTAINER_CLI) image prune --all --force --filter label=project=trusted-cluster-operator
	# Prune --mount=type=cache data: podman uses --build-cache, docker uses builder prune (no label filter supported by either)
	@if $(CONTAINER_CLI) image prune --help 2>&1 | grep -q -- '--build-cache'; then \
		$(CONTAINER_CLI) image prune --force --build-cache; \
	else \
		$(CONTAINER_CLI) builder prune --force --filter type=exec.cachemount; \
	fi

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
	cargo test --workspace --bins --lib

test-release: crds-rs
	cargo test --workspace --bins --lib --release

INTEGRATION_TEST_ENV = RUST_LOG=info REGISTRY=$(REGISTRY) TAG=$(TAG) \
	TRUSTEE_IMAGE=$(TRUSTEE_IMAGE) APPROVED_IMAGE=$(APPROVED_IMAGE) TEST_IMAGE=$(TEST_IMAGE)
INTEGRATION_TEST_FLAGS = --features virtualization -- --nocapture --test-threads=$(INTEGRATION_TEST_THREADS)

attestation-tests: generate trusted-cluster-gen crds-rs
	$(INTEGRATION_TEST_ENV) cargo test --test attestation $(INTEGRATION_TEST_FLAGS)

trusted-execution-cluster-tests: generate trusted-cluster-gen crds-rs
	$(INTEGRATION_TEST_ENV) cargo test --test trusted_execution_cluster $(INTEGRATION_TEST_FLAGS)

upgrade-tests: generate trusted-cluster-gen crds-rs
	$(INTEGRATION_TEST_ENV) \
	UPGRADE_OLD_REGISTRY=$(UPGRADE_OLD_REGISTRY) \
	UPGRADE_OLD_TAG=$(UPGRADE_OLD_TAG) \
	UPGRADE_OLD_TRUSTEE_TAG=$(UPGRADE_OLD_TRUSTEE_TAG) \
	cargo test --test upgrade $(INTEGRATION_TEST_FLAGS)

integration-tests: attestation-tests trusted-execution-cluster-tests upgrade-tests

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

$(CONTROLLER_GEN): $(LOCALBIN)
	curl -fsSL https://github.com/kubernetes-sigs/controller-tools/releases/download/$(CONTROLLER_TOOLS_VERSION)/controller-gen-$(OS)-$(ARCH) -o $(CONTROLLER_GEN) \
		&& chmod +x $(CONTROLLER_GEN) \
		|| $(call go-install-tool,$(CONTROLLER_GEN),controller-gen,sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

$(YQ): $(LOCALBIN)
	curl -fsSL https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(OS)_$(ARCH) -o $(YQ) \
		&& chmod +x $(YQ) \
		|| $(call go-install-tool,$(YQ),yq,github.com/mikefarah/yq/v4,$(YQ_VERSION))

$(KOPIUM): $(LOCALBIN)
	{ curl -fsSL https://github.com/kube-rs/kopium/releases/download/$(KOPIUM_VERSION)/kopium-$(KOPIUM_TARGET).tar.xz \
		| tar -xJ -C $(LOCALBIN) \
		&& mv $(LOCALBIN)/kopium $(KOPIUM); } \
		|| $(call cargo-install-tool,$(KOPIUM),kopium,$(KOPIUM_VERSION))

build-tools: $(CONTROLLER_GEN) $(KOPIUM)
yq: $(YQ)

prepare-release:
ifndef VERSION
	$(error VERSION is undefined. Usage: make prepare-release VERSION=0.2.2 [DRY_RUN=1])
endif
	scripts/prepare-release.sh $(if $(DRY_RUN),--dry-run) $(VERSION)

define go-install-tool
[ -f "$(1)" ] || { \
	set -e; \
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
