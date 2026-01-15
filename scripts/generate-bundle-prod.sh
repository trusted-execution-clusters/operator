#!/usr/bin/env bash

# SPDX-FileCopyrightText: Yalan Zhang <yalzhang@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

set -euo pipefail

BUNDLE_VERSION=""
PREVIOUS_CSV=""
NAMESPACE="trusted-execution-clusters"

while getopts "v:p:n:" opt; do
  case $opt in
    v) BUNDLE_VERSION="$OPTARG" ;;
    p) PREVIOUS_CSV="$OPTARG" ;;
    n) NAMESPACE="$OPTARG" ;;
    *) echo "Usage: $0 -v <bundle-version> [-p <previous-csv>] [-n <namespace>]"; exit 1 ;;
  esac
done

[[ -z "$BUNDLE_VERSION" ]] && { echo "Error: bundle version cannot be empty"; exit 1; }

# Required environment variables
for var in OPERATOR_IMAGE COMPUTE_PCRS_IMAGE REG_SERVER_IMAGE ATTESTATION_KEY_REGISTER_IMAGE TRUSTEE_IMAGE; do
    : "${!var:?Please export $var}"
done

PROJECT_ROOT="$(pwd)"
BUNDLE_DIR="${PROJECT_ROOT}/bundle"
BUNDLE_MANIFESTS="${BUNDLE_DIR}/manifests"
BUNDLE_METADATA="${BUNDLE_DIR}/metadata"
CSV_TEMPLATE="${PROJECT_ROOT}/bundle/static/manifests/trusted-cluster-operator.clusterserviceversion.yaml"
ANNOTATIONS_TEMPLATE="${PROJECT_ROOT}/bundle/static/metadata/annotations.yaml"
RBAC_ROLE_FILE="${PROJECT_ROOT}/config/rbac/role.yaml"
METRICS_AUTH_ROLE_FILE="${PROJECT_ROOT}/config/rbac/metrics_auth_role.yaml"

echo "=> Cleaning previous bundle..."
rm -rf "${BUNDLE_MANIFESTS}" "${BUNDLE_METADATA}"
mkdir -p "${BUNDLE_MANIFESTS}" "${BUNDLE_METADATA}"

echo "=> Copying CRDs and static assets..."
shopt -s nullglob
cp "${PROJECT_ROOT}/config/crd"/*.yaml "${BUNDLE_MANIFESTS}/"
cp "${PROJECT_ROOT}/config/rbac"/*.yaml "${BUNDLE_MANIFESTS}/"
rm -f "${BUNDLE_MANIFESTS}/kustomization.yaml"
rm -f "${BUNDLE_MANIFESTS}/service_account.yaml"
# Remove operator's main RBAC files - these are defined in CSV's clusterPermissions instead
# This prevents OLM from creating duplicate ClusterRoles and ClusterRoleBindings
rm -f "${BUNDLE_MANIFESTS}/role.yaml"
rm -f "${BUNDLE_MANIFESTS}/role_binding.yaml"
cp "$CSV_TEMPLATE" "${BUNDLE_MANIFESTS}/"
cp "$ANNOTATIONS_TEMPLATE" "${BUNDLE_METADATA}/"

echo "=> Patching CSV with images, env vars, version, and RBAC rules..."
CSV_FILE="${BUNDLE_MANIFESTS}/trusted-cluster-operator.clusterserviceversion.yaml"

# Patch metadata and version
yq -i ".metadata.name = \"trusted-cluster-operator.v${BUNDLE_VERSION}\"" "$CSV_FILE"
yq -i ".spec.version = \"${BUNDLE_VERSION}\"" "$CSV_FILE"
yq -i ".metadata.annotations.containerImage = \"${OPERATOR_IMAGE}\"" "$CSV_FILE"

# Patch deployment container image
yq -i ".spec.install.spec.deployments[0].spec.template.spec.containers[0].image = \"${OPERATOR_IMAGE}\"" "$CSV_FILE"

# Patch relatedImages section for air-gapped environments
yq -i "(.spec.relatedImages[] | select(.name == \"trusted-cluster-operator\")).image = \"${OPERATOR_IMAGE}\"" "$CSV_FILE"
yq -i "(.spec.relatedImages[] | select(.name == \"compute-pcrs\")).image = \"${COMPUTE_PCRS_IMAGE}\"" "$CSV_FILE"
yq -i "(.spec.relatedImages[] | select(.name == \"registration-server\")).image = \"${REG_SERVER_IMAGE}\"" "$CSV_FILE"
yq -i "(.spec.relatedImages[] | select(.name == \"attestation-key-register\")).image = \"${ATTESTATION_KEY_REGISTER_IMAGE}\"" "$CSV_FILE"
yq -i "(.spec.relatedImages[] | select(.name == \"trustee\")).image = \"${TRUSTEE_IMAGE}\"" "$CSV_FILE"

# Patch RBAC rules
yq -i ".spec.install.spec.clusterPermissions[0].rules = load(\"${RBAC_ROLE_FILE}\").rules" "$CSV_FILE"
yq -i ".spec.install.spec.clusterPermissions[1].rules = load(\"${METRICS_AUTH_ROLE_FILE}\").rules" "$CSV_FILE"

echo "=> Removing hardcoded namespaces from RBAC bindings (OLM will inject them)..."
for binding_file in leader_election_role_binding.yaml; do
  file_path="${BUNDLE_MANIFESTS}/${binding_file}"
  if [ -f "$file_path" ]; then
    echo "--> Removing namespace from ${binding_file}..."
    yq -i "del(.subjects[0].namespace)" "$file_path"
  else
    echo "WARN: Binding file ${binding_file} not found in bundle, skipping patch."
  fi
done

echo "=> Removing metrics-auth standalone manifests (now in CSV clusterPermissions)..."
rm -f "${BUNDLE_MANIFESTS}/metrics_auth_role.yaml"
rm -f "${BUNDLE_MANIFESTS}/metrics_auth_role_binding.yaml"

# Set .spec.replaces for automatic upgrades if provided
if [[ -n "$PREVIOUS_CSV" ]]; then
  echo "=> Setting .spec.replaces to $PREVIOUS_CSV"
  yq -i ".spec.replaces = \"$PREVIOUS_CSV\"" "$CSV_FILE"
fi

echo "=> Validating OLM bundle..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

cp -r "${BUNDLE_MANIFESTS}" "$TMP_DIR/manifests"
cp -r "${BUNDLE_METADATA}" "$TMP_DIR/metadata"

(cd "$TMP_DIR" && operator-sdk bundle validate . --select-optional suite=operatorframework --verbose)

echo "=> Bundle validated successfully!"
echo "=> OLM bundle ready at ${BUNDLE_DIR}"
