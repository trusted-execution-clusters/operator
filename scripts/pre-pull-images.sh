#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

set -o pipefail

KV_VERSION=v1.7.0
IMAGES=(
	"quay.io/kubevirt/virt-launcher:${KV_VERSION}"
	"quay.io/kubevirt/virt-handler:${KV_VERSION}"
	"quay.io/kubevirt/virt-api:${KV_VERSION}"
	"quay.io/kubevirt/virt-controller:${KV_VERSION}"
	"quay.io/kubevirt/virt-operator:${KV_VERSION}"
	"$TRUSTEE_IMAGE"
	"$APPROVED_IMAGE"
)

FAILED_IMAGES=()
PULLED_IMAGES=0

echo "=========================================="
echo "Pre-pulling images to Docker daemon"
echo "=========================================="
echo "Note: Failures are non-fatal - K8s will pull on-demand"
echo ""

for IMAGE in "${IMAGES[@]}"; do
	# Skip empty image names
	if [ -z "$IMAGE" ]; then
		echo "[WARN] Skipping empty image reference"
		continue
	fi

	echo "Pulling: $IMAGE"

	if docker pull "$IMAGE" 2>&1; then
		echo "[SUCCESS] Pulled: $IMAGE"
		PULLED_IMAGES=$((PULLED_IMAGES + 1))
	else
		echo "[WARN] Failed to pull: $IMAGE (will retry during pod creation)"
		FAILED_IMAGES+=("$IMAGE")
	fi

	echo "-------------------------------"
done

echo ""
echo "=========================================="
echo "Pre-pull Summary"
echo "=========================================="
echo "Successfully pulled: ${PULLED_IMAGES}/${#IMAGES[@]} images"

if [ ${#FAILED_IMAGES[@]} -gt 0 ]; then
	echo ""
	echo "Failed images (will be pulled on-demand):"
	for img in "${FAILED_IMAGES[@]}"; do
		echo "  - $img"
	done
	echo ""
	echo "Note: This is non-fatal. Tests will pull images as needed."
fi

echo ""
echo "Images are cached in Docker daemon."
echo "Kubernetes pods will use imagePullPolicy: IfNotPresent to leverage this cache."
echo ""

# Exit successfully even if some images failed
# The purpose is optimization, not a hard requirement
exit 0
