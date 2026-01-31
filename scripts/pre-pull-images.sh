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

	if docker pull "$IMAGE" >/dev/null 2>&1; then
		echo "[SUCCESS] Pulled: $IMAGE"
	else
		echo "[WARN] Failed to pull: $IMAGE (will retry during pod creation)"
	fi

	echo "-------------------------------"
done

exit 0
