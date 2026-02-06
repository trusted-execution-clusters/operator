#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

KV_VERSION=v1.7.0
IMAGES=(
	"quay.io/kubevirt/virt-launcher:${KV_VERSION}"
	"quay.io/kubevirt/virt-handler:${KV_VERSION}"
	"quay.io/kubevirt/virt-api:${KV_VERSION}"
	"quay.io/kubevirt/virt-controller:${KV_VERSION}"
	"quay.io/kubevirt/virt-operator:${KV_VERSION}"
	"$TRUSTEE_IMAGE"
	"$APPROVED_IMAGE"
	"$TEST_IMAGE"
)

for IMAGE in "${IMAGES[@]}"; do
    echo "Pulling: $IMAGE"
    docker pull "$IMAGE"
    if [ $? -eq 0 ]; then
        echo "Successfully pulled $IMAGE"
    else
        echo "Error: Failed to pull $IMAGE"
    fi
	 kind load docker-image $IMAGE
    echo "-------------------------------"
done
