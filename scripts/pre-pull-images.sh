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
	"quay.io/trusted-execution-clusters/key-broker-service:20260106"
	"quay.io/trusted-execution-clusters/fedora-coreos-kubevirt:20260106"
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
