#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

secondary_approved_image() {
    sed -nE 's/pub const COMBINE_PCRS_UPDATE_TEST_IMAGE_REF: &str = "(.*)";/\1/p' test_utils/src/constants.rs
}

## Special handling for the approved image because of the kind issue with
## loading images used by image volumes. See:
##   https://github.com/kubernetes-sigs/kind/issues/4099
pull_approved_image() {
	local image=$1
	local index=$2
	local local_image="localhost:5000/approved-image-${index}:latest"
	echo "Pulling approved image: $image"
	docker pull "$image"
	docker tag "$image" "$local_image"
	docker push "$local_image"
	docker exec -ti kind-control-plane crictl pull "$local_image"
	echo "-------------------------------"
}

pull_approved_image "$APPROVED_IMAGE" 0
pull_approved_image "$(secondary_approved_image)" 1

KV_VERSION=v1.7.0
IMAGES=(
	"quay.io/kubevirt/virt-launcher:${KV_VERSION}"
	"quay.io/kubevirt/virt-handler:${KV_VERSION}"
	"quay.io/kubevirt/virt-api:${KV_VERSION}"
	"quay.io/kubevirt/virt-controller:${KV_VERSION}"
	"quay.io/kubevirt/virt-operator:${KV_VERSION}"
	"$TRUSTEE_IMAGE"
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
