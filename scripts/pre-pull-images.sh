#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0


## Special handling for the approved image because of the kind issue with
## loading images used by image volumes. See:
##   https://github.com/kubernetes-sigs/kind/issues/4099
LOCAL_APPROVED_IMAGE=localhost:5000/approved-image:latest
docker pull $APPROVED_IMAGE
docker tag $APPROVED_IMAGE $LOCAL_APPROVED_IMAGE
docker push $LOCAL_APPROVED_IMAGE
docker exec -ti  kind-control-plane crictl pull $LOCAL_APPROVED_IMAGE

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
