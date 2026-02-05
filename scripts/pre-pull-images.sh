#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

# Pre-pull images that are used by integration tests to speed up test execution.

IMAGES=(
	"$TRUSTEE_IMAGE"
	"$APPROVED_IMAGE"
)

for IMAGE in "${IMAGES[@]}"; do
    echo "Pulling: $IMAGE"
    docker pull "$IMAGE" && kind load docker-image "$IMAGE" || echo "Error: Failed to pull $IMAGE"
    echo "-------------------------------"
done
