#!/usr/bin/env bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

set -xo errexit

. scripts/common.sh

if [ "$(kind get clusters 2>/dev/null)" != "kind" ]; then
	kind create cluster --config kind/config.yaml
	kubectl wait --for=condition=Ready pod -l component=kube-apiserver -n kube-system
fi

reg_name='kind-registry'
reg_port='5000'
args=""
if [ "$RUNTIME" == podman ]; then
	args=$args" --replace"
fi
if [ "$($RUNTIME inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  $RUNTIME run $args --network kind \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    registry:2
fi

REGISTRY_DIR="/etc/containerd/certs.d/localhost:${reg_port}"
for node in $(kind get nodes); do
  $RUNTIME exec "${node}" mkdir -p "${REGISTRY_DIR}"
  cat <<EOF | $RUNTIME exec -i "${node}" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml"
[host."http://${reg_name}:5000"]
EOF
done

if [ "$($RUNTIME inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
  $RUNTIME network connect "kind" "${reg_name}"
fi

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

# Mirror calico image from quay to avoid to hit the pull rate limit from Docker Hub
CALICO_FILE=/tmp/calico.yaml
CALICO_VERSION=$(git ls-remote --tags https://github.com/projectcalico/api | grep "$(go list -m -json github.com/projectcalico/api | jq -r '.Version | split("-") | .[-1]')" | sed 's|.*refs/tags/||')
curl -Lo $CALICO_FILE "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
sed -i 's|docker.io/calico|quay.io/calico|g' $CALICO_FILE
kubectl apply -f $CALICO_FILE
