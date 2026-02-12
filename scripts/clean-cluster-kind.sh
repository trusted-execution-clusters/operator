#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

set -x

. scripts/common.sh

kubectl delete trustedexecutionclusters trusted-execution-cluster -n trusted-execution-clusters || true
kubectl delete deploy trusted-cluster-operator -n trusted-execution-clusters || true
