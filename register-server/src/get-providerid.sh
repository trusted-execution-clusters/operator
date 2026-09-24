#!/bin/bash
# SPDX-FileCopyrightText: Roy Kaufman <rkaufman@redhat.com>
#
# SPDX-License-Identifier: MIT


set -euo pipefail


UUID="<YOUR_UUID>"
BIND_URL="<YOUR_BIND_SERVER_URL>"
# PEM of the register-server CA, or empty when the server is plain HTTP.
CA_CERT="<YOUR_CA_CERT>"

IMDS_URL="http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"

# Azure Instance Metadata Service returns the ARM resource ID of this VM.
PROVIDER_ID="azure://$(curl -fsS --retry 5 --retry-connrefused --retry-delay 5 -H 'Metadata: true' "$IMDS_URL" | jq -r .resourceId)"

# TODO: Fall back to AWS and GCP.
# AWS: aws:///<availability-zone>/<instance-id>
# AWS_BASE="http://169.254.169.254/latest"
# AWS_AZ="$(curl -fsS "$AWS_BASE/meta-data/placement/availability-zone")"
# AWS_INSTANCE_ID="$(curl -fsS "$AWS_BASE/meta-data/instance-id")"
# PROVIDER_ID="aws:///$AWS_AZ/$AWS_INSTANCE_ID"
#
# GCP: gce://<project>/<zone>/<instance-name>
# GCP_BASE="http://metadata.google.internal/computeMetadata/v1"
# GCP_PROJECT="$(curl -fsS -H 'Metadata-Flavor: Google' "$GCP_BASE/project/project-id")"
# GCP_ZONE="$(curl -fsS -H 'Metadata-Flavor: Google' "$GCP_BASE/instance/zone")"
# GCP_ZONE="${GCP_ZONE##*/}"
# GCP_NAME="$(curl -fsS -H 'Metadata-Flavor: Google' "$GCP_BASE/instance/name")"
# PROVIDER_ID="gce://$GCP_PROJECT/$GCP_ZONE/$GCP_NAME"


curl_args=(-fsS -X PUT -H 'Content-Type: application/json'
	--retry 5 --retry-connrefused --retry-delay 5)

# Pin the register-server CA so curl can verify the HTTPS certificate.
if [ -n "$CA_CERT" ]; then
	ca_file="$(mktemp)"
	trap 'rm -f "$ca_file"' EXIT
	printf '%s' "$CA_CERT" >"$ca_file"
	curl_args+=(--cacert "$ca_file")
fi

curl "${curl_args[@]}" \
	-d "$(jq -nc --arg uuid "$UUID" --arg providerID "$PROVIDER_ID" '{uuid: $uuid, providerID: $providerID}')" \
	"$BIND_URL"

echo "UUID=$UUID providerID=$PROVIDER_ID"
