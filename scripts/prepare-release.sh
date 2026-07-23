#!/usr/bin/env bash

# SPDX-FileCopyrightText: Chirag Rao <crao@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

# How to run (example):
# ./scripts/prepare-release.sh 0.2.1

# Steps followed:
# 1. Validate passed params.
# 2. Update [package] version in all related Cargo.toml files in our owned workspaces.
# 3. Update CSV template with new version.
# 4. Update README with new version.
# 5. Refresh Cargo.lock for workspace package versions.

set -euo pipefail

DRY_RUN=false
VERSION=""


function usage() {
    echo "Usage: $0 [--dry-run] <VERSION>"
    echo "  VERSION must be bare semver (e.g. 0.2.1), without a leading 'v'."
    exit 1;
}

# Validate passed params.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; usage ;;
        *) VERSION="$1"; shift ;;
    esac
done

# Print usage and exit if VERSION is not set.
[[ -z "$VERSION" ]] && usage

# Reject a leading 'v' — image tags add it later.
if [[ "$VERSION" == v* ]]; then
    echo "ERROR: VERSION must not start with 'v'. Got: $VERSION"
    exit 1
fi

# Require MAJOR.MINOR.PATCH (semver).
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: VERSION must match MAJOR.MINOR.PATCH. Got: $VERSION"
    exit 1
fi

# Get the project root directory.
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Gets only local workspace packages, not dependencies. 
mapfile -t CRATES < <(
    cargo metadata --no-deps --format-version=1 \
        | jq -r --arg root "$PROJECT_ROOT/" \
            '.packages[] | select(.source == null) | .manifest_path | sub($root; "")'
)

if [[ ${#CRATES[@]} -eq 0 ]]; then
    echo "ERROR: no workspace member Cargo.toml files found via cargo metadata" >&2
    exit 1
fi

echo "=> Updating [package] version (crate own version only) to $VERSION ..."
for file in "${CRATES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "WARN: $file not found, skipping"
        continue
    fi
    if $DRY_RUN; then
        echo "[dry-run] set [package].version in $file"
    else
        # Only rewrite version under [package]; stop at the next [section].
        sed -i '/^\[package\]/,/^\[/{s/^version = ".*"/version = "'"$VERSION"'"/}' "$file"
    fi
done

CSV="bundle/static/manifests/trusted-cluster-operator.clusterserviceversion.yaml"
echo "=> Updating CSV template: $CSV ..."
if $DRY_RUN; then
    echo "[dry-run] Update image tags, metadata.name, spec.version in $CSV"
else
    # Update metadata.name
    sed -i 's/^\(  name: trusted-cluster-operator\.\)v[0-9]\+\.[0-9]\+\.[0-9]\+/\1v'"$VERSION"'/' "$CSV"
    # Update spec.version
    sed -i 's/^\(  version: \)[0-9]\+\.[0-9]\+\.[0-9]\+/\1'"$VERSION"'/' "$CSV"
    # Update containerImage annotation (TEC operator image)
    sed -i 's|\(containerImage: "quay.io/trusted-execution-clusters/trusted-cluster-operator:\)[^"]*|\1v'"$VERSION"'|' "$CSV"
    # Update TEC component image tags (but NOT trustee/key-broker-service)
    # Matches image refs with :0.x.y or :v0.x.y for TEC images, replaces with :v$VERSION
    sed -i \
        -e 's|\(quay.io/trusted-execution-clusters/trusted-cluster-operator:\)v\?[0-9]\+\.[0-9]\+\.[0-9]\+|\1v'"$VERSION"'|g' \
        -e 's|\(quay.io/trusted-execution-clusters/compute-pcrs:\)v\?[0-9]\+\.[0-9]\+\.[0-9]\+|\1v'"$VERSION"'|g' \
        -e 's|\(quay.io/trusted-execution-clusters/registration-server:\)v\?[0-9]\+\.[0-9]\+\.[0-9]\+|\1v'"$VERSION"'|g' \
        -e 's|\(quay.io/trusted-execution-clusters/attestation-key-register:\)v\?[0-9]\+\.[0-9]\+\.[0-9]\+|\1v'"$VERSION"'|g' \
        "$CSV"
fi

# Potential drift if the README TAG example line changes shape.
README="README.md"
echo "=> Updating $README ..."
if $DRY_RUN; then
    echo "[dry-run] Update TAG export and OLM note in $README"
else
    sed -i 's/^\(export TAG=\).*/\1v'"$VERSION"'/' "$README"
    # Update the Note about TAG/OLM
    sed -i '/^> \*\*Note:\*\*/c\> **Note:** The `TAG` is the image tag (e.g., `v'"$VERSION"'`). OLM requires bare semver for bundle versions; the Makefile derives `OLM_VERSION` by stripping a leading `v` from `TAG`.' "$README"
fi

echo "=> Refreshing Cargo.lock for workspace package versions ..."
if $DRY_RUN; then
    echo "[dry-run] cargo metadata --format-version=1 (syncs Cargo.lock without upgrading deps)"
else
    # Sync package versions into Cargo.lock without upgrading third-party deps.
    cargo metadata --format-version=1 >/dev/null
fi

echo ""
echo "=== prepare-release $VERSION complete ==="
echo "Files updated:"
for file in "${CRATES[@]}"; do
    echo "  - $file"
done
echo "  - $CSV"
echo "  - $README"
echo "  - Cargo.lock"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Commit: git commit -am 'Release $VERSION'"
echo "  3. Tag: git tag $VERSION"
echo "  4. Push: git push origin main $VERSION"
