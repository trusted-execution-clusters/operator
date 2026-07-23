# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
# SPDX-FileCopyrightText: Yair Podemsky <ypodemsk@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

ARG build_type=release

# Unified builder stage — compiles all binaries in a single cargo invocation.
FROM ghcr.io/trusted-execution-clusters/buildroot:fedora AS builder
ARG build_type
WORKDIR /build

COPY Makefile Cargo.toml Cargo.lock go.mod go.sum .
COPY api api
COPY lib lib

# Copy Cargo.toml and lib.rs stubs for dependency pre-build caching.
COPY operator/Cargo.toml operator/
COPY operator/src/lib.rs operator/src/
COPY compute-pcrs/Cargo.toml compute-pcrs/
COPY compute-pcrs/src/lib.rs compute-pcrs/src/
COPY register-server/Cargo.toml register-server/
COPY register-server/src/lib.rs register-server/src/
COPY attestation-key-register/Cargo.toml attestation-key-register/
COPY attestation-key-register/src/lib.rs attestation-key-register/src/

RUN sed -i 's/members = .*/members = ["lib", "operator", "compute-pcrs", "register-server", "attestation-key-register"]/' Cargo.toml && \
    sed -i '/\[dev-dependencies\]/,$d' operator/Cargo.toml && \
    sed -i '/\[dev-dependencies\]/,$d' register-server/Cargo.toml && \
    sed -i '/trusted-cluster-operator-test-utils/d' lib/Cargo.toml && \
    git clone --depth 1 https://github.com/trusted-execution-clusters/reference-values && \
    make crds-rs

# In debug builds, pre-build dependencies to avoid full rebuild on source changes.
RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    if [ "$build_type" = debug ]; then \
      cargo build -p operator -p compute-pcrs -p register-server -p attestation-key-register; \
    fi

COPY operator/src operator/src
COPY compute-pcrs/src compute-pcrs/src
COPY register-server/src register-server/src
COPY attestation-key-register/src attestation-key-register/src

RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    release_flag="" && \
    profile_dir="debug" && \
    if [ "$build_type" = release ]; then release_flag="--release"; profile_dir="release"; fi && \
    cargo build \
      -p operator \
      -p compute-pcrs \
      -p register-server \
      -p attestation-key-register \
      $release_flag && \
    mkdir -p /output && \
    cp /build/target/${profile_dir}/operator /output/ && \
    cp /build/target/${profile_dir}/compute-pcrs /output/ && \
    cp /build/target/${profile_dir}/register-server /output/ && \
    cp /build/target/${profile_dir}/attestation-key-register /output/ && \
    mkdir -p /output/reference-values && \
    cp -r /build/reference-values/efivars /output/reference-values/ && \
    cp -r /build/reference-values/mok-variables /output/reference-values/

# Distribution stages
FROM quay.io/fedora/fedora:43 AS operator
COPY --from=builder /output/operator /usr/bin

FROM quay.io/fedora/fedora:43 AS compute-pcrs
COPY --from=builder /output/compute-pcrs /usr/bin
COPY --from=builder /output/reference-values /reference-values

FROM quay.io/fedora/fedora:43 AS register-server
COPY --from=builder /output/register-server /usr/bin
EXPOSE 3030
ENTRYPOINT ["/usr/bin/register-server"]

FROM quay.io/fedora/fedora:43 AS attestation-key-register
COPY --from=builder /output/attestation-key-register /usr/bin
EXPOSE 8001
ENTRYPOINT ["/usr/bin/attestation-key-register"]
