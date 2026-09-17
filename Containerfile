# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
# SPDX-FileCopyrightText: Yair Podemsky <ypodemsk@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

ARG build_type=release
ARG build_target=operator
ARG deployment_base=quay.io/fedora/fedora-minimal:43

# Unified builder stage — compiles all binaries in a single cargo invocation.
FROM ghcr.io/trusted-execution-clusters/buildroot:fedora AS builder
LABEL project=trusted-cluster-operator
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
COPY kbs-event-proxy/Cargo.toml kbs-event-proxy/
COPY kbs-event-proxy/src/main.rs kbs-event-proxy/src/

RUN sed -i 's/members = .*/members = ["lib", "operator", "compute-pcrs", "register-server", "attestation-key-register", "kbs-event-proxy"]/' Cargo.toml && \
    sed -i '/\[dev-dependencies\]/,$d' operator/Cargo.toml && \
    sed -i '/\[dev-dependencies\]/,$d' register-server/Cargo.toml && \
    sed -i '/trusted-cluster-operator-test-utils/d' lib/Cargo.toml

RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    make crds-rs

# In debug builds, pre-build dependencies to avoid full rebuild on source changes.
RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    if [ "$build_type" = debug ]; then \
      cargo build -p operator -p compute-pcrs -p register-server -p attestation-key-register -p kbs-event-proxy; \
    fi

COPY operator/src operator/src
COPY compute-pcrs/src compute-pcrs/src
COPY register-server/src register-server/src
COPY attestation-key-register/src attestation-key-register/src
COPY kbs-event-proxy/src kbs-event-proxy/src

RUN --mount=type=cache,target=/build/target \
    --mount=type=cache,target=/usr/local/cargo/registry \
    release_flag="" && \
    if [ "$build_type" = release ]; then release_flag="--release"; fi && \
    cargo build \
      -p operator \
      -p compute-pcrs \
      -p register-server \
      -p attestation-key-register \
      -p kbs-event-proxy \
      $release_flag

RUN --mount=type=cache,target=/build/target \
    profile_dir="debug" && \
    if [ "$build_type" = release ]; then profile_dir="release"; fi && \
    mkdir -p /output && \
    cp /build/target/${profile_dir}/operator /output/ && \
    cp /build/target/${profile_dir}/compute-pcrs /output/ && \
    cp /build/target/${profile_dir}/register-server /output/ && \
    cp /build/target/${profile_dir}/attestation-key-register /output/ && \
    cp /build/target/${profile_dir}/kbs-event-proxy /output/

# Distribution stages
FROM ${deployment_base} AS operator
COPY --from=builder /output/operator /usr/bin
ENTRYPOINT ["/usr/bin/operator"]

FROM ${deployment_base} AS attestation-key-register
COPY --from=builder /output/attestation-key-register /usr/bin
EXPOSE 8001
ENTRYPOINT ["/usr/bin/attestation-key-register"]

FROM ${deployment_base} AS register-server
COPY --from=builder /output/register-server /usr/bin
EXPOSE 3030
ENTRYPOINT ["/usr/bin/register-server"]

FROM ${deployment_base} AS kbs-event-proxy
COPY --from=builder /output/kbs-event-proxy /usr/bin
EXPOSE 8080
ENTRYPOINT ["/usr/bin/kbs-event-proxy"]

FROM builder AS compute-pcrs-data
RUN rv_line=$(cargo metadata --format-version=1 | jq -r '.packages[] | select(.name == "reference-values") | .source') && \
    rv_repo=$(echo "$rv_line" | sed 's/^git+//;s/[?#].*//') && \
    rv_commit=$(echo "$rv_line" | sed 's/.*#//') && \
    git clone "$rv_repo" reference-values && \
    git -C reference-values checkout "$rv_commit"
RUN mkdir -p /output/reference-values && \
    mv /build/reference-values/efivars /output/reference-values/ && \
    mv /build/reference-values/mok-variables /output/reference-values/

FROM ${deployment_base} AS compute-pcrs
COPY --from=compute-pcrs-data /output/compute-pcrs /usr/bin
COPY --from=compute-pcrs-data /output/reference-values /reference-values
ENTRYPOINT ["/usr/bin/compute-pcrs"]

# Allow environments without --target support, which only read the last stage, to set the stage through the build arg
FROM ${build_target} AS final
