# Trusted Execution Cluster Operator (trusted-cluster-operator)

This repository contains a Kubernetes operator for managing Trusted Execution Clusters. The operator introduces a
`TrustedExecutionCluster` Custom Resource Definition (CRD) which allows users to declaratively manage the configuration
of a trusted execution cluster and Trustee server, a core component which handles the attestation process.

The operator watches for `TrustedExecutionCluster` resources and ensures that the necessary configurations for the Trustee
(such as KBS configuration, attestation policies, and resource policies) are correctly set up and maintained 
within the cluster.

## Repository Structure

The operator relies on Rust crates for its functionality.

### Operator components

-   `/operator`: Contains the source code for the Kubernetes operator itself.
-   `/register-server`: A server that provides Clevis PINs for key retrieval with random UUIDs.
-   `/attestation-key-register`: A server that accepts attestation key registrations from VMs and creates AttestationKey resources.
-   `/compute-pcrs`: A program to compute PCR reference values using the [compute-pcrs library](https://github.com/trusted-execution-clusters/compute-pcrs) and update the related ApprovedImage status with the computed pcr values.

### Other crates

-   `/lib`: Shared Rust definitions, including translated CRDs
-   `/tests`: Non-unit tests; most rely on a cluster being available. Many of those also rely on a virtualization backend.
-   `/test_utils`: Operator setup helpers and virtualization backends

### Other components

-   `/docs`, `/examples`
-   `/api`: Defines the `TrustedExecutionCluster` Custom Resource Definition (CRD) and associated CRDs and RBAC definitions in Go. Also contains a program to generate a `TrustedExecutionCluster` CR and associated deployment.
-   `/scripts`: Helper scripts for managing a local `kind` development cluster.
-   `/config`: The default output directory for generated manifests. This directory is not checked into source control.
-   `/tools`: Tracking tool versions for autoupdates
-   `/must-gather`: for OpenShift CI

## Getting Started

### Prerequisites

-   Rust toolchain
-   `podman` or `docker` (set `CONTAINER_CLI` and `RUNTIME` environment variables accordingly)
-   `kubectl`
-   `kind`
-   `operator-sdk` (refer to its official documentation for installation instructions)

### Quick Start

Create the cluster and deploy the operator.

To use Docker:
```bash
export CONTAINER_CLI=docker
export RUNTIME=docker
```

To use Podman (these exports can be omitted as Podman is the default):
```bash
export CONTAINER_CLI=podman
export RUNTIME=podman
```

Then run the following commands:
```bash
make cluster-up
make REGISTRY=localhost:5000 PUSH_FLAGS="--tls-verify=false" push # optional: use BUILD_TYPE=debug
make REGISTRY=localhost:5000 install-operator NAMESPACE=trusted-execution-clusters
```

See the [getting-started guide](docs/usage/getting-started-guide.md#install-the-operator) for installation prerequisites,
namespace selection, and cleanup.


### Apply CRDs

To install or update CRDs after changing the API definitions, run:

```bash
make apply-crds
```

This target runs `make generate`, then applies all CRDs in `config/crd`, including the generated cert-manager CRDs,
to the current `kubectl` context.


### Install using the integration test setup

```bash
make install-operator
```

This target deploys the operator, a `TrustedExecutionCluster`, and an `ApprovedImage` in a new test namespace,
then waits for installation to complete. It requires cert-manager and its CRDs to be installed.
The namespace is kept for inspection; the output includes a cleanup command.
See the [test setup documentation](tests/README.md#install-the-operator-with-the-integration-test-setup) for details.

### Test

Run a VM as described in the
[investigations](https://github.com/trusted-execution-clusters/investigations?tab=readme-ov-file#example-with-the-trusted-execution-clusters-operator-and-a-local-vm)
repository.

### OLM Bundle Workflow

This operator can be packaged and deployed as an OLM bundle. This workflow supports deploying to any Kubernetes cluster with access to a container registry.

**1. Prerequisites**

For local development (kind):
```bash
# Set RUNTIME=docker if using Docker instead of Podman
make cluster-up
# Login to your remote container registry (e.g., quay.io)
docker login quay.io
# Install OLM on your target cluster
(cd /tmp && operator-sdk olm install)
```

**2. Set Environment Variables**

Define the container registry, image tag, and CLI.

```bash
export REGISTRY=quay.io/<your-username>
export TAG=v0.2.3
export CONTAINER_CLI=docker # or podman
```
> **Note:** The `TAG` must be a valid semantic version (e.g., `v0.2.3`). OLM does not support tags like `latest` for bundle versions. Use an unreleased version tag to build with the latest code.

**3. Build, Validate, and Push**

The `push-all` target builds all operator images, generates the bundle, builds the bundle image, and pushes everything to the specified `$REGISTRY`.

```bash
make push-all
```

**4. Deploy the Bundle**

Deploy the bundle to your cluster. You can install it in any namespace.

```bash
# Example: Install in namespace 'trusted-execution-clusters'
kubectl create namespace trusted-execution-clusters || true
(cd /tmp && operator-sdk run bundle ${REGISTRY}/trusted-cluster-operator-bundle:${TAG} --namespace trusted-execution-clusters)
```

> **OpenShift Users:** After deploying the bundle, you need to manually create the SecurityContextConstraints (SCC). Apply the SCC template with your installation namespace:
> ```bash
> sed 's/<NAMESPACE>/trusted-execution-clusters/g' config/openshift/scc.yaml | kubectl apply -f -
> ```

**5. Create the Custom Resource**

Once the operator is running, you need to create a `TrustedExecutionCluster` custom resource to make it functional.

First, you must update the example CR with the correct public address for the Trustee service, which must be accessible from your worker nodes or VMs.

> **Note:** The image specifications (`trusteeImage`, `pcrsComputeImage`, `registerServerImage`, `attestationKeyRegisterImage`) are optional. If not specified, the operator will use default images. Only specify them if you need to use custom or specific versions.

```bash
# For KubeVirt VMs running in the cluster, use the service DNS name, for example:
export TRUSTEE_ADDR=kbs-service.trusted-execution-clusters.svc.cluster.local

# Update the CR with the trustee address (yq is installed via `make build-tools`)
yq -i '.spec.publicTrusteeAddr = "'$TRUSTEE_ADDR'" | .spec.registerServerPort = 8000 | .spec.trusteeKbsPort = 8080' \
  config/deploy/trusted_execution_cluster_cr.yaml

# Apply the configured CRs
kubectl apply -f config/deploy/trusted_execution_cluster_cr.yaml
kubectl apply -f config/deploy/approved_image_cr.yaml
```

#### **Cleaning Up the Bundle Deployment**

To remove all resources deployed by the bundle, use the `cleanup` command with the operator's package name:

```bash
(cd /tmp && operator-sdk cleanup trusted-cluster-operator --namespace trusted-execution-clusters)
```

### Quick Start Cleanup

To clean up your environment after running the non-OLM `Quick Start` method, execute the following commands:
```bash
kubectl delete namespace trusted-execution-clusters
# Note: You must use the same RUNTIME environment variable for `cluster-down`
# that you used for `cluster-up`. For example:
# RUNTIME=docker make cluster-down
make cluster-down
make clean
```

## Licenses

See [LICENSES](LICENSES).
