# Trusted Execution Cluster Operator (trusted-cluster-operator)

This repository contains a Kubernetes operator for managing Trusted Execution Clusters. The operator introduces a
`TrustedExecutionCluster` Custom Resource Definition (CRD) which allows users to declaratively manage the configuration
of a trusted execution cluster and Trustee server, a core component which handles the attestation process.

The operator watches for `TrustedExecutionCluster` resources and ensures that the necessary configurations for the Trustee
(such as KBS configuration, attestation policies, and resource policies) are correctly set up and maintained 
within the cluster.

## Repository Structure

-   `/api`: Defines the `TrustedExecutionCluster` Custom Resource Definition (CRD) and associated CRDs and RBAC definitions in Go. Also contains a program to generate a `TrustedExecutionCluster` CR and associated deployment.
-   `/operator`: Contains the source code for the Kubernetes operator itself.
-   `/register-server`: A server that provides Clevis PINs for key retrieval with random UUIDs.
-   `/compute-pcrs`: A program to compute PCR reference values using the [compute-pcrs library](https://github.com/trusted-execution-clusters/compute-pcrs) and insert them into a ConfigMap, run as a Job.
-   `/lib`: Shared Rust definitions, including translated CRDs
-   `/scripts`: Helper scripts for managing a local `kind` development cluster.
-   `/config`: The default output directory for generated manifests. This directory is not checked into source control.

## Getting Started

### Prerequisites

-   Rust toolchain
-   `podman` or `docker` (set `CONTAINER_CLI` and `RUNTIME` environment variables accordingly)
-   `kubectl`
-   `kind`
-   `operator-sdk` (refer to its official documentation for installation instructions)

### Quick Start

Create the cluster and deploy the operator.

Provide an address where the VM you will attest from can access the cluster.
When using a local kind & libvirt VM, this may be your gateway address (`default via …` in `ip route`) for user libvirt or bridge (`virbr0` in `ip route`) for system libvirt.

```bash
$ ip route
...
192.168.122.0/24 dev virbr0 proto kernel scope link src 192.168.122.1
...
$ ip=192.168.122.1
```

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
make REGISTRY=localhost:5000 manifests
make TRUSTEE_ADDR=$ip install
```

The KBS port will be forwarded to `8080` on your machine; the node register server to `8000`, where new Ignition configs are served at `/register`.

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
export TAG=0.1.0
export CONTAINER_CLI=docker # or podman
```
> **Note:** The `TAG` must be a valid semantic version (e.g., `0.1.0`). OLM does not support tags like `latest` for bundle versions.

**3. Build, Validate, and Push**

The `push-all` target builds all operator images, generates the bundle, builds the bundle image, and pushes everything to the specified `$REGISTRY`.

```bash
make push-all
```

**4. Deploy the Bundle**

Deploy the bundle to your cluster. We use `trusted-execution-clusters` as an example namespace.

```bash
kubectl create namespace trusted-execution-clusters || true
(cd /tmp && operator-sdk run bundle ${REGISTRY}/trusted-cluster-operator-bundle:${TAG} --namespace trusted-execution-clusters)
```

**5. Create the Custom Resource**

Once the operator is running, you need to create a `TrustedExecutionCluster` custom resource to make it functional.

First, you must update the example CR with the correct public address for the Trustee service, which must be accessible from your worker nodes or VMs.

```bash
# Determine an address reachable by the VMs (for libvirt, usually the bridge IP)
ip route | grep virbr0
# Example output:
# 192.168.122.0/24 dev virbr0 proto kernel scope link src 192.168.122.1
export TRUSTEE_ADDR=192.168.122.1

# Update the CR with the trustee address (yq is installed via `make build-tools`)
yq -i '.spec.publicTrusteeAddr = "'$TRUSTEE_ADDR':8080"' \
  config/deploy/trusted_execution_cluster_cr.yaml

# Apply the configured CRs
kubectl apply -f config/deploy/trusted_execution_cluster_cr.yaml
kubectl apply -f config/deploy/approved_image_cr.yaml
kubectl apply -f kind/kbs-forward.yaml
kubectl apply -f kind/register-forward.yaml
```

#### **Cleaning Up the Bundle Deployment**

To remove all resources deployed by the bundle, use the `cleanup` command with the operator's package name:

```bash
(cd /tmp && operator-sdk cleanup trusted-cluster-operator --namespace trusted-execution-clusters)
```

### Quick Start Cleanup

To clean up your environment after running the non-OLM `Quick Start` method, execute the following commands:
```bash
make cluster-cleanup
# Note: You must use the same RUNTIME environment variable for `cluster-down`
# that you used for `cluster-up`. For example:
# RUNTIME=docker make cluster-down
make cluster-down
make clean
```

## Licenses

See [LICENSES](LICENSES).
