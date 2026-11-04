# Getting started guide

This guide provides several sections and best-practises for developers to get started working on the Trusted Execution Clusters (TEC) operator.

## Kuberetes

In order to be able to use and install the TEC operator, you require a working Kubernetes cluster.

For development, we suggest using [kind](https://github.com/kubernetes-sigs/kind) which creates a containerized ready one-node cluster.

Kind can be used with `docker` or `podman`. Although, we set `podman` as default, right now there are some networking issues, therefore, the suggested runtime to use is `docker` at the moment. The runtime can be configured with:
```console
export RUNTIME=docker
```

The `CONTAINER_CLI` env var will used for building and pushing. If you require a non-Podman engine for building and pushing images, you can override it with the `$CONTAINER_CLI` variable.
```console
export CONTAINER_CLI=docker
```

In order to interact with the cluster, `kubectl` is required.
```console
dnf install -y kubectl
```

Our kind cluster configuration is available under the `kind` directory and it uses the script `scripts/create-cluster-kind.sh`. 
Make sure any previously installed cluster is deleted before attempting to install a new one:
```console
make cluster-down
```

The cluster can be simply created by running:
```console
make cluster-up
```
The kind cluster exposes 3 ports on the host:
+ port 8080: for the KBS (Key Broker Server)
+ port 8000: for the machine registration
+ port 8001: for the trusted attestation key registration

These ports can be used in order to access the endpoint if you are creating the VMs externally to the cluster, for example via Libvirt.

Alongside the kind cluster, a registry is launcher. The registry will serve on port 5000, so users can tag and push images to the local registry at `localhost:5000`. Also cluster containers can be deployed using the `localhost:5000` registry.

This is, for example, used for the local build when you don't want to use an external registry.

## Build and install the operator

### Required tools

To build the operator the following tools are needed:

* `make`: for the general set of build tools
* `docker`/`podman` - for building container images
* `cargo`, `rustfmt` - if you want to compile the code locally and for running the linter
* `golang` - for the Kubernetes Custom Resource Definitions (CRDs).

### Build process

The images of the project can be built in a container with:
```console
make image
```
This operations build 4 images:
+ the operator
+ the registration server for the machine
+ the registration server for the attestation keys
+ the computation for the reference values

Afterwards, the images can be published in the local registry:
```console
export REGISTRY=localhost:5000/trusted-execution-clusters
make push
```

The operator needs to be configured with the networking setup where the attestation server and key register will be externally reachable by the machines for the attestation. This can be configured during the installation of the operator by setting the env variable `TRUSTEE_ADDR` and `AK_REGISTRATION_ADDR` respectively.

Example:
```console
export TRUSTEE_ADDR=kbs-service.trusted-execution-clusters.svc.cluster.local
export AK_REGISTRATION_ADDR=attestation-key-register.trusted-execution-clusters.svc.cluster.local

```

Finally, the operator can be installed with:
### Install the operator

The cluster must have cert-manager and its CRDs installed. `make cluster-up` installs these for the local kind cluster.
The installation also uses the Rust toolchain and native build dependencies (`openssl-devel` and `gcc-c++` on Fedora).

From the repository root, install into a namespace of your choice:

```console
make install-operator NAMESPACE=trusted-execution-clusters
```

`make install-operator` uses the integration-test setup to generate manifests, create certificates and Secrets,
apply CRDs and RBAC, and deploy the operator, a `TrustedExecutionCluster`, and an `ApprovedImage`.
It waits for the operator and its services to become ready, the `ApprovedImage` to become committed,
and the `TrustedExecutionCluster` installation to complete. The namespace is kept so you can inspect and use the installation.

`NAMESPACE` sets the exact namespace name and takes precedence over `TEST_NAMESPACE_PREFIX`.
The namespace must not already exist. If `NAMESPACE` is unset or empty, setup creates a unique namespace
named `test-<random-suffix>`. You can add a prefix to that generated name instead:

```console
make install-operator TEST_NAMESPACE_PREFIX=my-dev-
```

Use an exact namespace for a single installation; leave `NAMESPACE` unset when running multiple integration tests
so each test gets its own namespace.

The installation output includes a cleanup command. For the explicit namespace above, run:

```console
kubectl delete namespace trusted-execution-clusters
```

Further customization of the project can be controlled with the following env variables:
+ NAMESPACE: sets the exact namespace for `make install-operator`
+ TEST_NAMESPACE_PREFIX: adds a prefix to generated namespace names when `NAMESPACE` is unset or empty
+ PLATFORM: configures the platform used during installation (defaults to `kind`; `kind_public` exposes services through the kind host ports)
+ INTEGRATION_TEST_THREADS: how many integration tests are run in parallel
+ REGISTRY: the registry used to publish the images
+ TAG: the tag used for the images when built and published
+ APPROVED_IMAGE: the image whose reference values are computed during installation (defaults to the image in the `Makefile`)
+ CONTAINER_CLI: runtime used to build container images (`podman` or `docker`)
+ RUNTIME: runtime used for creating the kind cluster (`podman` or `docker`)
+ PUSH_FLAGS: additional flags to be used with `CONTAINER_CLI` when pushing images


## Testing and exploring using KubeVirt VMs

[KubeVirt](https://github.com/kubevirt/kubevirt) is a framework which enables to deploy Virtual Machines in a Kubernetes cluster. We use KubeVirt VMs in order to test the operator functionalities in the integration tests.

There is also an example available at in the [examples](https://github.com/trusted-execution-clusters/operator/tree/main/examples) directory.

A VM can be created by:  
```console
examples/create-ignition-secret.sh examples/ignition-coreos.json coreos-ignition-secret
kubectl apply -f examples/vm-coreos-ign.yaml 
```
Then, the serial console of the VM can be accessed with [`virtctl`](https://kubevirt.io/user-guide/user_workloads/virtctl_client_tool/).
```console
virtctl console <vm-name>
```

## Debugging attestation failures

On the node, if the clevis pin hasn't be configured with an infinity number of retries, you will finally get a rescue shell. In there you can check the clevis pin and trustee attester log:
```console
journalctl -u ignition-disks.service
```

It is very practical if you can test the attestation manually by calling the `trustee-attester`
```console
trustee-attester --url <url> get-resource --path <path>
```
The `url` and the `path` can be found in the clevis pin configuration, for example, visible in the ignition-disks service log.

The main reasons why the VM isn't properly booting because of the attestation can be due to some networking misconfigurations or the actual attestation process is failing. 

The networking can be easily debugged with `curl` or the manual testing with the`trustee-attester`.

The attestation failing can be debugged by verifying the deployment of trustee.
```console
kubectl logs -n trusted-execution-clusters <trustee-deplyoment>
```

In the logs, trustee prints the content of the TPM PCR registers. They need to match with the reference values present in the the trustee pod.
