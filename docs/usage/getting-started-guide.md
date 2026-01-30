# Getting started guide

This guide provides several sections and best-practises for developers to get started working on the Trusted Execution Clusters (TEC) operator.

## Kuberetes cluster setup

In order to be able to use and install the TEC operator, you require a working Kubernetes cluster.

For development, we suggest using [kind](https://github.com/kubernetes-sigs/kind) which creates a containerized ready one-node cluster.

Kind can be used with `docker`or `podman`. Although, we set `podman` as default, right now there are some networking issues, therefore, the suggested runtime to use is `docker` at the moment. The runtime can be configured with:
```console
export RUNTIME=docker
```

Our kind cluster configuration is available under the `kind` directory and it uses the script `scripts/create-cluster-kind.sh`. The cluster can be simply created by running:
```console
make cluster-up
```
The kind cluster exposes 3 ports on the host:
+ port 8080: for the KBS (Key Broker Server)
+ port 8000: for the machine registration
+ port 8001: for the trusted attestation key

These ports can be used in order to access the endpoint if you are creating the VMs externally to the cluster, for example via Libvirt.

Alongside the kind cluster, a registry is running and can be accessed with tagging, pushing and pulling the images using `locahost:5000` from and to the host and the cluster as well.

This is, for example, used for the local build when you don't want to use an external registry.

## Build and install the operator

The images of the project can be built in a container with:
```console
make image
```
This operations build 4 images:
+ the operator
+ the registration server for the machine
+ the registration server for the attestation keys
+ the computation for the reference value

Afterwards, the images can be published in the local registry:
```console
export REGISTRY=localhost:5000/trusted-execution-clusters
make push
```

Before installing the operator, the manifests of the operator needs to be generated
```console
make manifests
```

The operator needs to be configured with the networking setup where the attestation server will be externally reachable by the machines for the attestation. This can be configured during the installation of the operator by setting the env variable `TRUSTEE_ADDR`.

Example:
```console
export TRUSTEE_ADDR=kbs-service.trusted-execution-clusters.svc.cluster.local
``` 

Finally, the operator can be installed with:
```console
make install
```

Further customization of the project can be controlled with the following env variables:
+ NAMESPACE: sets the namespace where the operator will be deplyoed
+ PLATFORM: use during the installation to configure the platform where the operator will be deployed (`kind` or `openshift`)
+ INTEGRATION_TEST_THREADS: how many integration tests are run in parallel
+ REGISTRY: the registry used to publish the images
+ TAG: the tag used for the images when built and published
+ CLI_RUNTIME: runtime used for build the container images (`podman` or `docker`)
+ RUNTIME: runtime used for creating the kind cluster (`podman` or `docker`)
+ PUSH_FLAGS: additional flag to be used with the CLI_RUNTIME


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

On the node, if the clevis pin hasn't be configured with an infinity retrial, you will finally get a rescue shell. In there you can check the clevis pin and trustee attester log:
```console
journalctl -u ignition-disks.service
```

It is very practical if you can test the attestation manually by calling the `trustee-attester`
```console
trustee-attester --url <url> get-resource --path <path>
```
The `url` and the `path` can be found in the clevis pin configuration, for example, visible in the ignition-disks service log.

The main reasons why the VM isn't properly booting because of the attestation can be due to some networking misconfigurations or the actual attestation process is failing. 

The networking can be easily debugged with `curl` or the manual testing with the`trutee-attester`.

The attestation failing can be debugged by verifying the deployment of trustee.
```console
kubectl logs -n trusted-execution-clusters <trustee-deplyoment>
```

In the logs, trustee prints the content of the TPM PCR registers. They need to match with the reference values present in the configmap `trustee-data` under `reference-values.json`.
