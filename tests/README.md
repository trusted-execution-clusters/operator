# Integration tests

The integration tests evaluate if the operator is functioning correctly. Each integration tests is deployed in a new
namespace in a way to guarantee the isolation of a test from the other, and to be able to run them in parallel.
The operator is installed in each namespace before running the actual tests with the `setup` function.
Upon a successful test, the namespace is cleaned up, otherwise it is kept for inspecting the state.

## Setup the integration tests locally
The tests use [`virtctl`](https://kubevirt.io/user-guide/user_workloads/virtctl_client_tool/) in order to interact with
VM, like getting the serial console and verifying that the guest has correctly booted by ssh-ing into it.

N.B KubeVirt requires the cluster to be run as a privileged container on the host in order to handle the devices. Therefore, for now, we have moved to Docker with kind in order to generate the cluster. In the future, we might be able to move to rootful podman.

Run the tests locally with kind:
```bash
export RUNTIME=docker
make cluster-up
export REGISTRY=localhost:5000/trusted-execution-clusters
make push
make install-kubevirt
# Set $INTEGRATION_TEST_THREADS to multi-thread (>4G memory per test)
make integration-tests
```

Each test can also be run independently using cargo test. Example:
```bash
$ cargo test test_trusted_execution_cluster_uninstall  -- --no-capture
```

## Run integration tests distributedly

When running integration tests elsewhere than on a local Kind cluster, set `$PLATFORM` to something else than `kind`.
Take into consideration:

- how VMs you are attesting can connect to services like Trustee
- how container images can be made available to the cluster

For enabling connection, you can export `$CLUSTER_URL`.
On OpenShift, you can instead export `PLATFORM=openshift` and the integration tests will use `oc expose` to expose services automatically.

For container images, you can export `REGISTRY` to something non-local, e.g. something public like quay.io.
On OpenShift, you can also use the internal registry:

```bash
# Define a namespace to push images to. Here, we name it after the user itself.
NAMESPACE=$(oc whoami)
oc create ns $NAMESPACE
HOST=$(oc get route default-route -n openshift-image-registry --template='{{ .spec.host }}')
podman login $HOST -u $(oc whoami) -p $(oc whoami -t)
export REGISTRY=$HOST/$NAMESPACE
make push
# Export REGISTRY to the internal URL
export REGISTRY=image-registry.openshift-image-registry.svc:5000/$NAMESPACE
```

### Run integration tests on Azure

Like the KubeVirt tests, the Azure integration tests create CoreOS VMs that retrieve a disk encryption key from Trustee, but do not execute a cluster join.
They rely on real [Azure Confidential VMs](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview) and Trustee's az-snp-vtpm attester.

#### Preparing an image

The image to boot the VM from must reside in a _storage container_ inside a _storage account_ and be referenced to from a _compute gallery_, all of which exist in a _resource group_.
This guide assumes that you have created the Azure resources in italics, and that you are logged in with the Azure CLI.

Create a CoreOS Azure image VHD, e.g. as per the [investigations repository](https://github.com/trusted-execution-clusters/investigations), **without the `tpm-attester` feature** in its trustee-attester until [trustee-gc#1277](https://github.com/confidential-containers/guest-components/issues/1277) is resolved.
Upload this blob and create an image definition and version based on it:

```bash
# Export $AZURE_SUBSCRIPTION_ID
# Set $resource_group, $storage_account, $storage_container, $compute_gallery
# Set $image, e.g. fedora-coreos-<version>-azure.x86_64.vhd
# Set image definition name, e.g. image_definition=fcos-cvm, and image version, e.g. image_version=0.1.0

# Retrieve connection string & storage account ID
cs=$(az storage account show-connection-string -g $resource_group -n $storage_account | jq -r .connectionString)
# Upload blob. We keep the file name here, but you can set the blob name in Azure
# to something else by changing the argument to -n.
az storage blob upload --connection-string $cs -c $storage_container -f $image -n $image
# Create image definition
az sig image-definition create -g $resource_group -r $compute_gallery -i $image_definition \
  --publisher example --offer example --sku standard \
  --features SecurityType=ConfidentialVmSupported --os-type Linux --hyper-v-generation V2
# Create image version. Adapt the name of the blob accordingly if you changed it above.
az sig image-version create -g $resource_group -r $compute_gallery -i $image_definition -e $image_version \
  --os-vhd-storage-account /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Storage/storageAccounts/$storage_account \
  --os-vhd-uri https://$storage_account.blob.core.windows.net/$storage_container/$image

# Set $TEST_IMAGE for the test
export TEST_IMAGE=/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Compute/galleries/$compute_gallery/images/$image_definition/versions/$image_version
```

#### Running the tests

To avoid confusion on shared subscriptions and/or clusters, you can export `TEST_NAMESPACE_PREFIX` and the created namespaces and resource groups will bear that prefix.

```bash
# Export $AZURE_SUBSCRIPTION_ID, $TEST_IMAGE as above
# Set VIRT_PROVIDER
export VIRT_PROVIDER=azure
# Run tests, or run individual tests as described above
make integration-tests
```
