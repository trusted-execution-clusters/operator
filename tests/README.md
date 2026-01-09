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
