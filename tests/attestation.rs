// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use trusted_cluster_operator_test_utils::*;

cfg_if::cfg_if! {
if #[cfg(feature = "virtualization")] {
use anyhow::Result;
use k8s_openapi::api::apps::v1::Deployment;
use kube::Api;
use trusted_cluster_operator_lib::Machine;
use trusted_cluster_operator_test_utils::virt::{self, VmBackend};

const ENCRYPTED_ROOT_ASSERT: &str = "should have an encrypted root device (attestation failed)";
const ENCRYPTED_ROOT_WARN: &str = "Backend reports that Machine IDs cannot be correlated to IP \
                                   addresses with this VIRT_PROVIDER (e.g. because of NAT). Disk \
                                   encryption test will only verify that the disk is encrypted, \
                                   not that it is encrypted with the expected key.";

struct SingleAttestationContext {
    root_key: Option<Vec<u8>>,
    backend: Box<dyn VmBackend>,
}

impl SingleAttestationContext {
    async fn verify_encrypted_root(&self) -> Result<bool> {
        self.backend.verify_encrypted_root(self.root_key.as_deref()).await
    }

    async fn cleanup(self) -> Result<()> {
        self.backend.cleanup().await
    }
}

impl SingleAttestationContext {
    async fn new(vm_name: &str, test_ctx: &TestContext) -> Result<Self> {
        let client = test_ctx.client();
        let namespace = test_ctx.namespace();
        let backend = virt::create_backend(client.clone(), namespace, vm_name)?;

        test_ctx.info(format!("Creating VM: {}", vm_name));
        backend.create_vm().await?;

        test_ctx.info(format!("Waiting for VM {} to reach Running state", vm_name));
        backend.wait_for_running(600).await?;
        test_ctx.info(format!("VM {} is Running", vm_name));

        test_ctx.info(format!("Waiting for SSH access to VM {}", vm_name));
        backend.wait_for_vm_ssh_ready(600).await?;
        test_ctx.info("SSH access is ready");

        let root_key = backend.get_root_key().await?;
        if root_key.is_none() {
            test_ctx.warn(ENCRYPTED_ROOT_WARN);
        }
        Ok(Self { root_key, backend })
    }
}

}
}

virt_test! {
async fn test_attestation() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let vm_name = "test-coreos-vm";
    let att_ctx = SingleAttestationContext::new(vm_name, &test_ctx).await?;

    test_ctx.info("Verifying encrypted root device");
    let has_encrypted_root = att_ctx.verify_encrypted_root().await?;

    assert!(has_encrypted_root, "VM {ENCRYPTED_ROOT_ASSERT}");
    test_ctx.info("Attestation successful: encrypted root device verified");
    att_ctx.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}

virt_test! {
async fn test_parallel_vm_attestation() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();
    test_ctx.info("Testing parallel VM attestation - launching 2 VMs simultaneously");

    // Launch both VMs in parallel
    let vm1_name = "test-coreos-vm1";
    let vm2_name = "test-coreos-vm2";
    let backend1 = virt::create_backend(client.clone(), namespace, vm1_name)?;
    let backend2 = virt::create_backend(client.clone(), namespace, vm2_name)?;

    test_ctx.info("Creating VM1 and VM2 in parallel");
    let (vm1_result, vm2_result) = tokio::join!(backend1.create_vm(), backend2.create_vm());
    vm1_result?;
    vm2_result?;
    test_ctx.info("Both VMs created successfully");

    // Wait for both VMs to reach Running state in parallel
    test_ctx.info("Waiting for both VMs to reach Running state");
    let (vm1_running, vm2_running) = tokio::join!(
        backend1.wait_for_running(600),
        backend2.wait_for_running(600)
    );

    vm1_running?;
    vm2_running?;
    test_ctx.info("Both VMs are Running");

    // Wait for SSH access on both VMs in parallel
    test_ctx.info("Waiting for SSH access on both VMs");
    let (ssh1_ready, ssh2_ready) = tokio::join!(
        backend1.wait_for_vm_ssh_ready(900),
        backend2.wait_for_vm_ssh_ready(900)
    );
    ssh1_ready?;
    ssh2_ready?;
    test_ctx.info("SSH access ready on both VMs");

    // Verify attestation on both VMs in parallel
    let root_key1 = backend1.get_root_key().await?;
    let root_key2 = backend2.get_root_key().await?;
    if root_key1.is_none() || root_key2.is_none() {
        test_ctx.warn(ENCRYPTED_ROOT_WARN);
    }
    test_ctx.info("Verifying encrypted root on both VMs");
    let (vm1_encrypted, vm2_encrypted) = tokio::join!(
        backend1.verify_encrypted_root(root_key1.as_deref()),
        backend2.verify_encrypted_root(root_key2.as_deref())
    );
    let vm1_has_encrypted_root = vm1_encrypted?;
    let vm2_has_encrypted_root = vm2_encrypted?;

    assert!(vm1_has_encrypted_root, "VM1 {ENCRYPTED_ROOT_ASSERT}");
    assert!(vm2_has_encrypted_root, "VM2 {ENCRYPTED_ROOT_ASSERT}");

    test_ctx.info("Both VMs successfully attested with encrypted root devices");
    backend1.cleanup().await?;
    backend2.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}

virt_test! {
async fn test_vm_reboot_attestation() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    test_ctx.info("Testing VM reboot - VM should successfully boot after multiple reboots");
    let vm_name = "test-coreos-reboot";
    let att_ctx = SingleAttestationContext::new(vm_name, &test_ctx).await?;

    test_ctx.info("Verifying initial encrypted root device");
    let has_encrypted_root = att_ctx.verify_encrypted_root().await?;
    assert!(
        has_encrypted_root,
        "VM should have encrypted root device on initial boot"
    );
    test_ctx.info("Initial boot: attestation successful");

    // Perform multiple reboots
    let num_reboots = 3;
    for i in 1..=num_reboots {
        test_ctx.info(format!("Performing reboot {} of {}", i, num_reboots));

        // Reboot the VM via SSH
        let _reboot_result = att_ctx.backend.ssh_exec("sudo systemctl reboot").await;

        test_ctx.info(format!("Waiting for lack of SSH access after reboot {}", i));
        att_ctx.backend.wait_for_vm_ssh_unavail(30).await?;

        test_ctx.info(format!("Waiting for SSH access after reboot {}", i));
        att_ctx.backend.wait_for_vm_ssh_ready(300).await?;

        // Verify encrypted root is still present after reboot
        test_ctx.info(format!("Verifying encrypted root after reboot {}", i));
        let has_encrypted_root = att_ctx.verify_encrypted_root().await?;
        assert!(
            has_encrypted_root,
            "VM should have encrypted root device after reboot {i}"
        );
        test_ctx.info(format!("Reboot {}: attestation successful", i));
    }

    test_ctx.info(format!(
        "VM successfully rebooted {num_reboots} times with encrypted root device maintained",
    ));
    att_ctx.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}

virt_test! {
async fn test_vm_reboot_delete_machine() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    test_ctx.info("Testing Machine deletion - VM should no longer boot successfully when its Machine CRD was removed");
    let vm_name = "test-coreos-delete";
    let att_ctx = SingleAttestationContext::new(vm_name, &test_ctx).await?;

    let machines: Api<Machine> = Api::namespaced(test_ctx.client().clone(), test_ctx.namespace());
    let list = machines.list(&Default::default()).await?;
    let name = list.items[0].metadata.name.as_ref().unwrap();
    machines.delete(name, &Default::default()).await?;
    wait_for_resource_deleted(&machines, name, 120, 5).await?;

    test_ctx.info("Performing reboot, expecting missing resource");
    let _reboot_result = att_ctx.backend.ssh_exec("sudo systemctl reboot").await;

    test_ctx.info("Waiting for lack of SSH access after reboot");
    att_ctx.backend.wait_for_vm_ssh_unavail(30).await?;

    test_ctx.info("Waiting for SSH access after machine removal");
    let wait = att_ctx.backend.wait_for_vm_ssh_ready(300).await;
    assert!(wait.is_err());

    att_ctx.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}

virt_test! {
async fn test_vm_restart_operator_existing() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    test_ctx.info("Testing operator restart - existing VM should still boot");
    let vm_name = "test-coreos-operator-restart-existing";
    let att_ctx = SingleAttestationContext::new(vm_name, &test_ctx).await?;

    let deployments: Api<Deployment> =
        Api::namespaced(test_ctx.client().clone(), test_ctx.namespace());
    deployments.restart("trusted-cluster-operator").await?;

    let _reboot_result = att_ctx.backend.ssh_exec("sudo systemctl reboot").await;

    test_ctx.info("Waiting for lack of SSH access after reboot");
    att_ctx.backend.wait_for_vm_ssh_unavail(30).await?;

    test_ctx.info("Waiting for SSH access after operator restart & reboot");
    let wait = att_ctx.backend.wait_for_vm_ssh_ready(300).await;
    assert!(wait.is_ok());

    att_ctx.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}

virt_test! {
async fn test_vm_restart_operator_new() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    test_ctx.info("Testing operator restart - new VM should boot");
    let vm_name = "test-coreos-operator-restart-new";

    let deployments: Api<Deployment> =
        Api::namespaced(test_ctx.client().clone(), test_ctx.namespace());
    deployments.restart("trusted-cluster-operator").await?;
    test_ctx.info("Restarted operator deployment");

    let att_ctx = SingleAttestationContext::new(vm_name, &test_ctx).await?;
    att_ctx.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}
