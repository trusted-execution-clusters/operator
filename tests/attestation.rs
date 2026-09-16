// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use trusted_cluster_operator_test_utils::*;

cfg_if::cfg_if! {
if #[cfg(feature = "virtualization")] {
use anyhow::{Context, Result};
use k8s_openapi::api::apps::v1::Deployment;
use kube::Api;
use std::time::Duration;
use trusted_cluster_operator_lib::{ApprovedImage, AttestationKey, Machine, TrustedExecutionCluster};
use trusted_cluster_operator_test_utils::constants::APPROVED_IMAGE_NAME;
use trusted_cluster_operator_test_utils::virt::{self, VmBackend};
use trusted_cluster_operator_test_utils::{Poller, VirtProvider, get_virt_provider, wait_for_event};

const ENCRYPTED_ROOT_CTX: &str = "should have an encrypted root device (attestation failed)";

struct SingleAttestationContext {
    root_key: Vec<u8>,
    backend: Box<dyn VmBackend>,
}

impl SingleAttestationContext {
    async fn verify_encrypted_root(&self) -> Result<()> {
        self.backend.verify_encrypted_root(&self.root_key).await
    }

    async fn cleanup(self) -> Result<()> {
        self.backend.cleanup().await
    }
}

impl SingleAttestationContext {
    async fn new(vm_name: &str, test_ctx: &TestContext) -> Result<Self> {
        let client = test_ctx.client();
        let namespace = test_ctx.namespace();

        let backend = virt::create_backend(client.clone(), namespace, vm_name).await?;

        test_ctx.info(format!("Creating VM: {vm_name}"));
        backend.create_vm().await?;

        test_ctx.info(format!("Waiting for VM {vm_name} to reach Running state"));
        backend.wait_for_running(scaled_timeout(600)).await?;
        test_ctx.info(format!("VM {vm_name} is Running"));

        test_ctx.info(format!("Waiting for SSH access to VM {vm_name}"));
        backend.wait_for_vm_ssh_ready(scaled_timeout(600), None).await?;
        test_ctx.info("SSH access is ready");

        let root_key = backend.get_root_key(client.clone(), namespace).await?;
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
    let ctx = format!("VM {ENCRYPTED_ROOT_CTX}");
    att_ctx.verify_encrypted_root().await.context(ctx)?;

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
    let backend1 = virt::create_backend(client.clone(), namespace, vm1_name).await?;
    let backend2 = virt::create_backend(client.clone(), namespace, vm2_name).await?;

    test_ctx.info("Creating VM1 and VM2 in parallel");
    let (vm1_result, vm2_result) = tokio::join!(backend1.create_vm(), backend2.create_vm());
    vm1_result?;
    vm2_result?;
    test_ctx.info("Both VMs created successfully");

    // Wait for both VMs to reach Running state in parallel
    test_ctx.info("Waiting for both VMs to reach Running state");
    let (vm1_running, vm2_running) = tokio::join!(
        backend1.wait_for_running(scaled_timeout(600)),
        backend2.wait_for_running(scaled_timeout(600))
    );

    vm1_running?;
    vm2_running?;
    test_ctx.info("Both VMs are Running");

    // Wait for SSH access on both VMs in parallel
    test_ctx.info("Waiting for SSH access on both VMs");
    let (ssh1_ready, ssh2_ready) = tokio::join!(
        backend1.wait_for_vm_ssh_ready(scaled_timeout(900), None),
        backend2.wait_for_vm_ssh_ready(scaled_timeout(900), None)
    );
    ssh1_ready?;
    ssh2_ready?;
    test_ctx.info("SSH access ready on both VMs");

    // Verify attestation on both VMs in parallel
    let root_key1 = backend1.get_root_key(client.clone(), namespace).await?;
    let root_key2 = backend2.get_root_key(client.clone(), namespace).await?;
    test_ctx.info("Verifying encrypted root on both VMs");
    let (vm1_encrypted, vm2_encrypted) = tokio::join!(
        backend1.verify_encrypted_root(&root_key1),
        backend2.verify_encrypted_root(&root_key2)
    );
    vm1_encrypted.context(format!("VM1 {ENCRYPTED_ROOT_CTX}"))?;
    vm2_encrypted.context(format!("VM2 {ENCRYPTED_ROOT_CTX}"))?;

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
    let ctx = "VM should have encrypted root device on initial boot";
    att_ctx.verify_encrypted_root().await.context(ctx)?;
    test_ctx.info("Initial boot: attestation successful");

    // Perform multiple reboots
    let num_reboots = 3;
    for i in 1..=num_reboots {
        test_ctx.info(format!("Performing reboot {i} of {num_reboots}"));

        let boot_id = att_ctx.backend.get_boot_id().await?;
        let _reboot_result = att_ctx.backend.ssh_exec("sudo systemctl reboot").await;

        test_ctx.info(format!("Waiting for SSH access after reboot {i}"));
        att_ctx.backend.wait_for_vm_ssh_ready(scaled_timeout(300), Some(&boot_id)).await?;

        // Verify encrypted root is still present after reboot
        test_ctx.info(format!("Verifying encrypted root after reboot {i}"));
        let ctx = format!("VM should have encrypted root device after reboot {i}");
        att_ctx.verify_encrypted_root().await.context(ctx)?;
        test_ctx.info(format!("Reboot {i}: attestation successful"));
    }

    test_ctx.info(format!(
        "VM successfully rebooted {num_reboots} times with encrypted root device maintained"
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
    wait_for_resource_deleted(&machines, name, scaled_timeout(120)).await?;

    test_ctx.info("Performing reboot, expecting missing resource");
    let boot_id = att_ctx.backend.get_boot_id().await?;
    let _reboot_result = att_ctx.backend.ssh_exec("sudo systemctl reboot").await;

    test_ctx.info("Waiting for SSH access after machine removal");
    let wait = att_ctx.backend.wait_for_vm_ssh_ready(scaled_timeout(300), Some(&boot_id)).await;
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

    let boot_id = att_ctx.backend.get_boot_id().await?;
    let _reboot_result = att_ctx.backend.ssh_exec("sudo systemctl reboot").await;

    test_ctx.info("Waiting for SSH access after operator restart & reboot");
    let wait = att_ctx.backend.wait_for_vm_ssh_ready(scaled_timeout(300), Some(&boot_id)).await;
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

virt_test! {
async fn test_attestation_events() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let vm_name = "test-coreos-events";
    let att_ctx = SingleAttestationContext::new(vm_name, &test_ctx).await?;

    test_ctx.info("Verifying encrypted root device");
    let ctx = format!("VM {ENCRYPTED_ROOT_CTX}");
    att_ctx.verify_encrypted_root().await.context(ctx)?;
    test_ctx.info("Attestation successful, verifying Kubernetes events");

    let tecs: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let tec = tecs.get("trusted-execution-cluster").await?;
    let has_ak_register = tec.spec.public_attestation_key_register_addr.is_some();

    let machines: Api<Machine> = Api::namespaced(client.clone(), namespace);
    let machine_list = machines.list(&Default::default()).await?;
    let machine_name = machine_list.items.first()
        .expect("No Machine found in namespace")
        .metadata
        .name
        .as_ref()
        .expect("Machine should have a name");

    wait_for_event(client, namespace, APPROVED_IMAGE_NAME, "ComputationStarted", scaled_timeout(60)).await?;
    test_ctx.info("Event ComputationStarted verified");

    wait_for_event(client, namespace, APPROVED_IMAGE_NAME, "ComputationCompleted", scaled_timeout(60)).await?;
    test_ctx.info("Event ComputationCompleted verified");

    wait_for_event(client, namespace, machine_name, "MachineRegistered", scaled_timeout(60)).await?;
    test_ctx.info("Event MachineRegistered verified");

    wait_for_event(client, namespace, machine_name, "KeyProvisioned", scaled_timeout(60)).await?;
    test_ctx.info("Event KeyProvisioned verified");

    if has_ak_register {
        let aks: Api<AttestationKey> = Api::namespaced(client.clone(), namespace);
        let ak = Poller::new()
            .with_timeout(Duration::from_secs(scaled_timeout(60)))
            .with_error_message("waiting for AttestationKey to be created")
            .poll_async(|| {
                let api = aks.clone();
                async move {
                    let list = api.list(&Default::default()).await?;
                    list.items
                        .into_iter()
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("No AttestationKey found yet"))
                }
            })
            .await?;
        let ak_name = ak.metadata.name.as_ref().expect("AttestationKey should have a name");

        test_ctx.info(format!("Found AttestationKey: {ak_name}"));

        wait_for_event(client, namespace, ak_name, "AttestationKeyRegistered", scaled_timeout(60)).await?;
        test_ctx.info("Event AttestationKeyRegistered verified");

        wait_for_event(client, namespace, ak_name, "AttestationKeyApproved", scaled_timeout(60)).await?;
        test_ctx.info("Event AttestationKeyApproved on AttestationKey verified");

        wait_for_event(client, namespace, machine_name, "AttestationKeyApproved", scaled_timeout(60)).await?;
        test_ctx.info("Event AttestationKeyApproved on Machine verified");
    } else {
        test_ctx.info("Skipping AttestationKey events (publicAttestationKeyRegisterAddr not set)");
    }

    test_ctx.info(format!("Deleting Machine {machine_name} to trigger KeyRevoked"));
    machines.delete(machine_name, &Default::default()).await?;
    wait_for_resource_deleted(&machines, machine_name, scaled_timeout(120)).await?;

    wait_for_event(client, namespace, machine_name, "KeyRevoked", scaled_timeout(60)).await?;
    test_ctx.info("Event KeyRevoked verified");

    test_ctx.info("All expected Kubernetes events verified");
    att_ctx.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}

virt_test! {
async fn test_kbs_proxy_attestation_events() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let vm_name = "test-coreos-proxy-events";
    let att_ctx = SingleAttestationContext::new(vm_name, &test_ctx).await?;

    test_ctx.info("Verifying encrypted root device");
    let ctx = format!("VM {ENCRYPTED_ROOT_CTX}");
    att_ctx.verify_encrypted_root().await.context(ctx)?;
    test_ctx.info("Attestation successful, verifying KBS proxy events");

    let machines: Api<Machine> = Api::namespaced(client.clone(), namespace);
    let machine_list = machines.list(&Default::default()).await?;
    assert_eq!(machine_list.items.len(), 1, "Expected exactly one Machine in namespace");
    let machine_name = machine_list.items.first()
        .expect("No Machine found in namespace")
        .metadata
        .name
        .as_ref()
        .expect("Machine should have a name");

    wait_for_event(client, namespace, machine_name, "AttestationSucceeded", scaled_timeout(60)).await?;
    test_ctx.info("Event AttestationSucceeded verified on Machine");

    test_ctx.info("Deleting ApprovedImage to trigger attestation failure on next boot");
    let approved_images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
    approved_images.delete(APPROVED_IMAGE_NAME, &Default::default()).await?;
    wait_for_resource_deleted(&approved_images, APPROVED_IMAGE_NAME, scaled_timeout(120)).await?;
    test_ctx.info("ApprovedImage deleted, reference values cleared in KBS");

    test_ctx.info("Rebooting VM to trigger re-attestation");
    let _reboot = att_ctx.backend.ssh_exec("sudo systemctl reboot").await;

    if get_virt_provider()? == VirtProvider::Azure {
        let event = wait_for_event(client, namespace, machine_name, "AttestationFailed", scaled_timeout(300)).await?;
        let machine_uuid = &machine_list.items[0].spec.id;
        let note = event.note.as_deref().unwrap_or("");
        assert!(note.contains(machine_uuid), "AttestationFailed note should contain machine UUID {machine_uuid}, got: {note}");
        test_ctx.info("Event AttestationFailed verified on Machine with UUID");
    } else {
        wait_for_event(client, namespace, "trusted-execution-cluster", "AttestationFailed", scaled_timeout(300)).await?;
        test_ctx.info("Event AttestationFailed verified on TrustedExecutionCluster");
    }

    att_ctx.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}
