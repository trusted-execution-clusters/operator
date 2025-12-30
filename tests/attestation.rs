// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use trusted_cluster_operator_test_utils::*;

#[cfg(feature = "virtualization")]
use trusted_cluster_operator_test_utils::virt;

#[cfg(feature = "virtualization")]
struct SingleAttestationContext {
    key_path: std::path::PathBuf,
    vm_name: String,
}

#[cfg(feature = "virtualization")]
impl SingleAttestationContext {
    async fn new(test_ctx: &TestContext) -> anyhow::Result<Self> {
        let client = test_ctx.client();
        let namespace = test_ctx.namespace();

        let (_private_key, public_key, key_path) = virt::generate_ssh_key_pair()?;
        test_ctx.info(format!(
            "Generated SSH key pair and added to ssh-agent: {:?}",
            key_path
        ));

        let vm_name = "test-coreos-vm";
        let register_server_url = format!(
            "http://register-server.{}.svc.cluster.local:8000/ignition-clevis-pin-trustee",
            namespace
        );
        let image = "quay.io/trusted-execution-clusters/fedora-coreos-kubevirt:latest";

        test_ctx.info(format!("Creating VM: {}", vm_name));
        virt::create_kubevirt_vm(
            client,
            namespace,
            vm_name,
            &public_key,
            &register_server_url,
            image,
        )
        .await?;

        test_ctx.info(format!("Waiting for VM {} to reach Running state", vm_name));
        virt::wait_for_vm_running(client, namespace, vm_name, 300).await?;
        test_ctx.info(format!("VM {} is Running", vm_name));

        test_ctx.info(format!("Waiting for SSH access to VM {}", vm_name));
        virt::wait_for_vm_ssh_ready(namespace, vm_name, &key_path, 600).await?;
        test_ctx.info("SSH access is ready");

        Ok(Self {
            key_path,
            vm_name: vm_name.to_string(),
        })
    }
}

#[cfg(feature = "virtualization")]
impl Drop for SingleAttestationContext {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.key_path);
    }
}

virt_test! {
async fn test_attestation() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let att_ctx = SingleAttestationContext::new(&test_ctx).await?;

    test_ctx.info("Verifying encrypted root device");
    let namespace = test_ctx.namespace();
    let has_encrypted_root =
        virt::verify_encrypted_root(namespace, &att_ctx.vm_name, &att_ctx.key_path).await?;

    assert!(
        has_encrypted_root,
        "VM should have an encrypted root device (attestation failed)"
    );
    test_ctx.info("Attestation successful: encrypted root device verified");

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

    // Generate SSH keys for both VMs
    let (_private_key1, public_key1, key_path1) = virt::generate_ssh_key_pair()?;
    let (_private_key2, public_key2, key_path2) = virt::generate_ssh_key_pair()?;
    test_ctx.info("Generated SSH key pairs for both VMs");

    let register_server_url = format!(
        "http://register-server.{}.svc.cluster.local:8000/ignition-clevis-pin-trustee",
        namespace
    );
    let image = "quay.io/trusted-execution-clusters/fedora-coreos-kubevirt:latest";

    // Launch both VMs in parallel
    let vm1_name = "test-coreos-vm1";
    let vm2_name = "test-coreos-vm2";

    test_ctx.info("Creating VM1 and VM2 in parallel");
    let (vm1_result, vm2_result) = tokio::join!(
        virt::create_kubevirt_vm(
            client,
            namespace,
            vm1_name,
            &public_key1,
            &register_server_url,
            image,
        ),
        virt::create_kubevirt_vm(
            client,
            namespace,
            vm2_name,
            &public_key2,
            &register_server_url,
            image,
        )
    );

    vm1_result?;
    vm2_result?;
    test_ctx.info("Both VMs created successfully");

    // Wait for both VMs to reach Running state in parallel
    test_ctx.info("Waiting for both VMs to reach Running state");
    let (vm1_running, vm2_running) = tokio::join!(
        virt::wait_for_vm_running(client, namespace, vm1_name, 300),
        virt::wait_for_vm_running(client, namespace, vm2_name, 300)
    );

    vm1_running?;
    vm2_running?;
    test_ctx.info("Both VMs are Running");

    // Wait for SSH access on both VMs in parallel
    test_ctx.info("Waiting for SSH access on both VMs");
    let (ssh1_ready, ssh2_ready) = tokio::join!(
        virt::wait_for_vm_ssh_ready(namespace, vm1_name, &key_path1, 900),
        virt::wait_for_vm_ssh_ready(namespace, vm2_name, &key_path2, 900)
    );

    ssh1_ready?;
    ssh2_ready?;
    test_ctx.info("SSH access ready on both VMs");

    // Verify attestation on both VMs in parallel
    test_ctx.info("Verifying encrypted root on both VMs");
    let (vm1_encrypted, vm2_encrypted) = tokio::join!(
        virt::verify_encrypted_root(namespace, vm1_name, &key_path1),
        virt::verify_encrypted_root(namespace, vm2_name, &key_path2)
    );

    let vm1_has_encrypted_root = vm1_encrypted?;
    let vm2_has_encrypted_root = vm2_encrypted?;

    // Clean up SSH keys
    let _ = std::fs::remove_file(&key_path1);
    let _ = std::fs::remove_file(&key_path2);

    assert!(
        vm1_has_encrypted_root,
        "VM1 should have an encrypted root device (attestation failed)"
    );
    assert!(
        vm2_has_encrypted_root,
        "VM2 should have an encrypted root device (attestation failed)"
    );

    test_ctx.info("Both VMs successfully attested with encrypted root devices");

    test_ctx.cleanup().await?;

    Ok(())
}
}

virt_test! {
async fn test_vm_reboot_attestation() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    test_ctx.info("Testing VM reboot - VM should successfully boot after multiple reboots");
    let att_ctx = SingleAttestationContext::new(&test_ctx).await?;
    let namespace = test_ctx.namespace();

    test_ctx.info("Verifying initial encrypted root device");
    let has_encrypted_root =
        virt::verify_encrypted_root(namespace, &att_ctx.vm_name, &att_ctx.key_path).await?;
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
        let _reboot_result = virt::virtctl_ssh_exec(
            namespace,
            &att_ctx.vm_name,
            &att_ctx.key_path,
            "sudo systemctl reboot",
        )
        .await;

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        test_ctx.info(format!("Waiting for SSH access after reboot {}", i));
        virt::wait_for_vm_ssh_ready(namespace, &att_ctx.vm_name, &att_ctx.key_path, 300).await?;

        // Verify encrypted root is still present after reboot
        test_ctx.info(format!("Verifying encrypted root after reboot {}", i));
        let has_encrypted_root =
            virt::verify_encrypted_root(namespace, &att_ctx.vm_name, &att_ctx.key_path).await?;
        assert!(
            has_encrypted_root,
            "VM should have encrypted root device after reboot {}",
            i
        );
        test_ctx.info(format!("Reboot {}: attestation successful", i));
    }

    test_ctx.info(format!(
        "VM successfully rebooted {} times with encrypted root device maintained",
        num_reboots
    ));

    test_ctx.cleanup().await?;

    Ok(())
}
}

virt_test! {
async fn test_vm_reboot_delete_machine() -> anyhow::Result<()> {
    use kube::Api;
    use trusted_cluster_operator_lib::Machine;

    let test_ctx = setup!().await?;
    test_ctx.info("Testing Machine deletion - VM should no longer boot successfully when its Machine CRD was removed");
    let att_ctx = SingleAttestationContext::new(&test_ctx).await?;

    let machines: Api<Machine> = Api::namespaced(test_ctx.client().clone(), test_ctx.namespace());
    let list = machines.list(&Default::default()).await?;
    let name = list.items[0].metadata.name.as_ref().unwrap();
    machines.delete(name, &Default::default()).await?;
    wait_for_resource_deleted(&machines, name, 120, 5).await?;

    test_ctx.info("Performing reboot, expecting missing resource");
    let _reboot_result = virt::virtctl_ssh_exec(
        test_ctx.namespace(),
        &att_ctx.vm_name,
        &att_ctx.key_path,
        "sudo systemctl reboot",
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    test_ctx.info("Waiting for SSH access after machine removal");
    let wait = virt::wait_for_vm_ssh_ready(
        test_ctx.namespace(),
        &att_ctx.vm_name,
        &att_ctx.key_path,
        300,
    )
    .await;
    assert!(wait.is_err());

    test_ctx.cleanup().await?;
    Ok(())
}
}
