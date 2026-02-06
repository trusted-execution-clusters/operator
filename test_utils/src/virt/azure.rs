// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use k8s_openapi::chrono::{self, Utc};
use serde_json::Value;
use std::{env, time};
use tokio::process::Command;

use super::{VmBackend, VmConfig, generate_ignition, ssh_exec};
use crate::{Poller, ensure_command, warn_frame};

const KEEP_ALIVE_MINUTES: i64 = 60;

pub struct AzureBackend {
    config: VmConfig,
    resource_group: String,
}

impl AzureBackend {
    pub fn new(config: VmConfig) -> Result<Self> {
        let resource_group = config.namespace.clone();
        Ok(Self {
            config,
            resource_group,
        })
    }

    async fn az(&self, args: &[&str]) -> Result<Value> {
        ensure_command("az")?;
        let out = ["--output", "json"];
        let output = Command::new("az").args(args).args(out).output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("az {} failed: {stderr}", args.join(" ")));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&stdout).context("Failed to parse az CLI output as JSON")
    }

    async fn az_rg(&self, mut args: Vec<&str>) -> Result<()> {
        ensure_command("az")?;
        args.extend(["--resource-group", &self.resource_group, "--output", "none"]);
        let output = Command::new("az").args(&args).output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("az {} failed: {stderr}", args.join(" ")));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl VmBackend for AzureBackend {
    async fn create_vm(&self) -> Result<()> {
        let vm = &self.config.vm_name;
        let vnet = &format!("{vm}-vnet");
        let ip = &format!("{vm}-ip");
        let nsg = &format!("{vm}-nsg");
        let nic = &format!("{vm}-nic");

        let location = env::var("AZURE_LOCATION").unwrap_or("eastus".to_string());
        let mut args = vec!["group", "create", "--name", &self.resource_group];
        args.extend(["--location", &location]);
        let output = Command::new("az").args(args).output().await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("az group create failed: {stderr}"));
        }

        let mut args = vec!["network", "vnet", "create", "--name", vnet];
        args.extend(["--address-prefix", "10.0.0.0/16"]);
        args.extend(["--subnet-name", "default", "--subnet-prefix", "10.0.0.0/24"]);
        self.az_rg(args).await?;

        let mut args = vec!["network", "public-ip", "create", "--name", ip];
        args.extend(["--sku", "Standard", "--allocation-method", "Static"]);
        self.az_rg(args).await?;

        self.az_rg(vec!["network", "nsg", "create", "--name", nsg])
            .await?;

        let mut args = vec!["network", "nsg", "rule", "create", "--nsg-name", nsg];
        args.extend(["--name", "AllowSSH", "--protocol", "Tcp"]);
        args.extend(["--priority", "1000", "--destination-port-range", "22"]);
        args.extend(["--access", "Allow", "--direction", "Inbound"]);
        self.az_rg(args).await?;

        let mut args = vec!["network", "nic", "create", "--name", nic];
        args.extend(["--vnet-name", vnet, "--subnet", "default"]);
        args.extend(["--network-security-group", nsg, "--public-ip-address", ip]);
        self.az_rg(args).await?;

        let ign = generate_ignition(&self.config, false).await?;
        let custom_data = ign.to_string();
        if !self.config.image.starts_with('/') && self.config.image.split(':').count() < 4 {
            let err = "Invalid Image URN. Expected 'Publisher:Offer:Sku:Version'";
            return Err(anyhow!(err));
        }

        let mut args = vec!["vm", "create", "--name", vm, "--nics", nic];
        args.extend(["--image", &self.config.image, "--size", "Standard_DC2as_v5"]);
        args.extend(["--os-disk-delete-option", "Delete"]);
        args.extend(["--storage-sku", "StandardSSD_LRS"]);
        args.extend(["--admin-username", "core"]);
        args.extend(["--ssh-key-values", &self.config.ssh_public_key]);
        args.extend(["--custom-data", &custom_data]);
        args.extend(["--security-type", "ConfidentialVM"]);
        args.extend(["--enable-secure-boot", "true", "--enable-vtpm", "true"]);
        args.extend(["--os-disk-security-encryption-type", "VMGuestStateOnly"]);

        let err = format!(
            "Request to create the VM {vm} has failed, but it may still have been created. \
             Log in manually to verify the VM does not keep running."
        );
        self.az_rg(args).await.context(warn_frame(&err))?;

        // Schedule auto-shutdown to control costs if cleanup fails
        let shutdown_time = Utc::now() + chrono::Duration::minutes(KEEP_ALIVE_MINUTES);
        let shutdown_str = shutdown_time.format("%H%M").to_string();
        let mut args = vec!["vm", "auto-shutdown", "--name", vm];
        args.extend(["--time", &shutdown_str]);
        let err = format!(
            "Request to auto-shutdown the VM {vm} has failed. \
             Log in manually to verify the VM was removed correctly."
        );
        self.az_rg(args).await.context(warn_frame(&err))?;

        Ok(())
    }

    async fn wait_for_running(&self, timeout_secs: u64) -> Result<()> {
        let vm_name = &self.config.vm_name;
        let poller = Poller::new()
            .with_timeout(time::Duration::from_secs(timeout_secs))
            .with_interval(time::Duration::from_secs(5))
            .with_error_message(format!(
                "virtualMachine {vm_name} did not reach PowerState/running after {timeout_secs}s",
            ));

        let args = [
            "vm",
            "get-instance-view",
            "--resource-group",
            &self.resource_group,
            "--name",
            &self.config.vm_name,
        ];
        let check_fn = || async move {
            let result = self.az(&args).await?;
            let statuses = result["instanceView"]["statuses"].as_array().unwrap();
            let check = |s: &&Value| s["code"] == "PowerState/running";
            let err = anyhow!("virtualMachine {vm_name} is not in running PowerState yet",);
            statuses.iter().find(check).map(|_| ()).ok_or(err)
        };
        poller.poll_async(check_fn).await
    }

    async fn ssh_exec(&self, command: &str) -> Result<String> {
        let (rg, ip_name) = (&self.resource_group, format!("{}-ip", self.config.vm_name));
        let mut args = vec!["network", "public-ip", "show", "--resource-group", rg];
        args.extend(["--name", &ip_name]);
        let result = self.az(&args).await?;

        let public_ip = result["ipAddress"].as_str().unwrap();
        ssh_exec(&format!(
            "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null core@{public_ip} '{command}'",
            self.config.ssh_private_key.display()
        )).await
    }

    async fn get_root_key(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn cleanup(&self) -> Result<()> {
        self.config.cleanup();
        let rg = &self.resource_group;

        let args1 = ["group", "delete", "--name", rg];
        let args2 = ["--yes", "--no-wait"];
        let output = Command::new("az").args(args1).args(args2).output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let err = format!(
                "Request to cleanup the Azure resource group {rg} failed. \
                 Log in manually to verify the resource group was removed correctly."
            );
            return Err(anyhow!("az group delete failed: {stderr}").context(warn_frame(&err)));
        }
        Ok(())
    }
}
