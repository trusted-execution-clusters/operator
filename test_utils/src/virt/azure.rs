use anyhow::{Context, Result, anyhow};
use azure_core::credentials::TokenCredential;
use azure_identity::DeveloperToolsCredential;
use k8s_openapi::chrono::{self, Utc};
use reqwest::{Client, header};
use serde_json::{Value, json};
use std::{env, sync::Arc, time};

use super::{VmBackend, VmConfig, generate_ignition, get_root_key, ssh_exec};
use crate::{Poller, get_env};

const AZURE_MGMT: &str = "https://management.azure.com";
const AZURE_SCOPE: &str = ".default";
const NET_API_VERSION: &str = "api-version=2025-05-01";
const VM_API_VERSION: &str = "api-version=2025-04-01";
// Old. Consider Start/Stop VMs v2
const SCHEDULES_API_VERSION: &str = "api-version=2018-09-15";
const KEEP_ALIVE_MINUTES: i64 = 60;
const NET_PATH: &str = "providers/Microsoft.Network";
const VMS_PATH: &str = "providers/Microsoft.Compute/virtualMachines";

pub struct AzureBackend {
    config: VmConfig,
    client: Client,
    rg_path: String,
    location: String,
    cred: Arc<DeveloperToolsCredential>,
}

impl AzureBackend {
    pub fn new(config: VmConfig) -> Result<Self> {
        let subscription_id = get_env("AZURE_SUBSCRIPTION_ID")?;
        let cred = DeveloperToolsCredential::new(None)?;
        let resource_group = config.namespace.clone();
        Ok(Self {
            config,
            client: Client::new(),
            rg_path: format!("subscriptions/{subscription_id}/resourceGroups/{resource_group}"),
            location: env::var("AZURE_LOCATION").unwrap_or("eastus".to_string()),
            cred,
        })
    }

    async fn get_token(&self) -> Result<String> {
        let scope = format!("{AZURE_MGMT}/{AZURE_SCOPE}");
        let token_response = self.cred.get_token(&[&scope], None).await?;
        Ok(token_response.token.secret().to_string())
    }

    async fn put_resource(&self, url: &str, body: &Value) -> Result<Value> {
        let token = self.get_token().await?;
        let req = self.client.put(url);
        let headers = req
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json");
        let response = headers.json(body).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await?;
            return Err(anyhow!("PUT {url} failed: {status} - {error_body}"));
        }
        let result = response.json().await?;
        Ok(result)
    }

    async fn delete_resource(&self, url: &str) -> Result<()> {
        let token = self.get_token().await?;
        let req = self.client.delete(url);
        let headers = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        let response = headers.send().await?;
        // 200, 202 (accepted), 204 (no content) are all success for DELETE
        if !response.status().is_success() && response.status().as_u16() != 202 {
            let status = response.status();
            let error_body = response.text().await?;
            return Err(anyhow::anyhow!(
                "DELETE {url} failed: {status} - {error_body}"
            ));
        }
        Ok(())
    }

    async fn get_resource(&self, url: &str) -> Result<Value> {
        let token = self.get_token().await?;
        let req = self.client.get(url);
        let headers = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        let response = headers.send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await?;
            return Err(anyhow!("GET {url} failed: {status} - {error_body}"));
        }
        let result = response.json().await?;
        Ok(result)
    }
}

#[async_trait::async_trait]
impl VmBackend for AzureBackend {
    async fn create_vm(&self) -> Result<()> {
        let rg_path = &self.rg_path;
        let mgmt_base = format!("{AZURE_MGMT}/{rg_path}");
        let rg_url = format!("{mgmt_base}?{VM_API_VERSION}");
        let rg_body = json!({"location": self.location});
        // TODO probably handle already_exists for parallel test
        self.put_resource(&rg_url, &rg_body).await?;

        let vm_name = &self.config.vm_name;
        let vnet_name = format!("{vm_name}-vnet");
        let vnet_url =
            format!("{mgmt_base}/{NET_PATH}/virtualNetworks/{vnet_name}?{NET_API_VERSION}",);
        // TODO check if necessary
        // If Microsoft returns to making these structures available
        // in a Rust SDK (was discontinued in version 0.22), use them.
        let vnet_body = json!({
            "location": self.location,
            "properties": {
                "addressSpace": {
                    "addressPrefixes": ["10.0.0.0/16"]
                },
                "subnets": [{
                    "name": "default",
                    "properties": {
                        "addressPrefix": "10.0.0.0/24"
                    }
                }]
            }
        });
        self.put_resource(&vnet_url, &vnet_body).await?;

        let ip_url =
            format!("{mgmt_base}/{NET_PATH}/publicIPAddresses/{vm_name}-ip?{NET_API_VERSION}",);
        let ip_body = json!({
            "location": self.location,
            "sku": {
                "name": "Standard"
            },
            "properties": {
                "publicIPAllocationMethod": "Static"
            }
        });
        let ip_result = self.put_resource(&ip_url, &ip_body).await?;

        let nsg_url =
            format!("{mgmt_base}/{NET_PATH}/networkSecurityGroups/{vm_name}-nsg?{NET_API_VERSION}");
        let nsg_body = json!({
            "location": self.location,
            "properties": {
                "securityRules": [{
                    "name": "AllowSSH",
                    "properties": {
                        "protocol": "Tcp",
                        "sourceAddressPrefix": "*",
                        "sourcePortRange": "*",
                        "destinationAddressPrefix": "*",
                        "destinationPortRange": "22",
                        "access": "Allow",
                        "direction": "Inbound",
                        "priority": 1000,
                        "description": "Allow SSH"
                    }
                }]
            }
        });
        let nsg_result = self.put_resource(&nsg_url, &nsg_body).await?;

        let nic_url =
            format!("{mgmt_base}/{NET_PATH}/networkInterfaces/{vm_name}-nic?{NET_API_VERSION}");
        let nic_body = json!({
            "location": self.location,
            "properties": {
                "networkSecurityGroup": {
                    "id": nsg_result["id"].as_str().unwrap(),
                },
                "ipConfigurations": [{
                    "name": "ipconfig1",
                    "properties": {
                        "subnet": {
                            "id": format!("{rg_path}/{NET_PATH}/virtualNetworks/{vnet_name}/subnets/default"),
                        },
                        "publicIPAddress": {
                            "id": ip_result["id"].as_str().unwrap(),
                        }
                    }
                }]
            }
        });
        let nic_result = self.put_resource(&nic_url, &nic_body).await?;

        let image_ref_json = if self.config.image.starts_with('/') {
            json!({ "id": self.config.image })
        } else {
            let parts: Vec<&str> = self.config.image.split(':').collect();
            if parts.len() < 4 {
                let err = "Invalid Image URN. Expected 'Publisher:Offer:Sku:Version'";
                return Err(anyhow!(err));
            }
            json!({
                "publisher": parts[0],
                "offer": parts[1],
                "sku": parts[2],
                "version": parts[3]
            })
        };

        let admin_username = "integration-tests";
        let vm_path = format!("{rg_path}/{VMS_PATH}/{vm_name}");
        let vm_url = format!("{AZURE_MGMT}/{vm_path}?{VM_API_VERSION}");
        let ign = generate_ignition(&self.config).await?;
        let vm_body = json!({
            "location": self.location,
            "properties": {
                "hardwareProfile": {
                    "vmSize": "Standard_DC2as_v5"
                },
                "storageProfile": {
                    "imageReference": image_ref_json,
                    "osDisk": {
                        "createOption": "FromImage",
                        "deleteOption": "Delete",
                        "managedDisk": {
                            "storageAccountType": "StandardSSD_LRS",
                            "securityProfile": {
                                "securityEncryptionType": "VMGuestStateOnly"
                            }
                        }
                    }
                },
                "osProfile": {
                    "computerName": vm_name,
                    "adminUsername": admin_username,
                    "linuxConfiguration": {
                        // TODO this didn't work earlier, so it might also be unnecessary
                        "disablePasswordAuthentication": true,
                        "ssh": {
                            "publicKeys": [
                                {
                                    "path": format!("/home/{}/.ssh/authorized_keys", admin_username),
                                    "keyData": self.config.ssh_public_key
                                }
                            ]
                        }
                    },
                    "customData": ign.as_str(),
                },
                "networkProfile": {
                    "networkInterfaces": [
                        {
                            "id": nic_result["id"].as_str().unwrap(),
                            "properties": {
                                "primary": true
                            }
                        }
                    ]
                },
                "securityProfile": {
                    "securityType": "ConfidentialVM",
                    "uefiSettings": {
                        "secureBootEnabled": true,
                        "vTpmEnabled": true
                    }
                }
            }
        });
        self.put_resource(&vm_url, &vm_body).await?;

        // Schedule VM shutdown at KEEP_ALIVE_MINUTES in the future to control costs if cleanup fails
        let shutdown_time = Utc::now() + chrono::Duration::minutes(KEEP_ALIVE_MINUTES);
        let shutdown_url = format!(
            "{mgmt_base}/providers/Microsoft.DevTestLab/schedules/shutdown-computevm-{vm_name}?{SCHEDULES_API_VERSION}"
        );
        let shutdown_body = json!({
            "location": self.location,
            "properties": {
                "status": "Enabled",
                "taskType": "ComputeVmShutdownTask",
                "dailyRecurrence": {
                    "time": shutdown_time.format("%H%M").to_string(),
                },
                "targetResourceId": vm_path,
                "timezoneId": "UTC",
            }
        });
        let warn = format!("=== WARNING ===
Request to auto-shutdown the VM at {vm_path} has failed. Log in manually to verify the VM was removed correctly.
=== END OF WARNING ===");
        self.put_resource(&shutdown_url, &shutdown_body)
            .await
            .context(warn)?;
        Ok(())
    }

    async fn wait_for_running(&self, timeout_secs: u64) -> Result<()> {
        let poller = Poller::new()
            .with_timeout(time::Duration::from_secs(timeout_secs))
            .with_interval(time::Duration::from_secs(5))
            .with_error_message(format!(
                "virtualMachine {} did not reach PowerState/running status after {timeout_secs} seconds",
                self.config.vm_name
            ));

        let check_fn = || async move {
            let vm_name = &self.config.vm_name;
            let rg_path = &self.rg_path;
            let url = format!(
                "{AZURE_MGMT}/{rg_path}/{VMS_PATH}/{vm_name}/instanceView?{VM_API_VERSION}"
            );
            let vm = self.get_resource(&url).await?;
            let statuses = vm["statuses"].as_array().unwrap();
            let check = |s: &&Value| s["code"] == "PowerState/running";
            let err = anyhow!("virtualMachine {vm_name} is not in running PowerState yet");
            statuses.iter().find(check).map(|_| ()).ok_or(err)
        };
        poller.poll_async(check_fn).await
    }

    async fn ssh_exec(&self, command: &str) -> Result<String> {
        let ip_url = format!(
            "{AZURE_MGMT}/{}/{NET_PATH}/publicIPAddresses/{}-ip?{NET_API_VERSION}",
            self.rg_path, self.config.vm_name
        );
        let response = self.get_resource(&ip_url).await?;
        let public_ip = response["properties"]["ipAddress"].as_str().unwrap();

        let full_cmd = format!(
            "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null core@{public_ip} '{command}'",
            self.config.ssh_private_key.display()
        );
        ssh_exec(&full_cmd).await
    }

    async fn get_root_key(&self) -> Result<Vec<u8>> {
        let nic_url = format!(
            "{AZURE_MGMT}/{}/{NET_PATH}/networkInterfaces/{}-nic?{NET_API_VERSION}",
            self.rg_path, self.config.vm_name
        );
        let response = self.get_resource(&nic_url).await?;
        let private_ip =
            &response["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"];
        get_root_key(&self.config, private_ip.as_str().unwrap()).await
    }

    async fn cleanup(&self) -> Result<()> {
        let rg_path = &self.rg_path;
        let url = format!("{AZURE_MGMT}/{rg_path}?{NET_API_VERSION}");
        let warn = format!("=== WARNING ===
Request to cleanup the Azure resource group at {rg_path} failed. Log in manually to verify the resource group was removed correctly.
=== END OF WARNING ===");
        self.delete_resource(&url).await.context(warn)
    }
}
