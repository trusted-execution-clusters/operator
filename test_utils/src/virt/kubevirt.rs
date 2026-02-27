// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use k8s_openapi::{api::core::v1::Secret, apimachinery::pkg::util::intstr::IntOrString};
use kube::{Api, api::ObjectMeta};
use std::{collections::BTreeMap, time::Duration};
use trusted_cluster_operator_lib::virtualmachines::*;

use super::{VmBackend, VmConfig, generate_ignition, ssh_exec};
use crate::{Poller, ensure_command};

pub struct KubevirtBackend(pub VmConfig);

#[async_trait::async_trait]
impl VmBackend for KubevirtBackend {
    async fn create_vm(&self) -> Result<()> {
        ensure_command("virtctl")?;
        let ignition_json = generate_ignition(&self.0).await?;

        // Create the secret with the ignition configuration
        let secret_name = format!("{}-ignition-secret", self.0.vm_name);
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                namespace: Some(self.0.namespace.to_string()),
                ..Default::default()
            },
            string_data: Some(BTreeMap::from([(
                "userdata".to_string(),
                ignition_json.to_string(),
            )])),
            ..Default::default()
        };

        let secrets: Api<Secret> = Api::namespaced(self.0.client.clone(), &self.0.namespace);
        secrets.create(&Default::default(), &secret).await?;

        let vm = VirtualMachine {
            metadata: ObjectMeta {
                name: Some(self.0.vm_name.clone()),
                namespace: Some(self.0.namespace.clone()),
                ..Default::default()
            },
            spec: VirtualMachineSpec {
                run_strategy: Some("Always".to_string()),
                template: VirtualMachineTemplate {
                    spec: Some(VirtualMachineTemplateSpec {
                        domain: VirtualMachineTemplateSpecDomain {
                            features: Some(VirtualMachineTemplateSpecDomainFeatures {
                                smm: Some(VirtualMachineTemplateSpecDomainFeaturesSmm {
                                    enabled: Some(true),
                                }),
                                ..Default::default()
                            }),
                            firmware: Some(VirtualMachineTemplateSpecDomainFirmware {
                                bootloader: Some(VirtualMachineTemplateSpecDomainFirmwareBootloader {
                                    efi: Some(VirtualMachineTemplateSpecDomainFirmwareBootloaderEfi {
                                        persistent: Some(true),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                            devices: VirtualMachineTemplateSpecDomainDevices {
                                disks: Some(vec![
                                    VirtualMachineTemplateSpecDomainDevicesDisks {
                                        name: "containerdisk".to_string(),
                                        disk: Some(VirtualMachineTemplateSpecDomainDevicesDisksDisk {
                                            bus: Some("virtio".to_string()),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    },
                                    VirtualMachineTemplateSpecDomainDevicesDisks {
                                        name: "cloudinitdisk".to_string(),
                                        disk: Some(VirtualMachineTemplateSpecDomainDevicesDisksDisk {
                                            bus: Some("virtio".to_string()),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    },
                                ]),
                                tpm: Some(VirtualMachineTemplateSpecDomainDevicesTpm {
                                    persistent: Some(true),
                                    ..Default::default()
                                }),
                                rng: Some(VirtualMachineTemplateSpecDomainDevicesRng {}),
                                ..Default::default()
                            },
                            resources: Some(VirtualMachineTemplateSpecDomainResources {
                                requests: Some(BTreeMap::from([
                                    (
                                        "memory".to_string(),
                                        IntOrString::String("4096M".to_string()),
                                    ),
                                    ("cpu".to_string(), IntOrString::Int(2)),
                                ])),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        volumes: Some(vec![
                            VirtualMachineTemplateSpecVolumes {
                                name: "containerdisk".to_string(),
                                container_disk: Some(VirtualMachineTemplateSpecVolumesContainerDisk {
                                    image: self.0.image.to_string(),
                                    image_pull_policy: Some("Always".to_string()),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            VirtualMachineTemplateSpecVolumes {
                                name: "cloudinitdisk".to_string(),
                                cloud_init_config_drive: Some(VirtualMachineTemplateSpecVolumesCloudInitConfigDrive {
                                    secret_ref: Some(VirtualMachineTemplateSpecVolumesCloudInitConfigDriveSecretRef {
                                        name: Some(secret_name),
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let vms: Api<VirtualMachine> = Api::namespaced(self.0.client.clone(), &self.0.namespace);
        vms.create(&Default::default(), &vm).await?;

        Ok(())
    }

    async fn wait_for_running(&self, timeout_secs: u64) -> Result<()> {
        let api: Api<VirtualMachine> = Api::namespaced(self.0.client.clone(), &self.0.namespace);

        let poller = Poller::new()
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_interval(Duration::from_secs(5))
            .with_error_message(format!(
                "VirtualMachine {} did not reach Running phase after {timeout_secs} seconds",
                self.0.vm_name
            ));

        let check_fn = || {
            let api = api.clone();
            async move {
                let vm = api.get(&self.0.vm_name).await?;
                let status = vm.status.and_then(|p| p.printable_status);
                if status.map(|s| s == "Running").unwrap_or(false) {
                    return Ok(());
                }
                let vm_name = &self.0.vm_name;
                let err = anyhow!("VirtualMachine {vm_name} is not in Running phase yet");
                Err(err)
            }
        };
        poller.poll_async(check_fn).await
    }

    async fn ssh_exec(&self, command: &str) -> Result<String> {
        let full_cmd = format!(
            "virtctl ssh -i {} core@vmi/{}/{} -t '-o IdentitiesOnly=yes' -t '-o StrictHostKeyChecking=no' --known-hosts /dev/null -c '{command}'",
            self.0.ssh_private_key.display(),
            self.0.vm_name,
            self.0.namespace,
        );

        ssh_exec(&full_cmd).await
    }

    async fn get_root_key(&self) -> Result<Option<Vec<u8>>> {
        // Extract the UUID from the Clevis token in the LUKS header
        let uuid_cmd = "sudo cryptsetup token export --token-id 0 /dev/vda4 | jq -r \".jwe.protected\" | base64 -d | jq -r \".clevis.path\" | cut -d/ -f2";
        let uuid_output = self
            .ssh_exec(uuid_cmd)
            .await
            .context("Failed to extract UUID from VM")?;
        let uuid = uuid_output.trim();

        if uuid.is_empty() {
            return Err(anyhow!("Retrieved empty UUID from VM"));
        }

        // Use the UUID to get the secret (secrets are named with just the UUID)
        let secrets: Api<Secret> = Api::namespaced(self.0.client.clone(), &self.0.namespace);
        let secret = secrets
            .get(uuid)
            .await
            .context(format!("Failed to get secret for UUID {uuid}"))?;
        Ok(Some(secret.data.unwrap().get("root").unwrap().0.clone()))
    }

    async fn cleanup(&self) -> Result<()> {
        self.0.cleanup();
        Ok(())
    }
}
