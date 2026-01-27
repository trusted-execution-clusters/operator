// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::{Api, api::ObjectMeta};
use std::{collections::BTreeMap, time::Duration};
use trusted_cluster_operator_lib::{
    virtualmachineinstances::VirtualMachineInstance, virtualmachines::*,
};

use super::{VmBackend, VmConfig, ssh_exec};
use crate::Poller;
use crate::virt::{generate_ignition, get_root_key};

pub struct KubevirtBackend(pub VmConfig);

#[async_trait::async_trait]
impl VmBackend for KubevirtBackend {
    async fn create_vm(&self) -> Result<()> {
        let ignition_json = generate_ignition(&self.0);
        let vm = VirtualMachine {
            metadata: ObjectMeta {
                name: Some(self.0.vm_name.clone()),
                namespace: Some(self.0.namespace.clone()),
                ..Default::default()
            },
            spec: VirtualMachineSpec {
                run_strategy: Some("Always".to_string()),
                template: VirtualMachineTemplate {
                    metadata: Some(BTreeMap::from([(
                        "annotations".to_string(),
                        serde_json::json!({"kubevirt.io/ignitiondata": ignition_json}),
                    )])),
                    spec: Some(VirtualMachineTemplateSpec {
                        domain: VirtualMachineTemplateSpecDomain {
                            features: Some(VirtualMachineTemplateSpecDomainFeatures {
                                smm: Some(VirtualMachineTemplateSpecDomainFeaturesSmm {
                                    enabled: Some(true),
                                }),
                                ..Default::default()
                            }),
                            firmware: Some(VirtualMachineTemplateSpecDomainFirmware {
                                bootloader: Some(
                                    VirtualMachineTemplateSpecDomainFirmwareBootloader {
                                        efi: Some(
                                            VirtualMachineTemplateSpecDomainFirmwareBootloaderEfi {
                                                persistent: Some(true),
                                                ..Default::default()
                                            },
                                        ),
                                        ..Default::default()
                                    },
                                ),
                                ..Default::default()
                            }),
                            devices: VirtualMachineTemplateSpecDomainDevices {
                                disks: Some(vec![VirtualMachineTemplateSpecDomainDevicesDisks {
                                    name: "containerdisk".to_string(),
                                    disk: Some(VirtualMachineTemplateSpecDomainDevicesDisksDisk {
                                        bus: Some("virtio".to_string()),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }]),
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
                        volumes: Some(vec![VirtualMachineTemplateSpecVolumes {
                            name: "containerdisk".to_string(),
                            container_disk: Some(VirtualMachineTemplateSpecVolumesContainerDisk {
                                image: self.0.image.clone(),
                                image_pull_policy: Some("Always".to_string()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }),
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
                if let Some(status) = vm.status {
                    if let Some(phase) = status.printable_status {
                        if phase.as_str() == "Running" {
                            return Ok(());
                        }
                    }
                }
                let vm_name = &self.0.vm_name;
                let err = anyhow!("VirtualMachine {vm_name} is not in Running phase yet");
                Err(err)
            }
        };
        poller.poll_async(check_fn).await
    }

    async fn ssh_exec(&self, command: &str) -> Result<String> {
        if which::which("virtctl").is_err() {
            let err = "virtctl command not found. Please install virtctl first.";
            return Err(anyhow!(err));
        }

        let full_cmd = format!(
            "virtctl ssh -i {} core@vmi/{}/{} -t '-o IdentitiesOnly=yes' -t '-o StrictHostKeyChecking=no' --known-hosts /dev/null -c '{command}'",
            self.0.ssh_private_key.display(),
            self.0.vm_name,
            self.0.namespace,
        );

        ssh_exec(&full_cmd).await
    }

    async fn get_root_key(&self) -> Result<Vec<u8>> {
        let vmis: Api<VirtualMachineInstance> =
            Api::namespaced(self.0.client.clone(), &self.0.namespace);
        let vmi = vmis.get(&self.0.vm_name).await?;
        let interfaces = vmi.status.unwrap().interfaces.unwrap();
        let ip = interfaces.first().unwrap().ip_address.clone().unwrap();
        get_root_key(&self.0, &ip).await
    }

    async fn cleanup(&self) -> Result<()> {
        // Stub, cleanup is handled by namespace removal
        Ok(())
    }
}
