// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use clevis_pin_trustee_lib::Key as ClevisKey;
use ignition_config::v3_5::{
    Config, Dropin, File, Ignition, IgnitionConfig, Passwd, Resource, Storage, Systemd, Unit, User,
};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use kube::{Api, Client};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use trusted_cluster_operator_lib::virtualmachines::*;

use super::Poller;

pub fn generate_ssh_key_pair() -> anyhow::Result<(String, String, std::path::PathBuf)> {
    use rand_core::OsRng;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command as StdCommand;

    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None })?;
    let private_key_str = private_key.to_openssh(LineEnding::LF)?.to_string();
    let public_key = private_key.public_key();
    let public_key_str = public_key.to_openssh()?;

    // Save private key to a temporary file
    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join(format!("ssh_key_{}", uuid::Uuid::new_v4()));
    fs::write(&key_path, &private_key_str)?;

    // Set proper permissions (0600) for SSH key
    let mut perms = fs::metadata(&key_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&key_path, perms)?;

    // Add key to ssh-agent using synchronous command
    let ssh_add_output = StdCommand::new("ssh-add")
        .arg(key_path.to_str().unwrap())
        .output()?;

    if !ssh_add_output.status.success() {
        let stderr = String::from_utf8_lossy(&ssh_add_output.stderr);
        // Clean up the key file if ssh-add fails
        let _ = fs::remove_file(&key_path);
        return Err(anyhow::anyhow!(
            "Failed to add SSH key to agent: {}",
            stderr
        ));
    }

    Ok((private_key_str, public_key_str, key_path))
}

pub fn generate_ignition_config(
    ssh_public_key: &str,
    register_server_url: &str,
) -> serde_json::Value {
    // Create the ignition configuration
    let ignition = Ignition {
        version: "3.5.0".to_string(),
        config: Some(IgnitionConfig {
            merge: Some(vec![Resource {
                source: Some(register_server_url.to_string()),
                compression: None,
                http_headers: None,
                verification: None,
            }]),
            replace: None,
        }),
        proxy: None,
        security: None,
        timeouts: None,
    };

    let mut user = User::new("core".to_string());
    user.ssh_authorized_keys = Some(vec![ssh_public_key.to_string()]);
    let config = Config {
        ignition,
        kernel_arguments: None,
        passwd: Some(Passwd {
            users: Some(vec![user]),
            groups: None,
        }),
        storage: Some(Storage {
            directories: None,
            disks: None,
            files: Some(vec![File {
                path: "/etc/profile.d/systemd-pager.sh".to_string(),
                contents: Some(Resource {
                    source: Some("data:,%23%20Tell%20systemd%20to%20not%20use%20a%20pager%20when%20printing%20information%0Aexport%20SYSTEMD_PAGER%3Dcat%0A".to_string()),
                    compression: Some(String::new()),
                    http_headers: None,
                    verification: None,
                }),
                mode: Some(420),
                append: None,
                group: None,
                overwrite: None,
                user: None,
            }]),
            filesystems: None,
            links: None,
            luks: None,
            raid: None,
        }),
        systemd: Some(Systemd {
            units: Some(vec![
                Unit {
                    name: "zincati.service".to_string(),
                    enabled: Some(false),
                    contents: None,
                    dropins: None,
                    mask: None,
                },
                Unit {
                    name: "serial-getty@ttyS0.service".to_string(),
                    enabled: None,
                    contents: None,
                    mask: None,
                    dropins: Some(vec![Dropin {
                        name: "autologin-core.conf".to_string(),
                        contents: Some("[Service]\n# Override Execstart in main unit\nExecStart=\n# Add new Execstart with `-` prefix to ignore failure`\nExecStart=-/usr/sbin/agetty --autologin core --noclear %I $TERM\n".to_string()),
                    }]),
                },
            ]),
        }),
    };

    serde_json::to_value(&config).expect("Failed to serialize ignition config")
}

/// Create a KubeVirt VirtualMachine with the specified configuration
pub async fn create_kubevirt_vm(
    client: &Client,
    namespace: &str,
    vm_name: &str,
    ssh_public_key: &str,
    register_server_url: &str,
    image: &str,
) -> anyhow::Result<()> {
    let ignition_config = generate_ignition_config(ssh_public_key, register_server_url);
    let ignition_json = serde_json::to_string(&ignition_config)?;

    let vm = VirtualMachine {
        metadata: ObjectMeta {
            name: Some(vm_name.to_string()),
            namespace: Some(namespace.to_string()),
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
                            image: image.to_string(),
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

    let vms: Api<VirtualMachine> = Api::namespaced(client.clone(), namespace);
    vms.create(&Default::default(), &vm).await?;

    Ok(())
}

/// Wait for a KubeVirt VirtualMachine to reach Running phase
pub async fn wait_for_vm_running(
    client: &Client,
    namespace: &str,
    vm_name: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let api: Api<VirtualMachine> = Api::namespaced(client.clone(), namespace);

    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(5))
        .with_error_message(format!(
            "VirtualMachine {} did not reach Running phase after {} seconds",
            vm_name, timeout_secs
        ));

    poller
        .poll_async(|| {
            let api = api.clone();
            let name = vm_name.to_string();
            async move {
                let vm = api.get(&name).await?;

                // Check VM status phase
                if let Some(status) = vm.status {
                    if let Some(phase) = status.printable_status {
                        if phase.as_str() == "Running" {
                            return Ok(());
                        }
                    }
                }

                Err(anyhow::anyhow!(
                    "VirtualMachine {} is not in Running phase yet",
                    name
                ))
            }
        })
        .await
}

pub async fn virtctl_ssh_exec(
    namespace: &str,
    vm_name: &str,
    key_path: &Path,
    command: &str,
) -> anyhow::Result<String> {
    if which::which("virtctl").is_err() {
        return Err(anyhow::anyhow!(
            "virtctl command not found. Please install virtctl first."
        ));
    }

    let _vm_target = format!("core@vmi/{}/{}", vm_name, namespace);
    let full_cmd = format!(
        "virtctl ssh -i {} core@vmi/{}/{} -t '-o IdentitiesOnly=yes' -t '-o StrictHostKeyChecking=no' --known-hosts /dev/null -c '{}'",
        key_path.display(),
        vm_name,
        namespace,
        command
    );

    let output = Command::new("sh").arg("-c").arg(full_cmd).output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("virtctl ssh command failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub async fn wait_for_vm_ssh_ready(
    namespace: &str,
    vm_name: &str,
    key_path: &Path,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(10))
        .with_error_message(format!(
            "SSH access to VM {}/{} did not become available after {} seconds",
            namespace, vm_name, timeout_secs
        ));

    poller
        .poll_async(|| {
            let ns = namespace.to_string();
            let vm = vm_name.to_string();
            let key = key_path.to_path_buf();
            async move {
                // Try a simple command to check if SSH is ready
                match virtctl_ssh_exec(&ns, &vm, &key, "echo ready").await {
                    Ok(_) => Ok(()),
                    Err(e) => Err(anyhow::anyhow!("SSH not ready yet: {}", e)),
                }
            }
        })
        .await
}

pub async fn verify_encrypted_root(
    namespace: &str,
    vm_name: &str,
    key_path: &Path,
    encryption_key: &[u8],
) -> anyhow::Result<bool> {
    let output = virtctl_ssh_exec(namespace, vm_name, key_path, "lsblk -o NAME,TYPE -J").await?;

    // Parse JSON output
    let lsblk_output: serde_json::Value = serde_json::from_str(&output)?;

    // Look for a device with name "root" and type "crypt"
    let get_children = |val: &serde_json::Value| {
        let children = val.get("children").and_then(|v| v.as_array());
        children.map(|v| v.to_vec()).unwrap_or_default()
    };
    let devices = lsblk_output.get("blockdevices").and_then(|v| v.as_array());
    for child in devices.into_iter().flatten().flat_map(get_children) {
        if get_children(&child).iter().any(|nested| {
            let name = nested.get("name").and_then(|n| n.as_str());
            let dev_type = nested.get("type").and_then(|t| t.as_str());
            name == Some("root") && dev_type == Some("crypt")
        }) {
            let jwk: ClevisKey = serde_json::from_slice(encryption_key)?;
            let key = jwk.key;
            let dev = child.get("name").and_then(|n| n.as_str()).unwrap();
            let cmd = format!(
                "jose jwe dec \
                 -k <(jose fmt -j '{{}}' -q oct -s kty -Uq $(printf {key} | jose b64 enc -I-) -s k -Uo-) \
                 -i <(sudo cryptsetup token export --token-id 0 /dev/{dev} | jose fmt -j- -Og jwe -o-) \
                 | sudo cryptsetup luksOpen --test-passphrase --key-file=- /dev/{dev}",
            );
            let exec = virtctl_ssh_exec(namespace, vm_name, key_path, &cmd).await;
            return exec.map(|_| true);
        }
    }

    Ok(false)
}
