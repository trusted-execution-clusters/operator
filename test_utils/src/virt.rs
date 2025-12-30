// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use ignition_config::v3_5::{
    Config, Dropin, File, Ignition, IgnitionConfig, Passwd, Resource, Storage, Systemd, Unit, User,
};
use kube::Client;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;

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
/// TODO create rust a create for KubeVirt virtual machines
pub async fn create_kubevirt_vm(
    client: &Client,
    namespace: &str,
    vm_name: &str,
    ssh_public_key: &str,
    register_server_url: &str,
    image: &str,
) -> anyhow::Result<()> {
    use kube::Api;
    use kube::api::PostParams;
    use kube::core::DynamicObject;
    use kube::discovery;

    let ignition_config = generate_ignition_config(ssh_public_key, register_server_url);
    let ignition_json = serde_json::to_string(&ignition_config)?;

    let vm_spec = serde_json::json!({
        "apiVersion": "kubevirt.io/v1",
        "kind": "VirtualMachine",
        "metadata": {
            "name": vm_name,
            "namespace": namespace
        },
        "spec": {
            "runStrategy": "Always",
            "template": {
                "metadata": {
                    "annotations": {
                        "kubevirt.io/ignitiondata": ignition_json
                    }
                },
                "spec": {
                    "domain": {
                        "features": {
                            "smm": {
                                "enabled": true
                            }
                        },
                        "firmware": {
                            "bootloader": {
                                "efi": {
                                    "persistent": true
                                }
                            }
                        },
                        "devices": {
                            "tpm": {
                                "persistent": true
                            },
                            "disks": [
                                {
                                    "name": "containerdisk",
                                    "disk": {
                                        "bus": "virtio"
                                    }
                                }
                            ],
                            "rng": {}
                        },
                        "resources": {
                            "requests": {
                                "cpu": "2",
                                "memory": "4096M"
                            }
                        }
                    },
                    "volumes": [
                        {
                            "name": "containerdisk",
                            "containerDisk": {
                                "image": image,
                                "imagePullPolicy": "Always"
                            }
                        }
                    ]
                }
            }
        }
    });

    let discovery = discovery::Discovery::new(client.clone()).run().await?;

    let apigroup = discovery
        .groups()
        .find(|g| g.name() == "kubevirt.io")
        .ok_or_else(|| anyhow::anyhow!("kubevirt.io API group not found"))?;

    let (ar, _caps) = apigroup
        .recommended_kind("VirtualMachine")
        .ok_or_else(|| anyhow::anyhow!("VirtualMachine kind not found"))?;

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let vm_object: DynamicObject = serde_json::from_value(vm_spec)?;

    api.create(&PostParams::default(), &vm_object).await?;

    Ok(())
}

/// Wait for a KubeVirt VirtualMachine to reach Running phase
pub async fn wait_for_vm_running(
    client: &Client,
    namespace: &str,
    vm_name: &str,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    use kube::api::Api;
    use kube::core::DynamicObject;
    use kube::discovery;

    // Discover the VirtualMachine API
    let discovery = discovery::Discovery::new(client.clone()).run().await?;

    let apigroup = discovery
        .groups()
        .find(|g| g.name() == "kubevirt.io")
        .ok_or_else(|| anyhow::anyhow!("kubevirt.io API group not found"))?;

    let (ar, _caps) = apigroup
        .recommended_kind("VirtualMachine")
        .ok_or_else(|| anyhow::anyhow!("VirtualMachine kind not found"))?;

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

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
                if let Some(status) = vm.data.get("status") {
                    if let Some(phase) = status.get("printableStatus") {
                        if let Some(phase_str) = phase.as_str() {
                            if phase_str == "Running" {
                                return Ok(());
                            }
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
) -> anyhow::Result<bool> {
    let output = virtctl_ssh_exec(namespace, vm_name, key_path, "lsblk -o NAME,TYPE -J").await?;

    // Parse JSON output
    let lsblk_output: serde_json::Value = serde_json::from_str(&output)?;

    // Look for a device with name "root" and type "crypt"
    if let Some(blockdevices) = lsblk_output.get("blockdevices") {
        if let Some(devices) = blockdevices.as_array() {
            for device in devices {
                // Check the device itself
                if is_root_crypt_device(device) {
                    return Ok(true);
                }

                // Check children devices recursively
                if let Some(children) = device.get("children") {
                    if let Some(children_arr) = children.as_array() {
                        for child in children_arr {
                            if is_root_crypt_device(child) {
                                return Ok(true);
                            }
                            // Check nested children
                            if let Some(nested_children) = child.get("children") {
                                if let Some(nested_arr) = nested_children.as_array() {
                                    for nested in nested_arr {
                                        if is_root_crypt_device(nested) {
                                            return Ok(true);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(false)
}

fn is_root_crypt_device(device: &serde_json::Value) -> bool {
    let name = device.get("name").and_then(|n| n.as_str());
    let dev_type = device.get("type").and_then(|t| t.as_str());

    if let (Some(n), Some(t)) = (name, dev_type) {
        if n == "root" && t == "crypt" {
            return true;
        }
    }

    false
}
