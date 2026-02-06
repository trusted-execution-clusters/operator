// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

pub mod azure;
pub mod kubevirt;

use anyhow::{Context, Result, anyhow};
use clevis_pin_trustee_lib::Key as ClevisKey;
use k8s_openapi::api::core::v1::Secret;
use kube::{Api, Client};
use std::{env, path::PathBuf, time::Duration};
use tokio::process::Command;

use endpoints::*;
use trusted_cluster_operator_lib::*;

use super::Poller;
use crate::{get_cluster_url, get_env};

/// Environment variable name for selecting the VM provider
pub const VIRT_PROVIDER_ENV: &str = "VIRT_PROVIDER";

#[derive(Clone)]
pub struct VmConfig {
    pub client: Client,
    pub namespace: String,
    pub vm_name: String,
    pub ssh_public_key: String,
    pub ssh_private_key: PathBuf,
    pub image: String,
}

impl VmConfig {
    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.ssh_private_key);
    }
}

pub fn generate_ssh_key_pair() -> Result<(String, PathBuf)> {
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
    let temp_dir = env::temp_dir();
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
        return Err(anyhow!("Failed to add SSH key to agent: {stderr}"));
    }

    Ok((public_key_str, key_path))
}

pub async fn generate_ignition(config: &VmConfig, with_ak: bool) -> Result<serde_json::Value> {
    use ignition_config::v3_5::*;
    let client = config.client.clone();
    let ns = &config.namespace;
    let register_server_url =
        get_cluster_url(client, ns, REGISTER_SERVER_SERVICE, REGISTER_SERVER_PORT).await?;
    let ignition = Ignition {
        version: "3.6.0-experimental".to_string(),
        config: Some(IgnitionConfig {
            merge: Some(vec![Resource {
                source: Some(format!(
                    "http://{register_server_url}/{REGISTER_SERVER_RESOURCE}"
                )),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut user = User::new("core".to_string());
    user.ssh_authorized_keys = Some(vec![config.ssh_public_key.clone()]);
    let mut serial_getty = Unit::new("serial-getty@ttyS0.service".to_string());
    serial_getty.dropins = Some(vec![Dropin {
        name: "autologin-core.conf".to_string(),
        contents: Some("[Service]\n# Override Execstart in main unit\nExecStart=\n# Add new Execstart with `-` prefix to ignore failure`\nExecStart=-/usr/sbin/agetty --autologin core --noclear %I $TERM\n".to_string()),
    }]);
    let mut pager = File::new("/etc/profile.d/systemd-pager.sh".to_string());
    pager.contents = Some(Resource {
        source: Some("data:,%23%20Tell%20systemd%20to%20not%20use%20a%20pager%20when%20printing%20information%0Aexport%20SYSTEMD_PAGER%3Dcat%0A".to_string()),
        compression: Some(String::new()),
        ..Default::default()
    });
    pager.mode = Some(0o644);
    let ignition_config = Config {
        ignition,
        kernel_arguments: None,
        passwd: Some(Passwd {
            users: Some(vec![user]),
            ..Default::default()
        }),
        storage: Some(Storage {
            files: Some(vec![pager]),
            ..Default::default()
        }),
        systemd: Some(Systemd {
            units: Some(vec![Unit::new("zincati.service".to_string()), serial_getty]),
        }),
    };

    let mut ignition_json = serde_json::to_value(&ignition_config).unwrap();
    if with_ak {
        ignition_json = patch_ak(config.client.clone(), ns, ignition_json).await?;
    }
    Ok(ignition_json)
}

async fn patch_ak(
    client: Client,
    namespace: &str,
    mut ignition: serde_json::Value,
) -> Result<serde_json::Value> {
    let svc = ATTESTATION_KEY_REGISTER_SERVICE;
    let port = ATTESTATION_KEY_REGISTER_PORT;
    let attestation_url = get_cluster_url(client, namespace, svc, port).await?;
    let ign_json = serde_json::json!({
        "attestation_key": {
            "registration": {
                "url": format!("http://{attestation_url}/{ATTESTATION_KEY_REGISTER_RESOURCE}"),
            }
        }
    });
    let obj = ignition.as_object_mut().unwrap();
    obj.insert("attestation".to_string(), ign_json);
    Ok(ignition)
}

pub async fn ssh_exec(command: &str) -> Result<String> {
    let output = Command::new("sh").arg("-c").arg(command).output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("ssh command failed: {stderr}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub async fn get_root_key(config: &VmConfig, ip: &str) -> Result<Vec<u8>> {
    let machines: Api<Machine> = Api::namespaced(config.client.clone(), &config.namespace);
    let list = machines.list(&Default::default()).await?;
    let retrieval = |m: &&Machine| m.spec.registration_address == ip;
    let err = format!("No machine found with registration IP {ip}");
    let machine = list.items.iter().find(retrieval).context(err)?;
    let machine_name = machine.metadata.name.clone().unwrap();
    let secret_name = machine_name.strip_prefix("machine-").unwrap();

    let secrets: Api<Secret> = Api::namespaced(config.client.clone(), &config.namespace);
    let secret = secrets.get(secret_name).await?;
    Ok(secret.data.unwrap().get("root").unwrap().0.clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VirtProvider {
    #[default]
    Kubevirt,
    Azure,
}

fn get_virt_provider() -> Result<VirtProvider> {
    match env::var(VIRT_PROVIDER_ENV) {
        Ok(val) => match val.to_lowercase().as_str() {
            "kubevirt" => Ok(VirtProvider::Kubevirt),
            "azure" => Ok(VirtProvider::Azure),
            v => Err(anyhow!(
                "Unknown {VIRT_PROVIDER_ENV} '{v}'. Supported providers: kubevirt, azure"
            )),
        },
        Err(env::VarError::NotPresent) => Ok(VirtProvider::default()),
        Err(e) => Err(anyhow!("{e}")),
    }
}

pub fn create_backend(
    client: Client,
    namespace: &str,
    vm_name: &str,
) -> Result<Box<dyn VmBackend>> {
    let provider = get_virt_provider()?;
    let (public_key, key_path) = generate_ssh_key_pair()?;
    let image = get_env("TEST_IMAGE")?;
    let config = VmConfig {
        client,
        namespace: namespace.to_string(),
        vm_name: vm_name.to_string(),
        ssh_public_key: public_key,
        ssh_private_key: key_path,
        image,
    };
    match provider {
        VirtProvider::Kubevirt => Ok(Box::new(kubevirt::KubevirtBackend(config))),
        VirtProvider::Azure => Ok(Box::new(azure::AzureBackend::new(config)?)),
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box)]
pub trait VmBackend: Send + Sync {
    async fn create_vm(&self) -> Result<()>;
    async fn wait_for_running(&self, timeout_secs: u64) -> Result<()>;
    async fn ssh_exec(&self, command: &str) -> Result<String>;
    async fn get_root_key(&self) -> Result<Option<Vec<u8>>>;
    async fn cleanup(&self) -> Result<()>;

    async fn wait_for_vm_ssh_ready(&self, timeout_secs: u64) -> Result<()> {
        self.wait_for_vm_ssh(timeout_secs, true).await
    }

    async fn wait_for_vm_ssh_unavail(&self, timeout_secs: u64) -> Result<()> {
        self.wait_for_vm_ssh(timeout_secs, false).await
    }

    async fn wait_for_vm_ssh(&self, timeout_secs: u64, await_start: bool) -> Result<()> {
        let avail_prefix = if await_start { "" } else { "un" };
        let poller = Poller::new()
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_interval(Duration::from_secs(10))
            .with_error_message(format!(
                "SSH access to VM did not become {}available after {} seconds",
                avail_prefix, timeout_secs
            ));

        let check_fn = || {
            async move {
                // Try a simple command to check if SSH is ready
                let result = self.ssh_exec("echo ready").await;
                let err = anyhow!("SSH not desired state yet: {result:?}");
                (result.is_err() ^ await_start).then_some(()).ok_or(err)
            }
        };
        poller.poll_async(check_fn).await
    }

    async fn verify_encrypted_root(&self, encryption_key: Option<&[u8]>) -> Result<bool> {
        let output = self.ssh_exec("lsblk -o NAME,TYPE -J").await?;
        let lsblk_output: serde_json::Value = serde_json::from_str(&output)?;

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
                if encryption_key.is_none() {
                    return Ok(true);
                }
                let jwk: ClevisKey = serde_json::from_slice(encryption_key.unwrap())?;
                let key = jwk.key;
                let dev = child.get("name").and_then(|n| n.as_str()).unwrap();
                let cmd = format!(
                    "jose jwe dec \
                     -k <(jose fmt -j '{{}}' -q oct -s kty -Uq $(printf {key} | jose b64 enc -I-) -s k -Uo-) \
                     -i <(sudo cryptsetup token export --token-id 0 /dev/{dev} | jose fmt -j- -Og jwe -o-) \
                     | sudo cryptsetup luksOpen --test-passphrase --key-file=- /dev/{dev}",
                );
                return self.ssh_exec(&cmd).await.map(|_| true);
            }
        }

        Ok(false)
    }
}
