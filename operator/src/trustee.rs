// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
// SPDX-FileCopyrightText: Dehan Meng <demeng@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use clevis_pin_trustee_lib::Key as ClevisKey;
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EmptyDirVolumeSource, EnvVar,
    KeyToPath, PodSpec, PodTemplateSpec, ProjectedVolumeSource, Secret, SecretProjection,
    SecretVolumeSource, Service, ServicePort, ServiceSpec, Volume, VolumeMount, VolumeProjection,
};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{LabelSelector, OwnerReference},
    util::intstr::IntOrString,
};

use kube::{
    Api, Client, Resource,
    api::{ObjectMeta, Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use log::{info, warn};
use operator::{
    ControllerError, RvContextData, TLS_DIR, controller_error_policy, controller_info,
    create_or_info_if_exists, read_certificate,
};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Serialize, Serializer};
use serde_json::{Value::String as JsonString, json};
use std::collections::BTreeMap;
use std::sync::Arc;

use trusted_cluster_operator_lib::reference_values::*;
use trusted_cluster_operator_lib::{Machine, endpoints::*};

const TRUSTEE_DATA_DIR: &str = "/opt/trustee";
pub const TRUSTEE_SECRETS_PATH: &str = "/opt/trustee/kbs-repository/default";
const KBS_CONFIG_FILE: &str = "kbs-config.toml";
pub(crate) const REFERENCE_VALUES_FILE: &str = "reference-values.json";

pub(crate) const TRUSTEE_DATA_MAP: &str = "trustee-data";
const ATT_POLICY_MAP: &str = "attestation-policy";
const TRUSTED_AK_KEYS_VOLUME: &str = "trusted-ak-keys";
const TRUSTED_AK_KEYS_DIR: &str = "/etc/tpm/trusted_ak_keys";
const TRUSTEE_AUTH_SECRET: &str = "trustee-auth";
const TRUSTEE_AUTH_KEY_DIR: &str = "/key";
const TRUSTEE_AUTH_PUB_KEY: &str = "public.pub";
const TRUSTEE_AUTH_PRIV_KEY: &str = "private.key";

fn primitive_date_time_to_str<S>(d: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Sync with Trustee
/// reference_value_provider_service::reference_value::ReferenceValue
/// (cannot import directly because its expiration doesn't serialize
/// right)
#[derive(Serialize)]
struct ReferenceValue {
    pub version: String,
    pub name: String,
    #[serde(serialize_with = "primitive_date_time_to_str")]
    pub expiration: DateTime<Utc>,
    pub value: serde_json::Value,
}

pub fn get_image_pcrs(image_pcrs_map: ConfigMap) -> Result<ImagePcrs> {
    let err = "Image PCRs map existed, but had no data";
    let image_pcrs_data = image_pcrs_map.data.context(err)?;
    let err = "Image PCRs data existed, but had no file";
    let image_pcrs_str = image_pcrs_data.get(PCR_CONFIG_FILE).context(err)?;
    serde_json::from_str(image_pcrs_str).map_err(Into::into)
}

fn recompute_reference_values(image_pcrs: ImagePcrs) -> Vec<ReferenceValue> {
    // TODO many grub+shim:many OS image recompute once supported
    let mut reference_values_in =
        BTreeMap::from([("svn".to_string(), vec![JsonString("1".to_string())])]);
    for pcr in image_pcrs.0.values().flat_map(|v| &v.pcrs) {
        reference_values_in
            .entry(format!("pcr{}", pcr.id))
            .or_default()
            .push(JsonString(pcr.value.clone()));
    }
    reference_values_in
        .iter()
        .map(|(name, values)| ReferenceValue {
            version: "0.1.0".to_string(),
            name: format!("tpm_{name}"),
            expiration: Utc::now() + chrono::Duration::days(365),
            value: serde_json::Value::Array(values.to_vec()),
        })
        .collect()
}

pub async fn update_reference_values(ctx: RvContextData) -> Result<()> {
    let config_maps: Api<ConfigMap> = Api::default_namespaced(ctx.client);

    let image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let reference_values = recompute_reference_values(get_image_pcrs(image_pcrs_map)?);
    let rv_json = serde_json::to_string(&reference_values)?;

    let mut trustee_map = config_maps.get(TRUSTEE_DATA_MAP).await?;
    let err = format!("ConfigMap {TRUSTEE_DATA_MAP} existed, but had no data");
    let trustee_data = trustee_map.data.as_mut().context(err)?;
    trustee_data.insert(REFERENCE_VALUES_FILE.to_string(), rv_json);

    config_maps
        .replace(TRUSTEE_DATA_MAP, &Default::default(), &trustee_map)
        .await?;
    info!("Recomputed reference values");
    Ok(())
}

pub struct Ed25519KeyPair {
    pub private_key_pem: Vec<u8>,
    pub public_key_pem: Vec<u8>,
}

fn generate_ed25519_key_pair() -> Result<Ed25519KeyPair> {
    let key = openssl::pkey::PKey::generate_ed25519()?;
    let private_key_pem = key.private_key_to_pem_pkcs8()?;
    let public_key_pem = key.public_key_to_pem()?;
    Ok(Ed25519KeyPair {
        private_key_pem,
        public_key_pem,
    })
}

fn generate_luks_key() -> Result<Vec<u8>> {
    // Constraint: 32 bytes b64-encoded, thus 24
    let mut pass = [0; 24];
    openssl::rand::rand_bytes(&mut pass)?;
    let key = general_purpose::STANDARD.encode(pass);
    let jwk = ClevisKey {
        key_type: "oct".to_string(),
        key,
    };
    serde_json::to_vec(&jwk).map_err(Into::into)
}
async fn get_auth_key_token(client: &Client) -> Result<String> {
    let secret_api: Api<Secret> = Api::default_namespaced(client.clone());
    let auth_secret = secret_api.get(TRUSTEE_AUTH_SECRET).await?;
    let auth_data = auth_secret.data.context("Auth secret has no data")?;
    let auth_key_bytes = auth_data
        .get("private.key")
        .context("Auth secret missing private.key")?;

    let claims = json!({
        "role": "admin",
        "exp": i32::MAX
    });

    let encoding_key = EncodingKey::from_ed_pem(auth_key_bytes.0.as_slice())?;

    let token = encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key)?;
    Ok(token)
}
async fn get_kbs_connection(client: &Client) -> Result<(String, Vec<String>)> {
    let tec = trusted_cluster_operator_lib::get_trusted_execution_cluster(client.clone()).await?;
    let secret_api: Api<Secret> = Api::default_namespaced(client.clone());

    if let Some(secret_name) = &tec.spec.trustee_secret {
        if let Ok(secret) = secret_api.get(secret_name).await {
            if let Some(ca_crt) = secret.data.as_ref().and_then(|d| d.get("ca.crt")) {
                let ca_pem = String::from_utf8(ca_crt.0.clone())
                    .context("ca certificate is not valid UTF-8")?;
                let trustee_addr = format!(
                    "https://{}",
                    tec.spec
                        .public_trustee_addr
                        .as_ref()
                        .context("TrustedExecutionCluster missing public_trustee_addr HTTPS")?
                );
                return Ok((trustee_addr, vec![ca_pem]));
            }
        }
    }

    Ok((
        format!(
            "http://{}",
            tec.spec
                .public_trustee_addr
                .as_ref()
                .context("TrustedExecutionCluster missing public_trustee_addr HTTP")?
        ),
        vec![],
    ))
}

pub fn secret_path(id: &str) -> String {
    format!("default/{id}/root")
}

pub async fn send_secret(client: Client, id: &str) -> Result<()> {
    let secret_api: Api<Secret> = Api::default_namespaced(client.clone());
    let auth_key_token = get_auth_key_token(&client).await?;
    let (url, certs) = get_kbs_connection(&client).await?;
    let secret = secret_api.get(id).await?;
    let secret_data = secret.data.context("Secret has no data")?;
    let resource_bytes = secret_data
        .get("root")
        .context("Secret missing root key")?
        .0
        .clone();
    let path = secret_path(id);
    info!("Sending secret {id} to KBS API...");
    kbs_client::set_resource(&url, Some(auth_key_token), resource_bytes, &path, certs).await?;
    info!("Secret {id} sent successfully");
    Ok(())
}

pub async fn delete_secret(client: Client, id: &str) -> Result<()> {
    let auth_key_token = get_auth_key_token(&client).await?;
    let (url, certs) = get_kbs_connection(&client).await?;
    let path = secret_path(id);
    info!("Deleting secret {id} to KBS API...");
    kbs_client::delete_resource(&url, Some(auth_key_token), &path, certs).await?;
    info!("Secret {id} deleted successfully");
    Ok(())
}

pub async fn sync_all_machine_luks_key(client: Client) -> Result<()> {
    let machine_api: Api<Machine> = Api::default_namespaced(client.clone());
    let machine_list = machine_api.list(&Default::default()).await?;

    let machine_ids: Vec<String> = machine_list
        .items
        .iter()
        .map(|machine| machine.spec.id.clone())
        .collect();

    info!("Syncing {} machine luks key to KBS", machine_ids.len());
    for id in &machine_ids {
        if let Err(e) = send_secret(client.clone(), id).await {
            warn!("Failed to sync secret {id} to KBS: {e}");
        }
    }
    Ok(())
}

async fn trustee_deployment_reconcile(
    deployment: Arc<Deployment>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    if let Some(status) = &deployment.status {
        if let Some(is_available) = &status.conditions {
            if is_available
                .iter()
                .any(|c| {
                    c.type_ == "Available" && c.status == "True"
                }) {
                    sync_all_machine_luks_key(Arc::unwrap_or_clone(client.clone()))
                        .await
                        .map_err(ControllerError::Anyhow)?;
                }
        }
    }
    Ok(Action::await_change())
}

pub async fn launch_trustee_sync_controller(client: Client) {
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    let watcher_config = watcher::Config {
        label_selector: Some(format!("app={TRUSTEE_APP_LABEL}")),
        ..Default::default()
    };
    tokio::spawn(
        Controller::new(deployments, watcher_config)
            .run(
                trustee_deployment_reconcile,
                controller_error_policy,
                Arc::new(client),
            )
            .for_each(controller_info),
    );
}

pub async fn update_attestation_keys(client: Client) -> Result<()> {
    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    let secret_list = secrets.list(&Default::default()).await?;

    let ak_secrets: Vec<String> = secret_list
        .items
        .iter()
        .filter(|secret| {
            // Filter out secrets that are being deleted
            if secret.metadata.deletion_timestamp.is_some() {
                return false;
            }

            secret
                .metadata
                .owner_references
                .as_ref()
                .map(|owners| owners.iter().any(|owner| owner.kind == "AttestationKey"))
                .unwrap_or(false)
        })
        .filter_map(|secret| secret.metadata.name.clone())
        .collect();

    let deployments: Api<Deployment> = Api::default_namespaced(client);
    let deployment = deployments.get(TRUSTEE_DEPLOYMENT).await?;
    let err = format!("Deployment {TRUSTEE_DEPLOYMENT} existed, but had no spec");
    let depl_spec = deployment.spec.as_ref().context(err)?;
    let err = format!("Deployment {TRUSTEE_DEPLOYMENT} existed, but had no pod spec");
    let pod_spec = depl_spec.template.spec.as_ref().context(err)?;

    // Get existing volumes and volumeMounts, filtering out the attestation key volume
    let mut volumes: Vec<Volume> = pod_spec
        .volumes
        .as_ref()
        .map(|v| {
            v.iter()
                .filter(|vol| vol.name != TRUSTED_AK_KEYS_VOLUME)
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    let err = format!("Deployment {TRUSTEE_DEPLOYMENT} existed, but had no containers");
    let container = pod_spec.containers.first().context(err)?;
    let mut vol_mounts: Vec<VolumeMount> = container
        .volume_mounts
        .as_ref()
        .map(|vm| {
            vm.iter()
                .filter(|mount| mount.name != TRUSTED_AK_KEYS_VOLUME)
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    if ak_secrets.is_empty() {
        info!(
            "No AttestationKey secrets found, removing projected volume from {TRUSTEE_DEPLOYMENT}"
        );
    } else {
        // Build the projected volume with all AttestationKey secrets
        let projections: Vec<VolumeProjection> = ak_secrets
            .iter()
            .map(|secret_name| VolumeProjection {
                secret: Some(SecretProjection {
                    name: secret_name.to_string(),
                    items: Some(vec![KeyToPath {
                        key: "public_key".to_string(),
                        path: format!("{secret_name}.pub"),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .collect();

        let projected_volume = Volume {
            name: TRUSTED_AK_KEYS_VOLUME.to_string(),
            projected: Some(ProjectedVolumeSource {
                sources: Some(projections),
                ..Default::default()
            }),
            ..Default::default()
        };

        volumes.push(projected_volume);

        vol_mounts.push(VolumeMount {
            name: TRUSTED_AK_KEYS_VOLUME.to_string(),
            mount_path: TRUSTED_AK_KEYS_DIR.to_string(),
            ..Default::default()
        });
    }

    // Check if volumes or volumeMounts have changed
    let volumes_changed = pod_spec.volumes.as_ref() != Some(&volumes);
    let vol_mounts_changed = container.volume_mounts.as_ref() != Some(&vol_mounts);

    if volumes_changed || vol_mounts_changed {
        // Patch the deployment with updated volumes and volumeMounts
        let patch = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": TRUSTEE_DEPLOYMENT
            },
            "spec": {
                "template": {
                    "spec": {
                        "volumes": volumes,
                        "containers": [{
                            "name": "kbs",
                            "volumeMounts": vol_mounts
                        }]
                    }
                }
            }
        });

        deployments
            .patch(
                TRUSTEE_DEPLOYMENT,
                &PatchParams::apply("trusted-cluster-operator").force(),
                &Patch::Apply(&patch),
            )
            .await?;
        info!("Successfully patched {TRUSTEE_DEPLOYMENT} with attestation key volumes");
    } else {
        info!("No changes to attestation key volumes, skipping deployment update");
    }

    Ok(())
}

pub async fn generate_secret(
    client: Client,
    id: &str,
    owner_reference: OwnerReference,
) -> Result<()> {
    let secret_data = k8s_openapi::ByteString(generate_luks_key()?);
    let data = BTreeMap::from([("root".to_string(), secret_data)]);

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(id.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    create_or_info_if_exists!(client, Secret, secret);
    Ok(())
}

pub async fn generate_trustee_auth_keys_secret(
    client: Client,
    owner_reference: OwnerReference,
) -> Result<()> {
    let key_pair = generate_ed25519_key_pair()?;
    let data = BTreeMap::from([
        (
            TRUSTEE_AUTH_PRIV_KEY.to_string(),
            k8s_openapi::ByteString(key_pair.private_key_pem),
        ),
        (
            TRUSTEE_AUTH_PUB_KEY.to_string(),
            k8s_openapi::ByteString(key_pair.public_key_pem),
        ),
    ]);

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(TRUSTEE_AUTH_SECRET.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    create_or_info_if_exists!(client, Secret, secret);
    Ok(())
}

pub async fn generate_attestation_policy(
    client: Client,
    owner_reference: OwnerReference,
) -> Result<()> {
    let policy_rego = include_str!("tpm.rego");
    let data = BTreeMap::from([
        ("default_cpu.rego".to_string(), policy_rego.to_string()),
        // Must create GPU policy or Trustee will attempt to write one to the read-only mount
        ("default_gpu.rego".to_string(), String::new()),
    ]);

    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(ATT_POLICY_MAP.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    create_or_info_if_exists!(client, ConfigMap, config_map);
    Ok(())
}

fn generate_kbs_config(has_certificate: bool) -> Result<String> {
    let kbs_config_template = include_str!("kbs-config.toml");
    let mut config: toml::Table = toml::from_str(kbs_config_template)?;

    let section_err = "kbs-config.toml missing http_server section";
    let http_section = config.get_mut("http_server").context(section_err)?;
    let server_err = "http_server is not a table";
    let http_server = http_section.as_table_mut().context(server_err)?;

    if has_certificate {
        let tls_key = toml::Value::String(format!("{TLS_DIR}/tls.key"));
        http_server.insert("private_key".to_string(), tls_key);
        let tls_cert = toml::Value::String(format!("{TLS_DIR}/tls.crt"));
        http_server.insert("certificate".to_string(), tls_cert);
    } else {
        http_server.insert("insecure_http".to_string(), toml::Value::Boolean(true));
    }

    Ok(toml::to_string(&config)?)
}

pub async fn generate_trustee_data(
    client: Client,
    owner_reference: OwnerReference,
    secret: &Option<String>,
) -> Result<()> {
    let has_certificate = read_certificate(client.clone(), secret).await?.is_some();
    let kbs_config = generate_kbs_config(has_certificate)?;
    let policy_rego = include_str!("resource.rego");

    let data = BTreeMap::from([
        ("kbs-config.toml".to_string(), kbs_config),
        ("policy.rego".to_string(), policy_rego.to_string()),
        (REFERENCE_VALUES_FILE.to_string(), "[]".to_string()),
    ]);

    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(TRUSTEE_DATA_MAP.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    create_or_info_if_exists!(client, ConfigMap, config_map);
    Ok(())
}

pub async fn generate_kbs_service(
    client: Client,
    owner_reference: OwnerReference,
    kbs_port: Option<i32>,
) -> Result<()> {
    let app_string = TRUSTEE_APP_LABEL.to_string();
    let selector = Some(BTreeMap::from([("app".to_string(), app_string)]));

    let service = Service {
        metadata: ObjectMeta {
            name: Some(TRUSTEE_SERVICE.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: selector.clone(),
            ports: Some(vec![ServicePort {
                name: Some("kbs-port".to_string()),
                port: kbs_port.unwrap_or(TRUSTEE_PORT),
                target_port: Some(IntOrString::Int(TRUSTEE_PORT)),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };
    create_or_info_if_exists!(client, Service, service);
    Ok(())
}

fn generate_kbs_volume_templates() -> [(&'static str, &'static str, Volume); 4] {
    [
        (
            ATT_POLICY_MAP,
            "/opt/trustee/policies/opa",
            Volume {
                config_map: Some(ConfigMapVolumeSource {
                    name: ATT_POLICY_MAP.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            TRUSTEE_DATA_MAP,
            TRUSTEE_DATA_DIR,
            Volume {
                config_map: Some(ConfigMapVolumeSource {
                    name: TRUSTEE_DATA_MAP.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "resource-dir",
            TRUSTEE_SECRETS_PATH,
            Volume {
                empty_dir: Some(EmptyDirVolumeSource {
                    medium: Some("Memory".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            TRUSTEE_AUTH_SECRET,
            TRUSTEE_AUTH_KEY_DIR,
            Volume {
                secret: Some(SecretVolumeSource {
                    secret_name: Some(TRUSTEE_AUTH_SECRET.to_string()),
                    items: Some(vec![KeyToPath {
                        key: "public.pub".to_string(),
                        path: "public.pub".to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
    ]
}

fn generate_kbs_pod_spec(image: &str, tls_volumes: Option<(Volume, VolumeMount)>) -> PodSpec {
    let volume_templates = generate_kbs_volume_templates();
    let mut volumes: Vec<Volume> = volume_templates
        .iter()
        .map(|(name, _, volume)| {
            let mut volume = volume.clone();
            volume.name = name.to_string();
            volume
        })
        .collect();
    let mut volume_mounts: Vec<VolumeMount> = volume_templates
        .iter()
        .map(|(name, mount_path, _)| VolumeMount {
            name: name.to_string(),
            mount_path: mount_path.to_string(),
            ..Default::default()
        })
        .collect();

    if let Some((volume, volume_mount)) = tls_volumes {
        volumes.push(volume);
        volume_mounts.push(volume_mount);
    }

    PodSpec {
        containers: vec![Container {
            command: Some(vec![
                "/usr/local/bin/kbs".to_string(),
                "--config-file".to_string(),
                format!("{TRUSTEE_DATA_DIR}/{KBS_CONFIG_FILE}"),
            ]),
            env: Some(vec![EnvVar {
                name: "RUST_LOG".to_string(),
                value: Some("debug".to_string()),
                ..Default::default()
            }]),
            image: Some(image.to_string()),
            name: "kbs".to_string(),
            ports: Some(vec![ContainerPort {
                container_port: TRUSTEE_PORT,
                ..Default::default()
            }]),
            volume_mounts: Some(volume_mounts),
            ..Default::default()
        }],
        volumes: Some(volumes),
        ..Default::default()
    }
}

pub async fn generate_kbs_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
    secret: &Option<String>,
) -> Result<()> {
    let selector = Some(BTreeMap::from([(
        "app".to_string(),
        TRUSTEE_APP_LABEL.to_string(),
    )]));
    let tls_volumes = read_certificate(client.clone(), secret).await?;
    let pod_spec = generate_kbs_pod_spec(image, tls_volumes);

    // Inspired by trustee-operator
    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(TRUSTEE_DEPLOYMENT.to_string()),
            labels: selector.clone(),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: selector.clone(),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: selector,
                    ..Default::default()
                }),
                spec: Some(pod_spec),
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    create_or_info_if_exists!(client, Deployment, deployment);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use http::{Method, Request, StatusCode};
    use trusted_cluster_operator_test_utils::mock_client::*;

    #[test]
    fn test_get_image_pcrs_success() {
        let config_map = dummy_pcrs_map();
        let image_pcrs = get_image_pcrs(config_map).unwrap();
        assert_eq!(image_pcrs.0["cos"].pcrs.len(), 2);
        assert_eq!(image_pcrs.0["cos"].pcrs[0].value, "pcr0_val");
    }

    #[test]
    fn test_get_image_pcrs_no_data() {
        let config_map = ConfigMap::default();
        let err = get_image_pcrs(config_map).err().unwrap();
        assert!(err.to_string().contains("but had no data"));
    }

    #[test]
    fn test_get_image_pcrs_no_file() {
        let config_map = ConfigMap {
            data: Some(BTreeMap::new()),
            ..Default::default()
        };
        let err = get_image_pcrs(config_map).err().unwrap();
        assert!(err.to_string().contains("but had no file"));
    }

    #[test]
    fn test_get_image_pcrs_invalid_json() {
        let data = BTreeMap::from([(PCR_CONFIG_FILE.to_string(), "not json".to_string())]);
        let config_map = ConfigMap {
            data: Some(data),
            ..Default::default()
        };
        assert!(get_image_pcrs(config_map).is_err());
    }

    #[test]
    fn test_recompute_reference_values() {
        let result = recompute_reference_values(dummy_pcrs());
        assert_eq!(result.len(), 3);
        let rv = result.iter().find(|rv| rv.name == "tpm_pcr0").unwrap();
        let val_arr = rv.value.as_array().unwrap();
        let vals: Vec<_> = val_arr.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(vals, vec!["pcr0_val".to_string()]);
    }

    #[tokio::test]
    async fn test_update_rvs_success() {
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => {
                assert!(req.uri().path().contains(PCR_CONFIG_MAP));
                Ok(serde_json::to_string(&dummy_pcrs_map()).unwrap())
            }
            (1, &Method::GET) | (2, &Method::PUT) => {
                assert!(req.uri().path().contains(TRUSTEE_DATA_MAP));
                Ok(serde_json::to_string(&dummy_trustee_map()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(3, clos, |client| {
            let ctx = generate_rv_ctx(client);
            assert!(update_reference_values(ctx).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_update_rvs_no_pcr_map() {
        let clos = async |req: Request<_>, _| match (req.uri().path(), req.method()) {
            (p, &Method::GET) if p.contains(PCR_CONFIG_MAP) => Err(StatusCode::NOT_FOUND),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        count_check!(1, clos, |client| {
            let ctx = generate_rv_ctx(client);
            assert!(update_reference_values(ctx).await.is_err());
        });
    }

    #[tokio::test]
    async fn test_update_rvs_no_trustee_map() {
        let clos = async |req: Request<_>, ctr| match (ctr, req.uri().path()) {
            (0, p) if p.contains(PCR_CONFIG_MAP) => {
                Ok(serde_json::to_string(&dummy_pcrs_map()).unwrap())
            }
            (1, p) if p.contains(TRUSTEE_DATA_MAP) => Err(StatusCode::NOT_FOUND),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, clos, |client| {
            let ctx = generate_rv_ctx(client);
            assert!(update_reference_values(ctx).await.is_err())
        });
    }

    #[tokio::test]
    async fn test_update_rvs_no_trustee_data() {
        let clos = async |req: Request<_>, ctr| match (ctr, req.uri().path()) {
            (0, p) if p.contains(PCR_CONFIG_MAP) => {
                Ok(serde_json::to_string(&dummy_pcrs_map()).unwrap())
            }
            (1, p) if p.contains(TRUSTEE_DATA_MAP) => {
                Ok(serde_json::to_string(&ConfigMap::default()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, clos, |client| {
            let ctx = generate_rv_ctx(client);
            let err = update_reference_values(ctx).await.err().unwrap();
            assert!(err.to_string().contains("but had no data"));
        });
    }

    #[test]
    fn test_generate_luks_key_returns_correct_size() {
        let jwk: ClevisKey = serde_json::from_slice(&generate_luks_key().unwrap()).unwrap();
        assert_eq!(jwk.key.len(), 32);
    }

    #[test]
    fn test_generate_ed25519_key_pair() {
        let pair = generate_ed25519_key_pair().unwrap();
        let priv_pem = String::from_utf8(pair.private_key_pem).unwrap();
        let pub_pem = String::from_utf8(pair.public_key_pem).unwrap();
        assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_generate_ed25519_key_pair_unique() {
        let pair1 = generate_ed25519_key_pair().unwrap();
        let pair2 = generate_ed25519_key_pair().unwrap();
        assert_ne!(pair1.private_key_pem, pair2.private_key_pem);
        assert_ne!(pair1.public_key_pem, pair2.public_key_pem);
    }

    #[tokio::test]
    async fn test_generate_att_policy_success() {
        let clos = |client| generate_attestation_policy(client, Default::default());
        test_create_success::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_att_policy_already_exists() {
        let clos = |client| generate_attestation_policy(client, Default::default());
        test_create_already_exists(clos).await;
    }

    #[tokio::test]
    async fn test_generate_att_policy_error() {
        let clos = |client| generate_attestation_policy(client, Default::default());
        test_create_error(clos).await;
    }

    #[tokio::test]
    async fn test_generate_secret_success() {
        let clos = |client| generate_secret(client, "id", Default::default());
        test_create_success::<_, _, Secret>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_secret_already_exists() {
        let clos = |client| generate_secret(client, "id", Default::default());
        test_create_already_exists(clos).await;
    }

    #[tokio::test]
    async fn test_generate_secret_error() {
        let clos = |client| generate_secret(client, "id", Default::default());
        test_create_error(clos).await;
    }

    #[tokio::test]
    async fn test_generate_trustee_data_success() {
        let clos = |client| generate_trustee_data(client, Default::default(), &None);
        test_create_success::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_trustee_data_already_exists() {
        let clos = |client| generate_trustee_data(client, Default::default(), &None);
        test_create_already_exists(clos).await;
    }

    #[tokio::test]
    async fn test_generate_trustee_data_error() {
        let clos = |client| generate_trustee_data(client, Default::default(), &None);
        test_create_error(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_service_success() {
        let clos = |client| generate_kbs_service(client, Default::default(), None);
        test_create_success::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_service_error() {
        let clos = |client| generate_kbs_service(client, Default::default(), Some(80));
        test_create_error(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_depl_success() {
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image", &None);
        test_create_success::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_depl_error() {
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image", &None);
        test_create_error(clos).await;
    }
}
