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
use k8s_openapi::api::apps::v1::{
    Deployment, DeploymentSpec, DeploymentStrategy, RollingUpdateDeployment,
};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EmptyDirVolumeSource, EnvVar,
    KeyToPath, PodSpec, PodTemplateSpec, Secret, SecretVolumeSource, Service, ServicePort,
    ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{LabelSelector, OwnerReference},
    util::intstr::IntOrString,
};
use kube::api::{ObjectMeta, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::{reflector::ObjectRef, watcher};
use kube::{Api, Client, Resource};
use log::{info, warn};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Value::String as JsonString, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use compute_pcrs_lib::tpmevents::combine::combine_images;
use operator::{ControllerError, OperatorContext, TLS_DIR, controller_error_policy};
use operator::{controller_info, create_or_info_if_exists, read_certificate};
use trusted_cluster_operator_lib::conditions::COMMITTED_CONDITION;
use trusted_cluster_operator_lib::reference_values::status_to_tpm_events;
use trusted_cluster_operator_lib::{ApprovedImage, ApprovedImageStatusPcrs, endpoints::*};

const TRUSTEE_DATA_DIR: &str = "/etc/kbs";
const KBS_CONFIG_FILE: &str = "kbs-config.toml";

pub(crate) const TRUSTEE_DATA_MAP: &str = "trustee-data";
const TRUSTEE_AUTH_SECRET: &str = "trustee-auth";
const TRUSTEE_AUTH_KEY_DIR: &str = "/opt/trustee/keys";
const TRUSTEE_STORAGE_VOLUME: &str = "trustee-storage";
const TRUSTEE_STORAGE_DIR: &str = "/opt/trustee/storage";
pub(crate) const TRUSTEE_AUTH_PUB_KEY: &str = "public.pub";
pub(crate) const TRUSTEE_AUTH_PRIV_KEY: &str = "private.key";

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
#[derive(Serialize, Deserialize)]
struct ReferenceValue {
    pub version: String,
    pub name: String,
    #[serde(serialize_with = "primitive_date_time_to_str")]
    pub expiration: DateTime<Utc>,
    pub value: serde_json::Value,
}

/// PCR registers compared by tpm.rego.
/// This is required to update reference values once a image is disallowed.
/// reference values can only be updated, not deleted.
/// on image disallow, we need to force update the reference values with the empty array.
const ATTESTED_PCR_IDS: [i64; 2] = [4, 14];

fn recompute_reference_values(all_pcrs: &[Vec<ApprovedImageStatusPcrs>]) -> Vec<ReferenceValue> {
    let mut reference_values_in =
        BTreeMap::from([("svn".to_string(), BTreeSet::from(["1".to_string()]))]);
    // Safe default in case pcr computation fails.
    for id in ATTESTED_PCR_IDS {
        reference_values_in.entry(format!("pcr{id}")).or_default();
    }

    let tpm_events: Vec<Vec<_>> = all_pcrs
        .iter()
        .map(|image_pcrs| status_to_tpm_events(image_pcrs))
        .collect();
    let pcr_combinations = combine_images(&tpm_events);
    for pcr in pcr_combinations.iter().flatten() {
        reference_values_in
            .entry(format!("pcr{}", pcr.id))
            .or_default()
            .insert(hex::encode(&pcr.value));
    }
    reference_values_in
        .iter()
        .map(|(name, values)| ReferenceValue {
            version: "0.1.0".to_string(),
            name: format!("tpm_{name}"),
            expiration: Utc::now() + chrono::Duration::days(365),
            value: serde_json::Value::Array(values.iter().map(|v| JsonString(v.clone())).collect()),
        })
        .collect()
}

pub async fn update_reference_values(ctx: &OperatorContext) -> Result<()> {
    let images: Api<ApprovedImage> = Api::default_namespaced(ctx.client.clone());
    let image_list = images.list(&Default::default()).await?;

    let all_pcrs: Vec<Vec<ApprovedImageStatusPcrs>> = image_list
        .items
        .iter()
        .filter(|img| img.metadata.deletion_timestamp.is_none())
        .filter(|img| {
            img.status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .is_some_and(|cs| {
                    cs.iter()
                        .any(|c| c.type_ == COMMITTED_CONDITION && c.status == "True")
                })
        })
        .filter_map(|img| img.status.as_ref().and_then(|s| s.pcrs.clone()))
        .collect();

    let reference_values = recompute_reference_values(&all_pcrs);

    sync_reference_values(ctx, &reference_values)
        .await
        .context("Failed to sync reference values to KBS")?;
    info!(
        "Recomputed reference values from {} committed images",
        all_pcrs.len()
    );
    Ok(())
}

fn get_auth_key_token(ctx: &OperatorContext) -> Result<String> {
    let obj_ref = ObjectRef::new(TRUSTEE_AUTH_SECRET).within(ctx.client.default_namespace());
    let err_ctx = format!("missing secret {TRUSTEE_AUTH_SECRET}");
    let auth_secret = ctx.secret_store.get(&obj_ref).context(err_ctx)?;

    let err_ctx = "Auth secret has no data";
    let auth_data = auth_secret.data.as_ref().context(err_ctx)?;
    let auth_key_bytes = auth_data
        .get(TRUSTEE_AUTH_PRIV_KEY)
        .context("Auth secret missing private.key")?;

    let claims = json!({
        "role": "admin",
        "exp": i32::MAX
    });

    let encoding_key = EncodingKey::from_ed_pem(auth_key_bytes.0.as_slice())?;

    let token = encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key)?;
    Ok(token)
}

fn get_kbs_connection(ctx: &OperatorContext) -> Result<(String, Vec<String>)> {
    let tec = ctx.get_opt_tec()?.context("no TEC found")?;
    let obj_ref = |name: &str| ObjectRef::new(name).within(ctx.client.default_namespace());

    if let Some(secret_name) = &tec.spec.trustee_secret {
        let err_ctx =
            format!("cluster specified Trustee secret {secret_name}, but it did not exist");
        let obj_ref = obj_ref(secret_name);
        let secret = ctx.secret_store.get(&obj_ref).context(err_ctx)?;
        let err_ctx = format!("Trustee secret {secret_name} did not have ca.crt");
        let secret_data = secret.data.as_ref();
        let ca_crt = secret_data.and_then(|d| d.get("ca.crt")).context(err_ctx)?;
        let ca_pem =
            String::from_utf8(ca_crt.0.clone()).context("ca certificate is not valid UTF-8")?;
        let trustee_addr = format!(
            "https://{}",
            tec.spec
                .public_trustee_addr
                .as_ref()
                .context("TrustedExecutionCluster missing public_trustee_addr HTTPS")?
        );
        return Ok((trustee_addr, vec![ca_pem]));
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

async fn sync_reference_values(
    ctx: &OperatorContext,
    reference_values: &[ReferenceValue],
) -> Result<()> {
    let auth_token = get_auth_key_token(ctx)?;
    let (url, certs) = get_kbs_connection(ctx)?;
    for rv in reference_values {
        kbs_client::set_sample_rv(
            url.clone(),
            rv.name.clone(),
            rv.value.clone(),
            Some(auth_token.clone()),
            certs.clone(),
        )
        .await?;
    }
    info!("Sent {} reference values to KBS", reference_values.len());
    Ok(())
}

pub async fn sync_resource_policy(ctx: &OperatorContext) -> Result<()> {
    let auth_token = get_auth_key_token(ctx)?;
    let (url, certs) = get_kbs_connection(ctx)?;
    let policy = include_str!("resource.rego");
    info!("Sending resource policy to KBS API...");
    kbs_client::set_resource_policy(&url, Some(auth_token), policy.as_bytes().to_vec(), certs)
        .await?;
    info!("Resource policy set successfully");
    Ok(())
}

pub async fn sync_attestation_policy(ctx: &OperatorContext) -> Result<()> {
    let auth_token = get_auth_key_token(ctx)?;
    let (url, certs) = get_kbs_connection(ctx)?;
    let policy = include_str!("tpm.rego");
    info!("Sending attestation policy to KBS API...");
    kbs_client::set_attestation_policy(
        &url,
        Some(auth_token),
        policy.as_bytes().to_vec(),
        Some("rego".to_string()),
        Some("default_cpu".to_string()),
        certs,
    )
    .await?;
    info!("Attestation policy set successfully");
    Ok(())
}

// Called directly in main.rs reconcile loop. Needs to have proper visibility between modules, but in the same crate.
pub(crate) async fn trustee_deployment_reconcile(
    deployment: Arc<Deployment>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    if let Some(status) = &deployment.status
        && let Some(is_available) = &status.conditions
        && is_available
            .iter()
            .any(|c| c.type_ == "Available" && c.status == "True")
    {
        if let Err(e) = sync_resource_policy(&ctx).await {
            warn!("Failed to sync resource policy to KBS: {e}");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
        if let Err(e) = sync_attestation_policy(&ctx).await {
            warn!("Failed to sync attestation policy to KBS: {e}");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
        if let Err(e) = update_reference_values(&ctx).await {
            warn!("Failed to sync reference values to KBS: {e}");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
        if let Err(e) = sync_all_machine_luks_key(&ctx).await {
            warn!("Failed to sync machine luks keys to KBS: {e}");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
        if let Err(e) = update_attestation_keys(&ctx).await {
            warn!("Failed to update attestation keys to KBS: {e}");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    }

    Ok(Action::await_change())
}

pub async fn launch_trustee_sync_controller(ctx: Arc<OperatorContext>) {
    let deployments: Api<Deployment> = Api::default_namespaced(ctx.client.clone());
    let watcher_config = watcher::Config {
        label_selector: Some(format!("app={TRUSTEE_APP_LABEL}")),
        ..Default::default()
    };
    tokio::spawn(
        Controller::new(deployments, watcher_config)
            .run(trustee_deployment_reconcile, controller_error_policy, ctx)
            .for_each(controller_info),
    );
}

pub struct Ed25519KeyPair {
    pub private_key_pem: Vec<u8>,
    pub public_key_pem: Vec<u8>,
}

pub fn generate_ed25519_key_pair() -> Result<Ed25519KeyPair> {
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

pub fn secret_path(id: &str) -> String {
    format!("default/{id}/root")
}

pub async fn send_secret(ctx: &OperatorContext, id: &str) -> Result<()> {
    let auth_key_token = get_auth_key_token(ctx)?;
    let (url, certs) = get_kbs_connection(ctx)?;
    let obj_ref = ObjectRef::new(id).within(ctx.client.default_namespace());
    let err_ctx = format!("missing secret {id}");
    let secret = ctx.secret_store.get(&obj_ref).context(err_ctx)?;
    let secret_data = secret.data.as_ref().context("Secret has no data")?;
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

pub async fn delete_secret(ctx: &OperatorContext, id: &str) -> Result<()> {
    let auth_key_token = get_auth_key_token(ctx)?;
    let (url, certs) = get_kbs_connection(ctx)?;
    let path = secret_path(id);
    info!("Deleting secret {id} to KBS API...");
    kbs_client::delete_resource(&url, Some(auth_key_token), &path, certs).await?;
    info!("Secret {id} deleted successfully");
    Ok(())
}

pub async fn register_ak(ctx: &OperatorContext, ak_secrets: &[String]) -> Result<()> {
    let auth_key_token = get_auth_key_token(ctx)?;
    let (url, certs) = get_kbs_connection(ctx)?;
    let ak_der: Vec<serde_json::Value> = ak_secrets
        .iter()
        .map(|ak| {
            let der = ak
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<String>();
            JsonString(der)
        })
        .collect();
    info!("Registering AK to KBS API...");
    kbs_client::set_sample_rv(
        url.to_string(),
        "trusted_aks".to_string(),
        serde_json::Value::Array(ak_der),
        Some(auth_key_token),
        certs,
    )
    .await?;
    info!("AK registered successfully");
    Ok(())
}

pub async fn sync_all_machine_luks_key(ctx: &OperatorContext) -> Result<()> {
    let machine_ids: Vec<String> = ctx
        .machine_store
        .state()
        .iter()
        .map(|machine| machine.spec.id.clone())
        .collect();

    info!("Syncing {} machine luks key to KBS", machine_ids.len());
    for id in &machine_ids {
        send_secret(ctx, id).await?;
    }
    Ok(())
}

pub async fn update_attestation_keys(ctx: &OperatorContext) -> Result<()> {
    let ak_secrets: Vec<String> = ctx
        .secret_store
        .state()
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
        .filter_map(|secret| {
            secret
                .data
                .as_ref()
                .and_then(|d| d.get("public_key"))
                .and_then(|pk| String::from_utf8(pk.0.clone()).ok())
        })
        .collect();

    if let Err(e) = register_ak(ctx, &ak_secrets).await {
        warn!("Failed to register AK to KBS: {e}");
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
        warn!(
            "Trustee deployment has no TLS certificate, starting KBS with insecure HTTP (not recommended for production)"
        );
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

    let data = BTreeMap::from([("kbs-config.toml".to_string(), kbs_config)]);

    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(TRUSTEE_DATA_MAP.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    // reuse the configmap during upgrade to avoid downtime.
    let cms: Api<ConfigMap> = Api::default_namespaced(client);
    if cms.get_opt(TRUSTEE_DATA_MAP).await?.is_some() {
        cms.patch(
            TRUSTEE_DATA_MAP,
            &PatchParams::default(),
            &Patch::Strategic(config_map),
        )
        .await?;
        info!("Patched trustee-data ConfigMap");
    } else {
        cms.create(&Default::default(), &config_map).await?;
        info!("Created trustee-data ConfigMap");
    }
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

fn generate_kbs_volume_templates() -> [(&'static str, &'static str, Volume); 3] {
    [
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
            TRUSTEE_AUTH_SECRET,
            TRUSTEE_AUTH_KEY_DIR,
            Volume {
                secret: Some(SecretVolumeSource {
                    secret_name: Some(TRUSTEE_AUTH_SECRET.to_string()),
                    items: Some(vec![KeyToPath {
                        key: TRUSTEE_AUTH_PUB_KEY.to_string(),
                        path: TRUSTEE_AUTH_PUB_KEY.to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            TRUSTEE_STORAGE_VOLUME,
            TRUSTEE_STORAGE_DIR,
            Volume {
                empty_dir: Some(EmptyDirVolumeSource::default()),
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

async fn build_kbs_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
    secret: &Option<String>,
) -> Result<Deployment> {
    let selector = Some(BTreeMap::from([(
        "app".to_string(),
        TRUSTEE_APP_LABEL.to_string(),
    )]));
    let tls_volumes = read_certificate(client, secret).await?;
    let pod_spec = generate_kbs_pod_spec(image, tls_volumes);

    Ok(Deployment {
        metadata: ObjectMeta {
            name: Some(TRUSTEE_DEPLOYMENT.to_string()),
            labels: selector.clone(),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            // Adding a rolling update strategy to prevent downtime during upgrade. If new trustee pod fails to come up, oldOne will still continue serving to ensure no downtime.
            strategy: Some(DeploymentStrategy {
                type_: Some("RollingUpdate".to_string()),
                rolling_update: Some(RollingUpdateDeployment {
                    max_unavailable: Some(IntOrString::Int(0)),
                    max_surge: Some(IntOrString::Int(1)),
                }),
            }),
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
    })
}

// Called during initial install.
pub async fn generate_kbs_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
    secret: &Option<String>,
) -> Result<()> {
    let deployment = build_kbs_deployment(client.clone(), owner_reference, image, secret).await?;
    create_or_info_if_exists!(client, Deployment, deployment);
    Ok(())
}

// Called during upgrade.
// Patches the deployment in place.
pub async fn apply_kbs_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
    secret: &Option<String>,
) -> Result<()> {
    let deployment = build_kbs_deployment(client.clone(), owner_reference, image, secret).await?;
    let deployments: Api<Deployment> = Api::default_namespaced(client);
    deployments
        .patch(
            TRUSTEE_DEPLOYMENT,
            &PatchParams::default(),
            &Patch::Strategic(deployment),
        )
        .await?;
    info!("Applied full Trustee Deployment spec for {image}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use http::{Method, Request, StatusCode};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use k8s_openapi::jiff::Timestamp;
    use kube::api::ObjectList;
    use trusted_cluster_operator_lib::conditions::COMMITTED_CONDITION;
    use trusted_cluster_operator_test_utils::mock_client::*;
    use trusted_cluster_operator_test_utils::test_error_method;

    fn reference_values_from(reference_values: &[ReferenceValue], rv_name: &str) -> Vec<String> {
        let rv = reference_values
            .iter()
            .find(|rv| rv.name == rv_name)
            .unwrap();
        let val_arr = rv.value.as_array().unwrap();
        val_arr.iter().map(|v| v.as_str().unwrap().into()).collect()
    }

    // Mock committed approved image.
    fn committed_approved_image(name: &str, pcrs: Vec<ApprovedImageStatusPcrs>) -> ApprovedImage {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
        ApprovedImage {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: trusted_cluster_operator_lib::ApprovedImageSpec {
                image: format!("quay.io/{name}@sha256:abc123"),
            },
            status: Some(trusted_cluster_operator_lib::ApprovedImageStatus {
                conditions: Some(vec![Condition {
                    type_: COMMITTED_CONDITION.to_string(),
                    status: "True".to_string(),
                    reason: "ImageCommitted".to_string(),
                    message: String::new(),
                    last_transition_time: Time(Timestamp::now()),
                    observed_generation: None,
                }]),
                pcrs: Some(pcrs),
                first_seen: None,
            }),
        }
    }

    // Makes sure the reference values are computed correctly for the dummy PCRs.
    #[test]
    fn test_recompute_reference_values() {
        let pcrs = vec![dummy_status_pcrs()];
        let result = recompute_reference_values(&pcrs);
        let vals = reference_values_from(&result, "tpm_pcr4");
        assert_eq!(vals, vec![dummy_pcr_value(4)]);
        let vals = reference_values_from(&result, "tpm_pcr14");
        assert_eq!(vals, vec![dummy_pcr_value(14)]);
    }

    // Makes sure the reference values are computed correctly for an empty PCRs, it should have a single value for the SVN, and empty values for the PCR4 and 14.
    #[test]
    fn test_recompute_reference_values_empty() {
        let result = recompute_reference_values(&[]);
        let vals = reference_values_from(&result, "tpm_svn");
        assert_eq!(vals, vec!["1"]);
        assert!(reference_values_from(&result, "tpm_pcr4").is_empty());
        assert!(reference_values_from(&result, "tpm_pcr14").is_empty());
    }

    // Tests combination PCR values.
    #[test]
    fn test_recompute_reference_values_multiple_images() {
        use compute_pcrs_lib::Pcr;
        use compute_pcrs_lib::tpmevents::{TPMEvent, TPMEventID};
        use trusted_cluster_operator_lib::reference_values::pcrs_to_status;

        let pcrs1 = dummy_status_pcrs();

        // Dummy PCR values for another approved image.
        let other_shim = TPMEvent {
            name: "shim".to_string(),
            pcr: 4,
            hash: vec![0x11; 32],
            id: TPMEventID::Pcr4Shim,
        };
        let other_grub = TPMEvent {
            name: "grub".to_string(),
            pcr: 4,
            hash: vec![0x22; 32],
            id: TPMEventID::Pcr4Grub,
        };
        let other_vmlinuz = TPMEvent {
            name: "vmlinuz".to_string(),
            pcr: 4,
            hash: vec![0x33; 32],
            id: TPMEventID::Pcr4Vmlinuz,
        };
        let other_mok = TPMEvent {
            name: "mokList".to_string(),
            pcr: 14,
            hash: vec![0x44; 32],
            id: TPMEventID::Pcr14MokList,
        };

        // Extend and compute PCR4 and 14 values for the other image.
        let other_pcr4 = Pcr::compile_from(&vec![other_shim, other_grub, other_vmlinuz]);
        let other_pcr14 = Pcr::compile_from(&vec![other_mok]);

        // Encode the PCR values for the other image.
        let pcr4_other_value = hex::encode(&other_pcr4.value);
        let pcr14_other_value = hex::encode(&other_pcr14.value);

        let pcrs2 = pcrs_to_status(&[other_pcr4, other_pcr14]);

        let result = recompute_reference_values(&[pcrs1, pcrs2]);

        // combine_images produces combinations respecting event groups:
        //   shim, grub  -> TPMEG_BOOTLOADER (must come from same image)
        //   vmlinuz     -> TPMEG_LINUX      (independent, can mix)
        // So for PCR4 we expect 4 valid states:
        //   1. img1 bootloader + img1 kernel  (pure image 1)
        //   2. img2 bootloader + img2 kernel  (pure image 2)
        //   3. img1 bootloader(includes shim and grub) + img2 kernel  (cross: rolling upgrade mid-state)
        //   4. img2 bootloader(includes shim and grub) + img1 kernel  (cross: rolling upgrade mid-state)
        let vals_pcr4 = reference_values_from(&result, "tpm_pcr4");
        assert_eq!(
            vals_pcr4.len(),
            4,
            "Expected 4 PCR4 combinations, got: {vals_pcr4:?}"
        );

        // Assert pure image PCR4 values
        assert!(vals_pcr4.contains(&dummy_pcr_value(4)));
        assert!(vals_pcr4.contains(&pcr4_other_value));

        // Assert combination PCR4 values
        // Cross-combination: image 1 bootloader (shim=0xaa, grub=0xbb) + image 2 kernel (vmlinuz=0x33)
        let cross_a = Pcr::compile_from(&vec![
            TPMEvent {
                name: "shim".into(),
                pcr: 4,
                hash: vec![0xaa; 32],
                id: TPMEventID::Pcr4Shim,
            },
            TPMEvent {
                name: "grub".into(),
                pcr: 4,
                hash: vec![0xbb; 32],
                id: TPMEventID::Pcr4Grub,
            },
            TPMEvent {
                name: "vmlinuz".into(),
                pcr: 4,
                hash: vec![0x33; 32],
                id: TPMEventID::Pcr4Vmlinuz,
            },
        ]);
        assert!(
            vals_pcr4.contains(&hex::encode(&cross_a.value)),
            "Missing cross-combination: img1 bootloader + img2 kernel"
        );

        // Cross-combination: image 2 bootloader (shim=0x11, grub=0x22) + image 1 kernel (vmlinuz=0xcc)
        let cross_b = Pcr::compile_from(&vec![
            TPMEvent {
                name: "shim".into(),
                pcr: 4,
                hash: vec![0x11; 32],
                id: TPMEventID::Pcr4Shim,
            },
            TPMEvent {
                name: "grub".into(),
                pcr: 4,
                hash: vec![0x22; 32],
                id: TPMEventID::Pcr4Grub,
            },
            TPMEvent {
                name: "vmlinuz".into(),
                pcr: 4,
                hash: vec![0xcc; 32],
                id: TPMEventID::Pcr4Vmlinuz,
            },
        ]);
        assert!(
            vals_pcr4.contains(&hex::encode(&cross_b.value)),
            "Missing cross-combination: img2 bootloader + img1 kernel"
        );

        // PCR14: mokList is in TPMEG_MOKVARS (independent group), so 2 values (one per image)
        let vals_pcr14 = reference_values_from(&result, "tpm_pcr14");
        assert!(vals_pcr14.len() >= 2);
        assert!(vals_pcr14.contains(&dummy_pcr_value(14)));
        assert!(vals_pcr14.contains(&pcr14_other_value));
    }

    #[tokio::test]
    async fn test_update_rvs_success() {
        let _ = jsonwebtoken_openssl::install_default();
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => {
                let image = committed_approved_image("cos", dummy_status_pcrs());
                let list = ObjectList {
                    items: vec![image],
                    types: Default::default(),
                    metadata: Default::default(),
                };
                Ok(serde_json::to_string(&list).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(1, clos, |client| {
            let mut auth = dummy_trustee_auth();
            auth.metadata.name = Some(TRUSTEE_AUTH_SECRET.to_string());
            let mut ctx = OperatorContext::new(client);
            ctx.secret_store = store_with(vec![auth]);
            ctx.tec_store = store_with(vec![dummy_cluster()]);
            // Dummy public_trustee_addr is not a real KBS; sync must fail.
            assert!(update_reference_values(&ctx).await.is_err());
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
        test_error_method!(clos, Method::POST);
    }

    #[tokio::test]
    async fn test_generate_trustee_data_success() {
        let clos = |client| generate_trustee_data(client, Default::default(), &None);
        let server = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => Err(StatusCode::NOT_FOUND),
            (1, &Method::POST) => Ok(serde_json::to_string(&ConfigMap::default()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, server, |client| {
            assert!(clos(client).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_generate_trustee_data_already_exists() {
        let clos = |client| generate_trustee_data(client, Default::default(), &None);
        let server = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => Ok(serde_json::to_string(&ConfigMap::default()).unwrap()),
            (1, &Method::PATCH) => Ok(serde_json::to_string(&ConfigMap::default()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, server, |client| {
            assert!(clos(client).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_generate_trustee_data_error() {
        let clos = |client| generate_trustee_data(client, Default::default(), &None);
        let server = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => Ok(serde_json::to_string(&ConfigMap::default()).unwrap()),
            (1, &Method::PATCH) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, server, |client| {
            assert!(clos(client).await.is_err());
        });
    }

    #[tokio::test]
    async fn test_generate_kbs_service_success() {
        let clos = |client| generate_kbs_service(client, Default::default(), None);
        test_create_success::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_service_error() {
        let clos = |client| generate_kbs_service(client, Default::default(), Some(80));
        test_error_method!(clos, Method::POST);
    }

    #[tokio::test]
    async fn test_generate_kbs_depl_success() {
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image", &None);
        test_create_success::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_depl_error() {
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image", &None);
        test_error_method!(clos, Method::POST);
    }

    #[tokio::test]
    async fn test_sync_all_machine_luks_key_empty() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let ctx = OperatorContext::new(client);
            assert!(sync_all_machine_luks_key(&ctx).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_sync_all_machine_luks_key_send_error() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let mut ctx = OperatorContext::new(client);
            ctx.machine_store = store_with(vec![dummy_machine("m1")]);
            assert!(sync_all_machine_luks_key(&ctx).await.is_err());
        });
    }

    #[tokio::test]
    async fn test_update_attestation_keys_empty() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let ctx = OperatorContext::new(client);
            assert!(update_attestation_keys(&ctx).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_update_attestation_keys_register_fails_gracefully() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let mut ctx = OperatorContext::new(client);
            ctx.secret_store = store_with(vec![dummy_ak_secret("ak1"), dummy_ak_secret("ak2")]);
            assert!(update_attestation_keys(&ctx).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_update_attestation_keys_register_success() {
        let _ = jsonwebtoken_openssl::install_default();
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let mut trustee_auth = dummy_trustee_auth();
            trustee_auth.metadata.name = Some(TRUSTEE_AUTH_SECRET.to_string());
            let mut ctx = OperatorContext::new(client);
            ctx.secret_store = store_with(vec![dummy_ak_secret("ak1"), trustee_auth]);
            ctx.tec_store = store_with(vec![dummy_cluster()]);
            assert!(update_attestation_keys(&ctx).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_update_attestation_keys_filters_deleting() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let mut deleting = dummy_ak_secret("ak-deleting");
            deleting.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
            let mut ctx = OperatorContext::new(client);
            ctx.secret_store = store_with(vec![deleting]);
            assert!(update_attestation_keys(&ctx).await.is_ok());
        });
    }
}
