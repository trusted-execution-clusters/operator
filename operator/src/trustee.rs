// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
// SPDX-FileCopyrightText: Dehan Meng <demeng@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use clevis_pin_trustee_lib::Key as ClevisKey;
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
use k8s_openapi::chrono::{DateTime, TimeDelta, Utc};
use kube::{
    Api, Client, Resource,
    api::{ObjectMeta, Patch, PatchParams},
};
use log::info;
use operator::{RvContextData, create_or_info_if_exists};
use serde::{Serialize, Serializer};
use serde_json::{Value::String as JsonString, json};
use std::collections::BTreeMap;

use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::reference_values::*;

const TRUSTEE_DATA_DIR: &str = "/opt/trustee";
pub const TRUSTEE_SECRETS_PATH: &str = "/opt/trustee/kbs-repository/default";
const KBS_CONFIG_FILE: &str = "kbs-config.toml";
pub(crate) const REFERENCE_VALUES_FILE: &str = "reference-values.json";

pub(crate) const TRUSTEE_DATA_MAP: &str = "trustee-data";
const ATT_POLICY_MAP: &str = "attestation-policy";
const TRUSTED_AK_KEYS_VOLUME: &str = "trusted-ak-keys";
const TRUSTED_AK_KEYS_DIR: &str = "/etc/tpm/trusted_ak_keys";

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
            expiration: Utc::now() + TimeDelta::days(365),
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

fn generate_secret_volume(id: &str) -> (Volume, VolumeMount) {
    (
        Volume {
            name: id.to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(id.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
        VolumeMount {
            name: id.to_string(),
            mount_path: format!("{TRUSTEE_SECRETS_PATH}/{id}"),
            ..Default::default()
        },
    )
}

pub async fn mount_secret(client: Client, id: &str) -> Result<()> {
    let result = do_mount_secret(client, id, true).await;
    info!("Mounted secret {id} to {TRUSTEE_DEPLOYMENT}");
    result
}

pub async fn unmount_secret(client: Client, id: &str) -> Result<()> {
    let result = do_mount_secret(client, id, false).await;
    info!("Unmounted secret {id} from {TRUSTEE_DEPLOYMENT}");
    result
}

pub async fn do_mount_secret(client: Client, id: &str, add: bool) -> Result<()> {
    let deployments: Api<Deployment> = Api::default_namespaced(client);
    let mut deployment = deployments.get(TRUSTEE_DEPLOYMENT).await?;
    let err = format!("Deployment {TRUSTEE_DEPLOYMENT} existed, but had no spec");
    let depl_spec = deployment.spec.as_mut().context(err)?;
    let err = format!("Deployment {TRUSTEE_DEPLOYMENT} existed, but had no pod spec");
    let pod_spec = depl_spec.template.spec.as_mut().context(err)?;
    let err = format!("Deployment {TRUSTEE_DEPLOYMENT} existed, but had no containers");
    let container = pod_spec.containers.get_mut(0).context(err)?;
    let vol_mounts = container.volume_mounts.get_or_insert_default();

    if add {
        let (volume, volume_mount) = generate_secret_volume(id);
        pod_spec.volumes.get_or_insert_default().push(volume);
        vol_mounts.push(volume_mount);
    } else {
        let vol_result = pod_spec.volumes.as_mut().and_then(|vs| {
            let pos = vs.iter().position(|v| v.name == id);
            pos.map(|p| vs.swap_remove(p))
        });
        if vol_result.is_none() {
            info!("Secret {id} was to be dropped, but volume had already been removed");
        }
        let vol_mount_result = container.volume_mounts.as_mut().and_then(|vms| {
            let pos = vms.iter().position(|v| v.name == id);
            pos.map(|p| vms.swap_remove(p))
        });
        if vol_mount_result.is_none() {
            info!("Secret {id} was to be dropped, but volume mount had already been removed");
        }
    }

    deployments
        .replace(TRUSTEE_DEPLOYMENT, &Default::default(), &deployment)
        .await?;
    Ok(())
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
                        path: format!("{}.pub", secret_name),
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

pub async fn generate_trustee_data(client: Client, owner_reference: OwnerReference) -> Result<()> {
    let kbs_config = include_str!("kbs-config.toml");
    let policy_rego = include_str!("resource.rego");

    let data = BTreeMap::from([
        ("kbs-config.toml".to_string(), kbs_config.to_string()),
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
    let selector = Some(BTreeMap::from([("app".to_string(), "kbs".to_string())]));

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
    ]
}

fn generate_kbs_pod_spec(image: &str) -> PodSpec {
    let volumes = generate_kbs_volume_templates();
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
            volume_mounts: Some(
                volumes
                    .iter()
                    .map(|(name, mount_path, _)| VolumeMount {
                        name: name.to_string(),
                        mount_path: mount_path.to_string(),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        }],
        volumes: Some(
            volumes
                .iter()
                .map(|(name, _, volume)| {
                    let mut volume = volume.clone();
                    volume.name = name.to_string();
                    volume.clone()
                })
                .collect(),
        ),
        ..Default::default()
    }
}

pub async fn generate_kbs_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
) -> Result<()> {
    let selector = Some(BTreeMap::from([("app".to_string(), "kbs".to_string())]));
    let pod_spec = generate_kbs_pod_spec(image);

    // Inspired by trustee-operator
    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(TRUSTEE_DEPLOYMENT.to_string()),
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
    use kube::client::Body;
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

    fn dummy_deployment() -> Deployment {
        Deployment {
            spec: Some(DeploymentSpec {
                replicas: Some(1),
                template: PodTemplateSpec {
                    spec: Some(PodSpec {
                        containers: vec![Container::default()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_mount_secret_success() {
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) | (1, &Method::PUT) => {
                Ok(serde_json::to_string(&dummy_deployment()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, clos, |client| {
            assert!(mount_secret(client, "id").await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_mount_secret_no_depl() {
        let clos = async |_, _| Err(StatusCode::NOT_FOUND);
        count_check!(1, clos, |client| {
            assert!(mount_secret(client, "id").await.is_err());
        });
    }

    #[tokio::test]
    async fn test_mount_secret_no_spec() {
        let clos = async |_, _| {
            let mut depl = dummy_deployment();
            depl.spec = None;
            Ok(serde_json::to_string(&depl).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = mount_secret(client, "id").await.err().unwrap();
            assert!(err.to_string().contains("but had no spec"));
        });
    }

    #[tokio::test]
    async fn test_mount_secret_no_pod_spec() {
        let clos = async |_, _| {
            let mut depl = dummy_deployment();
            let spec = depl.spec.as_mut().unwrap();
            spec.template.spec = None;
            Ok(serde_json::to_string(&depl).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = mount_secret(client, "id").await.err().unwrap();
            assert!(err.to_string().contains("but had no pod spec"));
        });
    }

    #[tokio::test]
    async fn test_mount_secret_no_containers() {
        let clos = async |_, _| {
            let mut depl = dummy_deployment();
            let spec = depl.spec.as_mut().unwrap();
            let pod_spec = spec.template.spec.as_mut().unwrap();
            pod_spec.containers = vec![];
            Ok(serde_json::to_string(&depl).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = mount_secret(client, "id").await.err().unwrap();
            assert!(err.to_string().contains("but had no containers"));
        });
    }

    #[tokio::test]
    async fn test_unmount_secret() {
        let clos = async |req: Request<Body>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => {
                let mut depl = dummy_deployment();
                let spec = depl.spec.as_mut().unwrap();
                let pod_spec = spec.template.spec.as_mut().unwrap();
                pod_spec.volumes = Some(vec![Volume {
                    name: "id".to_string(),
                    ..Default::default()
                }]);
                let container = pod_spec.containers.get_mut(0).unwrap();
                container.volume_mounts = Some(vec![VolumeMount {
                    name: "id".to_string(),
                    ..Default::default()
                }]);
                Ok(serde_json::to_string(&depl).unwrap())
            }
            (1, &Method::PUT) => {
                let bytes = req.into_body().collect_bytes().await.unwrap().to_vec();
                let body = String::from_utf8_lossy(&bytes);
                assert!(!body.contains("id"));
                Ok(serde_json::to_string(&dummy_deployment()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, clos, |client| {
            assert!(unmount_secret(client, "id").await.is_ok());
        });
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
        let clos = |client| generate_trustee_data(client, Default::default());
        test_create_success::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_trustee_data_already_exists() {
        let clos = |client| generate_trustee_data(client, Default::default());
        test_create_already_exists(clos).await;
    }

    #[tokio::test]
    async fn test_generate_trustee_data_error() {
        let clos = |client| generate_trustee_data(client, Default::default());
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
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image");
        test_create_success::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_generate_kbs_depl_error() {
        let clos = |client| generate_kbs_deployment(client, Default::default(), "image");
        test_create_error(clos).await;
    }
}
