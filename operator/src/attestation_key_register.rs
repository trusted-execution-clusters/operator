// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, PodSpec, PodTemplateSpec, Secret, Service, ServicePort, ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
    util::intstr::IntOrString,
};
use kube::{
    Api, Client, Resource,
    api::{Patch, PatchParams},
    runtime::{
        Controller,
        controller::Action,
        finalizer,
        finalizer::Event,
        reflector::{self, ObjectRef, Store},
        watcher,
    },
};
use log::info;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use trusted_cluster_operator_lib::conditions::ATTESTATION_KEY_MACHINE_APPROVE;
use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::{AttestationKey, AttestationKeyStatus, Machine, update_status};

use crate::conditions::attestation_key_approved_condition;
use crate::trustee;
use operator::{
    ControllerError, TLS_DIR, controller_error_policy, create_or_info_if_exists, read_certificate,
    upsert_condition,
};

/// Shared context for the three attestation-key controllers.
/// Stores give local cache access to avoid repeated API-server reads.
pub struct AkContextData {
    pub client: Client,
    pub machine_store: Store<Machine>,
    pub ak_store: Store<AttestationKey>,
    pub secret_store: Store<Secret>,
    pub deployment_store: Store<Deployment>,
}

impl AkContextData {
    pub fn new(client: Client) -> Self {
        let (machine_store, machine_writer) = reflector::store::<Machine>();
        let (ak_store, ak_writer) = reflector::store::<AttestationKey>();
        let (secret_store, secret_writer) = reflector::store::<Secret>();
        let (deployment_store, deployment_writer) = reflector::store::<Deployment>();

        crate::spawn_reflector::<Machine>(machine_writer, client.clone(), "Machine");
        crate::spawn_reflector::<AttestationKey>(ak_writer, client.clone(), "AttestationKey");
        crate::spawn_reflector::<Secret>(secret_writer, client.clone(), "Secret");
        crate::spawn_reflector::<Deployment>(deployment_writer, client.clone(), "Deployment");

        Self {
            client,
            machine_store,
            ak_store,
            secret_store,
            deployment_store,
        }
    }

    pub async fn sync_caches(&self, timeout: Duration) -> Result<()> {
        crate::sync_cache(&self.machine_store, "Machine", timeout).await?;
        crate::sync_cache(&self.ak_store, "AttestationKey", timeout).await?;
        crate::sync_cache(&self.secret_store, "Secret", timeout).await?;
        crate::sync_cache(&self.deployment_store, "Deployment", timeout).await?;
        Ok(())
    }
}

const INTERNAL_ATTESTATION_KEY_REGISTER_PORT: i32 = 8001;
const ATTESTATION_KEY_SECRET_FINALIZER: &str =
    "trusted-execution-clusters.io/attestationkey-secret-finalizer";

pub async fn create_attestation_key_register_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
    secret: &Option<String>,
) -> Result<()> {
    let app_label = ATTESTATION_KEY_REGISTER_APP_LABEL;
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let mut args = vec![
        "--port".to_string(),
        ATTESTATION_KEY_REGISTER_PORT.to_string(),
    ];
    let volumes = read_certificate(client.clone(), secret).await?;
    if volumes.is_some() {
        args.push("--cert-path".to_string());
        args.push(format!("{TLS_DIR}/tls.crt"));
        args.push("--key-path".to_string());
        args.push(format!("{TLS_DIR}/tls.key"));
    }

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(ATTESTATION_KEY_REGISTER_DEPLOYMENT.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some("trusted-cluster-operator".to_string()),
                    containers: vec![Container {
                        name: ATTESTATION_KEY_REGISTER_DEPLOYMENT.to_string(),
                        image: Some(image.to_string()),
                        ports: Some(vec![ContainerPort {
                            container_port: ATTESTATION_KEY_REGISTER_PORT,
                            ..Default::default()
                        }]),
                        args: Some(args),
                        volume_mounts: volumes.as_ref().map(|(_, vm)| vec![vm.clone()]),
                        ..Default::default()
                    }],
                    volumes: volumes.as_ref().map(|(v, _)| vec![v.clone()]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    create_or_info_if_exists!(client, Deployment, deployment);
    info!("Attestation key register deployment created successfully");
    Ok(())
}

pub async fn create_attestation_key_register_service(
    client: Client,
    owner_reference: OwnerReference,
    attestation_key_register_port: Option<i32>,
) -> Result<()> {
    let app_label = "attestation-key-register";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let service = Service {
        metadata: ObjectMeta {
            name: Some(ATTESTATION_KEY_REGISTER_SERVICE.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: attestation_key_register_port
                    .unwrap_or(INTERNAL_ATTESTATION_KEY_REGISTER_PORT),
                target_port: Some(IntOrString::Int(INTERNAL_ATTESTATION_KEY_REGISTER_PORT)),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    create_or_info_if_exists!(client, Service, service);
    info!("Attestation key register service created successfully");
    Ok(())
}

async fn ak_reconcile(
    ak: Arc<AttestationKey>,
    ctx: Arc<AkContextData>,
) -> Result<Action, ControllerError> {
    let ak_name = ak.metadata.name.clone().unwrap_or_default();
    info!("Attestation Key reconciliation for: {ak_name}");

    for machine in ctx.machine_store.state() {
        if ak.spec.uuid.as_ref() == Some(&machine.spec.id) {
            approve_ak(&ak, &machine, &ctx).await?;
            return Ok(Action::await_change());
        }
    }
    Ok(Action::await_change())
}

async fn machine_reconcile(
    machine: Arc<Machine>,
    ctx: Arc<AkContextData>,
) -> Result<Action, ControllerError> {
    info!(
        "Machine reconciliation for: {}",
        machine.metadata.name.clone().unwrap_or_default()
    );

    // Check if the machine is being deleted
    if machine.metadata.deletion_timestamp.is_some() {
        info!(
            "Machine {} is being deleted, updating attestation key volumes",
            machine.metadata.name.clone().unwrap_or_default()
        );
        return Ok(Action::await_change());
    }

    for ak in ctx.ak_store.state() {
        if let Some(ak_uuid) = &ak.spec.uuid
            && *ak_uuid == machine.spec.id
        {
            approve_ak(&ak, &machine, &ctx).await?;
            return Ok(Action::await_change());
        }
    }
    Ok(Action::await_change())
}

async fn approve_ak(ak: &AttestationKey, machine: &Machine, ctx: &AkContextData) -> Result<()> {
    let name = ak.metadata.name.clone().unwrap_or_default();
    let client = &ctx.client;
    let aks: Api<AttestationKey> = Api::default_namespaced(client.clone());

    let generation = ak.metadata.generation;
    let approve_reason = ATTESTATION_KEY_MACHINE_APPROVE;
    let condition = attestation_key_approved_condition(approve_reason, generation, &ak.status);
    let mut conditions = ak.status.as_ref().and_then(|s| s.conditions.clone());
    let changed = upsert_condition(&mut conditions, condition);

    if changed {
        let status = AttestationKeyStatus { conditions };
        update_status!(aks, &name, status)?;
        info!("Approved attestation key {name}");
    }

    let machine_name = machine.metadata.name.clone().unwrap_or_default();
    let has_machine_owner = ak
        .metadata
        .owner_references
        .as_ref()
        .map(|owners| {
            owners
                .iter()
                .any(|owner| owner.kind == "Machine" && owner.name == machine_name)
        })
        .unwrap_or(false);

    if !has_machine_owner {
        let machine_owner_reference =
            trusted_cluster_operator_lib::generate_owner_reference(machine)?;

        let patch = json!({
            "metadata": {
                "ownerReferences": [machine_owner_reference]
            }
        });

        aks.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;
        info!("Set Machine as owner of AttestationKey {name}");
    }

    let secret_name = name.clone();
    let ns = client.default_namespace().to_string();
    let secret_exists = ctx
        .secret_store
        .get(&ObjectRef::new(&secret_name).within(&ns))
        .is_some();

    if !secret_exists {
        let public_key_data = ByteString(ak.spec.public_key.as_bytes().to_vec());
        let data = BTreeMap::from([("public_key".to_string(), public_key_data)]);

        let owner_reference = trusted_cluster_operator_lib::generate_owner_reference(ak)?;

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                owner_references: Some(vec![owner_reference]),
                finalizers: Some(vec![ATTESTATION_KEY_SECRET_FINALIZER.to_string()]),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        create_or_info_if_exists!(client.clone(), Secret, secret);
        info!("Created secret {secret_name} for attestation key {name} with finalizer");
    }

    Ok(())
}

async fn secret_reconcile(
    secret: Arc<Secret>,
    ctx: Arc<AkContextData>,
) -> Result<Action, ControllerError> {
    let secret_name = secret.metadata.name.clone().unwrap_or_default();

    // Only handle secrets owned by AttestationKey
    let is_ak_secret = secret
        .metadata
        .owner_references
        .as_ref()
        .map(|owners| owners.iter().any(|owner| owner.kind == "AttestationKey"))
        .unwrap_or(false);

    if !is_ak_secret {
        return Ok(Action::await_change());
    }

    info!("Secret reconciliation for AttestationKey secret: {secret_name}");

    let secrets: Api<Secret> = Api::default_namespaced(ctx.client.clone());
    let ctx = ctx.clone();
    finalizer(&secrets, ATTESTATION_KEY_SECRET_FINALIZER, secret, |ev| async move {
        match ev {
            Event::Apply(_secret) => {
                // On creation/update, just update the trustee deployment volumes
                trustee::update_attestation_keys(&ctx)
                    .await
                    .map(|_| Action::await_change())
                    .map_err(|e| {
                        eprintln!("Error updating attestation key volumes on secret apply: {e}");
                        finalizer::Error::<ControllerError>::ApplyFailed(e.into())
                    })
            }
            Event::Cleanup(secret) => {
                let secret_name = secret.metadata.name.clone().unwrap_or_default();
                info!(
                    "AttestationKey secret {secret_name} is being deleted, updating trustee deployment volumes"
                );
                // Update trustee deployment - secrets with deletion_timestamp will be filtered out
                trustee::update_attestation_keys(&ctx)
                    .await
                    .map(|_| Action::await_change())
                    .map_err(|e| {
                        eprintln!(
                            "Error updating attestation key volumes during secret deletion: {e}"
                        );
                        finalizer::Error::<ControllerError>::CleanupFailed(e.into())
                    })
            }
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile attestation key secret: {e}").into())
}

pub async fn launch_ak_controller(ctx: Arc<AkContextData>) {
    let aks: Api<AttestationKey> = Api::default_namespaced(ctx.client.clone());
    tokio::spawn(
        Controller::new(aks, watcher::Config::default())
            .run(ak_reconcile, controller_error_policy, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("reconciled {o:?}"),
                    Err(e) => info!("reconcile failed: {e:?}"),
                }
            }),
    );
}

pub async fn launch_machine_ak_controller(ctx: Arc<AkContextData>) {
    let machines: Api<Machine> = Api::default_namespaced(ctx.client.clone());
    tokio::spawn(
        Controller::new(machines, watcher::Config::default())
            .run(machine_reconcile, controller_error_policy, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("machine reconciled for ak approval {o:?}"),
                    Err(e) => info!("machine reconcile failed: {e:?}"),
                }
            }),
    );
}

pub async fn launch_secret_ak_controller(ctx: Arc<AkContextData>) {
    let secrets: Api<Secret> = Api::default_namespaced(ctx.client.clone());
    tokio::spawn(
        Controller::new(secrets, watcher::Config::default())
            .run(secret_reconcile, controller_error_policy, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("secret reconciled for ak volumes {o:?}"),
                    Err(e) => info!("secret reconcile failed: {e:?}"),
                }
            }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Request, StatusCode};
    use trusted_cluster_operator_test_utils::mock_client::*;
    use trusted_cluster_operator_test_utils::test_error_method;

    #[tokio::test]
    async fn test_create_ak_register_depl_success() {
        let clos = |client| {
            create_attestation_key_register_deployment(client, Default::default(), "image", &None)
        };
        test_create_success::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_create_ak_register_depl_error() {
        let clos = |client| {
            create_attestation_key_register_deployment(client, Default::default(), "image", &None)
        };
        test_error_method!(clos, Method::POST);
    }

    #[tokio::test]
    async fn test_create_ak_register_svc_success() {
        let clos =
            |client| create_attestation_key_register_service(client, Default::default(), None);
        test_create_success::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_create_ak_register_svc_error() {
        let clos =
            |client| create_attestation_key_register_service(client, Default::default(), Some(80));
        test_error_method!(clos, Method::POST);
    }
}
