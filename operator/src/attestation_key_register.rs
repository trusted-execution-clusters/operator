// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, PodSpec, PodTemplateSpec, Secret, Service, ServicePort, ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
    util::intstr::IntOrString,
};
use kube::api::{Patch, PatchParams};
use kube::runtime::{Controller, controller::Action, reflector::ObjectRef, watcher};
use kube::runtime::{events::EventType, finalizer, finalizer::Event};
use kube::{Api, Client, Resource};
use log::{info, warn};
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};

use trusted_cluster_operator_lib::conditions::ATTESTATION_KEY_MACHINE_APPROVE;
use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::{AttestationKey, Machine, record_event};

use crate::conditions::{attestation_key_approved_condition, machine_ak_approved_condition};
use crate::trustee;
use operator::{
    ControllerError, KIND_LABEL_KEY, LONG_REQUEUE, OperatorContext, TLS_DIR,
    controller_error_policy, create_or_info_if_exists, patch_status_condition, read_certificate,
};

const INTERNAL_ATTESTATION_KEY_REGISTER_PORT: i32 = 8001;
const ATTESTATION_KEY_SECRET_FINALIZER: &str =
    "trusted-execution-clusters.io/attestationkey-secret-finalizer";
const ATTESTATION_KEY_LABEL_VALUE: &str = "attestationkey";

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
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let ak_name = ak.metadata.name.clone().unwrap_or_default();
    info!("Attestation Key reconciliation for: {ak_name}");

    for machine in ctx.machine_store.state() {
        if ak.spec.uuid.as_ref() == Some(&machine.spec.id) {
            approve_ak(&ak, &machine, &ctx).await?;
            return Ok(LONG_REQUEUE);
        }
    }
    Ok(LONG_REQUEUE)
}

async fn machine_reconcile(
    machine: Arc<Machine>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    info!(
        "Machine reconciliation for: {}",
        machine.metadata.name.clone().unwrap_or_default()
    );

    // Check if the machine is being deleted
    if machine.metadata.deletion_timestamp.is_some() {
        info!(
            "Machine {} is being deleted, updating attestation key",
            machine.metadata.name.clone().unwrap_or_default()
        );
        return Ok(LONG_REQUEUE);
    }

    for ak in ctx.ak_store.state() {
        if let Some(ak_uuid) = &ak.spec.uuid
            && *ak_uuid == machine.spec.id
        {
            approve_ak(&ak, &machine, &ctx).await?;
            return Ok(LONG_REQUEUE);
        }
    }

    let machine_name = machine.metadata.name.clone().unwrap_or_default();
    let condition =
        machine_ak_approved_condition(false, machine.metadata.generation, &machine.status);
    patch_status_condition::<Machine, _>(
        ctx.client.clone(),
        &machine_name,
        &machine.status,
        condition,
        "attestation-key-register",
    )
    .await?;

    Ok(LONG_REQUEUE)
}

async fn approve_ak(ak: &AttestationKey, machine: &Machine, ctx: &OperatorContext) -> Result<()> {
    let name = ak.metadata.name.clone().unwrap_or_default();
    let client = &ctx.client;
    let aks: Api<AttestationKey> = Api::default_namespaced(client.clone());

    let machine_name = machine.metadata.name.clone().unwrap_or_default();
    let condition = attestation_key_approved_condition(
        ATTESTATION_KEY_MACHINE_APPROVE,
        ak.metadata.generation,
        &ak.status,
    );

    if patch_status_condition::<AttestationKey, _>(
        client.clone(),
        &name,
        &ak.status,
        condition,
        "attestation-key-register",
    )
    .await?
    {
        info!("Approved attestation key {name}");

        let ak_ref: ObjectReference = ak.object_ref(&());
        let machine_ref: ObjectReference = machine.object_ref(&());
        record_event(
            &ctx.recorder,
            &ak_ref,
            EventType::Normal,
            "AttestationKeyApproved",
            format!("Attestation key {name} approved for machine {machine_name}"),
            "Approving",
            Some(machine_ref.clone()),
        )
        .await;
        record_event(
            &ctx.recorder,
            &machine_ref,
            EventType::Normal,
            "AttestationKeyApproved",
            format!("Machine {machine_name} matched attestation key {name}"),
            "Approving",
            Some(ak_ref),
        )
        .await;
    }
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
    let obj_ref = ObjectRef::new(&secret_name).within(client.default_namespace());
    let secret_exists = ctx.secret_store.get(&obj_ref).is_some();

    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    if !secret_exists {
        let public_key_data = ByteString(ak.spec.public_key.as_bytes().to_vec());
        let data = BTreeMap::from([("public_key".to_string(), public_key_data)]);

        let owner_reference = trusted_cluster_operator_lib::generate_owner_reference(ak)?;

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                labels: Some(BTreeMap::from([(
                    KIND_LABEL_KEY.to_string(),
                    ATTESTATION_KEY_LABEL_VALUE.to_string(),
                )])),
                owner_references: Some(vec![owner_reference]),
                finalizers: Some(vec![ATTESTATION_KEY_SECRET_FINALIZER.to_string()]),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        create_or_info_if_exists!(client.clone(), Secret, secret);
        info!("Created secret {secret_name} for attestation key {name} with finalizer");
    } else {
        // Ensures the AttestationKey secret has the label the secret controller watches on.
        ensure_secret_label(&secrets, &secret_name).await?;
    }

    let machine_condition =
        machine_ak_approved_condition(true, machine.metadata.generation, &machine.status);
    if patch_status_condition::<Machine, _>(
        client.clone(),
        &machine_name,
        &machine.status,
        machine_condition,
        "attestation-key-register",
    )
    .await?
    {
        info!("Set AttestationKeyApproved condition on Machine {machine_name}");
    }

    Ok(())
}

// Secrets created by older operator versions lack the label, as older operator versions watched all secrets, without label filters.
async fn ensure_secret_label(secrets: &Api<Secret>, name: &str) -> Result<()> {
    let Some(secret) = secrets.get_opt(name).await? else {
        return Ok(());
    };
    let has_label = secret
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(KIND_LABEL_KEY))
        .is_some_and(|v| v == ATTESTATION_KEY_LABEL_VALUE);
    if !has_label {
        let patch = json!({
            "metadata": {
                "labels": {
                    KIND_LABEL_KEY: ATTESTATION_KEY_LABEL_VALUE
                }
            }
        });
        secrets
            .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;
        info!("Patched missing {KIND_LABEL_KEY} label onto secret {name}");
    }
    Ok(())
}

async fn secret_reconcile(
    secret: Arc<Secret>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let secret_name = secret.metadata.name.clone().unwrap_or_default();
    info!("Secret reconciliation for AttestationKey secret: {secret_name}");

    let secrets: Api<Secret> = Api::default_namespaced(ctx.client.clone());
    finalizer(
        &secrets,
        ATTESTATION_KEY_SECRET_FINALIZER,
        secret,
        |ev| async move {
            match ev {
                Event::Apply(_secret) => {
                    // On creation/update, just update the AK via trustee API
                    trustee::update_attestation_keys(&ctx)
                        .await
                        .map(|_| LONG_REQUEUE)
                        .map_err(|e| {
                            warn!("Error updating attestation key volumes on secret apply: {e}");
                            warn!("Error updating attestation key on secret apply: {e}");
                            finalizer::Error::<ControllerError>::ApplyFailed(e.into())
                        })
                }
                Event::Cleanup(secret) => {
                    let secret_name = secret.metadata.name.clone().unwrap_or_default();

                    // If TEC is already being deleted, trustee will be deleted too, so no need to update it.
                    let tec_deleting = ctx
                        .get_opt_tec()
                        .ok()
                        .flatten()
                        .is_none_or(|tec| tec.metadata.deletion_timestamp.is_some());

                    if tec_deleting {
                        info!(
                            "TrustedExecutionCluster is being deleted, \
                         skipping trustee update for AttestationKey secret {secret_name}"
                        );
                        return Ok(LONG_REQUEUE);
                    }

                    info!("AttestationKey secret {secret_name} is being deleted, updating trustee");
                    // Update trustee deployment - secrets with deletion_timestamp will be filtered out
                    trustee::update_attestation_keys(&ctx)
                        .await
                        .map(|_| LONG_REQUEUE)
                        .map_err(|e| {
                            warn!("Error updating attestation key during secret deletion: {e}");
                            finalizer::Error::<ControllerError>::CleanupFailed(e.into())
                        })
                }
            }
        },
    )
    .await
    .map_err(|e| anyhow!("failed to reconcile attestation key secret: {e}").into())
}

pub async fn launch_ak_controller(ctx: Arc<OperatorContext>) {
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

pub async fn launch_machine_ak_controller(ctx: Arc<OperatorContext>) {
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

pub async fn launch_secret_ak_controller(ctx: Arc<OperatorContext>) {
    let secrets: Api<Secret> = Api::default_namespaced(ctx.client.clone());
    let wc = watcher::Config::default()
        .labels(&format!("{KIND_LABEL_KEY}={ATTESTATION_KEY_LABEL_VALUE}"));
    tokio::spawn(
        Controller::new(secrets, wc)
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
