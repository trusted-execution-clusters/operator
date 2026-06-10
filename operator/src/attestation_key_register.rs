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
    Api, Client,
    api::{ListParams, ObjectList, Patch, PatchParams},
    runtime::{Controller, controller::Action, finalizer, finalizer::Event, watcher},
};
use log::info;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc};

use trusted_cluster_operator_lib::conditions::ATTESTATION_KEY_MACHINE_APPROVE;
use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::{AttestationKey, AttestationKeyStatus, Machine, update_status};

use crate::conditions::attestation_key_approved_condition;
use crate::trustee;
use operator::{
    ControllerError, TLS_DIR, apply_resource, controller_error_policy, read_certificate,
    upsert_condition,
};

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

    apply_resource!(client, Deployment, deployment);
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

    apply_resource!(client, Service, service);
    info!("Attestation key register service created successfully");
    Ok(())
}

async fn ak_reconcile(
    ak: Arc<AttestationKey>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    let ak_name = ak.metadata.name.clone().unwrap_or_default();
    info!("Attestation Key reconciliation for: {ak_name}");

    let client = Arc::unwrap_or_clone(client);
    let machines: Api<Machine> = Api::default_namespaced(client.clone());
    let lp = ListParams::default();
    let machine_list: ObjectList<Machine> = machines.list(&lp).await.map_err(|e| {
        eprintln!("Error fetching machine list: {e}");
        ControllerError::Anyhow(e.into())
    })?;
    for machine in &machine_list.items {
        if ak.spec.uuid.as_ref() == Some(&machine.spec.id) {
            approve_ak(&ak, machine, client.clone()).await?;
            return Ok(Action::await_change());
        }
    }
    Ok(Action::await_change())
}

async fn machine_reconcile(
    machine: Arc<Machine>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    info!(
        "Machine reconciliation for: {}",
        machine.metadata.name.clone().unwrap_or_default()
    );
    let client = Arc::unwrap_or_clone(client);

    // Check if the machine is being deleted
    if machine.metadata.deletion_timestamp.is_some() {
        info!(
            "Machine {} is being deleted, updating attestation key volumes",
            machine.metadata.name.clone().unwrap_or_default()
        );
        return Ok(Action::await_change());
    }

    let aks: Api<AttestationKey> = Api::default_namespaced(client.clone());
    let lp = ListParams::default();
    let ak_list: ObjectList<AttestationKey> = aks.list(&lp).await.map_err(|e| {
        eprintln!("Error fetching attestation key list: {e}");
        ControllerError::Anyhow(e.into())
    })?;
    for ak in ak_list.items {
        if let Some(ak_uuid) = &ak.spec.uuid
            && *ak_uuid == machine.spec.id
        {
            approve_ak(&ak, &machine, client.clone()).await?;
            return Ok(Action::await_change());
        }
    }
    Ok(Action::await_change())
}

async fn approve_ak(ak: &AttestationKey, machine: &Machine, client: Client) -> Result<()> {
    let name = ak.metadata.name.clone().unwrap_or_default();
    let aks: Api<AttestationKey> = Api::default_namespaced(client.clone());

    let generation = ak.metadata.generation;
    let approve_reason = ATTESTATION_KEY_MACHINE_APPROVE;
    let condition = attestation_key_approved_condition(approve_reason, generation, &ak.status);
    let mut conditions = ak.status.as_ref().and_then(|s| s.conditions.clone());
    let changed = upsert_condition(&mut conditions, condition);

    if changed {
        let status = AttestationKeyStatus { conditions };
        update_status!(
            aks,
            &name,
            status,
            AttestationKey,
            trusted_cluster_operator_lib::FIELD_MANAGER
        )?;
        info!("Approved attestation key {name}");
    }

    let machine_name = machine.metadata.name.clone().unwrap_or_default();
    let has_machine_owner_controller = ak
        .metadata
        .owner_references
        .as_ref()
        .map(|owners| {
            owners.iter().any(|owner| {
                owner.kind == "Machine"
                    && owner.name == machine_name
                    && owner.controller == Some(true)
            })
        })
        .unwrap_or(false);

    if !has_machine_owner_controller {
        let owner_controller_reference =
            trusted_cluster_operator_lib::generate_owner_controller_reference(machine)?;

        // Replacing the owner of the AttestationKey to the Machine controller, as now the AttestationKey is tied to the Machine.
        let patch = json!({
            "metadata": {
                "ownerReferences": [owner_controller_reference]
            }
        });

        // This requires a client-side patch since merge patches replaces entire owners field. SSA would upsert, and cause issues where we might not cleanly remove the TEC owner reference.
        aks.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;
        info!("Set Machine as owner-controller of AttestationKey {name}");
    }

    let secret_name = name.clone();
    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    let secret_exists = secrets.get(&secret_name).await.is_ok();

    if !secret_exists {
        let public_key_data = ByteString(ak.spec.public_key.as_bytes().to_vec());
        let data = BTreeMap::from([("public_key".to_string(), public_key_data)]);

        let owner_controller_reference =
            trusted_cluster_operator_lib::generate_owner_controller_reference(ak)?;

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                owner_references: Some(vec![owner_controller_reference]),
                finalizers: Some(vec![ATTESTATION_KEY_SECRET_FINALIZER.to_string()]),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        apply_resource!(client.clone(), Secret, secret);
        info!("Created secret {secret_name} for attestation key {name} with finalizer");
    }

    Ok(())
}

async fn secret_reconcile(
    secret: Arc<Secret>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    let secret_name = secret.metadata.name.clone().unwrap_or_default();

    // Only handle secrets controlled by an AttestationKey
    let is_ak_secret = secret
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners
                .iter()
                .any(|owner| owner.kind == "AttestationKey" && owner.controller == Some(true))
        });

    if !is_ak_secret {
        return Ok(Action::await_change());
    }

    info!("Secret reconciliation for AttestationKey secret: {secret_name}");

    let secrets: Api<Secret> = Api::default_namespaced(Arc::unwrap_or_clone(client.clone()));
    finalizer(&secrets, ATTESTATION_KEY_SECRET_FINALIZER, secret, |ev| async move {
        match ev {
            Event::Apply(_secret) => {
                // On creation/update, just update the trustee deployment volumes
                let client = Arc::unwrap_or_clone(client);
                trustee::update_attestation_keys(client)
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
                let client = Arc::unwrap_or_clone(client);
                // Update trustee deployment - secrets with deletion_timestamp will be filtered out
                match trustee::update_attestation_keys(client).await {
                    Ok(_) => Ok(Action::await_change()),
                    Err(e) if e.to_string().contains("not found") => {
                        info!("Trustee deployment not found during secret cleanup (likely already deleted)");
                        Ok(Action::await_change())
                    }
                    Err(e) => {
                        eprintln!(
                            "Error updating attestation key volumes during secret deletion: {e}"
                        );
                        Err(finalizer::Error::<ControllerError>::CleanupFailed(e.into()))
                    }
                }
            }
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile attestation key secret: {e}").into())
}

pub async fn launch_ak_controller(client: Client) {
    let aks: Api<AttestationKey> = Api::default_namespaced(client.clone());
    tokio::spawn(
        Controller::new(aks, watcher::Config::default())
            .run(ak_reconcile, controller_error_policy, Arc::new(client))
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("reconciled {o:?}"),
                    Err(e) => info!("reconcile failed: {e:?}"),
                }
            }),
    );
}

pub async fn launch_machine_ak_controller(client: Client) {
    let machines: Api<Machine> = Api::default_namespaced(client.clone());
    tokio::spawn(
        Controller::new(machines, watcher::Config::default())
            .run(machine_reconcile, controller_error_policy, Arc::new(client))
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("machine reconciled for ak approval {o:?}"),
                    Err(e) => info!("machine reconcile failed: {e:?}"),
                }
            }),
    );
}

pub async fn launch_secret_ak_controller(client: Client) {
    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    tokio::spawn(
        Controller::new(secrets, watcher::Config::default())
            .run(secret_reconcile, controller_error_policy, Arc::new(client))
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
    use http::{Method, Request};
    use trusted_cluster_operator_test_utils::mock_client::*;

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
        test_create_error(clos).await;
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
        test_create_error(clos).await;
    }

    fn dummy_ak() -> AttestationKey {
        AttestationKey {
            metadata: ObjectMeta {
                name: Some("ak-test".to_string()),
                uid: Some("ak-uid".to_string()),
                generation: Some(1),
                ..Default::default()
            },
            spec: trusted_cluster_operator_lib::AttestationKeySpec {
                public_key: "test-key".to_string(),
                uuid: Some("machine-uuid".to_string()),
            },
            status: None,
        }
    }

    fn dummy_machine() -> Machine {
        Machine {
            metadata: ObjectMeta {
                name: Some("machine-test".to_string()),
                uid: Some("machine-uid".to_string()),
                ..Default::default()
            },
            spec: trusted_cluster_operator_lib::MachineSpec {
                id: "machine-uuid".to_string(),
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn test_approve_ak_full_flow() {
        // approve_ak with no prior status, no Machine owner, and secret not existing:
        // 1. PATCH /status (SSA status update). AttestationKey is approved.
        // 2. PATCH owner transfer (Merge). Ownership transfered to Machine.
        // 3. GET secret (check existence)
        // 4. PATCH secret (apply_resource! SSA create)
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::PATCH) => {
                assert!(req.uri().path().contains("/status"));
                Ok(serde_json::to_string(&dummy_ak()).unwrap())
            }
            (1, &Method::PATCH) => {
                assert!(!req.uri().path().contains("/status"));
                Ok(serde_json::to_string(&dummy_ak()).unwrap())
            }
            (2, &Method::GET) => Err(http::StatusCode::NOT_FOUND),
            (3, &Method::PATCH) => {
                let body = get_body_string(req).await;
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                let owners = v["metadata"]["ownerReferences"]
                    .as_array()
                    .expect("Secret must have ownerReferences");
                assert_eq!(
                    owners[0]["kind"], "AttestationKey",
                    "Secret must be owned by AttestationKey"
                );
                assert_eq!(
                    owners[0]["controller"], true,
                    "AttestationKey must be controller of Secret"
                );
                assert_eq!(
                    owners[0]["uid"], "ak-uid",
                    "Secret owner UID must match AK UID"
                );

                // Asserting finalizers
                let finalizers = v["metadata"]["finalizers"]
                    .as_array()
                    .expect("Secret must have finalizers");
                assert!(
                    finalizers.iter().any(|f| f
                        .as_str()
                        .unwrap()
                        .contains("attestationkey-secret-finalizer")),
                    "Secret must have the attestation key secret finalizer"
                );
                let data = v["data"].as_object().expect("Secret must have data");
                assert!(
                    data.contains_key("public_key"),
                    "Secret data must contain public_key"
                );
                Ok(serde_json::to_string(&Secret::default()).unwrap())
            }

            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(4, clos, |client| {
            let ak = dummy_ak();
            let machine = dummy_machine();
            assert!(approve_ak(&ak, &machine, client).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_approve_ak_already_approved_and_owned() {
        // Building a pre-populated AttestationKey with the approved condition. This would prevent upsert from changing the status field, preventing the initial status PATCH.
        // Further-more, we set owner of AttestationKey to the Machine, so that no owner transfer PATCH is needed.
        // Further, get secret returns valid secret, so no secret PATCH is needed.
        // Only 1 GET call to fetch secret is needed.
        let mut ak = dummy_ak();
        let approve_reason =
            trusted_cluster_operator_lib::conditions::ATTESTATION_KEY_MACHINE_APPROVE;
        let existing_condition = crate::conditions::attestation_key_approved_condition(
            approve_reason,
            ak.metadata.generation,
            &ak.status,
        );
        ak.status = Some(AttestationKeyStatus {
            conditions: Some(vec![existing_condition]),
        });
        ak.metadata.owner_references = Some(vec![OwnerReference {
            kind: "Machine".to_string(),
            name: "machine-test".to_string(),
            uid: "machine-uid".to_string(),
            api_version: "trusted-execution-clusters.io/v1alpha1".to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }]);

        // No status or owner PATCH needed; only GET secret (exists)
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => Ok(serde_json::to_string(&Secret::default()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(1, clos, |client| {
            let machine = dummy_machine();
            assert!(approve_ak(&ak, &machine, client).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_approve_ak_status_update_error() {
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::PATCH) => Err(http::StatusCode::INTERNAL_SERVER_ERROR),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(1, clos, |client| {
            let ak = dummy_ak();
            let machine = dummy_machine();
            assert!(approve_ak(&ak, &machine, client).await.is_err());
        });
    }

    #[tokio::test]
    async fn test_approve_ak_status_patch_contains_approved_condition() {
        use kube::client::Body;
        let clos = async |req: Request<Body>, ctr| match (ctr, req.method()) {
            // Validates whether attestation key is immediately approved as per TOFU (Trust on first use) principles.
            // Also makes sure that the approved condition is set to True, and the reason is MachineCreated.
            (0, &Method::PATCH) => {
                assert!(
                    req.uri().path().contains("/status"),
                    "First PATCH must target /status subresource"
                );
                let body = get_body_string(req).await;
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                let conditions = v["status"]["conditions"]
                    .as_array()
                    .expect("Status body must contain conditions array");
                let approved_type =
                    trusted_cluster_operator_lib::conditions::ATTESTATION_KEY_APPROVED_CONDITION;
                let approved = conditions.iter().find(|c| c["type"] == approved_type);
                assert!(
                    approved.is_some(),
                    "Must contain the '{approved_type}' condition"
                );
                let cond = approved.unwrap();
                assert_eq!(cond["status"], "True", "Approved condition must be True");
                assert_eq!(
                    cond["reason"], ATTESTATION_KEY_MACHINE_APPROVE,
                    "Reason must be MachineCreated"
                );
                Ok(serde_json::to_string(&dummy_ak()).unwrap())
            }
            (1, &Method::PATCH) => Ok(serde_json::to_string(&dummy_ak()).unwrap()),
            (2, &Method::GET) => Err(http::StatusCode::NOT_FOUND),
            (3, &Method::PATCH) => Ok(serde_json::to_string(&Secret::default()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(4, clos, |client| {
            let ak = dummy_ak();
            let machine = dummy_machine();
            assert!(approve_ak(&ak, &machine, client).await.is_ok());
        });
    }

    // Makes sure that the owner transfer patch uses merge patch, and not SSA patch.
    // SSA can't transfer ownership, and would cause issues where we might not cleanly remove the TEC owner reference.
    #[tokio::test]
    async fn test_approve_ak_owner_transfer_uses_merge_patch() {
        use kube::client::Body;
        let clos = async |req: Request<Body>, ctr| match (ctr, req.method()) {
            (0, &Method::PATCH) => Ok(serde_json::to_string(&dummy_ak()).unwrap()),
            (1, &Method::PATCH) => {
                assert!(
                    !req.uri().path().contains("/status"),
                    "Owner transfer must not target /status"
                );
                let query = req.uri().query().unwrap_or("");
                assert!(
                    !query.contains("fieldManager"),
                    "Merge patch must NOT use a field manager (not SSA): {query}"
                );
                let content_type = req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                assert!(
                    content_type.contains("merge-patch"),
                    "Owner transfer must use Merge patch, got content-type: {content_type}"
                );
                let body = get_body_string(req).await;
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                let owners = v["metadata"]["ownerReferences"]
                    .as_array()
                    .expect("Merge patch must set ownerReferences");
                assert_eq!(
                    owners.len(),
                    1,
                    "Must replace entire ownerReferences (not append)"
                );
                assert_eq!(owners[0]["kind"], "Machine", "New owner must be Machine");
                assert_eq!(owners[0]["name"], "machine-test");
                assert_eq!(owners[0]["controller"], true, "Machine must be controller");
                Ok(serde_json::to_string(&dummy_ak()).unwrap())
            }
            (2, &Method::GET) => Err(http::StatusCode::NOT_FOUND),
            (3, &Method::PATCH) => Ok(serde_json::to_string(&Secret::default()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(4, clos, |client| {
            let ak = dummy_ak();
            let machine = dummy_machine();
            assert!(approve_ak(&ak, &machine, client).await.is_ok());
        });
    }
}
