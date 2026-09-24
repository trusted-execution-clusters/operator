// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, Node, PodSpec, PodTemplateSpec, Service, ServicePort, ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
    util::intstr::IntOrString,
};
use kube::runtime::{
    controller::{Action, Controller},
    events::EventType,
    finalizer,
    finalizer::Event,
    reflector::ObjectRef,
};
use kube::{Api, Client, Resource};
use log::{info, warn};
use std::{collections::BTreeMap, sync::Arc};

use crate::conditions::machine_key_provisioned_condition;
use crate::trustee;
use operator::*;
use trusted_cluster_operator_lib::{Machine, endpoints::*, record_event};

/// Finalizer name to discard decryption keys when a machine is deleted
const MACHINE_FINALIZER: &str = "finalizer.machine.trusted-execution-clusters.io";

/// Finalizer name to delete the matching Machine when a Node is deleted
const NODE_FINALIZER: &str = "trusted-execution-clusters.io/node";

pub async fn create_register_server_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
    secret: &Option<String>,
) -> Result<()> {
    let labels = BTreeMap::from([("app".to_string(), REGISTER_SERVER_APP_LABEL.to_string())]);

    let mut args = vec!["--port".to_string(), REGISTER_SERVER_PORT.to_string()];
    let volumes = read_certificate(client.clone(), secret).await?;
    if volumes.is_some() {
        args.push("--cert-path".to_string());
        args.push(format!("{TLS_DIR}/tls.crt"));
        args.push("--key-path".to_string());
        args.push(format!("{TLS_DIR}/tls.key"));
    }

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(REGISTER_SERVER_DEPLOYMENT.to_string()),
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
                        name: REGISTER_SERVER_DEPLOYMENT.to_string(),
                        image: Some(image.to_string()),
                        ports: Some(vec![ContainerPort {
                            container_port: REGISTER_SERVER_PORT,
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
    info!("Register server deployment created successfully");
    Ok(())
}

pub async fn create_register_server_service(
    client: Client,
    owner_reference: OwnerReference,
    register_server_port: Option<i32>,
) -> Result<()> {
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let service = Service {
        metadata: ObjectMeta {
            name: Some(REGISTER_SERVER_SERVICE.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("register-server-port".to_string()),
                port: register_server_port.unwrap_or(REGISTER_SERVER_PORT),
                target_port: Some(IntOrString::Int(REGISTER_SERVER_PORT)),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    create_or_info_if_exists!(client, Service, service);
    info!("Register server service created successfully");
    Ok(())
}

async fn keygen_reconcile(
    machine: Arc<Machine>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let machines: Api<Machine> = Api::default_namespaced(ctx.client.clone());
    let recorder = ctx.recorder.clone();
    finalizer(&machines, MACHINE_FINALIZER, machine, |ev| async move {
        match ev {
            Event::Apply(machine) => {
                let machine_ref: ObjectReference = machine.object_ref(&());
                let id = machine.spec.id.clone();
                let machine_name = machine.metadata.name.clone().unwrap_or_default();
                let generation = machine.metadata.generation;
                let existing_status = machine.status.clone();
                let result = async {
                    let owner_reference = generate_owner_reference(&Arc::unwrap_or_clone(machine))?;
                    let provisioning_result = async {
                        trustee::generate_secret(ctx.client.clone(), &id, owner_reference).await?;
                        trustee::send_secret(&ctx, &id).await
                    }
                    .await;

                    let provisioned = provisioning_result.is_ok();
                    let condition = machine_key_provisioned_condition(
                        provisioned,
                        generation,
                        &existing_status,
                    );
                    patch_status_condition::<Machine, _>(
                        ctx.client.clone(),
                        &machine_name,
                        &existing_status,
                        condition,
                        "register-server",
                    )
                    .await?;
                    provisioning_result?;
                    Ok::<(), anyhow::Error>(())
                }
                .await;
                if result.is_ok() {
                    record_event(
                        &recorder,
                        &machine_ref,
                        EventType::Normal,
                        "KeyProvisioned",
                        format!("Decryption key provisioned for machine {id}"),
                        "Provisioning",
                        None,
                    )
                    .await;
                } else {
                    record_event(
                        &recorder,
                        &machine_ref,
                        EventType::Warning,
                        "KeyProvisioningFailed",
                        format!("Failed to provision decryption key for machine {id}"),
                        "Provisioning",
                        None,
                    )
                    .await;
                }
                result
                    .map(|_| LONG_REQUEUE)
                    .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into()))
            }
            Event::Cleanup(machine) => {
                let machine_ref: ObjectReference = machine.object_ref(&());
                let id = &machine.spec.id;

                // Check if the TrustedExecutionCluster is being deleted
                // If so, skip unmounting the secret as everything will be cleaned up
                if let Some(owner_refs) = &machine.metadata.owner_references
                    && let Some(tec_owner) = owner_refs
                        .iter()
                        .find(|owner| owner.kind == "TrustedExecutionCluster")
                {
                    let tec_name = &tec_owner.name;
                    let ns = ctx.client.default_namespace();
                    match ctx.tec_store.get(&ObjectRef::new(tec_name).within(ns)) {
                        Some(tec) if tec.metadata.deletion_timestamp.is_some() => {
                            info!(
                                "TrustedExecutionCluster {tec_name} is being deleted, \
                                 skipping delete_secret for Machine {}",
                                machine.metadata.name.as_deref().unwrap_or("unknown")
                            );
                            return Ok(LONG_REQUEUE);
                        }
                        None => {
                            info!(
                                "TrustedExecutionCluster {tec_name} not found, \
                                 skipping delete_secret for Machine {}",
                                machine.metadata.name.as_deref().unwrap_or("unknown")
                            );
                            return Ok(LONG_REQUEUE);
                        }
                        _ => {
                            // TEC exists and is not being deleted, proceed with unmount_secret
                        }
                    }
                }
                let result = trustee::delete_secret(&ctx, id).await;
                if result.is_ok() {
                    record_event(
                        &recorder,
                        &machine_ref,
                        EventType::Normal,
                        "KeyRevoked",
                        format!("Decryption key revoked for machine {id}"),
                        "Revoking",
                        None,
                    )
                    .await;
                }
                result
                    .map(|_| LONG_REQUEUE)
                    .map_err(|e| finalizer::Error::<ControllerError>::CleanupFailed(e.into()))
            }
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile on machine: {e}").into())
}

pub async fn launch_keygen_controller(ctx: Arc<OperatorContext>) {
    let machines: Api<Machine> = Api::default_namespaced(ctx.client.clone());
    tokio::spawn(
        Controller::new(machines, Default::default())
            .run(keygen_reconcile, controller_error_policy, ctx)
            .for_each(controller_info),
    );
}

/// Delete Machine with providerID matches the given Node's providerID.
async fn delete_machines_for_node(client: Client, node: &Node) -> Result<()> {
    let provider_id = match node.spec.as_ref().and_then(|s| s.provider_id.as_deref()) {
        Some(id) => id,
        None => {
            let name = node.metadata.name.as_deref().unwrap_or("unknown");
            return Err(anyhow!("Node {name} has no providerID"));
        }
    };

    let machines: Api<Machine> = Api::default_namespaced(client);
    let list = match machines.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            warn!("Failed to list Machines: {e:#}");
            return Ok(());
        }
    };

    let mut deleted = false;
    for machine in list.items {
        if machine.spec.provider_id.as_deref() != Some(provider_id) {
            continue;
        }
        let Some(name) = machine.metadata.name.as_deref() else {
            continue;
        };
        match machines.delete(name, &Default::default()).await {
            Ok(_) => {
                info!("Deleted Machine {name} for deleted Node with providerID {provider_id}");
                deleted = true;
            }
            Err(e) => warn!("Failed to delete Machine {name}: {e:#}"),
        }
    }
    if !deleted {
        warn!("No matching Machine found for Node with providerID {provider_id}");
    }
    Ok(())
}

async fn node_reconcile(
    node: Arc<Node>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let nodes: Api<Node> = Api::all(ctx.client.clone());
    finalizer(&nodes, NODE_FINALIZER, node, |ev| async move {
        match ev {
            Event::Apply(_) => Ok(Action::await_change()),

            Event::Cleanup(node) => delete_machines_for_node(ctx.client.clone(), &node)
                .await
                .map(|_| LONG_REQUEUE)
                .map_err(|e| finalizer::Error::<ControllerError>::CleanupFailed(e.into())),
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile on node: {e}").into())
}

pub async fn launch_node_controller(ctx: Arc<OperatorContext>) {
    let nodes: Api<Node> = Api::all(ctx.client.clone());
    tokio::spawn(
        Controller::new(nodes, Default::default())
            .run(node_reconcile, controller_error_policy, ctx)
            .for_each(controller_info),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Request, StatusCode};
    use k8s_openapi::api::core::v1::NodeSpec;
    use kube::api::ObjectList;
    use trusted_cluster_operator_lib::MachineSpec;
    use trusted_cluster_operator_test_utils::mock_client::*;
    use trusted_cluster_operator_test_utils::test_error_method;

    fn node_with_provider_id(provider_id: Option<&str>) -> Node {
        Node {
            metadata: ObjectMeta {
                name: Some("node-1".to_string()),
                ..Default::default()
            },
            spec: Some(NodeSpec {
                provider_id: provider_id.map(str::to_string),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn machine_with_provider_id(name: &str, provider_id: &str) -> Machine {
        Machine {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: MachineSpec {
                id: name.to_string(),
                provider_id: Some(provider_id.to_string()),
            },
            status: None,
        }
    }

    fn machine_list(items: Vec<Machine>) -> ObjectList<Machine> {
        ObjectList {
            types: Default::default(),
            metadata: Default::default(),
            items,
        }
    }

    #[tokio::test]
    async fn test_create_reg_server_depl_success() {
        let clos =
            |client| create_register_server_deployment(client, Default::default(), "image", &None);
        test_create_success::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_create_reg_server_depl_error() {
        let clos =
            |client| create_register_server_deployment(client, Default::default(), "image", &None);
        test_error_method!(clos, Method::POST);
    }

    #[tokio::test]
    async fn test_create_reg_server_svc_success() {
        let clos = |client| create_register_server_service(client, Default::default(), None);
        test_create_success::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_create_reg_server_svc_error() {
        let clos = |client| create_register_server_service(client, Default::default(), Some(80));
        test_error_method!(clos, Method::POST);
    }

    #[tokio::test]
    async fn test_delete_machines_for_node_no_provider_id() {
        let clos = async |_, _| Ok(serde_json::to_string(&machine_list(vec![])).unwrap());
        count_check!(0, clos, |client| {
            let node = node_with_provider_id(None);
            let err = delete_machines_for_node(client, &node).await.unwrap_err();
            assert!(err.to_string().contains("has no providerID"));
        });
    }

    // A matching Machine is listed and then deleted (one GET, one DELETE).
    #[tokio::test]
    async fn test_delete_machines_for_node_deletes_match() {
        let clos = async |req: Request<_>, _| {
            let machine = machine_with_provider_id("machine-1", "azure:///vm-1");
            if req.method() == Method::GET {
                Ok(serde_json::to_string(&machine_list(vec![machine])).unwrap())
            } else if req.method() == Method::DELETE {
                Ok(serde_json::to_string(&machine).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}")
            }
        };
        count_check!(2, clos, |client| {
            let node = node_with_provider_id(Some("azure:///vm-1"));
            assert!(delete_machines_for_node(client, &node).await.is_ok());
        });
    }

    // No Machine matches the Node's providerID: list only, no delete, still Ok.
    #[tokio::test]
    async fn test_delete_machines_for_node_no_match() {
        let clos = async |req: Request<_>, _| {
            if req.method() == Method::GET {
                let other = machine_with_provider_id("machine-other", "azure:///vm-other");
                Ok(serde_json::to_string(&machine_list(vec![other])).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}")
            }
        };
        count_check!(1, clos, |client| {
            let node = node_with_provider_id(Some("azure:///vm-1"));
            assert!(delete_machines_for_node(client, &node).await.is_ok());
        });
    }
}
