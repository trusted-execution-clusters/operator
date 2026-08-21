// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, PodSpec, PodTemplateSpec, Service, ServicePort, ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
    util::intstr::IntOrString,
};
use kube::runtime::{
    controller::{Action, Controller},
    finalizer,
    finalizer::Event,
    reflector::ObjectRef,
};
use kube::{Api, Client, Resource};
use log::info;
use std::{collections::BTreeMap, sync::Arc};

use crate::trustee;
use operator::*;
use trusted_cluster_operator_lib::{Machine, endpoints::*};

/// Finalizer name to discard decryption keys when a machine is deleted
const MACHINE_FINALIZER: &str = "finalizer.machine.trusted-execution-clusters.io";

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
    finalizer(&machines, MACHINE_FINALIZER, machine, |ev| async move {
        match ev {
            Event::Apply(machine) => {
                let id = &machine.spec.id.clone();
                async {
                    let owner_reference = generate_owner_reference(&Arc::unwrap_or_clone(machine))?;
                    trustee::generate_secret(ctx.client.clone(), id, owner_reference).await?;
                    trustee::mount_secret(&ctx, id).await
                }
                .await
                .map(|_| LONG_REQUEUE)
                .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into()))
            }
            Event::Cleanup(machine) => {
                let id = &machine.spec.id;

                // Check if the TrustedExecutionCluster is being deleted
                // If so, skip unmounting the secret as everything will be cleaned up
                if let Some(owner_refs) = &machine.metadata.owner_references
                    && let Some(tec_owner) = owner_refs
                        .iter()
                        .find(|owner| owner.kind == "TrustedExecutionCluster")
                {
                    let tec_name = &tec_owner.name;
                    let ns = ctx.client.default_namespace().to_string();
                    match ctx.tec_store.get(&ObjectRef::new(tec_name).within(&ns)) {
                        Some(tec) if tec.metadata.deletion_timestamp.is_some() => {
                            info!(
                                "TrustedExecutionCluster {tec_name} is being deleted, \
                                 skipping unmount_secret for Machine {}",
                                machine.metadata.name.as_deref().unwrap_or("unknown")
                            );
                            return Ok(LONG_REQUEUE);
                        }
                        None => {
                            info!(
                                "TrustedExecutionCluster {tec_name} not found, \
                                 skipping unmount_secret for Machine {}",
                                machine.metadata.name.as_deref().unwrap_or("unknown")
                            );
                            return Ok(LONG_REQUEUE);
                        }
                        _ => {
                            // TEC exists and is not being deleted, proceed with unmount_secret
                        }
                    }
                }

                trustee::unmount_secret(&ctx, id)
                    .await
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Request, StatusCode};
    use trusted_cluster_operator_test_utils::mock_client::*;
    use trusted_cluster_operator_test_utils::test_error_method;

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
}
