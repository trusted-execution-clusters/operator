// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::{
    api::{
        apps::v1::{Deployment, DeploymentSpec},
        core::v1::{
            Container, ContainerPort, PodSpec, PodTemplateSpec, Service, ServicePort, ServiceSpec,
        },
    },
    apimachinery::pkg::{
        apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
        util::intstr::IntOrString,
    },
};
use kube::runtime::{
    controller::{Action, Controller},
    finalizer,
    finalizer::Event,
};
use kube::{Api, Client, Resource};
use log::info;
use std::{collections::BTreeMap, sync::Arc};

use crate::trustee;
use operator::*;
use trusted_cluster_operator_lib::Machine;

const INTERNAL_REGISTER_SERVER_PORT: i32 = 8000;
/// Finalizer name to discard decryption keys when a machine is deleted
const MACHINE_FINALIZER: &str = "finalizer.machine.trusted-execution-clusters.io";

pub async fn create_register_server_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
) -> Result<()> {
    let name = "register-server";
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
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
                        name: name.to_string(),
                        image: Some(image.to_string()),
                        ports: Some(vec![ContainerPort {
                            container_port: INTERNAL_REGISTER_SERVER_PORT,
                            ..Default::default()
                        }]),
                        args: Some(vec![
                            "--port".to_string(),
                            INTERNAL_REGISTER_SERVER_PORT.to_string(),
                        ]),
                        ..Default::default()
                    }],
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
    let name = "register-server";
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let service = Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: register_server_port.unwrap_or(INTERNAL_REGISTER_SERVER_PORT),
                target_port: Some(IntOrString::Int(INTERNAL_REGISTER_SERVER_PORT)),
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
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    let machines: Api<Machine> = Api::default_namespaced(Arc::unwrap_or_clone(client.clone()));
    finalizer(&machines, MACHINE_FINALIZER, machine, |ev| async move {
        match ev {
            Event::Apply(machine) => {
                let kube_client = Arc::unwrap_or_clone(client);
                let id = &machine.spec.id.clone();
                async {
                    let owner_reference = generate_owner_reference(&Arc::unwrap_or_clone(machine))?;
                    trustee::generate_secret(kube_client.clone(), id, owner_reference).await?;
                    trustee::mount_secret(kube_client, id).await
                }
                .await
                .map(|_| Action::await_change())
                .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into()))
            }
            Event::Cleanup(machine) => {
                let kube_client = Arc::unwrap_or_clone(client);
                let id = &machine.spec.id;
                trustee::unmount_secret(kube_client, id)
                    .await
                    .map(|_| Action::await_change())
                    .map_err(|e| finalizer::Error::<ControllerError>::CleanupFailed(e.into()))
            }
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile on machine: {e}").into())
}

pub async fn launch_keygen_controller(client: Client) {
    let machines: Api<Machine> = Api::default_namespaced(client.clone());
    tokio::spawn(
        Controller::new(machines, Default::default())
            .run(keygen_reconcile, controller_error_policy, Arc::new(client))
            .for_each(controller_info),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusted_cluster_operator_test_utils::mock_client::*;

    #[tokio::test]
    async fn test_create_reg_server_depl_success() {
        let clos = |client| create_register_server_deployment(client, Default::default(), "image");
        test_create_success::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_create_reg_server_depl_error() {
        let clos = |client| create_register_server_deployment(client, Default::default(), "image");
        test_create_error(clos).await;
    }

    #[tokio::test]
    async fn test_create_reg_server_svc_success() {
        let clos = |client| create_register_server_service(client, Default::default(), None);
        test_create_success::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_create_reg_server_svc_error() {
        let clos = |client| create_register_server_service(client, Default::default(), Some(80));
        test_create_error(clos).await;
    }
}
