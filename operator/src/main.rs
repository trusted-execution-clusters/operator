// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use env_logger::Env;
use futures_util::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::{Api, Client};
use log::{error, info, warn};

use operator::generate_owner_reference;
use trusted_cluster_operator_lib::{TrustedExecutionCluster, TrustedExecutionClusterStatus};
use trusted_cluster_operator_lib::{conditions::*, update_status};

mod conditions;
#[cfg(test)]
mod test_utils;
mod reference_values;
mod register_server;
mod trustee;

use crate::conditions::*;
use operator::*;

fn is_installed(status: Option<TrustedExecutionClusterStatus>) -> bool {
    let chk = |c: &Condition| c.type_ == INSTALLED_CONDITION && c.status == "True";
    status
        .and_then(|s| s.conditions)
        .map(|cs| cs.iter().any(chk))
        .unwrap_or(false)
}

async fn reconcile(
    cluster: Arc<TrustedExecutionCluster>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    let generation = cluster.metadata.generation;
    let known_address = cluster.spec.public_trustee_addr.is_some();
    let address_condition = known_trustee_address_condition(known_address, generation);
    let mut conditions = Some(vec![address_condition]);

    let kube_client = Arc::unwrap_or_clone(client);
    let err = "trusted execution cluster had no name";
    let name = &cluster.metadata.name.clone().expect(err);
    let clusters: Api<TrustedExecutionCluster> = Api::default_namespaced(kube_client.clone());

    if cluster.metadata.deletion_timestamp.is_some() {
        info!("Registered deletion of TrustedExecutionCluster {name}");
        let condition = installed_condition(NOT_INSTALLED_REASON_UNINSTALLING, generation);
        conditions.as_mut().unwrap().push(condition);
        update_status!(clusters, name, TrustedExecutionClusterStatus { conditions })?;
        return Ok(Action::await_change());
    }

    if is_installed(cluster.status.clone()) {
        return Ok(Action::await_change());
    }

    let list = clusters.list(&Default::default()).await;
    let cluster_list = list.map_err(Into::<anyhow::Error>::into)?;
    if cluster_list.items.len() > 1 {
        let namespace = kube_client.default_namespace();
        warn!(
            "More than one TrustedExecutionCluster found in namespace {namespace}. \
             trusted-cluster-operator does not support more than one TrustedExecutionCluster. Requeueing...",
        );
        let condition = installed_condition(NOT_INSTALLED_REASON_NON_UNIQUE, generation);
        conditions.as_mut().unwrap().push(condition);
        update_status!(clusters, name, TrustedExecutionClusterStatus { conditions })?;
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    info!("Setting up TrustedExecutionCluster {name}");
    let mut installing = conditions.clone();
    let condition = installed_condition(NOT_INSTALLED_REASON_INSTALLING, generation);
    installing.as_mut().unwrap().push(condition);
    let status = TrustedExecutionClusterStatus {
        conditions: installing,
    };
    update_status!(clusters, name, status)?;

    install_trustee_configuration(kube_client.clone(), &cluster).await?;
    install_register_server(kube_client, &cluster).await?;
    let condition = installed_condition(INSTALLED_REASON, generation);
    conditions.as_mut().unwrap().push(condition);
    update_status!(clusters, name, TrustedExecutionClusterStatus { conditions })?;
    Ok(Action::await_change())
}

async fn install_trustee_configuration(
    client: Client,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let owner_reference = generate_owner_reference(cluster)?;

    match trustee::generate_trustee_data(client.clone(), owner_reference.clone()).await {
        Ok(_) => info!("Generate configmap for the KBS configuration",),
        Err(e) => error!("Failed to create the KBS configuration configmap: {e}"),
    }

    let rv_ctx = RvContextData {
        client: client.clone(),
        owner_reference: owner_reference.clone(),
        pcrs_compute_image: cluster.spec.pcrs_compute_image.clone(),
    };
    reference_values::launch_rv_image_controller(rv_ctx.clone()).await;
    reference_values::launch_rv_job_controller(rv_ctx.clone()).await;
    match reference_values::create_pcrs_config_map(client.clone(), owner_reference.clone()).await {
        Ok(_) => info!("Created bare configmap for PCRs"),
        Err(e) => error!("Failed to create the PCRs configmap: {e}"),
    }

    match trustee::generate_attestation_policy(client.clone(), owner_reference.clone()).await {
        Ok(_) => info!("Generate configmap for the attestation policy",),
        Err(e) => error!("Failed to create the attestation policy configmap: {e}"),
    }

    let kbs_port = cluster.spec.trustee_kbs_port;
    match trustee::generate_kbs_service(client.clone(), owner_reference.clone(), kbs_port).await {
        Ok(_) => info!("Generate the KBS service"),
        Err(e) => error!("Failed to create the KBS service: {e}"),
    }

    let trustee_image = &cluster.spec.trustee_image;
    match trustee::generate_kbs_deployment(client, owner_reference, trustee_image).await {
        Ok(_) => info!("Generate the KBS deployment"),
        Err(e) => error!("Failed to create the KBS deployment: {e}"),
    }

    Ok(())
}

async fn install_register_server(client: Client, cluster: &TrustedExecutionCluster) -> Result<()> {
    let owner_reference = generate_owner_reference(cluster)?;

    match register_server::create_register_server_deployment(
        client.clone(),
        owner_reference.clone(),
        &cluster.spec.register_server_image,
    )
    .await
    {
        Ok(_) => info!("Register server deployment created/updated successfully"),
        Err(e) => error!("Failed to create register server deployment: {e}"),
    }

    let port = cluster.spec.register_server_port;
    match register_server::create_register_server_service(client.clone(), owner_reference, port)
        .await
    {
        Ok(_) => info!("Register server service created/updated successfully"),
        Err(e) => error!("Failed to create register server service: {e}"),
    }

    register_server::launch_keygen_controller(client).await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let kube_client = Client::try_default().await?;
    info!("trusted execution clusters operator",);
    let cl: Api<TrustedExecutionCluster> = Api::default_namespaced(kube_client.clone());

    let client = Arc::new(kube_client);
    Controller::new(cl, watcher::Config::default())
        .run(reconcile, controller_error_policy, client)
        .for_each(controller_info)
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{Method, Request, StatusCode};
    use k8s_openapi::{apimachinery::pkg::apis::meta::v1::Time, chrono::Utc};
    use kube::api::ObjectList;
    use kube::client::Body;

    use super::*;
    use trusted_cluster_operator_test_utils::mock_client::*;

    #[tokio::test]
    async fn test_reconcile_uninstalling() {
        let clos = async |req: Request<Body>, ctr| match req.method() {
            &Method::PATCH => {
                assert_body_contains(req, NOT_INSTALLED_REASON_UNINSTALLING).await;
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(1, clos, |client| {
            let mut cluster = dummy_cluster();
            cluster.metadata.deletion_timestamp = Some(Time(Utc::now()));
            let result = reconcile(Arc::new(cluster), Arc::new(client)).await;
            assert_eq!(result.unwrap(), Action::await_change());
        });
    }

    #[tokio::test]
    async fn test_reconcile_non_unique() {
        let clos = async |req: Request<_>, ctr| {
            if ctr == 0 && req.method() == Method::GET {
                let object_list = ObjectList::<TrustedExecutionCluster> {
                    items: vec![dummy_cluster(), dummy_cluster()],
                    types: Default::default(),
                    metadata: Default::default(),
                };
                Ok(serde_json::to_string(&object_list).unwrap())
            } else if ctr == 1 && req.method() == Method::PATCH {
                assert_body_contains(req, NOT_INSTALLED_REASON_NON_UNIQUE).await;
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}, counter {ctr}");
            }
        };
        count_check!(2, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            let result = reconcile(cluster, Arc::new(client)).await;
            assert_eq!(result.unwrap(), Action::requeue(Duration::from_secs(60)));
        });
    }

    #[tokio::test]
    async fn test_reconcile_error() {
        let clos = async |req: Request<_>, _| match req {
            r if r.method() == Method::GET => Err(StatusCode::INTERNAL_SERVER_ERROR),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        count_check!(1, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            let result = reconcile(cluster, Arc::new(client)).await;
            assert!(result.is_err());
        });
    }
}
