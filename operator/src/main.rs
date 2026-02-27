// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::sync::{Arc, Mutex};
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

mod attestation_key_register;
mod conditions;
mod reference_values;
mod register_server;
#[cfg(test)]
mod test_utils;
mod trustee;

use crate::conditions::*;
use operator::*;

struct ClusterContext {
    client: Client,
    /// UID of cluster that watchers are based on
    uid: Mutex<Option<String>>,
}

fn is_installed(status: Option<TrustedExecutionClusterStatus>) -> bool {
    let chk = |c: &Condition| c.type_ == INSTALLED_CONDITION && c.status == "True";
    status
        .and_then(|s| s.conditions)
        .map(|cs| cs.iter().any(chk))
        .unwrap_or(false)
}

/// Launch reference value-related watchers. Is run once per TrustedExecutionCluster and operator
/// process. Returns whether watchers were launched.
async fn launch_rv_watchers(
    cluster: Arc<TrustedExecutionCluster>,
    ctx: Arc<ClusterContext>,
    name: &str,
) -> Result<bool> {
    let client = ctx.client.clone();
    let mut launch_watchers = false;
    if let Ok(mut ctx_uid) = ctx.uid.lock() {
        let err = format!("TrustedExecutionCluster {name} had no UID");
        let cluster_uid = cluster.metadata.uid.clone().expect(&err);
        if ctx_uid.is_none() || ctx_uid.clone() != Some(cluster_uid.clone()) {
            launch_watchers = true;
            *ctx_uid = Some(cluster_uid);
        }
    } else {
        warn!("Failed to acquire lock on context UID store");
    }
    if launch_watchers {
        info!(
            "First registration of TrustedExecutionCluster {name} by this operator. \
             Launching reference value watchers."
        );
        let owner_reference = generate_owner_reference(&*cluster)?;
        let rv_ctx = RvContextData {
            client,
            owner_reference: owner_reference.clone(),
            pcrs_compute_image: cluster.spec.pcrs_compute_image.clone(),
        };
        reference_values::launch_rv_image_controller(rv_ctx.clone()).await;
        reference_values::launch_rv_job_controller(rv_ctx.clone()).await;
    }
    Ok(launch_watchers)
}

async fn reconcile(
    cluster: Arc<TrustedExecutionCluster>,
    ctx: Arc<ClusterContext>,
) -> Result<Action, ControllerError> {
    let generation = cluster.metadata.generation;
    let known_address = cluster.spec.public_trustee_addr.is_some();
    let address_condition = known_trustee_address_condition(known_address, generation);
    let mut conditions = Some(vec![address_condition]);

    let kube_client = ctx.client.clone();
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

    let _ = launch_rv_watchers(cluster.clone(), ctx.clone(), name).await?;

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
    install_register_server(kube_client.clone(), &cluster).await?;
    install_attestation_key_register(kube_client, &cluster).await?;
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

    Ok(())
}

async fn install_attestation_key_register(
    client: Client,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let owner_reference = generate_owner_reference(cluster)?;

    match attestation_key_register::create_attestation_key_register_deployment(
        client.clone(),
        owner_reference.clone(),
        &cluster.spec.attestation_key_register_image,
    )
    .await
    {
        Ok(_) => info!("Attestation key register deployment created/updated successfully"),
        Err(e) => error!("Failed to create attestation key register deployment: {e}"),
    }

    let port = cluster.spec.attestation_key_register_port;
    match attestation_key_register::create_attestation_key_register_service(
        client.clone(),
        owner_reference,
        port,
    )
    .await
    {
        Ok(_) => info!("Attestation key register service created/updated successfully"),
        Err(e) => error!("Failed to create attestation key register service: {e}"),
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let kube_client = Client::try_default().await?;
    info!("trusted execution clusters operator",);
    let cl: Api<TrustedExecutionCluster> = Api::default_namespaced(kube_client.clone());

    // Launch all controllers except reference value-related ones
    register_server::launch_keygen_controller(kube_client.clone()).await;
    attestation_key_register::launch_ak_controller(kube_client.clone()).await;
    attestation_key_register::launch_machine_ak_controller(kube_client.clone()).await;
    attestation_key_register::launch_secret_ak_controller(kube_client.clone()).await;

    let ctx = Arc::new(ClusterContext {
        client: kube_client,
        uid: Mutex::new(None),
    });
    Controller::new(cl, watcher::Config::default())
        .run(reconcile, controller_error_policy, ctx)
        .for_each(controller_info)
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{Method, Request, StatusCode};
    use k8s_openapi::{apimachinery::pkg::apis::meta::v1::Time, jiff::Timestamp};
    use kube::api::ObjectList;
    use kube::client::Body;

    use super::*;
    use trusted_cluster_operator_test_utils::mock_client::*;

    fn dummy_cluster_ctx(client: Client) -> ClusterContext {
        ClusterContext {
            client,
            uid: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn test_launch_watchers_create() {
        let clos = async |req, ctr| panic!("unexpected API interaction: {req:?}, counter {ctr}");
        count_check!(0, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            let ctx = Arc::new(dummy_cluster_ctx(client));
            assert!(launch_rv_watchers(cluster, ctx, "test").await.unwrap());
        });
    }

    #[tokio::test]
    async fn test_launch_watchers_update() {
        let clos = async |req, ctr| panic!("unexpected API interaction: {req:?}, counter {ctr}");
        count_check!(0, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            let mut ctx = dummy_cluster_ctx(client);
            ctx.uid = Mutex::new(Some("def".to_string()));
            let result = launch_rv_watchers(cluster, Arc::new(ctx), "test");
            assert!(result.await.unwrap());
        });
    }

    #[tokio::test]
    async fn test_launch_watchers_existing() {
        let clos = async |req, ctr| panic!("unexpected API interaction: {req:?}, counter {ctr}");
        count_check!(0, clos, |client| {
            let cluster = dummy_cluster();
            let mut ctx = dummy_cluster_ctx(client);
            ctx.uid = Mutex::new(cluster.metadata.uid.clone());
            let result = launch_rv_watchers(Arc::new(cluster), Arc::new(ctx), "test");
            assert!(!result.await.unwrap());
        });
    }

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
            cluster.metadata.deletion_timestamp = Some(Time(Timestamp::now()));
            let result = reconcile(Arc::new(cluster), Arc::new(dummy_cluster_ctx(client))).await;
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
            } else if 1 < ctr && ctr < 4 {
                // Watchers
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            } else if ctr == 4 && req.method() == Method::PATCH {
                assert_body_contains(req, NOT_INSTALLED_REASON_NON_UNIQUE).await;
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}, counter {ctr}");
            }
        };
        count_check!(4, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            let result = reconcile(cluster, Arc::new(dummy_cluster_ctx(client))).await;
            assert_eq!(result.unwrap(), Action::requeue(Duration::from_secs(60)));
        });
    }

    #[tokio::test]
    async fn test_reconcile_error() {
        let clos = async |req: Request<_>, _| match req {
            r if r.method() == Method::GET => Err(StatusCode::INTERNAL_SERVER_ERROR),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        count_check!(3, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            let result = reconcile(cluster, Arc::new(dummy_cluster_ctx(client))).await;
            assert!(result.is_err());
        });
    }
}
