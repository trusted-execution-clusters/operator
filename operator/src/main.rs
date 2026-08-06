// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::env;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use env_logger::Env;
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector;
use kube::runtime::watcher;
use kube::{Api, Client};
use log::{info, warn};

use operator::OperatorContext;
use operator::{generate_owner_reference, spawn_reflector, sync_cache, upsert_condition};
use trusted_cluster_operator_lib::{
    ApprovedImage, AttestationKey, Machine, TrustedExecutionCluster, TrustedExecutionClusterStatus,
    conditions::*, images::*, update_status,
};

mod attestation_key_register;
mod conditions;
mod reference_values;
mod register_server;
#[cfg(test)]
mod test_utils;
mod trustee;

use crate::conditions::*;
use operator::*;

/// Default fallback version tag for Trustee image if RELATED_IMAGE_TRUSTEE is not set.
const TRUSTEE_VERSION: &str = "v0.17.0";

/// Default fallback version tag for operator-managed component images from compile time environment variable (comes from operator crate Cargo.toml)
const COMPONENT_VERSION: &str = match option_env!("COMPONENT_VERSION") {
    Some(v) => v,
    None => concat!("v", env!("CARGO_PKG_VERSION")),
};

/// Default registry
const TEC_REGISTRY: &str = "quay.io/trusted-execution-clusters";

fn is_installed(status: Option<TrustedExecutionClusterStatus>) -> bool {
    let chk = |c: &Condition| c.type_ == INSTALLED_CONDITION && c.status == "True";
    status
        .and_then(|s| s.conditions)
        .map(|cs| cs.iter().any(chk))
        .unwrap_or(false)
}

async fn reconcile(
    cluster: Arc<TrustedExecutionCluster>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let generation = cluster.metadata.generation;
    let known_address = cluster.spec.public_trustee_addr.is_some();
    let existing_status = &cluster.status;
    let address_condition =
        known_trustee_address_condition(known_address, generation, existing_status);

    // Get existing conditions or default to empty vector
    let mut conditions = existing_status.as_ref().and_then(|s| s.conditions.clone());
    // Update or insert address condition to prevent rebuilding the status object from scratch every time the reconcile is called.
    let _ = upsert_condition(&mut conditions, address_condition);

    let kube_client = ctx.client.clone();
    let err = "trusted execution cluster had no name";
    let name = &cluster.metadata.name.clone().expect(err);
    let clusters: Api<TrustedExecutionCluster> = Api::default_namespaced(kube_client.clone());

    if cluster.metadata.deletion_timestamp.is_some() {
        info!("Registered deletion of TrustedExecutionCluster {name}");
        let uninstalling_reason = NOT_INSTALLED_REASON_UNINSTALLING;
        let uninstall_condition =
            installed_condition(uninstalling_reason, generation, existing_status);
        let changed = upsert_condition(&mut conditions, uninstall_condition);
        if changed {
            update_status!(clusters, name, TrustedExecutionClusterStatus { conditions })?;
        }
        return Ok(LONG_REQUEUE);
    }

    if is_installed(cluster.status.clone()) {
        return Ok(LONG_REQUEUE);
    }

    if ctx.tec_store.state().len() > 1 {
        let namespace = kube_client.default_namespace();
        warn!(
            "More than one TrustedExecutionCluster found in namespace {namespace}. \
             trusted-cluster-operator does not support more than one TrustedExecutionCluster. Requeueing...",
        );
        let non_unique_condition =
            installed_condition(NOT_INSTALLED_REASON_NON_UNIQUE, generation, existing_status);
        let changed = upsert_condition(&mut conditions, non_unique_condition);
        if changed {
            update_status!(clusters, name, TrustedExecutionClusterStatus { conditions })?;
        }
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    info!("Setting up TrustedExecutionCluster {name}");
    let installing_condition =
        installed_condition(NOT_INSTALLED_REASON_INSTALLING, generation, existing_status);
    let changed = upsert_condition(&mut conditions, installing_condition);
    if changed {
        let status = TrustedExecutionClusterStatus {
            conditions: conditions.clone(),
        };
        update_status!(clusters, name, status)?;
    }

    if let Err(e) = install_components(&kube_client, &cluster).await {
        // warn with `:?` to also get context
        warn!("Installation of a component failed: {e:?}\nRequeueing...");
        return Ok(Action::requeue(Duration::from_secs(60)));
    }
    reference_values::adopt_approved_images(&ctx, &cluster).await?;

    let installed_condition = installed_condition(INSTALLED_REASON, generation, existing_status);
    let changed = upsert_condition(&mut conditions, installed_condition);
    if changed {
        let status = TrustedExecutionClusterStatus { conditions };
        update_status!(clusters, name, status)?;
    }
    Ok(LONG_REQUEUE)
}

async fn install_components(client: &Client, cluster: &TrustedExecutionCluster) -> Result<()> {
    install_trustee_configuration(client.clone(), cluster).await?;
    install_register_server(client.clone(), cluster).await?;
    install_attestation_key_register(client.clone(), cluster).await?;
    Ok(())
}

async fn install_trustee_configuration(
    client: Client,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let owner_reference = generate_owner_reference(cluster)?;

    let trustee_secret = &cluster.spec.trustee_secret;
    trustee::generate_trustee_data(client.clone(), owner_reference.clone(), trustee_secret)
        .await
        .context("Failed to create the KBS configuration configmap")?;
    info!("Generated configmap for the KBS configuration");

    trustee::generate_attestation_policy(client.clone(), owner_reference.clone())
        .await
        .context("Failed to create the attestation policy configmap")?;
    info!("Generated configmap for the attestation policy");

    let kbs_port = cluster.spec.trustee_kbs_port;
    trustee::generate_kbs_service(client.clone(), owner_reference.clone(), kbs_port)
        .await
        .context("Failed to create the KBS service")?;
    info!("Generated the KBS service");

    let default = format!("{TEC_REGISTRY}/key-broker-service:{TRUSTEE_VERSION}");
    let trustee_image = env::var(RELATED_IMAGE_TRUSTEE).ok().unwrap_or(default);
    trustee::generate_kbs_deployment(client, owner_reference, &trustee_image, trustee_secret)
        .await
        .context("Failed to create the KBS deployment")?;
    info!("Generated the KBS deployment");

    Ok(())
}

async fn install_register_server(client: Client, cluster: &TrustedExecutionCluster) -> Result<()> {
    let owner_reference = generate_owner_reference(cluster)?;

    let env = RELATED_IMAGE_REGISTRATION_SERVER;
    let default_image = format!("{TEC_REGISTRY}/registration-server:{COMPONENT_VERSION}");
    let register_server_image = env::var(env).ok().unwrap_or(default_image);
    register_server::create_register_server_deployment(
        client.clone(),
        owner_reference.clone(),
        &register_server_image,
        &cluster.spec.register_server_secret,
    )
    .await
    .context("Failed to create register server deployment")?;
    info!("Register server deployment created/updated successfully");

    let port = cluster.spec.register_server_port;
    register_server::create_register_server_service(client.clone(), owner_reference, port)
        .await
        .context("Failed to create register server service")?;
    info!("Register server service created/updated successfully");

    Ok(())
}

async fn install_attestation_key_register(
    client: Client,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let owner_reference = generate_owner_reference(cluster)?;

    let env = RELATED_IMAGE_ATTESTATION_KEY_REGISTER;
    let default_image = format!("{TEC_REGISTRY}/attestation-key-register:{COMPONENT_VERSION}");
    let attestation_key_register_image = env::var(env).ok().unwrap_or(default_image);
    attestation_key_register::create_attestation_key_register_deployment(
        client.clone(),
        owner_reference.clone(),
        &attestation_key_register_image,
        &cluster.spec.attestation_key_register_secret,
    )
    .await
    .context("Failed to create attestation key register deployment")?;
    info!("Attestation key register deployment created/updated successfully");

    attestation_key_register::create_attestation_key_register_service(
        client.clone(),
        owner_reference,
        cluster.spec.attestation_key_register_port,
    )
    .await
    .context("Failed to create attestation key register service")?;
    info!("Attestation key register service created/updated successfully");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let kube_client = Client::try_default().await?;
    info!("trusted execution clusters operator");

    const CACHE_SYNC_TIMEOUT: Duration = Duration::from_secs(60);

    // Create all reflector stores and spawn background watchers.
    let (tec_store, tec_writer) = reflector::store::<TrustedExecutionCluster>();
    let (cm_store, cm_writer) = reflector::store::<ConfigMap>();
    let (deployment_store, deployment_writer) = reflector::store::<Deployment>();
    let (machine_store, machine_writer) = reflector::store::<Machine>();
    let (ak_store, ak_writer) = reflector::store::<AttestationKey>();
    let (secret_store, secret_writer) = reflector::store::<Secret>();
    let (image_store, image_writer) = reflector::store::<ApprovedImage>();

    let tec_kind = "TrustedExecutionCluster";
    spawn_reflector::<TrustedExecutionCluster>(tec_writer, kube_client.clone(), tec_kind);
    spawn_reflector::<ConfigMap>(cm_writer, kube_client.clone(), "ConfigMap");
    spawn_reflector::<Deployment>(deployment_writer, kube_client.clone(), "Deployment");
    spawn_reflector::<Machine>(machine_writer, kube_client.clone(), "Machine");
    spawn_reflector::<AttestationKey>(ak_writer, kube_client.clone(), "AttestationKey");
    spawn_reflector::<Secret>(secret_writer, kube_client.clone(), "Secret");
    spawn_reflector::<ApprovedImage>(image_writer, kube_client.clone(), "ApprovedImage");

    let mut ctx = OperatorContext::new(kube_client.clone());
    ctx.tec_store = tec_store;
    ctx.cm_store = cm_store;
    ctx.deployment_store = deployment_store;
    ctx.machine_store = machine_store;
    ctx.ak_store = ak_store;
    ctx.secret_store = secret_store;
    ctx.image_store = image_store;
    let ctx = Arc::new(ctx);

    // Best-effort wait for caches; controllers will work with
    // partially-filled stores if the sync times out.
    macro_rules! sync {
        ($($name:expr => $store:expr),+ $(,)?) => {$(
            if let Err(e) = sync_cache(&$store, $name, CACHE_SYNC_TIMEOUT).await {
                warn!("{} cache sync incomplete, controllers will retry: {e}", $name);
            }
        )+};
    }
    sync! {
        "TrustedExecutionCluster" => ctx.tec_store,
        "ConfigMap" => ctx.cm_store,
        "Deployment" => ctx.deployment_store,
        "Machine" => ctx.machine_store,
        "AttestationKey" => ctx.ak_store,
        "Secret" => ctx.secret_store,
        "ApprovedImage" => ctx.image_store,
    }

    info!("Starting controllers");

    let cl: Api<TrustedExecutionCluster> = Api::default_namespaced(kube_client.clone());

    register_server::launch_keygen_controller(ctx.clone()).await;
    attestation_key_register::launch_ak_controller(ctx.clone()).await;
    attestation_key_register::launch_machine_ak_controller(ctx.clone()).await;
    attestation_key_register::launch_secret_ak_controller(ctx.clone()).await;
    reference_values::create_pcrs_config_map(kube_client.clone()).await?;
    reference_values::launch_rv_image_controller(ctx.clone()).await;
    reference_values::launch_rv_job_controller(ctx.clone()).await;

    Controller::new(cl, watcher::Config::default())
        .run(reconcile, controller_error_policy, ctx)
        .for_each(controller_info)
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{Method, Request, StatusCode};
    use k8s_openapi::api::apps::v1::Deployment;
    use k8s_openapi::api::core::v1::{ConfigMap, Service};
    use k8s_openapi::{apimachinery::pkg::apis::meta::v1::Time, jiff::Timestamp};
    use kube::client::Body;
    use kube::runtime::{reflector, watcher};

    use super::*;
    use trusted_cluster_operator_test_utils::mock_client::*;

    fn op_ctx_with_two_tecs(client: Client) -> OperatorContext {
        let (tec_store, mut writer) = reflector::store::<TrustedExecutionCluster>();
        let mut second = dummy_cluster();
        second.metadata.name = Some("test2".to_string());
        writer.apply_watcher_event(&watcher::Event::Init);
        writer.apply_watcher_event(&watcher::Event::InitApply(dummy_cluster()));
        writer.apply_watcher_event(&watcher::Event::InitApply(second));
        writer.apply_watcher_event(&watcher::Event::InitDone);
        let mut ctx = OperatorContext::new(client);
        ctx.tec_store = tec_store;
        ctx
    }

    #[tokio::test]
    async fn test_reconcile_uninstalling() {
        let clos = async |req: Request<Body>, ctr| match req.method() {
            &Method::PATCH => {
                let body = get_body_string(req).await;
                assert!(body.contains(NOT_INSTALLED_REASON_UNINSTALLING),);
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(1, clos, |client| {
            let mut cluster = dummy_cluster();
            cluster.metadata.deletion_timestamp = Some(Time(Timestamp::now()));
            let result = reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client))).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    #[tokio::test]
    async fn test_reconcile_non_unique() {
        let clos = async |req: Request<_>, ctr| {
            if ctr == 0 && req.method() == Method::PATCH {
                let body = get_body_string(req).await;
                assert!(body.contains(NOT_INSTALLED_REASON_NON_UNIQUE));
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}, counter {ctr}");
            }
        };
        count_check!(1, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            let ctx = Arc::new(op_ctx_with_two_tecs(client));
            let result = reconcile(cluster, ctx).await;
            assert_eq!(result.unwrap(), Action::requeue(Duration::from_secs(60)));
        });
    }

    #[tokio::test]
    async fn test_reconcile_error() {
        let clos = async |req: Request<_>, _| match req {
            r if r.method() == Method::PATCH => Err(StatusCode::INTERNAL_SERVER_ERROR),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        count_check!(1, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            let ctx = Arc::new(op_ctx_with_two_tecs(client));
            let result = reconcile(cluster, ctx).await;
            assert!(result.is_err());
        });
    }

    fn dummy_foreign_condition() -> Condition {
        Condition {
            type_: "ForeignCondition".to_string(),
            status: "True".to_string(),
            reason: "ExternalController".to_string(),
            message: "Set by another controller".to_string(),
            last_transition_time: Time(Timestamp::now()),
            observed_generation: None,
        }
    }

    // Makes sure that uninstall trigger preserves foreign independent controller conditions, and our operator doesn't overwrite it in the reconcile function. Tests insert of our upsert_condition function.
    #[tokio::test]
    async fn test_reconcile_uninstall_preserves_foreign_controller_condition_by_inserting_owned_condition()
     {
        let foreign_condition = dummy_foreign_condition();

        let clos = async |req: Request<Body>, ctr| match req.method() {
            &Method::PATCH => {
                let body = get_body_string(req).await;
                assert!(body.contains("ForeignCondition"));
                assert!(body.contains("ExternalController"));
                assert!(body.contains(NOT_INSTALLED_REASON_UNINSTALLING));
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };

        count_check!(1, clos, |client| {
            let mut cluster = dummy_cluster();
            cluster.metadata.deletion_timestamp = Some(Time(Timestamp::now()));
            cluster.status = Some(TrustedExecutionClusterStatus {
                conditions: Some(vec![foreign_condition]),
            });
            let result = reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client))).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    // Tests the update of our upsert functionality, preserving foreign conditions, and updating operator's owned condition.
    // End to end unit test of the reconcile function, to ensure that new conditions are inserted and existing conditions are updated, without overwriting foreign conditions and creating conditions from scratch.
    #[tokio::test]
    async fn test_reconcile_install_preserves_foreign_condition_while_updating_owned_condition() {
        let foreign_condition = dummy_foreign_condition();

        let pre_existing_installed = Condition {
            type_: INSTALLED_CONDITION.to_string(),
            status: "False".to_string(),
            reason: NOT_INSTALLED_REASON_INSTALLING.to_string(),
            message: "Installation is in progress".to_string(),
            last_transition_time: Time(Timestamp::now()),
            observed_generation: None,
        };

        // adopt_approved_images now reads from image_store (empty) — no GET needed.
        // 8 POSTs for install, then 1 PATCH for final status.
        let clos = async |req: Request<Body>, ctr| {
            if ctr < 8 && req.method() == Method::POST {
                use serde_json::to_string;
                let resp = match ctr {
                    // Trustee
                    0 => to_string(&ConfigMap::default()),
                    1 => to_string(&ConfigMap::default()),
                    2 => to_string(&Service::default()),
                    3 => to_string(&Deployment::default()),
                    // Registration server
                    4 => to_string(&Deployment::default()),
                    5 => to_string(&Service::default()),
                    // Attestation key register server
                    6 => to_string(&Deployment::default()),
                    7 => to_string(&Service::default()),
                    _ => unreachable!("unexpected counter {ctr}"),
                };
                Ok(resp.unwrap())
            } else if ctr == 8 && req.method() == Method::PATCH {
                let body = req.into_body().collect_bytes().await.unwrap().to_vec();
                let body = String::from_utf8_lossy(&body);
                assert!(body.contains("ForeignCondition"),);

                // Also assert that the installed condition is updated to True from False, and only 1 installed condition is updated and present.
                let patch: serde_json::Value = serde_json::from_str(&body).unwrap();
                let err = "conditions should be an array";
                let conditions = patch["status"]["conditions"].as_array().expect(err);
                let chk = |c: &&serde_json::Value| c["type"] == "Installed";
                let installed: Vec<_> = conditions.iter().filter(chk).collect();
                assert_eq!(
                    installed.len(),
                    1,
                    "Expected exactly one Installed condition, found {}",
                    installed.len()
                );
                assert_eq!(
                    installed[0]["status"], "True",
                    "Installed condition should be updated to True"
                );
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}, counter {ctr}");
            }
        };

        let mut cluster = dummy_cluster();
        cluster.status = Some(TrustedExecutionClusterStatus {
            conditions: Some(vec![pre_existing_installed, foreign_condition]),
        });
        count_check!(9, clos, |client| {
            let result = reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client))).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    // This test ensures that if the condition is not changed, the status is not patched. The transition_time and all other fields remain same.
    #[tokio::test]
    async fn test_reconcile_no_patch_when_conditions_unchanged() {
        let clos1 = async |req: Request<Body>, _| match *req.method() {
            Method::PATCH => Ok(serde_json::to_string(&dummy_cluster()).unwrap()),
            _ => panic!("unexpected: {req:?}"),
        };

        // Deletion makes 1 patch status.
        count_check!(1, clos1, |client| {
            let mut cluster = dummy_cluster();
            cluster.metadata.deletion_timestamp = Some(Time(Timestamp::now()));
            reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client)))
                .await
                .unwrap();
        });

        // Building the uninstalling cluster state.
        let dummy = dummy_cluster();
        let existing_status = &dummy.status; // None
        let generation = dummy.metadata.generation;
        let known_address = dummy.spec.public_trustee_addr.is_some();

        let mut conditions = None;
        let _ = upsert_condition(
            &mut conditions,
            known_trustee_address_condition(known_address, generation, existing_status),
        );
        let _ = upsert_condition(
            &mut conditions,
            installed_condition(
                NOT_INSTALLED_REASON_UNINSTALLING,
                generation,
                existing_status,
            ),
        );

        assert_eq!(conditions.as_ref().unwrap().len(), 2);

        let clos2 = async |req: Request<Body>, _| panic!("unexpected API call: {req:?}");

        // Reconcile should not send another patch request, as conditions are exactly the same.
        count_check!(0, clos2, |client| {
            let mut cluster = dummy_cluster();
            cluster.metadata.deletion_timestamp = Some(Time(Timestamp::now()));
            cluster.status = Some(TrustedExecutionClusterStatus { conditions });
            reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client)))
                .await
                .unwrap();
        });
    }
}
