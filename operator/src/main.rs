// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use env_logger::Env;
use futures_util::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher;
use kube::{Api, Client};
use log::{error, info, warn};

use operator::{generate_owner_reference, upsert_condition};
use trusted_cluster_operator_lib::{TrustedExecutionCluster, TrustedExecutionClusterStatus};
use trusted_cluster_operator_lib::{conditions::*, images::*, update_status};

mod attestation_key_register;
mod conditions;
mod reference_values;
mod register_server;
#[cfg(test)]
mod test_utils;
mod trustee;

use crate::conditions::*;
use operator::*;

/// Default version tag for operator-managed component images
const COMPONENT_VERSION: &str = "0.2.0";

/// Get image from CR spec, falling back to environment variable (set by OLM), then default.
/// This enables disconnected/airgap installations where OLM rewrites RELATED_IMAGE_* env vars.
fn get_image_or_env(cr_image: &Option<String>, env_var: &str, default: &str) -> String {
    cr_image
        .clone()
        .or_else(|| env::var(env_var).ok())
        .unwrap_or_else(|| default.to_string())
}

struct ClusterContext {
    client: Client,
    /// UID of cluster that watchers are based on
    uid: Mutex<Option<String>>,
    tec_store: Store<TrustedExecutionCluster>,
}

impl ClusterContext {
    fn new(client: Client) -> Self {
        let (tec_store, tec_writer) = reflector::store::<TrustedExecutionCluster>();

        spawn_reflector::<TrustedExecutionCluster>(
            tec_writer,
            client.clone(),
            "TrustedExecutionCluster",
        );

        Self {
            client,
            uid: Mutex::new(None),
            tec_store,
        }
    }

    async fn sync_cache_tec(&self, timeout: Duration) -> Result<()> {
        sync_cache(&self.tec_store, "TrustedExecutionCluster", timeout).await
    }
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
        let pcrs_compute_image = get_image_or_env(
            &cluster.spec.pcrs_compute_image,
            RELATED_IMAGE_COMPUTE_PCRS,
            &format!("quay.io/trusted-execution-clusters/compute-pcrs:{COMPONENT_VERSION}"),
        );
        let rv_ctx = RvContextData {
            client,
            owner_reference: owner_reference.clone(),
            pcrs_compute_image,
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
        return Ok(Action::await_change());
    }

    let _ = launch_rv_watchers(cluster.clone(), ctx.clone(), name).await?;

    if is_installed(cluster.status.clone()) {
        return Ok(Action::await_change());
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

    install_trustee_configuration(kube_client.clone(), &cluster).await?;
    install_register_server(kube_client.clone(), &cluster).await?;
    install_attestation_key_register(kube_client, &cluster).await?;
    let installed_condition = installed_condition(INSTALLED_REASON, generation, existing_status);
    let changed = upsert_condition(&mut conditions, installed_condition);
    if changed {
        let status = TrustedExecutionClusterStatus { conditions };
        update_status!(clusters, name, status)?;
    }
    Ok(Action::await_change())
}

async fn install_trustee_configuration(
    client: Client,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let owner_reference = generate_owner_reference(cluster)?;

    let trustee_secret = &cluster.spec.trustee_secret;
    match trustee::generate_trustee_data(client.clone(), owner_reference.clone(), trustee_secret)
        .await
    {
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

    let trustee_image = get_image_or_env(
        &cluster.spec.trustee_image,
        RELATED_IMAGE_TRUSTEE,
        "quay.io/trusted-execution-clusters/key-broker-service:20260106",
    );
    match trustee::generate_kbs_deployment(client, owner_reference, &trustee_image, trustee_secret)
        .await
    {
        Ok(_) => info!("Generate the KBS deployment"),
        Err(e) => error!("Failed to create the KBS deployment: {e}"),
    }

    Ok(())
}

async fn install_register_server(client: Client, cluster: &TrustedExecutionCluster) -> Result<()> {
    let owner_reference = generate_owner_reference(cluster)?;

    let register_server_image = get_image_or_env(
        &cluster.spec.register_server_image,
        RELATED_IMAGE_REGISTRATION_SERVER,
        &format!("quay.io/trusted-execution-clusters/registration-server:{COMPONENT_VERSION}"),
    );
    match register_server::create_register_server_deployment(
        client.clone(),
        owner_reference.clone(),
        &register_server_image,
        &cluster.spec.register_server_secret,
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

    let attestation_key_register_image = get_image_or_env(
        &cluster.spec.attestation_key_register_image,
        RELATED_IMAGE_ATTESTATION_KEY_REGISTER,
        &format!("quay.io/trusted-execution-clusters/attestation-key-register:{COMPONENT_VERSION}"),
    );
    match attestation_key_register::create_attestation_key_register_deployment(
        client.clone(),
        owner_reference.clone(),
        &attestation_key_register_image,
        &cluster.spec.attestation_key_register_secret,
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

    const CACHE_SYNC_TIMEOUT: Duration = Duration::from_secs(60);

    // Launch controllers that do not depend on reflector caches first.
    register_server::launch_keygen_controller(kube_client.clone()).await;

    // Spawn reflectors (starts background list-watch immediately).
    let ak_ctx = Arc::new(attestation_key_register::AkContextData::new(
        kube_client.clone(),
    ));
    let ctx = Arc::new(ClusterContext::new(kube_client.clone()));

    // Best-effort wait for caches; controllers will work with
    // partially-filled stores if the sync times out.
    if let Err(e) = ak_ctx.sync_caches(CACHE_SYNC_TIMEOUT).await {
        warn!("AK cache sync incomplete, controllers will retry: {e}");
    }
    if let Err(e) = ctx.sync_cache_tec(CACHE_SYNC_TIMEOUT).await {
        warn!("TEC cache sync incomplete, controller will retry: {e}");
    }

    info!("Starting controllers");

    let cl: Api<TrustedExecutionCluster> = Api::default_namespaced(kube_client.clone());

    attestation_key_register::launch_ak_controller(ak_ctx.clone()).await;
    attestation_key_register::launch_machine_ak_controller(ak_ctx.clone()).await;
    attestation_key_register::launch_secret_ak_controller(ak_ctx).await;
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
            tec_store: reflector::store::<TrustedExecutionCluster>().0,
        }
    }

    /// Build a Store pre-populated with two distinct TrustedExecutionCluster objects.
    fn two_cluster_tec_store() -> Store<TrustedExecutionCluster> {
        let (store, mut writer) = reflector::store::<TrustedExecutionCluster>();
        let mut second = dummy_cluster();
        second.metadata.name = Some("test2".to_string());
        writer.apply_watcher_event(&watcher::Event::Init);
        writer.apply_watcher_event(&watcher::Event::InitApply(dummy_cluster()));
        writer.apply_watcher_event(&watcher::Event::InitApply(second));
        writer.apply_watcher_event(&watcher::Event::InitDone);
        store
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
                let body = get_body_string(req).await;
                assert!(body.contains(NOT_INSTALLED_REASON_UNINSTALLING),);
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
            if ctr == 0 && req.method() == Method::PATCH {
                let body = get_body_string(req).await;
                assert!(body.contains(NOT_INSTALLED_REASON_NON_UNIQUE));
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}, counter {ctr}");
            }
        };
        let store = two_cluster_tec_store();
        count_check!(1, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            // Pre-set uid to match the cluster so launch_rv_watchers skips spawning.
            let ctx = Arc::new(ClusterContext {
                client,
                uid: Mutex::new(Some("uid".to_string())),
                tec_store: store,
            });
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
        let store = two_cluster_tec_store();
        count_check!(1, clos, |client| {
            let cluster = Arc::new(dummy_cluster());
            // Pre-set uid to match the cluster so launch_rv_watchers skips spawning.
            let ctx = Arc::new(ClusterContext {
                client,
                uid: Mutex::new(Some("uid".to_string())),
                tec_store: store,
            });
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
            let result = reconcile(Arc::new(cluster), Arc::new(dummy_cluster_ctx(client))).await;
            assert_eq!(result.unwrap(), Action::await_change());
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

        let clos = async |req: Request<Body>, _ctr| {
            match *req.method() {
                Method::GET => {
                    let object_list = ObjectList::<TrustedExecutionCluster> {
                        items: vec![dummy_cluster()],
                        types: Default::default(),
                        metadata: Default::default(),
                    };
                    Ok(serde_json::to_string(&object_list).unwrap())
                }
                Method::POST => Ok(serde_json::to_string(&dummy_cluster()).unwrap()),
                Method::PATCH => {
                    let body = req.into_body().collect_bytes().await.unwrap().to_vec();
                    let body = String::from_utf8_lossy(&body);
                    assert!(body.contains("ForeignCondition"),);

                    // If body doesn't contain INSTALLED_REASON, that means its the patch call for Installing, hence returning early.
                    if !body.contains(INSTALLED_REASON) {
                        return Ok(serde_json::to_string(&dummy_cluster()).unwrap());
                    }

                    // Also assert that the installed condition is updated to True from False, and only 1 installed condition is updated and present.
                    let patch: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let conditions = patch["status"]["conditions"]
                        .as_array()
                        .expect("conditions should be an array");
                    let installed: Vec<_> = conditions
                        .iter()
                        .filter(|c| c["type"] == "Installed")
                        .collect();
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
                }
                _ => panic!("unexpected API interaction: {req:?}"),
            }
        };

        let request_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let client = MockClient::new(clos, "test".to_string(), request_count).into_client();

        let mut cluster = dummy_cluster();
        cluster.status = Some(TrustedExecutionClusterStatus {
            conditions: Some(vec![pre_existing_installed, foreign_condition]),
        });
        let result = reconcile(Arc::new(cluster), Arc::new(dummy_cluster_ctx(client))).await;
        assert_eq!(result.unwrap(), Action::await_change());
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
            reconcile(Arc::new(cluster), Arc::new(dummy_cluster_ctx(client)))
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
            reconcile(Arc::new(cluster), Arc::new(dummy_cluster_ctx(client)))
                .await
                .unwrap();
        });
    }
}
