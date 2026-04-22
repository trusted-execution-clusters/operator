// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::env;
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

/// Default tag for Trustee image
const TRUSTEE_VERSION: &str = "v0.17.0";
/// Default version tag for operator-managed component images
const COMPONENT_VERSION: &str = "0.2.0";
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
    client: Arc<Client>,
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

    let kube_client = Arc::unwrap_or_clone(client);
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
    install_attestation_key_register(kube_client.clone(), &cluster).await?;
    reference_values::adopt_approved_images(kube_client, &cluster).await?;

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

    match trustee::generate_attestation_policy(client.clone(), owner_reference.clone()).await {
        Ok(_) => info!("Generate configmap for the attestation policy",),
        Err(e) => error!("Failed to create the attestation policy configmap: {e}"),
    }

    let kbs_port = cluster.spec.trustee_kbs_port;
    match trustee::generate_kbs_service(client.clone(), owner_reference.clone(), kbs_port).await {
        Ok(_) => info!("Generate the KBS service"),
        Err(e) => error!("Failed to create the KBS service: {e}"),
    }

    let default = format!("{TEC_REGISTRY}/key-broker-service:{TRUSTEE_VERSION}");
    let trustee_image = env::var(RELATED_IMAGE_TRUSTEE).ok().unwrap_or(default);
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

    let env = RELATED_IMAGE_REGISTRATION_SERVER;
    let default_image = format!("{TEC_REGISTRY}/registration-server:{COMPONENT_VERSION}");
    let register_server_image = env::var(env).ok().unwrap_or(default_image);
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

    let env = RELATED_IMAGE_ATTESTATION_KEY_REGISTER;
    let default_image = format!("{TEC_REGISTRY}/attestation-key-register:{COMPONENT_VERSION}");
    let attestation_key_register_image = env::var(env).ok().unwrap_or(default_image);
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
    let cl: Api<TrustedExecutionCluster> = Api::default_namespaced(kube_client.clone());

    register_server::launch_keygen_controller(kube_client.clone()).await;
    attestation_key_register::launch_ak_controller(kube_client.clone()).await;
    attestation_key_register::launch_machine_ak_controller(kube_client.clone()).await;
    attestation_key_register::launch_secret_ak_controller(kube_client.clone()).await;
    reference_values::create_pcrs_config_map(kube_client.clone()).await?;
    reference_values::launch_rv_image_controller(kube_client.clone()).await;
    reference_values::launch_rv_job_controller(kube_client.clone()).await;

    Controller::new(cl, watcher::Config::default())
        .run(reconcile, controller_error_policy, Arc::new(kube_client))
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
    use trusted_cluster_operator_lib::ApprovedImage;

    use super::*;
    use trusted_cluster_operator_test_utils::mock_client::*;

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
                let body = get_body_string(req).await;
                assert!(body.contains(NOT_INSTALLED_REASON_NON_UNIQUE));
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
            let result = reconcile(Arc::new(cluster), Arc::new(client)).await;
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

        let clos = async |req: Request<Body>, ctr| {
            if ctr == 0 && req.method() == Method::GET {
                let object_list = ObjectList::<TrustedExecutionCluster> {
                    items: vec![dummy_cluster()],
                    types: Default::default(),
                    metadata: Default::default(),
                };
                Ok(serde_json::to_string(&object_list).unwrap())
            } else if (0 < ctr && ctr < 9 || ctr == 11) && req.method() == Method::POST {
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            } else if ctr == 9 && req.method() == Method::GET {
                let object_list = ObjectList::<ApprovedImage> {
                    items: Vec::new(),
                    types: Default::default(),
                    metadata: Default::default(),
                };
                Ok(serde_json::to_string(&object_list).unwrap())
            } else if ctr == 10 && req.method() == Method::PATCH {
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
        count_check!(11, clos, |client| {
            let result = reconcile(Arc::new(cluster), Arc::new(client)).await;
            assert_eq!(result.unwrap(), Action::await_change());
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
            let kube_client = Arc::new(client);
            reconcile(Arc::new(cluster), kube_client).await.unwrap();
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
            let kube_client = Arc::new(client);
            reconcile(Arc::new(cluster), kube_client).await.unwrap();
        });
    }
}
