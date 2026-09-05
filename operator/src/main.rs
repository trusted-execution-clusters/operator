// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::env;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
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
use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::{
    ApprovedImage, ApprovedImageStatus, AttestationKey, Machine, TrustedExecutionCluster,
    TrustedExecutionClusterStatus, committed_condition,
};
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

fn deployment_ready_timeout() -> Duration {
    let secs = std::env::var("DEPLOYMENT_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    Duration::from_secs(secs)
}

/// Default fallback version tag for Trustee image if RELATED_IMAGE_TRUSTEE is not set.
const TRUSTEE_VERSION: &str = "v0.20.0";

/// Default fallback version tag for operator-managed component images from compile time environment variable (comes from operator crate Cargo.toml)
const COMPONENT_VERSION: &str = match option_env!("COMPONENT_VERSION") {
    Some(v) => v,
    None => concat!("v", env!("CARGO_PKG_VERSION")),
};

/// Default registry
const TEC_REGISTRY: &str = "quay.io/trusted-execution-clusters";
/// Keep a read timeout to allow hanging operations to retry (same as write timeout). This breaks
/// exec/attach operations without traffic for more than 5 minutes, but we do not use those.
const KUBE_READ_TIMEOUT: Duration = Duration::from_secs(295);

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
            update_status!(
                clusters,
                name,
                TrustedExecutionClusterStatus {
                    conditions,
                    observed_operator_version: None
                }
            )?;
        }

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
            update_status!(
                clusters,
                name,
                TrustedExecutionClusterStatus {
                    conditions,
                    observed_operator_version: None
                }
            )?;
        }
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    if is_installed(cluster.status.clone()) {
        // Get the observed operator version from the status.
        let observed = cluster
            .status
            .as_ref()
            .and_then(|s| s.observed_operator_version.as_deref());

        // No need to upgrade if the version is the same as the COMPONENT_VERSION.
        if observed == Some(COMPONENT_VERSION) {
            return Ok(LONG_REQUEUE);
        }

        // A previous upgrade failed and requires manual intervention;
        // do not retry automatically.
        // TODO: Add a retry count before giving up and requiring manual intervention.
        let has_failed = conditions.as_ref().is_some_and(|cs| {
            cs.iter()
                .any(|c| c.type_ == UPGRADE_CONDITION && c.reason == UPGRADE_FAILED)
        });
        if has_failed {
            return Ok(LONG_REQUEUE);
        }

        // UPGRADE BRANCH
        info!("Upgrading TrustedExecutionCluster {name} from {observed:?} to {COMPONENT_VERSION}");
        let upgrade_cond = upgrade_condition(
            UPGRADE_CONDITION,
            UPGRADE_IN_PROGRESS,
            generation,
            existing_status,
            None,
        );

        upsert_condition(&mut conditions, upgrade_cond);
        let status = TrustedExecutionClusterStatus {
            conditions: conditions.clone(),
            observed_operator_version: existing_status
                .as_ref()
                .and_then(|s| s.observed_operator_version.clone()),
        };
        update_status!(clusters, name, status)?;

        // Run the upgrade
        let upgrade_result =
            run_upgrade(&ctx, &cluster, &mut conditions, generation, existing_status).await;

        // If the upgrade fails, set the Upgrade=Failed condition and return.
        if let Err(e) = upgrade_result {
            warn!("Upgrade failed: {e:?}. Setting Upgrade=Failed.");

            let failed = upgrade_condition(
                UPGRADE_CONDITION,
                UPGRADE_FAILED,
                generation,
                existing_status,
                Some(&format!("{e:#}")),
            );
            upsert_condition(&mut conditions, failed);
            let status = TrustedExecutionClusterStatus {
                conditions,
                observed_operator_version: existing_status
                    .as_ref()
                    .and_then(|s| s.observed_operator_version.clone()),
            };
            update_status!(clusters, name, status)?;
            return Ok(LONG_REQUEUE);
        }

        let upgrade_done = upgrade_condition(
            UPGRADE_CONDITION,
            UPGRADE_COMPLETE,
            generation,
            existing_status,
            None,
        );
        upsert_condition(&mut conditions, upgrade_done);

        // Only updating observed_operator_version with COMPONENT_VERSION if the upgrade was successful.
        let status = TrustedExecutionClusterStatus {
            conditions,
            observed_operator_version: Some(COMPONENT_VERSION.to_string()),
        };
        update_status!(clusters, name, status)?;
        return Ok(LONG_REQUEUE);
    }

    // FRESH COMPONENT INSTALL BRANCH
    info!("Setting up TrustedExecutionCluster {name}");
    let installing_condition =
        installed_condition(NOT_INSTALLED_REASON_INSTALLING, generation, existing_status);
    let changed = upsert_condition(&mut conditions, installing_condition);
    // Not setting observed_operator_version here, as it will be updated only once the fresh install has completed successfully.
    if changed {
        let status = TrustedExecutionClusterStatus {
            conditions: conditions.clone(),
            observed_operator_version: None,
        };
        update_status!(clusters, name, status)?;
    }

    if let Err(e) = install_components(&kube_client, &cluster).await {
        // warn with `:?` to also get context
        warn!("Installation of a component failed: {e:?}\nRequeueing...");
        return Ok(Action::requeue(Duration::from_secs(60)));
    }
    reference_values::adopt_approved_images(&ctx, &cluster).await?;

    // Updating observed_operator_version because the fresh install is complete.
    let installed_condition = installed_condition(INSTALLED_REASON, generation, existing_status);
    let changed = upsert_condition(&mut conditions, installed_condition);
    if changed {
        let status = TrustedExecutionClusterStatus {
            conditions,
            observed_operator_version: Some(COMPONENT_VERSION.to_string()),
        };
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

// Each time there is a operator upgrade, all approved images are invalidated to trigger PCR recomputation.
async fn invalidate_all_approved_images(client: &Client) -> Result<()> {
    let images: Api<ApprovedImage> = Api::default_namespaced(client.clone());
    let image_list = images.list(&Default::default()).await?;

    for image in image_list.items {
        let name = match image.metadata.name.as_ref() {
            Some(n) => n.clone(),
            None => continue,
        };
        // Deleting any compute pcr job with same unique identifier, so that it can be re-created.
        reference_values::delete_compute_pcrs_job(client, &image.spec.image)
            .await
            .context("Failed to delete compute-pcrs Job before PCR recomputation")?;

        // Setting the not committed condition to trigger PCR recomputation.
        let not_committed = committed_condition(
            NOT_COMMITTED_REASON_COMPUTING,
            image.metadata.generation,
            &image.status,
        );

        let mut conditions = image.status.as_ref().and_then(|s| s.conditions.clone());
        upsert_condition(&mut conditions, not_committed);
        let status = ApprovedImageStatus {
            conditions,
            pcrs: None,
            first_seen: image.status.as_ref().and_then(|s| s.first_seen.clone()),
        };
        update_status!(images, &name, status)?;
        info!("Invalidated ApprovedImage {name} for PCR recomputation");
    }
    Ok(())
}

// Main upgrade function that runs the upgrade process.
async fn run_upgrade(
    ctx: &Arc<OperatorContext>,
    cluster: &TrustedExecutionCluster,
    conditions: &mut Option<Vec<Condition>>,
    generation: Option<i64>,
    existing_status: &Option<TrustedExecutionClusterStatus>,
) -> Result<()> {
    // Upgrade trustee component, with fresh install of trustee.
    converge_trustee(ctx, cluster)
        .await
        .context("Trustee upgrade stage failed")?;
    let trustee_done = upgrade_condition(
        TRUSTEE_UPGRADE_CONDITION,
        UPGRADE_COMPLETE,
        generation,
        existing_status,
        None,
    );
    upsert_condition(conditions, trustee_done);

    // Now upgrading the related images.
    converge_related_images(&ctx.client, cluster)
        .await
        .context("Related images upgrade stage failed")?;
    let related_images_done = upgrade_condition(
        RELATED_IMAGES_UPGRADE_CONDITION,
        UPGRADE_COMPLETE,
        generation,
        existing_status,
        None,
    );
    upsert_condition(conditions, related_images_done);

    Ok(())
}

/// True when the Deployment's desired generation is fully rolled out: the
/// controller has observed the spec, no old replicas remain, and every updated
/// replica is available.
fn deployment_rollout_complete(depl: &Deployment) -> bool {
    let Some(status) = depl.status.as_ref() else {
        return false;
    };
    // The observed generation is at least as new as the desired generation. This ensures a new replicaset has rolled out.
    let generation_seen =
        status.observed_generation.unwrap_or(0) >= depl.metadata.generation.unwrap_or(0);
    // Atleast 1 replica is available
    let desired = depl.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
    let replicas = status.replicas.unwrap_or(0);
    let updated = status.updated_replicas.unwrap_or(0);
    let available = status.available_replicas.unwrap_or(0);
    generation_seen && updated >= desired && replicas <= updated && available >= updated
}

async fn wait_for_deployment_available(client: &Client, name: &str) -> Result<()> {
    use kube::runtime::wait::await_condition;

    let deadline = deployment_ready_timeout();
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    info!("Waiting for Deployment {name} rollout to complete (timeout {deadline:?})...");
    let done = await_condition(deployments, name, |d: Option<&Deployment>| {
        d.is_some_and(deployment_rollout_complete)
    });
    tokio::time::timeout(deadline, done)
        .await
        .map_err(|_| anyhow!("Deployment {name} did not become ready within {deadline:?}"))??;
    info!("Deployment {name} rollout complete");
    Ok(())
}

async fn converge_trustee(
    ctx: &Arc<OperatorContext>,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let client = &ctx.client;
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());

    // Get trustee deployment.
    let trustee_depl = match deployments.get_opt(TRUSTEE_DEPLOYMENT).await? {
        Some(d) => d,
        None => return Ok(()),
    };

    let default = format!("{TEC_REGISTRY}/key-broker-service:{TRUSTEE_VERSION}");
    let desired_image = env::var(RELATED_IMAGE_TRUSTEE).ok().unwrap_or(default);

    // Current image of the trustee deployment.
    let live_image = trustee_depl
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|ps| ps.containers.first())
        .and_then(|c| c.image.as_deref());

    // If the image is already at the desired version, no need to update.
    if live_image == Some(desired_image.as_str()) {
        info!("Trustee image already at desired version, re-syncing API state");
    } else {
        info!(
            "Trustee image drift detected: live={} desired={desired_image}",
            live_image.unwrap_or("<none>")
        );

        // Patch config and the Deployment in place.
        // Deployment or trustee-data ConfigMap is not deleted: old pods mount that
        // ConfigMap, and RollingUpdate (maxUnavailable=0) keeps them serving if the new image never becomes Ready.
        let owner_reference = generate_owner_reference(cluster)?;
        let trustee_secret = &cluster.spec.trustee_secret;

        // Generate the trustee data and auth keys.
        trustee::generate_trustee_data(client.clone(), owner_reference.clone(), trustee_secret)
            .await
            .context("Failed to apply KBS configuration")?;
        trustee::generate_trustee_auth_keys_secret(client.clone(), owner_reference.clone())
            .await
            .context("Failed to create auth keys")?;

        // Patching the deployment.
        trustee::apply_kbs_deployment(
            client.clone(),
            owner_reference,
            &desired_image,
            trustee_secret,
        )
        .await
        .context("Failed to apply Trustee Deployment")?;
        info!("Trustee resources updated for upgrade to {desired_image}");
    }

    wait_for_deployment_available(client, TRUSTEE_DEPLOYMENT)
        .await
        .context("Trustee pod failed to become ready after upgrade")?;

    invalidate_all_approved_images(client)
        .await
        .context("Failed to invalidate ApprovedImages during Trustee upgrade")?;

    let trustee_depl = deployments.get(TRUSTEE_DEPLOYMENT).await?;

    // Sync attestation policy, reference values, machine luks keys, and attestation keys with API once deployment is available.
    trustee::trustee_deployment_reconcile(Arc::new(trustee_depl), Arc::clone(ctx))
        .await
        .map_err(|e| anyhow!("{e}"))
        .context("Failed to sync Trustee API state after upgrade")?;

    info!("Trustee upgrade complete: API state synced");
    Ok(())
}

async fn converge_related_images(client: &Client, cluster: &TrustedExecutionCluster) -> Result<()> {
    // As ak-register and register-server are stateless, a simple patch is enough to upgrade them.
    converge_related_image(
        client,
        cluster,
        REGISTER_SERVER_DEPLOYMENT,
        RELATED_IMAGE_REGISTRATION_SERVER,
        &format!("{TEC_REGISTRY}/registration-server:{COMPONENT_VERSION}"),
        REGISTER_SERVER_DEPLOYMENT,
    )
    .await?;
    converge_related_image(
        client,
        cluster,
        ATTESTATION_KEY_REGISTER_DEPLOYMENT,
        RELATED_IMAGE_ATTESTATION_KEY_REGISTER,
        &format!("{TEC_REGISTRY}/attestation-key-register:{COMPONENT_VERSION}"),
        "attestation-key-register",
    )
    .await?;
    Ok(())
}

async fn converge_related_image(
    client: &Client,
    _cluster: &TrustedExecutionCluster,
    deployment_name: &str,
    env_var: &str,
    default_image: &str,
    container_name: &str,
) -> Result<()> {
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    let depl = match deployments.get_opt(deployment_name).await? {
        Some(d) => d,
        None => return Ok(()),
    };

    let desired_image = env::var(env_var).ok().unwrap_or(default_image.to_string());

    let live_image = depl
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|ps| ps.containers.first())
        .and_then(|c| c.image.as_deref());

    // if current image = desired image, skip.
    if live_image == Some(desired_image.as_str()) {
        return Ok(());
    }

    info!(
        "{deployment_name} image drift detected: live={} desired={desired_image}",
        live_image.unwrap_or("<none>")
    );

    // Simple patch to update the container name and image.
    let patch = serde_json::json!({
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": container_name,
                        "image": desired_image
                    }]
                }
            }
        }
    });

    deployments
        .patch(
            deployment_name,
            &kube::api::PatchParams::apply("trusted-cluster-operator"),
            &kube::api::Patch::Strategic(patch),
        )
        .await
        .context(format!(
            "Failed to patch {deployment_name} Deployment image"
        ))?;
    info!("Patched {deployment_name} to image {desired_image}");

    // Wait for the deployment to be available.
    wait_for_deployment_available(client, deployment_name)
        .await
        .context(format!(
            "{deployment_name} failed to become ready after upgrade"
        ))?;
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

    trustee::generate_trustee_auth_keys_secret(client.clone(), owner_reference.clone())
        .await
        .context("Failed to create the auth keys")?;
    info!("Generated auth keys for the KBS API");
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
    let _ = jsonwebtoken_openssl::install_default();
    let mut config = kube::Config::infer().await?;
    config.read_timeout = Some(KUBE_READ_TIMEOUT);
    let kube_client = Client::try_from(config)?;
    info!("trusted execution clusters operator");

    const CACHE_SYNC_TIMEOUT: Duration = Duration::from_secs(60);

    // Create all reflector stores and spawn background watchers.
    let (tec_store, tec_writer) = reflector::store::<TrustedExecutionCluster>();
    let (cm_store, cm_writer) = reflector::store::<ConfigMap>();
    let (machine_store, machine_writer) = reflector::store::<Machine>();
    let (ak_store, ak_writer) = reflector::store::<AttestationKey>();
    let (secret_store, secret_writer) = reflector::store::<Secret>();
    let (image_store, image_writer) = reflector::store::<ApprovedImage>();

    let tec_kind = "TrustedExecutionCluster";
    spawn_reflector::<TrustedExecutionCluster>(tec_writer, kube_client.clone(), tec_kind);
    spawn_reflector::<ConfigMap>(cm_writer, kube_client.clone(), "ConfigMap");
    spawn_reflector::<Machine>(machine_writer, kube_client.clone(), "Machine");
    spawn_reflector::<AttestationKey>(ak_writer, kube_client.clone(), "AttestationKey");
    spawn_reflector::<Secret>(secret_writer, kube_client.clone(), "Secret");
    spawn_reflector::<ApprovedImage>(image_writer, kube_client.clone(), "ApprovedImage");

    let mut ctx = OperatorContext::new(kube_client.clone());
    ctx.tec_store = tec_store;
    ctx.cm_store = cm_store;
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
    reference_values::launch_rv_image_controller(ctx.clone()).await;
    reference_values::launch_rv_job_controller(ctx.clone()).await;
    trustee::launch_trustee_sync_controller(ctx.clone()).await;

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
    use k8s_openapi::api::core::v1::{ConfigMap, Secret, Service};
    use k8s_openapi::{apimachinery::pkg::apis::meta::v1::Time, jiff::Timestamp};
    use kube::api::ObjectList;
    use kube::client::Body;

    use super::*;
    use crate::test_utils::store_with;
    use trusted_cluster_operator_test_utils::mock_client::*;

    fn make_deployment(name: &str, image_tag: &str) -> Deployment {
        use k8s_openapi::api::apps::v1::DeploymentSpec;
        use k8s_openapi::api::core::v1::{Container, PodSpec, PodTemplateSpec};

        Deployment {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                template: PodTemplateSpec {
                    spec: Some(PodSpec {
                        containers: vec![Container {
                            name: name.to_string(),
                            image: Some(format!("registry.example.com/{name}:{image_tag}")),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn op_ctx_with_two_tecs(client: Client) -> OperatorContext {
        let mut second = dummy_cluster();
        second.metadata.name = Some("test2".to_string());
        let mut ctx = OperatorContext::new(client);
        ctx.tec_store = store_with(vec![dummy_cluster(), second]);
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
                observed_operator_version: None,
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

        // generate_trustee_data does get_opt (GET, 404) then create (POST).
        // Remaining installs are POSTs. Final call is a status PATCH.
        let clos = async |req: Request<Body>, ctr| {
            if ctr == 0 && req.method() == Method::GET {
                // get_opt for trustee-data ConfigMap: not found on fresh install
                Err(StatusCode::NOT_FOUND)
            } else if (1..=8).contains(&ctr) && req.method() == Method::POST {
                use serde_json::to_string;
                let resp = match ctr {
                    // install_trustee_configuration
                    1 => to_string(&ConfigMap::default()), // trustee-data
                    2 => to_string(&Secret::default()),    // trustee-auth
                    3 => to_string(&Service::default()),   // kbs-service
                    4 => to_string(&Deployment::default()), // trustee-deployment
                    // install_register_server
                    5 => to_string(&Deployment::default()),
                    6 => to_string(&Service::default()),
                    // install_attestation_key_register
                    7 => to_string(&Deployment::default()),
                    8 => to_string(&Service::default()),
                    _ => unreachable!("unexpected counter {ctr}"),
                };
                Ok(resp.unwrap())
            } else if ctr == 9 && req.method() == Method::PATCH {
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
            observed_operator_version: None,
        });
        count_check!(10, clos, |client| {
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
            cluster.status = Some(TrustedExecutionClusterStatus {
                conditions,
                observed_operator_version: None,
            });
            reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client)))
                .await
                .unwrap();
        });
    }

    // Tests the installed condition is set to True when the operator version is the same as the component version.
    #[tokio::test]
    async fn test_reconcile_installed_same_version_returns_long_requeue() {
        let installed = Condition {
            type_: INSTALLED_CONDITION.to_string(),
            status: "True".to_string(),
            reason: INSTALLED_REASON.to_string(),
            message: String::new(),
            last_transition_time: Time(Timestamp::now()),
            observed_generation: None,
        };

        let clos = async |req: Request<Body>, _| panic!("unexpected API call: {req:?}");

        count_check!(0, clos, |client| {
            let mut cluster = dummy_cluster();
            cluster.status = Some(TrustedExecutionClusterStatus {
                conditions: Some(vec![installed]),
                observed_operator_version: Some(COMPONENT_VERSION.to_string()),
            });
            let result = reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client))).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    // Tests that reconcile detects a version mismatch.
    #[tokio::test]
    async fn test_reconcile_upgrade_version_mismatch() {
        let installed = Condition {
            type_: INSTALLED_CONDITION.to_string(),
            status: "True".to_string(),
            reason: INSTALLED_REASON.to_string(),
            message: String::new(),
            last_transition_time: Time(Timestamp::now()),
            observed_generation: None,
        };

        let clos = async |req: Request<Body>, ctr| match (ctr, req.method()) {
            // Upgrade Upgrade=InProgress status patch
            (0, &Method::PATCH) => Ok(serde_json::to_string(&dummy_cluster()).unwrap()),
            // converge_trustee: get_opt Deployment (not found = no Trustee to upgrade)
            (1, &Method::GET) => Err(StatusCode::NOT_FOUND),
            // converge_related_images: get_opt register-server (not found)
            (2, &Method::GET) => Err(StatusCode::NOT_FOUND),
            // converge_related_images: get_opt ak-register (not found)
            (3, &Method::GET) => Err(StatusCode::NOT_FOUND),
            // Final upgrade complete status patch
            (4, &Method::PATCH) => {
                // Nothing to upgrade, so Upgrade=Complete status patch.
                let body = get_body_string(req).await;
                assert!(body.contains(UPGRADE_COMPLETE));
                assert!(body.contains(COMPONENT_VERSION));
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };

        count_check!(5, clos, |client| {
            let mut cluster = dummy_cluster();
            cluster.status = Some(TrustedExecutionClusterStatus {
                conditions: Some(vec![installed]),
                observed_operator_version: Some("old-version".to_string()),
            });
            let result = reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client))).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    // Failure path: Upgrade=Failed status patch test.
    #[tokio::test]
    async fn test_reconcile_upgrade_trustee_config_fail_sets_failed() {
        let installed = Condition {
            type_: INSTALLED_CONDITION.to_string(),
            status: "True".to_string(),
            reason: INSTALLED_REASON.to_string(),
            message: String::new(),
            last_transition_time: Time(Timestamp::now()),
            observed_generation: None,
        };

        let clos = async |req: Request<Body>, ctr| match (ctr, req.method()) {
            // Upgrade InProgress status patch
            (0, &Method::PATCH) => Ok(serde_json::to_string(&dummy_cluster()).unwrap()),
            // converge_trustee: get_opt Deployment -- found with old image
            (1, &Method::GET) => {
                let depl = make_deployment(TRUSTEE_DEPLOYMENT, "0.1.0");
                Ok(serde_json::to_string(&depl).unwrap())
            }
            // generate_trustee_data: ConfigMap already exists
            (2, &Method::GET) => Ok(serde_json::to_string(&ConfigMap::default()).unwrap()),
            // generate_trustee_data: patch ConfigMap -- fail
            (3, &Method::PATCH) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            // Final Upgrade=Failed status patch
            (4, &Method::PATCH) => {
                let body = get_body_string(req).await;
                assert!(
                    body.contains(UPGRADE_FAILED),
                    "Should contain Failed reason, got: {body}"
                );
                assert!(
                    body.contains("0.1.0"),
                    "Should preserve old observedOperatorVersion '0.1.0', got: {body}"
                );
                Ok(serde_json::to_string(&dummy_cluster()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };

        count_check!(5, clos, |client| {
            let mut cluster = dummy_cluster();
            cluster.status = Some(TrustedExecutionClusterStatus {
                conditions: Some(vec![installed]),
                observed_operator_version: Some("0.1.0".to_string()),
            });
            let result = reconcile(Arc::new(cluster), Arc::new(OperatorContext::new(client))).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    fn mock_approved_image(name: &str, with_first_seen: bool) -> ApprovedImage {
        ApprovedImage {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: trusted_cluster_operator_lib::ApprovedImageSpec {
                image: format!("quay.io/{name}@sha256:abc"),
            },
            status: Some(ApprovedImageStatus {
                conditions: Some(vec![]),
                pcrs: Some(crate::test_utils::dummy_status_pcrs()),
                first_seen: if with_first_seen {
                    Some("2026-01-01T00:00:00Z".to_string())
                } else {
                    None
                },
            }),
        }
    }

    #[tokio::test]
    async fn test_invalidate_clears_pcrs_but_keeps_conditions() {
        let clos = async |req: Request<Body>, ctr| {
            let mut image = mock_approved_image("img1", false);
            let committed = Condition {
                type_: COMMITTED_CONDITION.to_string(),
                status: "True".to_string(),
                reason: COMMITTED_REASON.to_string(),
                message: String::new(),
                last_transition_time: Time(Timestamp::now()),
                observed_generation: None,
            };
            image.status.as_mut().unwrap().conditions = Some(vec![committed]);
            match (ctr, req.method()) {
                (0, &Method::GET) => {
                    let list = ObjectList {
                        items: vec![image],
                        types: Default::default(),
                        metadata: Default::default(),
                    };
                    Ok(serde_json::to_string(&list).unwrap())
                }
                (1, &Method::DELETE) => Err(StatusCode::NOT_FOUND),
                (2, &Method::PATCH) => {
                    let body = get_body_string(req).await;
                    assert!(
                        body.contains(NOT_COMMITTED_REASON_COMPUTING),
                        "Committed should be set to Computing"
                    );
                    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let conditions = parsed["status"]["conditions"].as_array().unwrap();
                    assert_eq!(conditions.len(), 1, "Should have exactly one condition");
                    assert_eq!(
                        conditions[0]["reason"], NOT_COMMITTED_REASON_COMPUTING,
                        "Condition reason should be Computing"
                    );
                    Ok(serde_json::to_string(&image).unwrap())
                }
                _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
            }
        };

        count_check!(3, clos, |client| {
            invalidate_all_approved_images(&client)
                .await
                .expect("invalidate should succeed");
        });
    }
}
