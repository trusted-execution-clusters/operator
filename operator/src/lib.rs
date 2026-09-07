// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

// This file has two intended purposes:
// - Speed up development by allowing for building dependencies in a lower container image layer.
// - Provide definitions and functionalities to be used across modules in this crate.
//
// Use in other crates is not an intended purpose.

use anyhow::{Result, anyhow};
use k8s_openapi::api::core::v1::{ConfigMap, Secret, SecretVolumeSource, Volume, VolumeMount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::Resource;
use kube::runtime::events::Recorder;
use kube::runtime::reflector::{self, Store};
use kube::{Api, Client, runtime::controller::Action};
use log::{info, warn};
use std::fmt::{Debug, Display};
use std::{sync::Arc, time::Duration};

// Re-export common functions from the lib
use kube::api::{Patch, PatchParams};
use trusted_cluster_operator_lib::Conditions;
use trusted_cluster_operator_lib::{
    ApprovedImage, AttestationKey, Machine, TrustedExecutionCluster,
};
pub use trusted_cluster_operator_lib::{
    generate_owner_reference, new_recorder, spawn_reflector, sync_cache,
};

/// Unified context shared across all controllers.
/// Stores give local cache access to avoid repeated API-server reads.
pub struct OperatorContext {
    pub client: Client,
    pub recorder: Recorder,
    pub tec_store: Store<TrustedExecutionCluster>,
    pub cm_store: Store<ConfigMap>,
    pub machine_store: Store<Machine>,
    pub ak_store: Store<AttestationKey>,
    pub secret_store: Store<Secret>,
    pub image_store: Store<ApprovedImage>,
    // Add a deployment store if ever required
}

impl OperatorContext {
    pub fn new(client: Client) -> Self {
        let recorder = new_recorder(client.clone(), "operator");
        Self {
            client,
            recorder,
            tec_store: reflector::store().0,
            cm_store: reflector::store().0,
            machine_store: reflector::store().0,
            ak_store: reflector::store().0,
            secret_store: reflector::store().0,
            image_store: reflector::store().0,
        }
    }

    /// Return the single TrustedExecutionCluster from the cache, or an error if more than one exists.
    pub fn get_opt_tec(&self) -> Result<Option<TrustedExecutionCluster>> {
        let state = self.tec_store.state();
        if state.len() > 1 {
            let ns = self.client.default_namespace();
            return Err(anyhow!(
                "More than one TrustedExecutionCluster found in namespace {ns}. \
                 trusted-cluster-operator does not support more than one TrustedExecutionCluster."
            ));
        }
        Ok(state.into_iter().next().map(Arc::unwrap_or_clone))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
}

pub fn controller_error_policy<R, E: Display, C>(_obj: Arc<R>, error: &E, _ctx: Arc<C>) -> Action {
    log::error!("{error}");
    Action::requeue(Duration::from_secs(60))
}

pub async fn controller_info<T: Debug, E: Debug>(res: Result<T, E>) {
    match res {
        Ok(o) => info!("reconciled {o:?}"),
        Err(e) => info!("reconcile failed: {e:?}"),
    }
}

#[macro_export]
macro_rules! create_or_info_if_exists {
    ($client:expr, $type:ident, $resource:ident) => {
        let api: Api<$type> = kube::Api::default_namespaced($client);
        let name = $resource.metadata.name.clone().unwrap();
        match api.create(&Default::default(), &$resource).await {
            Ok(_) => info!("Create {} {}", $type::kind(&()), name),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                info!("{} {} already exists", $type::kind(&()), name);
            }
            Err(e) => return Err(e.into()),
        }
    };
}

pub const KIND_LABEL_KEY: &str = "kind";
pub const TLS_DIR: &str = "/etc/tls";
/// As per kube-rs docs, it's possible to miss events and requeue_after = None should only be used
/// when it is known another requeue is imminent. Use this requeue duration for cases where no
/// further action is usually needed, but eventual consistency is desired.
pub const LONG_REQUEUE: Action = Action::requeue(Duration::from_hours(1));

/// Reads a TLS certificate secret and returns the Volume and VolumeMount for it.
/// Returns None if the secret name is not provided or the secret does not exist.
pub async fn read_certificate(
    client: Client,
    secret_name: &Option<String>,
) -> Result<Option<(Volume, VolumeMount)>> {
    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    if secret_name.is_none() {
        return Ok(None);
    }
    let secret_name = secret_name.as_ref().unwrap();
    let secret = secrets.get(secret_name).await;

    if secret.is_err() {
        warn!("Certificate secret {secret_name} was provided, but could not be retrieved");
        return Ok(None);
    }

    let volume = Volume {
        name: secret_name.clone(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(secret_name.clone()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let volume_mount = VolumeMount {
        name: secret_name.clone(),
        mount_path: TLS_DIR.to_string(),
        ..Default::default()
    };
    Ok(Some((volume, volume_mount)))
}

// TODO: Port this functionality to kube-rs API.
// Update condition if already present, otherwise append(insert) it into the conditions vector.
// Inspired by k8s.io/apimachinery/pkg/api/meta.SetStatusCondition
pub fn upsert_condition(
    existing_conditions: &mut Option<Vec<Condition>>,
    new_condition: Condition,
) -> bool {
    let conditions_vec = existing_conditions.get_or_insert_with(Vec::new);

    if let Some(existing) = conditions_vec
        .iter_mut()
        .find(|c| c.type_ == new_condition.type_)
    {
        let mut changed = false;

        // Being faithful to kubernetes API semantics, only update transition time if status changes.
        if existing.status != new_condition.status {
            existing.status = new_condition.status;
            existing.last_transition_time = Time(Timestamp::now());
            changed = true;
        }

        if existing.reason != new_condition.reason {
            existing.reason = new_condition.reason;
            changed = true;
        }

        if existing.message != new_condition.message {
            existing.message = new_condition.message;
            changed = true;
        }

        if existing.observed_generation != new_condition.observed_generation {
            existing.observed_generation = new_condition.observed_generation;
            changed = true;
        }

        changed
    } else {
        conditions_vec.push(new_condition);
        true
    }
}

pub async fn patch_status_condition<K, S>(
    client: Client,
    name: &str,
    existing_status: &Option<S>,
    condition: Condition,
    field_manager: &str,
) -> Result<bool>
where
    K: Resource<Scope = k8s_openapi::NamespaceResourceScope>
        + Clone
        + serde::de::DeserializeOwned
        + Debug,
    K::DynamicType: Default,
    S: Conditions,
{
    let mut conditions = existing_status
        .as_ref()
        .and_then(|s| s.conditions().clone());
    if upsert_condition(&mut conditions, condition.clone()) {
        let api: Api<K> = Api::default_namespaced(client);
        let patch = Patch::Apply(serde_json::json!({
            "apiVersion": K::api_version(&Default::default()),
            "kind": K::kind(&Default::default()),
            "status": { "conditions": [condition] }
        }));
        api.patch_status(name, &PatchParams::apply(field_manager), &patch)
            .await
            .map_err(Into::<anyhow::Error>::into)?;
        return Ok(true);
    }
    Ok(false)
}
