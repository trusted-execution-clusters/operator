// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

// This file has two intended purposes:
// - Speed up development by allowing for building dependencies in a lower container image layer.
// - Provide definitions and functionalities to be used across modules in this crate.
//
// Use in other crates is not an intended purpose.

use anyhow::Result;
use k8s_openapi::api::core::v1::{Secret, SecretVolumeSource, Volume, VolumeMount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::{Api, Client, runtime::controller::Action};
use log::{info, warn};
use std::fmt::{Debug, Display};
use std::{sync::Arc, time::Duration};

// Re-export common functions from the lib
pub use trusted_cluster_operator_lib::generate_owner_reference;

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

pub const TLS_DIR: &str = "/etc/tls";

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
