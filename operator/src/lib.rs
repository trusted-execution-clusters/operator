// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

// This file has two intended purposes:
// - Speed up development by allowing for building dependencies in a lower container image layer.
// - Provide definitions and functionalities to be used across modules in this crate.
//
// Use in other crates is not an intended purpose.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::{Client, runtime::controller::Action};
use log::info;
use std::fmt::{Debug, Display};
use std::{sync::Arc, time::Duration};

// Re-export common functions from the lib
pub use trusted_cluster_operator_lib::generate_owner_reference;

#[derive(Clone)]
pub struct RvContextData {
    pub client: Client,
    pub owner_reference: OwnerReference,
    pub pcrs_compute_image: String,
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
