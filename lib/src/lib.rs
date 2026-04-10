// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

pub mod conditions;
pub mod endpoints;
pub mod reference_values;

mod kopium;
#[allow(clippy::all)]
mod vendor_kopium;
use k8s_openapi::jiff::Timestamp;
pub use kopium::approvedimages::*;
pub use kopium::attestationkeys::*;
pub use kopium::ingresses as openshift_ingresses;
pub use kopium::machines::*;
pub use kopium::routes;
pub use kopium::trustedexecutionclusters::*;
pub use vendor_kopium::virtualmachineinstances;
pub use vendor_kopium::virtualmachines;

use anyhow::Context;
use conditions::*;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, OwnerReference, Time};
use kube::Resource;

#[macro_export]
macro_rules! update_status {
    ($api:ident, $name:expr, $status:expr) => {{
        let patch = kube::api::Patch::Merge(serde_json::json!({"status": $status}));
        $api.patch_status($name, &Default::default(), &patch).await
            .map_err(Into::<anyhow::Error>::into)
    }}
}

pub fn condition_status(status: bool) -> String {
    match status {
        true => "True".to_string(),
        false => "False".to_string(),
    }
}

pub trait Conditions {
    fn conditions(&self) -> &Option<Vec<Condition>>;
}

impl Conditions for TrustedExecutionClusterStatus {
    fn conditions(&self) -> &Option<Vec<Condition>> {
        &self.conditions
    }
}

impl Conditions for AttestationKeyStatus {
    fn conditions(&self) -> &Option<Vec<Condition>> {
        &self.conditions
    }
}

impl Conditions for ApprovedImageStatus {
    fn conditions(&self) -> &Option<Vec<Condition>> {
        &self.conditions
    }
}

pub fn transition_time<S: Conditions>(
    existing_status: &Option<S>,
    type_: &str,
    new_status: &str,
) -> Time {
    let get = |s: &S| s.conditions().clone();
    let conditions = existing_status.as_ref().and_then(get);
    let find = |c: &Condition| type_ == c.type_ && new_status == c.status;
    let existing = conditions.and_then(|cs| cs.into_iter().find(find));
    let time = existing.map(|c| c.last_transition_time);
    time.unwrap_or(Time(Timestamp::now()))
}

pub fn committed_condition(
    reason: &str,
    generation: Option<i64>,
    existing_status: &Option<ApprovedImageStatus>,
) -> Condition {
    let status = condition_status(reason == COMMITTED_REASON);
    let type_ = COMMITTED_CONDITION;
    Condition {
        type_: type_.to_string(),
        reason: reason.to_string(),
        message: match reason {
            NOT_COMMITTED_REASON_COMPUTING => "Computation is ongoing. Check jobs for progress.",
            NOT_COMMITTED_REASON_NO_DIGEST => {
                "Image did not specify a digest. \
                 Only images with a digest are supported to avoid ambiguity."
            }
            NOT_COMMITTED_REASON_FAILED => "Computation failed, check operator log for details",
            _ => "",
        }
        .to_string(),
        last_transition_time: transition_time(existing_status, type_, &status),
        status,
        observed_generation: generation,
    }
}

/// Generate an OwnerReference for any Kubernetes resource
pub fn generate_owner_reference<T: Resource<DynamicType = ()>>(
    object: &T,
) -> anyhow::Result<OwnerReference> {
    let name = object.meta().name.clone();
    let uid = object.meta().uid.clone();
    let kind = T::kind(&()).to_string();
    Ok(OwnerReference {
        api_version: T::api_version(&()).to_string(),
        block_owner_deletion: Some(true),
        controller: Some(true),
        name: name.context(format!("{} had no name", kind.clone()))?,
        uid: uid.context(format!("{} had no UID", kind.clone()))?,
        kind,
    })
}

/// Get the single TrustedExecutionCluster in the namespace
///
/// Returns an error if:
/// - No TrustedExecutionCluster is found
/// - More than one TrustedExecutionCluster is found (not supported)
pub async fn get_trusted_execution_cluster(
    client: kube::Client,
) -> anyhow::Result<TrustedExecutionCluster> {
    use kube::Api;

    let namespace = client.default_namespace().to_string();
    let clusters: Api<TrustedExecutionCluster> = Api::default_namespaced(client);
    let params = Default::default();
    let mut list = clusters.list(&params).await?;

    if list.items.is_empty() {
        return Err(anyhow::Error::msg(format!(
            "No TrustedExecutionCluster found in namespace {namespace}. \
             Ensure that this service is in the same namespace as the TrustedExecutionCluster."
        )));
    } else if list.items.len() > 1 {
        return Err(anyhow::Error::msg(format!(
            "More than one TrustedExecutionCluster found in namespace {namespace}. \
             trusted-cluster-operator does not support more than one TrustedExecutionCluster."
        )));
    }

    Ok(list.items.pop().unwrap())
}
