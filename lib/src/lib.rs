// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

pub mod conditions;
pub mod endpoints;
pub mod images;
pub mod reference_values;

mod kopium;
#[allow(clippy::all)]
mod vendor_kopium;
use k8s_openapi::jiff::Timestamp;
pub use kopium::approvedimages::*;
pub use kopium::attestationkeys::*;
pub use kopium::machines::*;
pub use kopium::trustedexecutionclusters::*;

pub use kopium::certificaterequests;
pub use kopium::certificates;
pub use kopium::clusterissuers;
pub use kopium::issuers;
pub use vendor_kopium::virtualmachineinstances;
pub use vendor_kopium::virtualmachines;

#[cfg(feature = "openshift")]
pub use kopium::machineconfigpools;
#[cfg(feature = "openshift")]
pub use kopium::machineconfigs;

use anyhow::{Context, Result, anyhow};
use conditions::*;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, OwnerReference, Time};
use kube::runtime::events::{Event as K8sEvent, EventType, Recorder};
use kube::runtime::wait::await_condition;
use kube::{Api, Client, Resource};
use std::time::Duration;

/// Finalizer added to the Secret backing an AttestationKey.
pub const ATTESTATION_KEY_SECRET_FINALIZER: &str =
    "trusted-execution-clusters.io/attestationkey-secret-finalizer";

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

impl Conditions for MachineStatus {
    fn conditions(&self) -> &Option<Vec<Condition>> {
        &self.conditions
    }
}

/// True if the status has a condition with the given type and reason.
pub fn has_condition<S: Conditions>(
    existing_status: &Option<S>,
    type_: &str,
    reason: &str,
) -> bool {
    existing_status
        .as_ref()
        .and_then(|s| s.conditions().as_ref())
        .is_some_and(|cs| cs.iter().any(|c| c.type_ == type_ && c.reason == reason))
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
            NOT_COMMITTED_REASON_PENDING => "Pod is pending, check pods for details",
            NOT_COMMITTED_REASON_FAILED => "Computation failed, check operator log for details",
            _ => "",
        }
        .to_string(),
        last_transition_time: transition_time(existing_status, type_, &status),
        status,
        observed_generation: generation,
    }
}

pub async fn record_event(
    recorder: &Recorder,
    reference: &ObjectReference,
    type_: EventType,
    reason: &str,
    note: String,
    action: &str,
    secondary: Option<ObjectReference>,
) {
    let ev = K8sEvent {
        type_,
        reason: reason.into(),
        note: Some(note),
        action: action.into(),
        secondary,
    };
    if let Err(e) = recorder.publish(&ev, reference).await {
        log::warn!("Failed to publish event: {e}");
    }
}

/// Generate an OwnerReference for any Kubernetes resource
pub fn generate_owner_reference<T: Resource<DynamicType = ()>>(
    object: &T,
) -> Result<OwnerReference> {
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

pub async fn get_opt_trusted_execution_cluster(
    client: Client,
) -> Result<Option<TrustedExecutionCluster>> {
    let namespace = client.default_namespace().to_string();
    let clusters: Api<TrustedExecutionCluster> = Api::default_namespaced(client);
    let list = clusters.list(&Default::default()).await?;
    if list.items.len() > 1 {
        return Err(anyhow!(
            "More than one TrustedExecutionCluster found in namespace {namespace}. \
             trusted-cluster-operator does not support more than one TrustedExecutionCluster."
        ));
    }
    Ok(list.items.into_iter().next())
}

/// Get the single TrustedExecutionCluster in the namespace (uncached)
pub async fn get_trusted_execution_cluster(client: Client) -> Result<TrustedExecutionCluster> {
    let namespace = client.default_namespace().to_string();
    let cluster = get_opt_trusted_execution_cluster(client).await;
    let err = anyhow!(
        "No TrustedExecutionCluster found in namespace {namespace}. \
         Ensure that this service is in the same namespace as the TrustedExecutionCluster."
    );
    cluster.and_then(|c| c.ok_or(err))
}

/// True when the Deployment's desired generation is fully rolled out: the controller has
/// observed the spec, no old replicas remain, and every updated replica is available.
pub fn deployment_rollout_complete(depl: &Deployment) -> bool {
    let Some(status) = depl.status.as_ref() else {
        return false;
    };
    let generation_seen =
        status.observed_generation.unwrap_or(0) >= depl.metadata.generation.unwrap_or(0);
    let desired = depl.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
    let replicas = status.replicas.unwrap_or(0);
    let updated = status.updated_replicas.unwrap_or(0);
    let available = status.available_replicas.unwrap_or(0);
    generation_seen && updated >= desired && replicas <= updated && available >= updated
}

/// Waits until `deployment_rollout_complete` for the named Deployment, or errors after `timeout_duration`.
pub async fn wait_for_deployment_rollout(
    client: &Client,
    namespace: &str,
    name: &str,
    timeout_duration: Duration,
) -> Result<()> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let done = await_condition(deployments, name, |d: Option<&Deployment>| {
        d.is_some_and(deployment_rollout_complete)
    });
    let ctx = format!("waiting {timeout_duration:?} for Deployment '{name}' rollout");
    tokio::time::timeout(timeout_duration, done)
        .await
        .context(ctx)??;
    Ok(())
}

/// Waits until the named resource no longer exists, or errors after `timeout_duration`.
pub async fn wait_for_resource_deleted<K>(
    api: &Api<K>,
    name: &str,
    timeout_duration: Duration,
) -> Result<()>
where
    K: Resource<DynamicType = ()> + Clone + std::fmt::Debug + Send + 'static,
    K: k8s_openapi::serde::de::DeserializeOwned,
{
    let deleted = |r: Option<&K>| r.is_none();
    let done = await_condition(api.clone(), name, deleted);
    let type_ = std::any::type_name::<K>();
    let ctx = format!("waiting {timeout_duration:?} for {type_} '{name}' deletion");
    tokio::time::timeout(timeout_duration, done)
        .await
        .context(ctx)??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use kube::api::ObjectList;
    use trusted_cluster_operator_test_utils::mock_client::*;

    #[tokio::test]
    async fn test_get_some_trusted_execution_cluster() {
        let clos = async |_, _| {
            let object_list = ObjectList {
                items: vec![dummy_cluster()],
                types: Default::default(),
                metadata: Default::default(),
            };
            Ok(serde_json::to_string(&object_list).unwrap())
        };
        count_check!(1, clos, |client| {
            let res = get_opt_trusted_execution_cluster(client).await;
            assert!(res.unwrap().is_some());
        });
    }

    #[tokio::test]
    async fn test_get_none_trusted_execution_cluster() {
        let clos = async |_, _| {
            let object_list = ObjectList::<TrustedExecutionCluster> {
                items: vec![],
                types: Default::default(),
                metadata: Default::default(),
            };
            Ok(serde_json::to_string(&object_list).unwrap())
        };
        count_check!(1, clos, |client| {
            let res = get_opt_trusted_execution_cluster(client).await;
            assert!(res.unwrap().is_none());
        });
    }

    #[tokio::test]
    async fn test_non_unique_trusted_execution_cluster() {
        let clos = async |_, _| {
            let object_list = ObjectList {
                items: vec![dummy_cluster(), dummy_cluster()],
                types: Default::default(),
                metadata: Default::default(),
            };
            Ok(serde_json::to_string(&object_list).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = get_opt_trusted_execution_cluster(client).await.unwrap_err();
            assert!(err.to_string().contains("More than one"));
        });
    }

    #[tokio::test]
    async fn test_get_opt_trusted_execution_cluster_error() {
        let clos = async |_, _| Err(StatusCode::INTERNAL_SERVER_ERROR);
        count_check!(1, clos, |client| {
            assert!(get_opt_trusted_execution_cluster(client).await.is_err());
        });
    }

    #[tokio::test]
    async fn test_get_no_trusted_execution_cluster() {
        let clos = async |_, _| {
            let object_list = ObjectList::<TrustedExecutionCluster> {
                items: vec![],
                types: Default::default(),
                metadata: Default::default(),
            };
            Ok(serde_json::to_string(&object_list).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = get_trusted_execution_cluster(client).await.unwrap_err();
            assert!(err.to_string().contains("No TrustedExecutionCluster found"));
        });
    }
}
