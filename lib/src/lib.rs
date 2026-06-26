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

use anyhow::{Context, Result, anyhow};
use conditions::*;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, OwnerReference, Time};
use kube::{Api, Client, Resource};

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

/// Get the single TrustedExecutionCluster in the namespace
pub async fn get_trusted_execution_cluster(client: Client) -> Result<TrustedExecutionCluster> {
    let namespace = client.default_namespace().to_string();
    let cluster = get_opt_trusted_execution_cluster(client).await;
    let err = anyhow!(
        "No TrustedExecutionCluster found in namespace {namespace}. \
         Ensure that this service is in the same namespace as the TrustedExecutionCluster."
    );
    cluster.and_then(|c| c.ok_or(err))
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
