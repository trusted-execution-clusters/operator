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
pub use kopium::approvedimages::*;
pub use kopium::attestationkeys::*;
pub use kopium::ingresses as openshift_ingresses;
pub use kopium::machines::*;
pub use kopium::routes;
pub use kopium::trustedexecutionclusters::*;

pub use kopium::certificaterequests;
pub use kopium::certificates;
pub use kopium::clusterissuers;
pub use kopium::issuers;
pub use vendor_kopium::virtualmachineinstances;
pub use vendor_kopium::virtualmachines;

use anyhow::{Context, Result, anyhow};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::{Api, Client, Resource};

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
