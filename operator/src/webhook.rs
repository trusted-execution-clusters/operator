// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::net::SocketAddr;
use std::path::Path;

use axum::response::{IntoResponse, Json};
use axum::{Router, http::StatusCode, routing::post};
use axum_server::tls_openssl::OpenSSLConfig;
use kube::{Api, Client};
use log::{error, info};
use serde::{Deserialize, Serialize};

use trusted_cluster_operator_lib::TrustedExecutionCluster;

const WEBHOOK_PORT: u16 = 9443;
const WEBHOOK_CERT_DIR: &str = "/etc/webhook/tls";

#[derive(Deserialize)]
struct AdmissionReview {
    request: AdmissionRequest,
}

#[derive(Deserialize)]
struct AdmissionRequest {
    uid: String,
    namespace: String,
}

#[derive(Serialize, Deserialize)]
struct AdmissionReviewResponse {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    response: AdmissionResponseBody,
}

#[derive(Serialize, Deserialize)]
struct AdmissionResponseBody {
    uid: String,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<AdmissionStatus>,
}

#[derive(Serialize, Deserialize)]
struct AdmissionStatus {
    message: String,
}

impl AdmissionReviewResponse {
    fn allowed(uid: String) -> Self {
        Self {
            api_version: "admission.k8s.io/v1".to_string(),
            kind: "AdmissionReview".to_string(),
            response: AdmissionResponseBody {
                uid,
                allowed: true,
                status: None,
            },
        }
    }

    fn denied(uid: String, message: String) -> Self {
        Self {
            api_version: "admission.k8s.io/v1".to_string(),
            kind: "AdmissionReview".to_string(),
            response: AdmissionResponseBody {
                uid,
                allowed: false,
                status: Some(AdmissionStatus { message }),
            },
        }
    }
}

/// Validate whether a TrustedExecutionCluster may be created in the given namespace.
async fn validate_uniqueness(
    client: Client,
    uid: String,
    namespace: &str,
) -> AdmissionReviewResponse {
    let clusters: Api<TrustedExecutionCluster> = Api::namespaced(client, namespace);
    match clusters.list(&Default::default()).await {
        Ok(list) if !list.items.is_empty() => {
            let existing = list.items[0].metadata.name.as_deref().unwrap_or("unknown");
            let msg = format!(
                "only one TrustedExecutionCluster is allowed per namespace; \
                 \"{existing}\" already exists"
            );
            info!("Denied TrustedExecutionCluster creation in {namespace}: {msg}");
            AdmissionReviewResponse::denied(uid, msg)
        }
        Ok(_) => {
            info!("Allowed TrustedExecutionCluster creation in {namespace}");
            AdmissionReviewResponse::allowed(uid)
        }
        Err(e) => {
            error!("Failed to list TrustedExecutionClusters: {e}");
            AdmissionReviewResponse::denied(uid, format!("{e:#}"))
        }
    }
}

async fn validate_handler(Json(review): Json<AdmissionReview>) -> impl IntoResponse {
    let uid = review.request.uid;
    let namespace = review.request.namespace;

    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create Kubernetes client: {e}");
            let resp = AdmissionReviewResponse::denied(uid, format!("{e:#}"));
            return (StatusCode::OK, Json(resp));
        }
    };

    let resp = validate_uniqueness(client, uid, &namespace).await;
    (StatusCode::OK, Json(resp))
}

pub async fn run_webhook_server() {
    let path = "/validate-trusted-execution-clusters-io-v1alpha1-trustedexecutioncluster";
    let app = Router::new().route(path, post(validate_handler));
    let addr = SocketAddr::from(([0, 0, 0, 0], WEBHOOK_PORT));
    let service = app.into_make_service();

    let cert_path = format!("{WEBHOOK_CERT_DIR}/tls.crt");
    let key_path = format!("{WEBHOOK_CERT_DIR}/tls.key");

    if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
        info!("Starting webhook server with TLS on https://{addr}");
        let config =
            OpenSSLConfig::from_pem_file(&cert_path, &key_path).expect("invalid PEM files");
        axum_server::bind_openssl(addr, config)
            .serve(service)
            .await
            .expect("webhook server failed");
    } else {
        info!("Webhook TLS certificates not found, starting without TLS on http://{addr}");
        axum_server::bind(addr)
            .serve(service)
            .await
            .expect("webhook server failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectList;
    use trusted_cluster_operator_test_utils::mock_client::*;

    fn cluster_list(count: usize) -> ObjectList<TrustedExecutionCluster> {
        ObjectList {
            items: (0..count).map(|_| dummy_cluster()).collect(),
            types: Default::default(),
            metadata: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_validate_allow() {
        let clos = async |_, _| Ok(serde_json::to_string(&cluster_list(0)).unwrap());
        count_check!(1, clos, |client| {
            let resp = validate_uniqueness(client, "uid".into(), "test").await;
            assert!(resp.response.allowed);
        });
    }

    #[tokio::test]
    async fn test_validate_deny() {
        let clos = async |_, _| Ok(serde_json::to_string(&cluster_list(1)).unwrap());
        count_check!(1, clos, |client| {
            let resp = validate_uniqueness(client, "uid".into(), "test").await;
            assert!(!resp.response.allowed);
            let msg = resp.response.status.unwrap().message;
            assert!(msg.contains("already exists"));
        });
    }

    #[tokio::test]
    async fn test_validate_error() {
        let clos = async |_, _: u32| Err(StatusCode::INTERNAL_SERVER_ERROR);
        count_check!(1, clos, |client| {
            let resp = validate_uniqueness(client, "uid".into(), "test").await;
            assert!(!resp.response.allowed);
        });
    }
}
