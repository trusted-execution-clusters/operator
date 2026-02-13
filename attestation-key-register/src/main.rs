// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use axum::response::{IntoResponse, Json};
use axum::{http::StatusCode, routing::put, Router};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use env_logger::Env;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use trusted_cluster_operator_lib::endpoints::ATTESTATION_KEY_REGISTER_RESOURCE;
use trusted_cluster_operator_lib::{
    generate_owner_reference, get_trusted_execution_cluster, AttestationKey, AttestationKeySpec,
};

#[derive(Parser)]
#[command(name = "attestation-key-register")]
#[command(about = "HTTP server that accepts attestation key registrations")]
struct Args {
    #[arg(short, long, default_value = "8001")]
    port: u16,
    #[arg(long)]
    cert_path: Option<String>,
    #[arg(long)]
    key_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttestationKeyRegistration {
    /// Public attestation key
    #[serde(alias = "attestation_key")]
    public_key: String,

    /// Optional uuid used for the machine registration
    #[serde(skip_serializing_if = "Option::is_none")]
    uuid: Option<String>,
}

async fn handle_registration(
    Json(registration): Json<AttestationKeyRegistration>,
) -> impl IntoResponse {
    info!("Received registration request: {registration:?}");

    let internal_error = |e: anyhow::Error| {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        error!("{e:?}");
        let msg = serde_json::json!({
            "status": "error",
            "message": format!("{e:#}"),
        });
        (code, Json(msg))
    };

    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => return internal_error(e.into()),
    };

    let api: Api<AttestationKey> = Api::default_namespaced(client.clone());

    // Get the TrustedExecutionCluster to use as owner reference
    let cluster = match get_trusted_execution_cluster(client.clone()).await {
        Ok(c) => c,
        Err(e) => return internal_error(e.context("Failed to get TrustedExecutionCluster")),
    };

    let owner_reference = match generate_owner_reference(&cluster) {
        Ok(o) => o,
        Err(e) => return internal_error(e.context("Failed to generate owner reference")),
    };

    match api.list(&Default::default()).await {
        Ok(existing_keys) => {
            for key in existing_keys.items {
                if key.spec.public_key == registration.public_key {
                    let existing_name = key.metadata.name.unwrap_or_default();
                    error!(
                        "Duplicate public key detected: already exists in AttestationKey '{existing_name}'"
                    );
                    return (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "status": "error",
                            "message": "Public key already registered",
                        })),
                    );
                }
            }
        }
        Err(e) => {
            return internal_error(
                anyhow::Error::from(e).context("Failed to check for existing keys"),
            )
        }
    }

    let name = format!("ak-{}", Uuid::new_v4());
    let attestation_key = AttestationKey {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: AttestationKeySpec {
            public_key: registration.public_key,
            uuid: registration.uuid,
        },
        status: None,
    };

    match api.create(&Default::default(), &attestation_key).await {
        Ok(created) => {
            let name = created.metadata.name.unwrap_or_default();
            info!("Successfully created AttestationKey: {name}",);
            let json = Json(serde_json::json!({
                "status": "success",
            }));
            (StatusCode::CREATED, json)
        }
        Err(e) => internal_error(anyhow::Error::from(e).context("Failed to create AttestationKey")),
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let endpoint = format!("/{ATTESTATION_KEY_REGISTER_RESOURCE}");
    let app = Router::new().route(&endpoint, put(handle_registration));
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let service = app.into_make_service();
    info!("Starting attestation key registration server on http://{addr}",);

    let run = if args.cert_path.is_some() && args.key_path.is_some() {
        let config = OpenSSLConfig::from_pem_file(args.cert_path.unwrap(), args.key_path.unwrap())
            .expect("invalid PEM files");
        axum_server::bind_openssl(addr, config).serve(service).await
    } else {
        axum_server::bind(addr).serve(service).await
    };
    run.expect("Server failed");
}
