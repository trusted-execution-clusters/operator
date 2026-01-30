// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Context;
use clap::Parser;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;
use uuid::Uuid;
use warp::{http::StatusCode, reply, Filter};

use trusted_cluster_operator_lib::endpoints::ATTESTATION_KEY_REGISTER_RESOURCE;
use trusted_cluster_operator_lib::{AttestationKey, AttestationKeySpec};

#[derive(Parser)]
#[command(name = "attestation-key-register")]
#[command(about = "HTTP server that accepts attestation key registrations")]
struct Args {
    #[arg(short, long, default_value = "8001")]
    port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttestationKeyRegistration {
    /// Public attestation key
    public_key: String,
    /// Optional address of the machine. If not provided, the request IP will be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,

    /// Optional platform for the machine corresponding to the attestation key.
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
}

async fn handle_registration(
    registration: AttestationKeyRegistration,
    client: Client,
    addr: Option<SocketAddr>,
) -> Result<impl warp::Reply, Infallible> {
    info!("Received registration request: {:?}", registration);

    let api: Api<AttestationKey> = Api::default_namespaced(client);

    match api.list(&Default::default()).await {
        Ok(existing_keys) => {
            for key in existing_keys.items {
                if key.spec.public_key == registration.public_key {
                    let existing_name = key.metadata.name.unwrap_or_default();
                    error!(
                        "Duplicate public key detected: already exists in AttestationKey '{}'",
                        existing_name
                    );
                    return Ok(reply::with_status(
                        reply::json(&serde_json::json!({
                            "status": "error",
                            "message": format!("Public key already registered"),
                        })),
                        StatusCode::CONFLICT,
                    ));
                }
            }
        }
        Err(e) => {
            error!("Failed to list AttestationKeys: {}", e);
            return Ok(reply::with_status(
                reply::json(&serde_json::json!({
                    "status": "error",
                    "message": format!("Failed to check for existing keys: {}", e),
                })),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    }

    let address = registration
        .address
        .or_else(|| addr.map(|socket_addr| socket_addr.ip().to_string()));

    let name = format!("ak-{}", Uuid::new_v4());
    let attestation_key = AttestationKey {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            ..Default::default()
        },
        spec: AttestationKeySpec {
            public_key: registration.public_key,
            address,
        },
        status: None,
    };

    match api.create(&Default::default(), &attestation_key).await {
        Ok(created) => {
            info!(
                "Successfully created AttestationKey: {}",
                created.metadata.name.unwrap_or_default()
            );
            Ok(reply::with_status(
                reply::json(&serde_json::json!({
                    "status": "success",
                })),
                StatusCode::CREATED,
            ))
        }
        Err(e) => {
            error!("Failed to create AttestationKey: {}", e);
            Ok(reply::with_status(
                reply::json(&serde_json::json!({
                    "status": "error",
                    "message": format!("Failed to create AttestationKey: {}", e),
                })),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

fn with_client(client: Client) -> impl Filter<Extract = (Client,), Error = Infallible> + Clone {
    warp::any().map(move || client.clone())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    info!(
        "Starting attestation key registration server on port {}",
        args.port
    );

    let client = Client::try_default()
        .await
        .context("Failed to create Kubernetes client")?;

    let register = warp::put()
        .and(warp::path(ATTESTATION_KEY_REGISTER_RESOURCE))
        .and(warp::body::json())
        .and(with_client(client))
        .and(warp::addr::remote())
        .and_then(handle_registration);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    info!("Listening on {}", addr);

    warp::serve(register).run(addr).await;

    Ok(())
}
