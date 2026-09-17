// SPDX-FileCopyrightText: Yair Podemsky <ypodemsk@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use env_logger::Env;
use k8s_openapi::api::core::v1::ObjectReference;
use kube::runtime::events::{EventType, Recorder};
use kube::runtime::reflector::{self, Store};
use kube::{Client, Resource};
use log::{error, info, warn};
use tokio::sync::Mutex;

use trusted_cluster_operator_lib::{
    Machine, get_trusted_execution_cluster, new_recorder, record_event, spawn_reflector, sync_cache,
};

// -- Types and state --

const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_BODY_SIZE: usize = 16 * 1024 * 1024;

const KBS_AUTH_PATH: &str = "/kbs/v0/auth";
const KBS_ATTEST_PATH: &str = "/kbs/v0/attest";
const KBS_RESOURCE_PATH_PREFIX: &str = "/kbs/v0/resource/default/";

#[derive(Parser)]
#[command(name = "kbs-event-proxy")]
#[command(about = "Reverse proxy for KBS that emits Kubernetes events for attestation activity")]
struct Args {
    #[arg(long, default_value = "8080")]
    listen_port: u16,

    #[arg(long, default_value = "https://127.0.0.1:8081")]
    backend_url: String,

    #[arg(long)]
    cert_path: Option<String>,

    #[arg(long)]
    key_path: Option<String>,
}

struct SessionInfo {
    tee_type: String,
    created: Instant,
}

struct ProxyState {
    http_client: reqwest::Client,
    kube_client: Client,
    machine_store: Store<Machine>,
    recorder: Recorder,
    backend_url: String,
    sessions: Mutex<HashMap<String, SessionInfo>>,
}

impl ProxyState {
    async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, s| s.created.elapsed() < SESSION_TIMEOUT);
    }
}

// -- Request/response parsing --

fn session_id_from_request(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix("kbs-session-id=").map(|v| v.to_string()))
}

fn session_id_from_response(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|s| {
            s.split(';')
                .next()
                .and_then(|pair| pair.strip_prefix("kbs-session-id="))
                .map(|v| v.to_string())
        })
}

fn machine_id_from_path(path: &str) -> Option<&str> {
    let stripped = path.strip_prefix(KBS_RESOURCE_PATH_PREFIX)?;
    stripped.strip_suffix("/root")
}

fn machine_id_from_attest_body(body: &[u8]) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    let body_str = json.get("init-data")?.get("body")?.as_str()?;
    let toml: toml::Value = toml::from_str(body_str).ok()?;
    toml.get("data")?.get("uuid")?.as_str().map(String::from)
}

// -- Kubernetes object lookups --

async fn lookup_cluster_ref(client: &Client) -> Option<ObjectReference> {
    match get_trusted_execution_cluster(client.clone()).await {
        Ok(tec) => Some(tec.object_ref(&())),
        Err(e) => {
            warn!("Failed to look up TrustedExecutionCluster for event: {e}");
            None
        }
    }
}

fn lookup_machine_ref(store: &Store<Machine>, machine_id: &str) -> Option<ObjectReference> {
    let machine_name = format!("machine-{machine_id}");
    store
        .state()
        .iter()
        .find(|m| m.meta().name.as_deref() == Some(machine_name.as_str()))
        .map(|m| m.object_ref(&()))
}

// -- RCAR attestation event handlers (auth -> attest -> resource) --

async fn handle_auth_response(state: &ProxyState, req_body: &[u8], resp_headers: &http::HeaderMap) {
    let session_id = match session_id_from_response(resp_headers) {
        Some(id) => id,
        None => return,
    };

    let tee_type = serde_json::from_slice::<serde_json::Value>(req_body)
        .ok()
        .and_then(|v| v.get("tee")?.as_str().map(String::from))
        .unwrap_or_else(|| "unknown".to_string());

    state.sessions.lock().await.insert(
        session_id,
        SessionInfo {
            tee_type,
            created: Instant::now(),
        },
    );
}

async fn handle_attest_response(
    state: &ProxyState,
    req_headers: &http::HeaderMap,
    req_body: &[u8],
    resp_status: StatusCode,
) {
    let session_id = match session_id_from_request(req_headers) {
        Some(id) => id,
        None => return,
    };

    let succeeded = resp_status == StatusCode::OK;

    let tee_type = {
        let sessions = state.sessions.lock().await;
        sessions
            .get(&session_id)
            .map(|s| s.tee_type.clone())
            .unwrap_or_else(|| "unknown".to_string())
    };

    if succeeded {
        return;
    }

    let machine_id = machine_id_from_attest_body(req_body);

    if let Some(id) = &machine_id {
        let machine_ref = lookup_machine_ref(&state.machine_store, id);
        let tec_ref = lookup_cluster_ref(&state.kube_client).await;
        if let Some(ref primary) = machine_ref {
            record_event(
                &state.recorder,
                primary,
                EventType::Warning,
                "AttestationFailed",
                format!("Attestation failed for machine {id} (TEE type: {tee_type})"),
                "Attesting",
                tec_ref,
            )
            .await;
            return;
        }
    }

    if let Some(tec_ref) = lookup_cluster_ref(&state.kube_client).await {
        let note = match &machine_id {
            Some(id) => format!("Attestation failed for machine {id} (TEE type: {tee_type})"),
            None => format!("Attestation failed for TEE type: {tee_type}"),
        };
        record_event(
            &state.recorder,
            &tec_ref,
            EventType::Warning,
            "AttestationFailed",
            note,
            "Attesting",
            None,
        )
        .await;
    }
}

async fn handle_resource_response(state: &ProxyState, path: &str, resp_status: StatusCode) {
    let machine_id = match machine_id_from_path(path) {
        Some(id) => id,
        None => return,
    };

    let machine_ref = match lookup_machine_ref(&state.machine_store, machine_id) {
        Some(r) => r,
        None => return,
    };

    let (event_type, reason, note) = match resp_status {
        StatusCode::OK => (
            EventType::Normal,
            "AttestationSucceeded",
            format!("KBS released secret for machine {machine_id}"),
        ),
        StatusCode::FORBIDDEN => (
            EventType::Warning,
            "ResourcePolicyDenied",
            format!("Resource policy denied access for machine {machine_id}"),
        ),
        StatusCode::UNAUTHORIZED => (
            EventType::Warning,
            "AttestationFailed",
            format!("Attestation rejected for machine {machine_id}"),
        ),
        _ => return,
    };
    record_event(
        &state.recorder,
        &machine_ref,
        event_type,
        reason,
        note,
        "Attesting",
        None,
    )
    .await;
}

// -- Reverse proxy core --

fn bad_gateway(msg: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from(msg.to_string()))
        .unwrap()
}

struct BackendResponse {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
}

async fn forward_request(
    state: &ProxyState,
    method: http::Method,
    backend_uri: &str,
    headers: &http::HeaderMap,
    body: Bytes,
) -> Result<BackendResponse, Response<Body>> {
    let mut forwarded = state
        .http_client
        .request(method, backend_uri)
        .headers(headers.clone())
        .body(body)
        .build()
        .map_err(|e| {
            error!("Failed to build backend request: {e}");
            bad_gateway("proxy error")
        })?;
    forwarded.headers_mut().remove(http::header::HOST);

    let resp = state.http_client.execute(forwarded).await.map_err(|e| {
        error!("Backend request failed: {e}");
        bad_gateway("backend unavailable")
    })?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.bytes().await.map_err(|e| {
        error!("Failed to read backend response: {e}");
        bad_gateway("proxy error")
    })?;

    Ok(BackendResponse {
        status,
        headers,
        body,
    })
}

async fn proxy_handler(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let req_headers = req.headers().clone();

    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_BODY_SIZE).await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read request body: {e}");
            return bad_gateway("proxy error");
        }
    };

    let backend_uri = format!(
        "{}{}",
        state.backend_url,
        uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
    );

    let backend = match forward_request(
        &state,
        method,
        &backend_uri,
        &req_headers,
        body_bytes.clone(),
    )
    .await
    {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if path == KBS_AUTH_PATH && backend.status == StatusCode::OK {
        handle_auth_response(&state, &body_bytes, &backend.headers).await;
    } else if path == KBS_ATTEST_PATH {
        handle_attest_response(&state, &req_headers, &body_bytes, backend.status).await;
    } else if path.starts_with(KBS_RESOURCE_PATH_PREFIX) {
        handle_resource_response(&state, &path, backend.status).await;
    }

    state.cleanup_expired_sessions().await;

    let mut response = Response::builder().status(backend.status);
    for (key, value) in &backend.headers {
        response = response.header(key, value);
    }
    response.body(Body::from(backend.body)).unwrap()
}

// -- Entry point --

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let http_client = reqwest::ClientBuilder::new()
        // Proxy takes KBS's certs and re-encrypts. Within pod namespace,
        // allow invalid certificates as the domain name will not match.
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to create HTTP client")?;

    let kube_client = Client::try_default()
        .await
        .context("Failed to create Kubernetes client")?;

    let (machine_store, machine_writer) = reflector::store::<Machine>();
    spawn_reflector::<Machine>(machine_writer, kube_client.clone(), "Machine");
    sync_cache(&machine_store, "Machine", Duration::from_secs(30)).await?;

    let state = Arc::new(ProxyState {
        http_client,
        kube_client: kube_client.clone(),
        machine_store,
        recorder: new_recorder(kube_client, "kbs-event-proxy"),
        backend_url: args.backend_url,
        sessions: Mutex::new(HashMap::new()),
    });

    let app = Router::new().fallback(proxy_handler).with_state(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], args.listen_port));
    let service = app.into_make_service();

    if let (Some(cert_path), Some(key_path)) = (args.cert_path, args.key_path) {
        let config = OpenSSLConfig::from_pem_file(cert_path, key_path)
            .context("Invalid PEM files for TLS")?;
        info!("Proxy listening on https://{addr}");
        axum_server::bind_openssl(addr, config)
            .serve(service)
            .await
            .context("Server failed")?;
    } else {
        info!("Proxy listening on http://{addr}");
        axum_server::bind(addr)
            .serve(service)
            .await
            .context("Server failed")?;
    }

    Ok(())
}
