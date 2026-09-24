// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{anyhow, Context};
use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Json};
use axum::{
    http::StatusCode,
    routing::{get, put},
    Router,
};
use axum_server::tls_openssl::OpenSSLConfig;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use clap::Parser;
use clevis_pin_trustee_lib::{
    AttestationKey, Config as ClevisConfig, NumRetries, Registration, Server as ClevisServer,
};
use env_logger::Env;
use ignition_config::v3_6::{
    Clevis, ClevisCustom, Config as IgnitionConfig, File, Filesystem, Luks, Resource, Storage,
    Systemd, Unit,
};
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{Patch, PatchParams};
use kube::runtime::events::{EventType, Recorder, Reporter};
use kube::{Api, Client};
// Imported only for its `object_ref` method; `as _` avoids clashing with
// `ignition_config::v3_6::Resource`.
use kube::Resource as _;
use log::{error, info};
use std::net::SocketAddr;
use uuid::Uuid;

use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::{
    generate_owner_reference, get_trusted_execution_cluster, record_event, Machine, MachineSpec,
};

/// Allow for an operator::KUBE_READ_TIMEOUT to hit (5 minutes) plus one minute,
/// thus 360s / 5s (clevis-pin-trustee's delay)
const RETRIES: u32 = 72;

/// Resource path where nodes report their providerID and UUID.
const BIND_RESOURCE: &str = "bind";

/// Script that reports the node's Azure providerID and UUID to the /bind endpoint.
const GET_PROVIDERID_SCRIPT: &str = include_str!("./get-providerid.sh");

/// It is a oneshot pulled in by multi-user.target and nothing depends on it, so a failure never blocks boot.
const TEC_BIND_UNIT: &str = "\
[Unit]
Description=Bind Azure providerID and UUID to the register-server
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/get-providerid.sh

[Install]
WantedBy=multi-user.target
";

#[derive(Parser)]
#[command(name = "register-server")]
#[command(about = "HTTP server that generates Clevis PINs with random UUIDs")]
struct Args {
    #[arg(short, long, default_value = "8000")]
    port: u16,

    #[arg(long)]
    cert_path: Option<String>,

    #[arg(long)]
    key_path: Option<String>,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    recorder: Recorder,
    /// "http" or "https": the scheme the node used to reach us, used to build
    /// the bind URL and decide whether the node needs our CA.
    scheme: &'static str,
}

/// Information about endpoints for clevis configuration
struct EndpointInfo {
    /// The public address of the Trustee server
    trustee_addr: String,
    /// The Trustee CA certificate (PEM-encoded) if TLS is enabled, None otherwise
    trustee_ca_cert: Option<String>,
    /// The public address of the AK registration server
    ak_registration_addr: Option<String>,
    /// AK registration CA certificate, identical to Trustee's if signed by the same root CA
    ak_registration_ca_cert: Option<String>,
}

async fn get_ca(client: Client, secret_name: &str) -> anyhow::Result<String> {
    let secrets: Api<Secret> = Api::default_namespaced(client);
    let secret = secrets.get(secret_name).await?;
    let err = format!("Secret {secret_name} does not contain ca.crt");
    let ca_data = secret.data.as_ref();
    let ca_bytes = ca_data.and_then(|data| data.get("ca.crt")).context(err)?;
    let ca_pem = String::from_utf8(ca_bytes.0.clone())?;
    Ok(ca_pem)
}

impl EndpointInfo {
    async fn create(client: Client) -> anyhow::Result<Self> {
        let cluster = get_trusted_execution_cluster(client.clone()).await?;
        let name = cluster.metadata.name.as_deref().unwrap_or("<no name>");
        let trustee_addr = cluster.spec.public_trustee_addr.context(format!(
            "TrustedExecutionCluster {name} did not specify a public Trustee address. \
             Add an address and re-register the node."
        ))?;

        let trustee_ca_cert = match &cluster.spec.trustee_secret {
            Some(name) => Some(get_ca(client.clone(), name).await?),
            None => None,
        };

        let ak_registration_ca_cert = match &cluster.spec.attestation_key_register_secret {
            Some(name) => Some(get_ca(client.clone(), name).await?),
            None => None,
        };

        Ok(EndpointInfo {
            trustee_addr,
            trustee_ca_cert,
            ak_registration_addr: cluster.spec.public_attestation_key_register_addr,
            ak_registration_ca_cert,
        })
    }
}

fn generate_bind_file(id: &str, rs_url: &str, ca_cert: Option<&str>) -> File {
    let script = GET_PROVIDERID_SCRIPT
        .replace("<YOUR_UUID>", id)
        .replace("<YOUR_BIND_SERVER_URL>", rs_url)
        .replace("<YOUR_CA_CERT>", ca_cert.unwrap_or(""));
    let mut file = File::new("/usr/local/bin/get-providerid.sh".to_string());
    file.mode = Some(0o755);
    file.overwrite = Some(true);
    file.contents = Some(Resource {
        source: Some(format!("data:;base64,{}", BASE64_STANDARD.encode(script))),
        ..Default::default()
    });
    file
}

fn generate_ignition(
    id: &str,
    endpoint_info: &EndpointInfo,
    rs_url: &str,
    rs_ca_cert: Option<&str>,
) -> IgnitionConfig {
    let ak_addr = endpoint_info.ak_registration_addr.as_deref();
    let attestation_key = ak_addr.map(|url| {
        let (ak_reg_scheme, ak_reg_cert) = match &endpoint_info.ak_registration_ca_cert {
            Some(ca_cert) => ("https", ca_cert.clone()),
            None => ("http", String::new()),
        };
        AttestationKey {
            registration: Registration {
                url: format!("{ak_reg_scheme}://{url}/{ATTESTATION_KEY_REGISTER_RESOURCE}"),
                uuid: id.to_string(),
                cert: ak_reg_cert,
            },
        }
    });

    let (trustee_scheme, trustee_cert) = match &endpoint_info.trustee_ca_cert {
        Some(ca_cert) => ("https", ca_cert.clone()),
        None => ("http", String::new()),
    };

    let clevis_conf = ClevisConfig {
        servers: vec![ClevisServer {
            url: format!("{trustee_scheme}://{}", endpoint_info.trustee_addr),
            cert: trustee_cert,
        }],
        path: format!("default/{id}/root"),
        // TODO retry forever once we don't need a debugging shell
        num_retries: Some(NumRetries::Finite(RETRIES)),
        initdata: None,
        // TODO add initdata, e.g.
        // #[derive(Serialize)]
        // struct Initdata {
        //     uuid: String,
        // }
        // let initdata = Initdata {
        //     uuid: id.to_string(),
        // };
        // ... initdata: serde_json::to_string(&initdata)?,
        attestation_key,
    };

    let luks_root = "root";

    let mut fs = Filesystem::new(format!("/dev/mapper/{luks_root}"));
    fs.format = Some("ext4".to_string());
    fs.label = Some(luks_root.to_string());
    fs.wipe_filesystem = Some(true);

    let mut luks = Luks::new(luks_root.to_string());
    luks.clevis = Some(Clevis {
        custom: Some(ClevisCustom {
            config: Some(serde_json::to_string(&clevis_conf).unwrap()),
            needs_network: Some(true),
            pin: Some("trustee".to_string()),
        }),
        ..Default::default()
    });
    luks.device = Some(format!("/dev/disk/by-partlabel/{luks_root}"));
    luks.label = Some(luks_root.to_string());
    luks.wipe_volume = Some(true);

    let mut bind_unit = Unit::new("bind.service".to_string());
    bind_unit.enabled = Some(true);
    bind_unit.contents = Some(TEC_BIND_UNIT.to_string());

    IgnitionConfig {
        storage: Some(Storage {
            files: Some(vec![generate_bind_file(id, rs_url, rs_ca_cert)]),
            filesystems: Some(vec![fs]),
            luks: Some(vec![luks]),
            ..Default::default()
        }),
        systemd: Some(Systemd {
            units: Some(vec![bind_unit]),
        }),
        ..Default::default()
    }
}

async fn register_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let kube_client = state.client;
    let recorder = state.recorder;
    let scheme = state.scheme;
    let internal_error = |e: anyhow::Error| {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        error!("{e:?}");
        let msg = serde_json::json!({
            "code": code.as_u16(),
            "message": format!("{e:#}")
        });
        (code, Json(msg))
    };

    // Get the TrustedExecutionCluster to use as owner reference for the Machine
    let cluster = match get_trusted_execution_cluster(kube_client.clone()).await {
        Ok(c) => c,
        Err(e) => return internal_error(e.context("Failed to get TrustedExecutionCluster")),
    };

    let owner_reference = match generate_owner_reference(&cluster) {
        Ok(o) => o,
        Err(e) => return internal_error(e.context("Failed to generate owner reference")),
    };

    match create_machine(kube_client.clone(), &id, owner_reference).await {
        Ok(machine) => {
            let machine_ref: ObjectReference = machine.object_ref(&());
            info!("Machine created successfully: machine-{id}");
            record_event(
                &recorder,
                &machine_ref,
                EventType::Normal,
                "MachineRegistered",
                format!("Machine machine-{id} registered"),
                "Registering",
                None,
            )
            .await;
        }
        Err(e) => return internal_error(e.context("Failed to create machine")),
    }
    let endpoint_info = match EndpointInfo::create(kube_client.clone()).await {
        Ok(info) => info,
        Err(e) => return internal_error(e.context("Failed to get endpoint info")),
    };

    // Over HTTPS, the node needs our CA to verify the bind request's TLS cert.
    let rs_ca_cert = match scheme {
        "https" => match &cluster.spec.register_server_secret {
            Some(name) => match get_ca(kube_client, name).await {
                Ok(ca) => Some(ca),
                Err(e) => return internal_error(e.context("Failed to get register-server CA")),
            },
            None => {
                let e = anyhow!(
                    "scheme is https but the TrustedExecutionCluster has no \
                     registerServerSecret, so the node cannot be given a CA to verify \
                     the bind endpoint"
                );
                return internal_error(e);
            }
        },
        _ => None,
    };

    // Reach the bind endpoint at the same address the node just used to reach us.
    let rs_url = match headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
        Some(host) => format!("{scheme}://{host}/{BIND_RESOURCE}"),
        None => return internal_error(anyhow::anyhow!("Request is missing a Host header")),
    };

    let ignition_config = generate_ignition(&id, &endpoint_info, &rs_url, rs_ca_cert.as_deref());
    let ignition_json = match serde_json::to_value(&ignition_config) {
        Ok(json) => json,
        Err(e) => return internal_error(e.into()),
    };

    (StatusCode::OK, Json(ignition_json))
}

/// Payload a node reports to /bind: its UUID and the providerID it discovered.
#[derive(serde::Deserialize)]
struct BindRequest {
    uuid: String,
    #[serde(rename = "providerID")]
    provider_id: String,
}

/// Patch the Machine named after the reported UUID with its providerID.
async fn bind_handler(
    State(AppState { client, .. }): State<AppState>,
    Json(req): Json<BindRequest>,
) -> impl IntoResponse {
    let machine_name = format!("machine-{}", req.uuid);
    info!(
        "Received bind request for {machine_name}: providerID={}",
        req.provider_id
    );

    let machines: Api<Machine> = Api::default_namespaced(client);
    let patch = serde_json::json!({ "spec": { "providerID": req.provider_id } });
    match machines
        .patch(
            &machine_name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await
    {
        Ok(_) => {
            info!("Patched {machine_name} with its providerID");
            StatusCode::OK
        }
        Err(e) => {
            error!("Failed to patch {machine_name}: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn create_machine(
    client: Client,
    uuid: &str,
    owner_reference: OwnerReference,
) -> anyhow::Result<Machine> {
    let machine_name = format!("machine-{uuid}");
    let machine = Machine {
        metadata: ObjectMeta {
            name: Some(machine_name.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: MachineSpec {
            id: uuid.to_string(),
            provider_id: None,
        },
        status: None,
    };

    let machines: Api<Machine> = Api::default_namespaced(client);
    let created = machines.create(&Default::default(), &machine).await?;
    info!("Created Machine: {machine_name} with UUID: {uuid}");
    Ok(created)
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let endpoint = format!("/{REGISTER_SERVER_RESOURCE}");
    let err = "failed to create Kubernetes client";
    let client = Client::try_default().await.expect(err);
    let reporter = Reporter {
        controller: "register-server".into(),
        instance: std::env::var("CONTROLLER_POD_NAME").ok(),
    };
    let scheme = if args.cert_path.is_some() && args.key_path.is_some() {
        "https"
    } else {
        "http"
    };
    let state = AppState {
        recorder: Recorder::new(client.clone(), reporter),
        client,
        scheme,
    };
    let bind_endpoint = format!("/{BIND_RESOURCE}");
    let app = Router::new()
        .route(&endpoint, get(register_handler))
        .route(&bind_endpoint, put(bind_handler))
        .with_state(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let service = app.into_make_service();

    let run = if let (Some(cert_path), Some(key_path)) = (args.cert_path, args.key_path) {
        let config = OpenSSLConfig::from_pem_file(cert_path, key_path).expect("invalid PEM files");
        info!("Starting server on https://{addr}");
        axum_server::bind_openssl(addr, config).serve(service).await
    } else {
        info!("Starting server on http://{addr}");
        axum_server::bind(addr).serve(service).await
    };

    run.expect("Server failed");
}

#[cfg(test)]
mod tests {
    use super::{create_machine, EndpointInfo, Machine};
    use http::{Method, Request, StatusCode};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
    use kube::api::ObjectList;
    use kube::api::ObjectMeta;
    use trusted_cluster_operator_lib::MachineSpec;
    use trusted_cluster_operator_lib::TrustedExecutionCluster;
    use trusted_cluster_operator_test_utils::mock_client::*;
    use trusted_cluster_operator_test_utils::test_error_method;

    fn dummy_clusters() -> ObjectList<TrustedExecutionCluster> {
        ObjectList {
            types: Default::default(),
            metadata: Default::default(),
            items: vec![dummy_cluster()],
        }
    }

    #[tokio::test]
    async fn test_create_endpoint() {
        let clos = async |_, _| Ok(serde_json::to_string(&dummy_clusters()).unwrap());
        count_check!(1, clos, |client| {
            let endpoint_info = EndpointInfo::create(client).await.unwrap();
            assert_eq!(endpoint_info.trustee_addr, "::".to_string());
            assert_eq!(endpoint_info.ak_registration_addr, Some("::".to_string()));
        });
    }

    #[tokio::test]
    async fn test_get_trustee_info_no_cluster() {
        let clos = async |_, _| {
            let mut clusters = dummy_clusters();
            clusters.items.clear();
            Ok(serde_json::to_string(&clusters).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = EndpointInfo::create(client).await.err().unwrap();
            assert!(err.to_string().contains("No TrustedExecutionCluster found"));
        });
    }

    #[tokio::test]
    async fn test_get_trustee_info_multiple() {
        let clos = async |_, _| {
            let mut clusters = dummy_clusters();
            clusters.items.push(clusters.items[0].clone());
            Ok(serde_json::to_string(&clusters).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = EndpointInfo::create(client).await.err().unwrap();
            assert!(err.to_string().contains("More than one"));
        });
    }

    #[tokio::test]
    async fn test_get_trustee_info_no_addr() {
        let clos = async |_, _| {
            let mut clusters = dummy_clusters();
            clusters.items[0].spec.public_trustee_addr = None;
            Ok(serde_json::to_string(&clusters).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = EndpointInfo::create(client).await.err().unwrap();
            let contains = "did not specify a public Trustee address";
            assert!(err.to_string().contains(contains));
        });
    }

    #[tokio::test]
    async fn test_get_public_trustee_error() {
        let clos = async |c| EndpointInfo::create(c).await.map(|_| ());
        test_error_method!(clos, Method::GET);
    }

    fn dummy_machine() -> Machine {
        Machine {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: MachineSpec {
                id: "test".to_string(),
                provider_id: None,
            },
            status: None,
        }
    }

    fn dummy_owner_reference() -> OwnerReference {
        OwnerReference {
            api_version: "trusted-execution-clusters.io/v1alpha1".to_string(),
            kind: "TrustedExecutionCluster".to_string(),
            name: "test-cluster".to_string(),
            uid: TEST_UID.to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }
    }

    #[tokio::test]
    async fn test_create_machine() {
        let clos = async |_, _| Ok(serde_json::to_string(&dummy_machine()).unwrap());
        count_check!(1, clos, |client| {
            let machine = create_machine(client, "test", dummy_owner_reference())
                .await
                .unwrap();
            assert_eq!(machine.metadata.name, Some("test".to_string()));
        });
    }

    #[tokio::test]
    async fn test_create_machine_error() {
        let clos = async |c| {
            let machine = create_machine(c, "test", dummy_owner_reference());
            machine.await.map(|_| ())
        };
        test_error_method!(clos, Method::POST);
    }
}
