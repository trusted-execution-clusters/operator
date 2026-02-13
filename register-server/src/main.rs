// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{anyhow, Context};
use axum::response::{IntoResponse, Json};
use axum::{extract::ConnectInfo, http::StatusCode};
use axum::{routing::get, Router};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use clevis_pin_trustee_lib::{Config as ClevisConfig, Server as ClevisServer};
use env_logger::Env;
use ignition_config::v3_5::{
    Clevis, ClevisCustom, Config as IgnitionConfig, Filesystem, Luks, Storage,
};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::{Api, Client};
use log::{error, info};
use std::net::SocketAddr;
use uuid::Uuid;

use trusted_cluster_operator_lib::endpoints::REGISTER_SERVER_RESOURCE;
use trusted_cluster_operator_lib::{
    generate_owner_reference, get_trusted_execution_cluster, Machine, MachineSpec,
};

/// Information about the Trustee server for clevis configuration
struct TrusteeInfo {
    /// The public address of the Trustee server
    public_addr: String,
    /// The CA certificate (PEM-encoded) if TLS is enabled, None otherwise
    ca_cert: Option<String>,
}

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

fn generate_ignition(id: &str, trustee_info: &TrusteeInfo) -> IgnitionConfig {
    let (scheme, cert) = match &trustee_info.ca_cert {
        Some(ca_cert) => ("https", ca_cert.clone()),
        None => ("http", String::new()),
    };
    let clevis_conf = ClevisConfig {
        servers: vec![ClevisServer {
            url: format!("{scheme}://{}", trustee_info.public_addr),
            cert,
        }],
        path: format!("default/{id}/root"),
        num_retries: None,
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
        // depending on ultimate design decision
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

    IgnitionConfig {
        storage: Some(Storage {
            filesystems: Some(vec![fs]),
            luks: Some(vec![luks]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn get_trustee_info(client: Client) -> anyhow::Result<TrusteeInfo> {
    let cluster = get_trusted_execution_cluster(client.clone()).await?;
    let name = cluster.metadata.name.as_deref().unwrap_or("<no name>");
    let public_addr = cluster.spec.public_trustee_addr.context(format!(
        "TrustedExecutionCluster {name} did not specify a public Trustee address. \
         Add an address and re-register the node."
    ))?;

    let ca_cert = if let Some(secret_name) = &cluster.spec.trustee_secret {
        let secrets: Api<Secret> = Api::default_namespaced(client);
        let secret = secrets.get(secret_name).await?;
        let err = format!("Trustee secret {secret_name} does not contain ca.crt");
        let ca_data = secret.data.as_ref();
        let ca_bytes = ca_data.and_then(|data| data.get("ca.crt")).expect(&err);
        let ca_pem = String::from_utf8(ca_bytes.0.clone())?;
        Some(ca_pem)
    } else {
        None
    };

    Ok(TrusteeInfo {
        public_addr,
        ca_cert,
    })
}

async fn register_handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let client_ip = addr.ip().to_string();

    info!("Registration request from IP: {client_ip}");

    let internal_error = |e: anyhow::Error| {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        error!("{e:?}");
        let msg = serde_json::json!({
            "code": code.as_u16(),
            "message": format!("{e:#}")
        });
        (code, Json(msg))
    };

    let kube_client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => return internal_error(e.into()),
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

    match create_machine(kube_client.clone(), &id, &client_ip, owner_reference).await {
        Ok(_) => info!("Machine created successfully: machine-{id}"),
        Err(e) => return internal_error(e.context("Failed to create machine")),
    }
    let trustee_info = match get_trustee_info(kube_client).await {
        Ok(info) => info,
        Err(e) => return internal_error(e.context("Failed to get Trustee info")),
    };

    let ignition = generate_ignition(&id, &trustee_info);
    let json = match serde_json::to_value(ignition) {
        Ok(json) => json,
        Err(e) => return internal_error(anyhow!("Failed to serialise Ignition: {e}")),
    };
    (StatusCode::OK, Json(json))
}

async fn create_machine(
    client: Client,
    uuid: &str,
    client_ip: &str,
    owner_reference: OwnerReference,
) -> anyhow::Result<()> {
    let machine_name = format!("machine-{uuid}");
    let machine = Machine {
        metadata: ObjectMeta {
            name: Some(machine_name.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: MachineSpec {
            id: uuid.to_string(),
            registration_address: client_ip.to_string(),
        },
        status: None,
    };

    let machines: Api<Machine> = Api::default_namespaced(client);
    machines.create(&Default::default(), &machine).await?;
    info!("Created Machine: {machine_name} with IP: {client_ip}");
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let endpoint = format!("/{REGISTER_SERVER_RESOURCE}");
    let app = Router::new().route(&endpoint, get(register_handler));
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    info!("Starting server on http://{}", addr);

    let run = if args.cert_path.is_some() && args.key_path.is_some() {
        let config = OpenSSLConfig::from_pem_file(args.cert_path.unwrap(), args.key_path.unwrap())
            .expect("invalid PEM files");
        axum_server::bind_openssl(addr, config).serve(service).await
    } else {
        axum_server::bind(addr).serve(service).await
    };
    run.expect("Server failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectList;
    use trusted_cluster_operator_lib::TrustedExecutionCluster;
    use trusted_cluster_operator_test_utils::mock_client::*;

    const TEST_IP: &str = "12.34.56.78";

    fn dummy_clusters() -> ObjectList<TrustedExecutionCluster> {
        ObjectList {
            types: Default::default(),
            metadata: Default::default(),
            items: vec![dummy_cluster()],
        }
    }

    #[tokio::test]
    async fn test_get_trustee_info() {
        let clos = async |_, _| Ok(serde_json::to_string(&dummy_clusters()).unwrap());
        count_check!(1, clos, |client| {
            let info = get_trustee_info(client).await.unwrap();
            assert_eq!(info.public_addr, "::".to_string());
            assert!(info.ca_cert.is_none());
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
            let err = get_trustee_info(client).await.err().unwrap();
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
            let err = get_trustee_info(client).await.err().unwrap();
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
            let err = get_trustee_info(client).await.err().unwrap();
            let contains = "did not specify a public Trustee address";
            assert!(err.to_string().contains(contains));
        });
    }

    #[tokio::test]
    async fn test_get_trustee_info_error() {
        test_get_error(async |c| get_trustee_info(c).await.map(|_| ())).await;
    }

    fn dummy_machine() -> Machine {
        Machine {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: MachineSpec {
                id: "test".to_string(),
                registration_address: TEST_IP.to_string(),
            },
            status: None,
        }
    }

    fn dummy_owner_reference() -> OwnerReference {
        OwnerReference {
            api_version: "trusted-execution-clusters.io/v1alpha1".to_string(),
            kind: "TrustedExecutionCluster".to_string(),
            name: "test-cluster".to_string(),
            uid: "test-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }
    }

    #[tokio::test]
    async fn test_create_machine() {
        let clos = async |_, _| Ok(serde_json::to_string(&dummy_machine()).unwrap());
        count_check!(1, clos, |client| {
            assert!(
                create_machine(client, "test", "::", dummy_owner_reference())
                    .await
                    .is_ok()
            );
        });
    }

    #[tokio::test]
    async fn test_create_machine_error() {
        test_create_error(async |c| {
            create_machine(c, "test", TEST_IP, dummy_owner_reference())
                .await
                .map(|_| ())
        })
        .await;
    }
}
