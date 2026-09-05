// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use constants::APPROVED_IMAGE_NAME;
use fs_extra::dir;
use glob::glob;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{
    LoadBalancerStatus, Namespace, Pod, Secret, Service, ServicePort, ServiceSpec, ServiceStatus,
};
use k8s_openapi::api::events::v1::Event;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{DeleteParams, ListParams, ObjectMeta, Patch, PatchParams};
use kube::runtime::wait::await_condition;
use kube::{Api, Client};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::{collections::BTreeMap, env, sync::Once, time::Duration};
use tokio::process::Command;
use tokio::time::timeout;
use trusted_cluster_operator_lib::certificates::{
    Certificate, CertificateIssuerRef, CertificateSpec, CertificateStatus,
};
use trusted_cluster_operator_lib::conditions::{COMMITTED_CONDITION, INSTALLED_CONDITION};
use trusted_cluster_operator_lib::issuers::{Issuer, IssuerCa, IssuerSpec};

use trusted_cluster_operator_lib::{
    ApprovedImage, ApprovedImageStatus, ApprovedImageStatusPcrsEvents, AttestationKey, Machine,
};
use trusted_cluster_operator_lib::{TrustedExecutionCluster, endpoints::*, images::*};

pub mod timer;
pub use timer::Poller;
pub mod constants;
pub mod mock_client;

#[cfg(feature = "virtualization")]
pub mod virt;

use compute_pcrs_lib::Pcr;

const TEST_TIMEOUT_MULTIPLIER_ENV: &str = "TEST_TIMEOUT_MULTIPLIER";
const EXPOSE_MAX_ATTEMPTS: u32 = 3;

const UPSTREAM_DIR_ENV: &str = "UPSTREAM_DIR";
const PLATFORM_ENV: &str = "PLATFORM";
const CLUSTER_URL_ENV: &str = "CLUSTER_URL";
const SET_CLUSTER_ERR: &str = "Set $CLUSTER_URL when $PLATFORM is none of: kind, openshift";
const YELLOW: &str = "\x1b[33m";
const ANSI_RESET: &str = "\x1b[0m";

const KIND_TRUSTEE_PORT: i32 = 31000;
const KIND_REGISTER_SERVER_PORT: i32 = 31001;
const KIND_ATTESTATION_KEY_REGISTER_PORT: i32 = 31002;

const ROOT_SECRET: &str = "root-secret";
const REG_SECRET: &str = "reg-srv-secret";
const TRUSTEE_SECRET: &str = "trustee-secret";
const ATT_REG_SECRET: &str = "att-reg-secret";
const REG_CERT: &str = "reg-srv-cert";
const TRUSTEE_CERT: &str = "trustee-cert";
const ATT_REG_CERT: &str = "att-reg-cert";
pub const OPERATOR_DEPLOYMENT: &str = "trusted-cluster-operator";

pub fn compare_pcrs(actual: &[Pcr], expected: &[Pcr]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }

    for (a, e) in actual.iter().zip(expected.iter()) {
        if a.id != e.id || a.value != e.value {
            return false;
        }
    }

    true
}

/// True when the Deployment's desired generation is fully rolled out: the controller has observed the spec, no old replicas remain, and every updated replica is available.
/// This attempts to prevent race conditions during rolling upgrades.
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

fn timeout_multiplier() -> f64 {
    env::var(TEST_TIMEOUT_MULTIPLIER_ENV)
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v.clamp(0.1, 100.0))
        .unwrap_or(1.0)
}

pub fn scaled_timeout(secs: u64) -> u64 {
    (secs as f64 * timeout_multiplier()).ceil() as u64
}

pub fn scaled_duration(secs: u64) -> Duration {
    Duration::from_secs(scaled_timeout(secs))
}

fn log_time() -> String {
    let fmt = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    fmt.to_string()
}

// Large warning frame, e.g. for paid cloud resources that may not have been shut down correctly
pub fn warn_frame(msg: &str) -> String {
    format!("{YELLOW}=== WARNING ===\n{msg}{ANSI_RESET}")
}

#[macro_export]
macro_rules! test_info {
    ($test_name:expr, $($arg:tt)*) => {{
        const GREEN: &str = "\x1b[32m";
        println!("{} {}INFO{}: {}: {}", log_time(), GREEN, ANSI_RESET, $test_name, format!($($arg)*));
    }}
}

#[macro_export]
macro_rules! test_warn {
    ($test_name:expr, $($arg:tt)*) => {{
        println!("{} {YELLOW}WARN{ANSI_RESET}: {}: {}", log_time(), $test_name, format!($($arg)*));
    }}
}

macro_rules! kube_apply {
    ($file:expr, $test_name:expr, $log:expr $(, kustomize = $kustomize:literal)? $(, fssa = $fssa:literal)?) => {
        test_info!($test_name, $log);
        #[allow(unused_mut)]
        let mut opt = "-f";
        $(
            if $kustomize {
                opt = "-k";
            }
        )?
        #[allow(unused_mut)]
        let mut args = vec!["apply", opt, $file];
        $(
            if $fssa {
                args.extend_from_slice(&["--server-side", "--force-conflicts"])
            }
        )?
        let apply_output = kubectl().args(args).output().await?;
        if !apply_output.status.success() {
            let stderr = String::from_utf8_lossy(&apply_output.stderr);
            return Err(anyhow!("{} failed: {}", $log, stderr));
        }
    }
}

pub const VIRT_PROVIDER_ENV: &str = "VIRT_PROVIDER";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VirtProvider {
    #[default]
    Kubevirt,
    Azure,
}

fn get_virt_provider() -> Result<VirtProvider> {
    match env::var(VIRT_PROVIDER_ENV) {
        Ok(val) => match val.to_lowercase().as_str() {
            "kubevirt" => Ok(VirtProvider::Kubevirt),
            "azure" => Ok(VirtProvider::Azure),
            v => Err(anyhow!(
                "Unknown {VIRT_PROVIDER_ENV} '{v}'. Supported providers: kubevirt, azure"
            )),
        },
        Err(env::VarError::NotPresent) => Ok(VirtProvider::default()),
        Err(e) => Err(anyhow!("{e}")),
    }
}

pub fn get_env(name: &str) -> Result<String> {
    env::var(name).map_err(|e| anyhow!("Environment variable {name} is required: {e}"))
}

pub fn ensure_command(name: &str) -> Result<()> {
    let result = which::which(name).map(|_| ());
    result.map_err(|_| anyhow!("Command {name} not found. Please install {name} first."))
}

fn kubectl() -> Command {
    match env::var(PLATFORM_ENV).as_deref().unwrap_or("kind") {
        "openshift" => Command::new("oc"),
        _ => Command::new("kubectl"),
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box)]
trait K8sPlatform: Send + Sync {
    fn add_scc(&self, kustomization: &mut serde_yaml::Value);
    async fn expose(
        &self,
        service: &str,
        deployment: &str,
        cert_name: &str,
        test_name: &str,
    ) -> Result<()>;
    async fn get_cluster_url(&self, service: &str, port: Option<i32>) -> Result<String>;
}

struct Kind {
    public: bool,
    client: Client,
    namespace: String,
}
struct OpenShift {
    client: Client,
    namespace: String,
}
struct OtherK8s {}

fn get_k8s_platform(client: &Client, namespace: &str) -> Box<dyn K8sPlatform> {
    let client = client.clone();
    let namespace = namespace.to_string();
    match env::var(PLATFORM_ENV).as_deref().unwrap_or("kind") {
        "kind" => Box::new(Kind {
            public: false,
            client,
            namespace,
        }),
        "kind_public" => Box::new(Kind {
            public: true,
            client,
            namespace,
        }),
        "openshift" => Box::new(OpenShift { client, namespace }),
        _ => Box::new(OtherK8s {}),
    }
}

#[async_trait::async_trait]
impl K8sPlatform for Kind {
    fn add_scc(&self, _: &mut serde_yaml::Value) {}
    async fn expose(&self, service: &str, _: &str, _: &str, _: &str) -> Result<()> {
        if !self.public {
            return Ok(());
        }
        let (app_label, port, node_port) = match service {
            TRUSTEE_SERVICE => Ok((TRUSTEE_APP_LABEL, TRUSTEE_PORT, KIND_TRUSTEE_PORT)),
            REGISTER_SERVER_SERVICE => Ok((
                REGISTER_SERVER_APP_LABEL,
                REGISTER_SERVER_PORT,
                KIND_REGISTER_SERVER_PORT,
            )),
            ATTESTATION_KEY_REGISTER_SERVICE => Ok((
                ATTESTATION_KEY_REGISTER_APP_LABEL,
                ATTESTATION_KEY_REGISTER_PORT,
                KIND_ATTESTATION_KEY_REGISTER_PORT,
            )),
            s => Err(anyhow!("unknown service: {s}")),
        }?;
        let service_port = ServicePort {
            name: Some("http".to_string()),
            node_port: Some(node_port),
            port,
            ..Default::default()
        };
        let services: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);
        let service = Service {
            metadata: ObjectMeta {
                name: Some(format!("{service}-forward")),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("NodePort".to_string()),
                ports: Some(vec![service_port]),
                selector: Some(BTreeMap::from([("app".to_string(), app_label.to_string())])),
                ..Default::default()
            }),
            ..Default::default()
        };
        services.create(&Default::default(), &service).await?;
        Ok(())
    }

    async fn get_cluster_url(&self, service: &str, port: Option<i32>) -> Result<String> {
        let url = format!("{service}.{}.svc.cluster.local", self.namespace);
        Ok(match port {
            Some(port) => format!("{url}:{port}"),
            None => url,
        })
    }
}

enum OpenShiftHost {
    Ip(String),
    Hostname(String),
    None,
}

impl OpenShift {
    async fn get_url(&self, service: &str) -> OpenShiftHost {
        let services: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);
        let Ok(svc) = services.get(service).await else {
            return OpenShiftHost::None;
        };
        let ingress = &svc.status.unwrap().load_balancer.unwrap().ingress.unwrap()[0];
        match (&ingress.hostname, &ingress.ip) {
            (Some(hostname), _) => OpenShiftHost::Hostname(hostname.clone()),
            (_, Some(ip)) => OpenShiftHost::Ip(ip.clone()),
            (None, None) => OpenShiftHost::None,
        }
    }
}

#[async_trait::async_trait]
impl K8sPlatform for OpenShift {
    fn add_scc(&self, kustomization: &mut serde_yaml::Value) {
        let err = "unexpected kustomization";
        let resources = kustomization.get_mut("resources").expect(err);
        let resource_seq = resources.as_sequence_mut().expect(err);
        resource_seq.push(serde_yaml::Value::String("scc.yaml".to_string()))
    }

    async fn expose(
        &self,
        service: &str,
        deployment: &str,
        cert_name: &str,
        _: &str,
    ) -> Result<()> {
        let services: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);
        let pp = Default::default();
        let duration = scaled_duration(120);
        let lb = json!({ "spec": { "type": "LoadBalancer" } });
        let clusterip = Patch::Merge(json!({ "spec": { "type": "ClusterIP" } }));

        let mut url = OpenShiftHost::None;
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 1..=EXPOSE_MAX_ATTEMPTS {
            services.patch(service, &pp, &Patch::Merge(&lb)).await?;

            let has_ingress = |svc: Option<&Service>| {
                let chk_lb = |bal: &LoadBalancerStatus| bal.ingress.is_some();
                let chk_st = |st: &ServiceStatus| st.load_balancer.as_ref().map(chk_lb);
                let chk_svc = |svc: &Service| svc.status.as_ref().and_then(chk_st);
                svc.and_then(chk_svc).unwrap_or(false)
            };
            let ctx = format!(
                "waiting for ingress on {service} (attempt {attempt}/{EXPOSE_MAX_ATTEMPTS})"
            );
            let ingress_ready = await_condition(services.clone(), service, has_ingress);
            match timeout(duration, ingress_ready).await {
                Err(_) => {
                    last_err = Some(anyhow!(ctx));
                    services.patch(service, &pp, &clusterip).await?;
                    continue;
                }
                Ok(Err(e)) => {
                    last_err = Some(anyhow::Error::from(e).context(ctx));
                    services.patch(service, &pp, &clusterip).await?;
                    continue;
                }
                Ok(Ok(_)) => {}
            }

            url = self.get_url(service).await;
            if let OpenShiftHost::Hostname(ref name) = url {
                let target = format!("{name}:0");
                let msg =
                    format!("{name} not DNS-resolvable (attempt {attempt}/{EXPOSE_MAX_ATTEMPTS})");
                let chk = || async { tokio::net::lookup_host(&target).await.map(|_| ()) };
                let poller = Poller::new().with_timeout(duration);
                if let Err(e) = poller.with_error_message(msg).poll_async(chk).await {
                    last_err = Some(e);
                    services.patch(service, &pp, &clusterip).await?;
                    continue;
                }
            }

            last_err = None;
            break;
        }
        if let Some(e) = last_err {
            return Err(e);
        }

        let certs: Api<Certificate> = Api::namespaced(self.client.clone(), &self.namespace);
        let cert = certs.get(cert_name).await?;
        let old_revision = cert.status.and_then(|st| st.revision).unwrap_or(0);
        let cert_patch = match url {
            OpenShiftHost::Ip(ip) => json!({
                "spec": {
                    "ipAddresses": [ip],
                    "dnsNames": [],
                }
            }),
            OpenShiftHost::Hostname(name) => json!({
                "spec": {
                    "dnsNames": [name],
                    "ipAddresses": []
                }
            }),
            OpenShiftHost::None => {
                return Err(anyhow!("expected service {service}"));
            }
        };
        let cert_merge = Patch::Merge(cert_patch);
        certs.patch(cert_name, &pp, &cert_merge).await?;

        let cert_reissued = |cert: Option<&Certificate>| {
            let chk = |st: &CertificateStatus| st.revision.map(|r| r > old_revision);
            cert.and_then(|c| c.status.as_ref().and_then(chk))
                .unwrap_or(false)
        };
        let cert_done = await_condition(certs, cert_name, cert_reissued);
        let ctx = format!("waiting for cert {cert_name} to have a rev newer than {old_revision}");
        timeout(duration, cert_done).await.context(ctx)??;

        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        deployments.restart(deployment).await?;

        Ok(())
    }

    async fn get_cluster_url(&self, service: &str, port: Option<i32>) -> Result<String> {
        let append_port = |e| match port {
            Some(p) => format!("{e}:{p}"),
            None => e,
        };
        Ok(match self.get_url(service).await {
            OpenShiftHost::Ip(ip) => append_port(ip),
            OpenShiftHost::Hostname(name) => append_port(name),
            // Service did not exist yet, put empty name in cert and patch upon expose
            OpenShiftHost::None => String::new(),
        })
    }
}

#[async_trait::async_trait]
impl K8sPlatform for OtherK8s {
    fn add_scc(&self, _: &mut serde_yaml::Value) {}

    async fn expose(&self, _: &str, _: &str, _: &str, test_name: &str) -> Result<()> {
        let warn = "You appear to be on an environment that is not Kind or OpenShift. \
                    Ensure operator services are reachable";
        test_warn!(test_name, "{warn}");
        Ok(())
    }

    async fn get_cluster_url(&self, _: &str, _: Option<i32>) -> Result<String> {
        Err(anyhow!(SET_CLUSTER_ERR))
    }
}

pub async fn get_cluster_url(
    client: &Client,
    namespace: &str,
    service: &str,
    port: Option<i32>,
) -> Result<String> {
    if let Ok(url) = env::var(CLUSTER_URL_ENV) {
        let full_url = format!("{service}.{namespace}.{url}");
        return Ok(match port {
            Some(port) => format!("{full_url}:{port}"),
            None => full_url,
        });
    }
    get_k8s_platform(client, namespace)
        .get_cluster_url(service, port)
        .await
}

pub async fn get_encoded_root_pem(client: Client, namespace: &str) -> Result<String> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let root_secret = secrets.get(ROOT_SECRET).await?;
    let ctx = format!("Root secret {ROOT_SECRET} had no ca.crt");
    let root_secret_data = root_secret.data.context(ctx.clone())?;
    let ca_pem_bytes = root_secret_data.get("ca.crt").context(ctx)?;
    let root_pem = String::from_utf8(ca_pem_bytes.0.clone())?;
    let encoded = utf8_percent_encode(&root_pem, NON_ALPHANUMERIC);
    Ok(format!("data:,{encoded}"))
}

static INIT: Once = Once::new();

#[derive(Clone)]
pub struct TestContext {
    client: Client,
    test_namespace: String,
    manifests_dir: String,
    test_name: String,
    delayed_approved_image: bool,
}

impl TestContext {
    pub async fn new(
        test_name: &str,
        delayed_approved_image: bool,
        approved_images: &[(&str, &str)],
    ) -> Result<Self> {
        Self::new_with_image_overrides(test_name, delayed_approved_image, approved_images, &[])
            .await
    }

    // Helper function to create a test context with image overrides. Useful for testing different image tags and versions in the same test, required for operator upgrade tests.
    pub async fn new_with_image_overrides(
        test_name: &str,
        delayed_approved_image: bool,
        approved_images: &[(&str, &str)],
        container_image_overrides: &[(&str, &str)],
    ) -> Result<Self> {
        INIT.call_once(|| {
            let _ = env_logger::builder().is_test(true).try_init();
        });

        let client = setup_test_client().await?;
        let namespace = test_namespace_name();

        let ctx = Self {
            client,
            test_namespace: namespace.clone(),
            manifests_dir: String::new(),
            test_name: test_name.to_string(),
            delayed_approved_image,
        };

        let manifests_dir = ctx.create_temp_manifests_dir()?;
        let mut ctx = ctx;
        ctx.manifests_dir = manifests_dir;

        ctx.create_namespace().await?;
        ctx.apply_operator_manifests(approved_images, container_image_overrides)
            .await?;

        test_info!(&ctx.test_name, "Execute test in the namespace {namespace}");

        Ok(ctx)
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn namespace(&self) -> &str {
        &self.test_namespace
    }

    pub fn info(&self, message: impl std::fmt::Display) {
        test_info!(&self.test_name, "{}", message);
    }

    pub fn warn(&self, message: impl std::fmt::Display) {
        test_warn!(&self.test_name, "{}", message);
    }

    pub async fn cleanup(&self) -> Result<()> {
        self.delete_trusted_execution_cluster().await?;
        let timeout = scaled_duration(60);
        self.info("Checking for resources and finalizer secrets");
        let msg = format!("Resources were left behind after {timeout:?}");
        let poller = Poller::new().with_timeout(timeout).with_error_message(msg);
        let chk = || async move {
            self.check_no_resources::<AttestationKey>().await?;
            self.check_no_resources::<ApprovedImage>().await?;
            self.check_no_resources::<Machine>().await?;
            // Prevents namespace deletion until these finalizers are also removed.
            self.check_no_finalizer_secrets().await?;
            Ok::<_, anyhow::Error>(())
        };
        poller.poll_async(chk).await?;
        self.info("Checks completed: No resources or finalizer secrets found");
        self.cleanup_namespace().await?;
        self.info(format!("Namespace {} deleted", self.test_namespace));
        self.cleanup_manifests_dir()?;
        self.info(format!(
            "Manifests directory {} deleted",
            self.manifests_dir
        ));
        Ok(())
    }

    async fn create_namespace(&self) -> Result<()> {
        self.info(format!("Creating test namespace: {}", self.test_namespace));
        let namespace_api: Api<Namespace> = Api::all(self.client.clone());
        let namespace = Namespace {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(self.test_namespace.clone()),
                labels: Some(BTreeMap::from([("test".to_string(), "true".to_string())])),
                ..Default::default()
            },
            ..Default::default()
        };

        namespace_api
            .create(&Default::default(), &namespace)
            .await?;
        Ok(())
    }

    async fn check_no_resources<K>(&self) -> Result<()>
    where
        K: kube::Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope> + Clone,
        K: k8s_openapi::serde::de::DeserializeOwned + std::fmt::Debug + Send + 'static,
    {
        let api: Api<K> = Api::namespaced(self.client.clone(), &self.test_namespace);
        let list = api.list(&Default::default()).await?;
        if let Some(item) = list.items.first() {
            return Err(anyhow!("Resource still present: {item:?}"));
        }
        Ok(())
    }

    async fn check_no_finalizer_secrets(&self) -> Result<()> {
        const AK_FINALIZER: &str = "trusted-execution-clusters.io/attestationkey-secret-finalizer";
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &self.test_namespace);
        for secret in api.list(&Default::default()).await? {
            let name = secret.metadata.name.as_deref().unwrap_or("?");
            let has_ak_finalizer = secret
                .metadata
                .finalizers
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|f| f == AK_FINALIZER);
            if has_ak_finalizer {
                return Err(anyhow!("Secret {name} still has {AK_FINALIZER}"));
            }
        }
        Ok(())
    }

    async fn delete_trusted_execution_cluster(&self) -> Result<()> {
        let tec_api: Api<TrustedExecutionCluster> =
            Api::namespaced(self.client.clone(), &self.test_namespace);
        let dp = DeleteParams::default();

        let tec_list = tec_api.list(&Default::default()).await?;

        for tec in &tec_list.items {
            if let Some(name) = &tec.metadata.name {
                self.info(format!("Deleting TrustedExecutionCluster: {name}"));
                tec_api.delete(name, &dp).await?;

                // Wait for the resource to be deleted
                wait_for_resource_deleted(&tec_api, name, scaled_timeout(120)).await?;
                self.info(format!("TrustedExecutionCluster {name} has been deleted"));
            }
        }

        Ok(())
    }

    async fn cleanup_namespace(&self) -> Result<()> {
        let namespace_api: Api<Namespace> = Api::all(self.client.clone());
        let dp = DeleteParams::default();

        match namespace_api.get(&self.test_namespace).await {
            Ok(_) => {
                namespace_api.delete(&self.test_namespace, &dp).await?;
                let timeout = scaled_timeout(300);
                wait_for_resource_deleted(&namespace_api, &self.test_namespace, timeout).await?;
                self.info(format!("Deleted namespace {}", self.test_namespace));
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                self.info("Namespace already deleted");
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    fn create_temp_manifests_dir(&self) -> Result<String> {
        let temp_dir = env::temp_dir();
        let manifests_dir = temp_dir.join(format!("manifests-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&manifests_dir)?;
        let dir_str = manifests_dir.to_str().unwrap();
        self.info(format!("Created temp manifests directory: {dir_str}"));
        Ok(dir_str.to_string())
    }

    fn cleanup_manifests_dir(&self) -> Result<()> {
        if Path::new(&self.manifests_dir).exists() {
            std::fs::remove_dir_all(&self.manifests_dir)?;
            let manifests_dir = &self.manifests_dir;
            self.info(format!("Removed manifests directory: {manifests_dir}",));
        }
        Ok(())
    }

    pub async fn wait_for_deployment_ready(
        &self,
        deployments_api: &Api<Deployment>,
        deployment_name: &str,
        timeout_secs: u64,
    ) -> Result<()> {
        test_info!(
            &self.test_name,
            "Waiting for deployment {} to be ready",
            deployment_name
        );
        let done = await_condition(
            deployments_api.clone(),
            deployment_name,
            |d: Option<&Deployment>| d.is_some_and(deployment_rollout_complete),
        );
        timeout(Duration::from_secs(timeout_secs), done)
            .await
            .context(format!(
                "{deployment_name} deployment did not fully roll out after {timeout_secs} seconds"
            ))??;
        Ok(())
    }

    /// Sets an env var on the operator Deployment, waits for the rollout, and waits for the old pod to fully terminate.
    pub async fn set_operator_related_image(
        &self,
        deployments: &Api<Deployment>,
        env_name: &str,
        image: &str,
    ) -> Result<()> {
        let patch = json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": OPERATOR_DEPLOYMENT,
                            "env": [{
                                "name": env_name,
                                "value": image
                            }]
                        }]
                    }
                }
            }
        });
        deployments
            .patch(
                OPERATOR_DEPLOYMENT,
                &PatchParams::apply("test-utils"),
                &Patch::Strategic(patch),
            )
            .await?;
        self.wait_for_deployment_ready(
            deployments,
            OPERATOR_DEPLOYMENT,
            scaled_duration(120).as_secs(),
        )
        .await
        .context("waiting for operator related-image env to roll out")?;

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), self.namespace());
        let lp = ListParams::default().labels("app=trusted-cluster-operator");
        let wait_old = async {
            loop {
                let list = pods.list(&lp).await?;
                let alive = list
                    .items
                    .iter()
                    .filter(|p| p.metadata.deletion_timestamp.is_none())
                    .count();
                if alive == 1 && list.items.len() == 1 {
                    // no delettion timestamp and only 1 single new pod.
                    break anyhow::Ok(());
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        };
        timeout(scaled_duration(60), wait_old)
            .await
            .context("old operator pod should terminate after rollout")??;
        Ok(())
    }

    async fn create_certificate(
        &self,
        service_name: &str,
        cert_name: &str,
        secret_name: &str,
        issuer_name: &str,
    ) -> Result<()> {
        let ns = &self.test_namespace;
        let domain = get_cluster_url(&self.client, ns, service_name, None).await?;
        let certs: Api<Certificate> = Api::namespaced(self.client.clone(), ns);
        let cert = Certificate {
            metadata: ObjectMeta {
                name: Some(cert_name.to_string()),
                ..Default::default()
            },
            spec: CertificateSpec {
                secret_name: secret_name.to_string(),
                issuer_ref: CertificateIssuerRef {
                    name: issuer_name.to_string(),
                    ..Default::default()
                },
                dns_names: Some(vec![domain]),
                ..Default::default()
            },
            ..Default::default()
        };
        certs.create(&Default::default(), &cert).await?;
        Ok(())
    }

    async fn set_certificates(&self) -> anyhow::Result<()> {
        let ns = &self.test_namespace;
        let root_issuer_name = "root-issuer";
        let root_issuer = Issuer {
            metadata: ObjectMeta {
                name: Some(root_issuer_name.to_string()),
                ..Default::default()
            },
            spec: IssuerSpec {
                self_signed: Some(Default::default()),
                ..Default::default()
            },
            ..Default::default()
        };
        let issuers: Api<Issuer> = Api::namespaced(self.client.clone(), ns);
        issuers.create(&Default::default(), &root_issuer).await?;
        let root_cert = Certificate {
            metadata: ObjectMeta {
                name: Some("root-cert".to_string()),
                ..Default::default()
            },
            spec: CertificateSpec {
                secret_name: ROOT_SECRET.to_string(),
                is_ca: Some(true),
                issuer_ref: CertificateIssuerRef {
                    name: root_issuer_name.to_string(),
                    ..Default::default()
                },
                common_name: Some("selfsigned-ca".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let certs: Api<Certificate> = Api::namespaced(self.client.clone(), ns);
        certs.create(&Default::default(), &root_cert).await?;
        let issuer_name = "issuer";
        let issuer = Issuer {
            metadata: ObjectMeta {
                name: Some(issuer_name.to_string()),
                ..Default::default()
            },
            spec: IssuerSpec {
                ca: Some(IssuerCa {
                    secret_name: ROOT_SECRET.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        issuers.create(&Default::default(), &issuer).await?;

        let svc = REGISTER_SERVER_SERVICE;
        self.create_certificate(svc, REG_CERT, REG_SECRET, issuer_name)
            .await?;
        self.create_certificate(TRUSTEE_SERVICE, TRUSTEE_CERT, TRUSTEE_SECRET, issuer_name)
            .await?;
        let svc = ATTESTATION_KEY_REGISTER_SERVICE;
        self.create_certificate(svc, ATT_REG_CERT, ATT_REG_SECRET, issuer_name)
            .await?;

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), &self.test_namespace);
        for secret in [REG_SECRET, TRUSTEE_SECRET, ATT_REG_SECRET] {
            wait_for_resource_created(&secrets, secret, scaled_timeout(60)).await?;
        }
        Ok(())
    }

    async fn generate_manifests(
        &self,
        workspace_root: &PathBuf,
        approved_images: &[(&str, &str)],
        container_image_overrides: &[(&str, &str)],
    ) -> Result<(PathBuf, PathBuf)> {
        let ns = self.test_namespace.clone();
        let controller_gen_pattern = workspace_root.join("bin/controller-gen-*");
        let pattern = controller_gen_pattern.to_str().unwrap();
        let err = anyhow!("No controller-gen found in bin/, run `make build-tools` first");
        let controller_gen_path = glob::glob(pattern)?.next().ok_or(err)??;

        self.info(format!(
            "Generating CRDs and RBAC with controller-gen at: {}",
            controller_gen_path.display(),
        ));

        let crd_temp_dir = Path::new(&self.manifests_dir).join("crd");
        let rbac_dir = workspace_root.join("config/rbac/");
        let options = dir::CopyOptions::new();
        dir::copy(rbac_dir, &self.manifests_dir, &options)?;
        let rbac_temp_dir = Path::new(&self.manifests_dir).join("rbac");
        std::fs::create_dir_all(&crd_temp_dir)?;

        let crd_temp_dir_str = crd_temp_dir.to_str().unwrap();
        let rbac_temp_dir_str = rbac_temp_dir.to_str().unwrap();

        let role_name = "rbac:roleName=trusted-cluster-operator-role";
        let mut args = vec![&role_name, "crd", "webhook", "paths=./api/..."];
        let crd_artifacts = format!("output:crd:artifacts:config={crd_temp_dir_str}");
        let rbac_artifacts = format!("output:rbac:artifacts:config={rbac_temp_dir_str}");
        args.extend_from_slice(&[&crd_artifacts, &rbac_artifacts]);
        let mut crd_gen_cmd = Command::new(&controller_gen_path);
        let crd_gen = crd_gen_cmd.args(args).current_dir(workspace_root).output();
        let crd_gen_output = crd_gen.await?;

        if !crd_gen_output.status.success() {
            let stderr = String::from_utf8_lossy(&crd_gen_output.stderr);
            return Err(anyhow!("Failed to generate CRDs and RBAC: {stderr}"));
        }
        self.info("CRDs and RBAC generated successfully");

        let trusted_cluster_gen_path = workspace_root.join("trusted-cluster-gen");
        if !trusted_cluster_gen_path.exists() {
            return Err(anyhow!(
                "trusted-cluster-gen not found at {}. Run 'make trusted-cluster-gen' first.",
                trusted_cluster_gen_path.display()
            ));
        }
        let repo = env::var("REGISTRY").unwrap_or_else(|_| "localhost:5000".to_string());
        let tag = env::var("TAG").unwrap_or_else(|_| "latest".to_string());
        let lookup = |key: &str| {
            container_image_overrides
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        };
        let trustee_image = lookup("TRUSTEE_IMAGE").map_or_else(|| get_env("TRUSTEE_IMAGE"), Ok)?;
        let approved_image = get_env("APPROVED_IMAGE")?;

        let mut args = vec!["-namespace", &ns, "-output-dir", &self.manifests_dir];
        let operator_img = lookup("OPERATOR_IMAGE").unwrap_or_else(|| {
            env::var("OPERATOR_IMAGE")
                .unwrap_or_else(|_| format!("{repo}/trusted-cluster-operator:{tag}"))
        });
        let compute_pcrs_img = lookup(RELATED_IMAGE_COMPUTE_PCRS).unwrap_or_else(|| {
            env::var(RELATED_IMAGE_COMPUTE_PCRS)
                .unwrap_or_else(|_| format!("{repo}/compute-pcrs:{tag}"))
        });
        let reg_srv_img = lookup(RELATED_IMAGE_REGISTRATION_SERVER).unwrap_or_else(|| {
            env::var(RELATED_IMAGE_REGISTRATION_SERVER)
                .unwrap_or_else(|_| format!("{repo}/registration-server:{tag}"))
        });
        let att_reg_img = lookup(RELATED_IMAGE_ATTESTATION_KEY_REGISTER).unwrap_or_else(|| {
            env::var(RELATED_IMAGE_ATTESTATION_KEY_REGISTER)
                .unwrap_or_else(|_| format!("{repo}/attestation-key-register:{tag}"))
        });
        args.extend(&["-image", &operator_img]);
        args.extend(&["-pcrs-compute-image", &compute_pcrs_img]);
        args.extend(&["-trustee-image", &trustee_image]);
        args.extend(&["-register-server-image", &reg_srv_img]);
        args.extend(&["-attestation-key-register-image", &att_reg_img]);
        let primary_approved_arg = format!("{},{approved_image}", constants::APPROVED_IMAGE_NAME);
        args.extend(&["-approved-image", &primary_approved_arg]);
        let approved_args: Vec<String> = approved_images
            .iter()
            .map(|&(n, r)| format!("{n},{r}"))
            .collect();
        for arg in &approved_args {
            args.extend(&["-approved-image", arg]);
        }
        let manifest_gen = Command::new(&trusted_cluster_gen_path).args(args).output();
        let manifest_gen_output = manifest_gen.await?;
        if !manifest_gen_output.status.success() {
            let stderr = String::from_utf8_lossy(&manifest_gen_output.stderr);
            return Err(anyhow!("Failed to generate manifests: {stderr}"));
        }
        Ok((crd_temp_dir, rbac_temp_dir))
    }

    async fn apply_operator_manifests(
        &self,
        approved_images: &[(&str, &str)],
        container_image_overrides: &[(&str, &str)],
    ) -> Result<()> {
        let manifests_dir = &self.manifests_dir;
        self.info(format!("Generating manifests in {manifests_dir}"));
        let workspace_root = env::var(UPSTREAM_DIR_ENV)
            .ok()
            .map(PathBuf::from)
            .unwrap_or(env::current_dir()?.join(".."));
        let (crd_temp_dir, rbac_temp_dir) = self
            .generate_manifests(&workspace_root, approved_images, container_image_overrides)
            .await?;
        self.info("Manifests generated successfully");

        self.set_certificates().await?;
        let tec = "trustedexecutionclusters.trusted-execution-clusters.io";
        let args = ["get", "crd", tec];
        let crd_check_output = kubectl().args(args).output().await?;

        if crd_check_output.status.success() {
            self.info("TrustedExecutionCluster CRD already exists, skipping CRD creation");
        } else {
            kube_apply!(
                crd_temp_dir.to_str().unwrap(),
                &self.test_name,
                "Applying CRDs",
                fssa = true
            );
        }

        self.info("Preparing RBAC manifests");
        let ns = self.test_namespace.clone();
        let sa_src = workspace_root.join("config/rbac/service_account.yaml");
        let sa_content = std::fs::read_to_string(&sa_src)?
            .replace("namespace: system", &format!("namespace: {ns}"));
        let sa_dst = rbac_temp_dir.join("service_account.yaml");
        std::fs::write(&sa_dst, sa_content)?;

        let role_path = rbac_temp_dir.join("role.yaml");
        let role_content = std::fs::read_to_string(&role_path)?.replace(
            "name: trusted-cluster-operator-role",
            &format!("name: {ns}-trusted-cluster-operator-role"),
        );
        std::fs::write(&role_path, role_content)?;

        let rb_src = workspace_root.join("config/rbac/role_binding.yaml");
        let rb = "name: manager-rolebinding";
        let role = "name: trusted-cluster-operator-role";
        let rb_content = std::fs::read_to_string(&rb_src)?
            .replace(rb, &format!("name: {ns}-manager-rolebinding"))
            .replace(role, &format!("name: {ns}-trusted-cluster-operator-role"))
            .replace("namespace: system", &format!("namespace: {ns}"));
        let rb_dst = rbac_temp_dir.join("role_binding.yaml");
        std::fs::write(&rb_dst, rb_content)?;

        let le_role_src = workspace_root.join("config/rbac/leader_election_role.yaml");
        let le_role_content = std::fs::read_to_string(&le_role_src)?
            .replace("namespace: system", &format!("namespace: {ns}"));
        let le_role_dst = rbac_temp_dir.join("leader_election_role.yaml");
        std::fs::write(&le_role_dst, le_role_content)?;

        let le_rb_src = workspace_root.join("config/rbac/leader_election_role_binding.yaml");
        let le_rb_content = std::fs::read_to_string(&le_rb_src)?
            .replace("namespace: system", &format!("namespace: {ns}"));
        let le_rb_dst = rbac_temp_dir.join("leader_election_role_binding.yaml");
        std::fs::write(&le_rb_dst, le_rb_content)?;

        self.info("Preparing RBAC kustomization");
        let platform = get_k8s_platform(&self.client, &self.test_namespace);
        let kustomization_src = workspace_root.join("config/rbac/kustomization.yaml.in");
        let kustomization_content = std::fs::read_to_string(&kustomization_src)?;
        let mut kustom_value: serde_yaml::Value = serde_yaml::from_str(&kustomization_content)?;
        let err = "unexpected kustomization";
        let kustom_map = kustom_value.as_mapping_mut().expect(err);
        let kustom_ns_key = serde_yaml::Value::String("namespace".to_string());
        kustom_map.insert(kustom_ns_key, serde_yaml::Value::String(ns.clone()));
        platform.add_scc(&mut kustom_value);
        let kustomization_target = serde_yaml::to_string(&kustom_value)?;
        let temp_kustomization_path = rbac_temp_dir.join("kustomization.yaml");
        std::fs::write(&temp_kustomization_path, kustomization_target)?;

        let scc_openshift_rb_src = workspace_root.join("config/openshift/scc.yaml");
        let scc_openshift_rb_content =
            std::fs::read_to_string(&scc_openshift_rb_src)?.replace("<NAMESPACE>", &ns);
        let scc_openshift_rb_dst = rbac_temp_dir.join("scc.yaml");
        std::fs::write(&scc_openshift_rb_dst, scc_openshift_rb_content)?;

        kube_apply!(
            rbac_temp_dir.to_str().unwrap(),
            &self.test_name,
            "Applying RBAC",
            kustomize = true,
            fssa = true
        );

        let manifests_path = Path::new(&self.manifests_dir);
        let operator_manifest_path = manifests_path.join("operator.yaml");
        let operator_manifest_str = operator_manifest_path.to_str().unwrap();
        kube_apply!(
            operator_manifest_str,
            &self.test_name,
            "Applying operator manifest"
        );

        self.info("Updating CR manifest with publicTrusteeAddr");

        self.apply_cr_manifests(manifests_path).await
    }

    async fn apply_cr_manifests(&self, manifests_path: &Path) -> Result<()> {
        let ns = &self.test_namespace;
        let cr_manifest_path = manifests_path.join("trusted_execution_cluster_cr.yaml");

        let cr_content = std::fs::read_to_string(&cr_manifest_path)?;
        let mut cr_value: serde_yaml::Value = serde_yaml::from_str(&cr_content)?;

        let spec_map = cr_value.get_mut("spec").unwrap().as_mapping_mut().unwrap();
        spec_map.insert(
            serde_yaml::Value::String("trusteeSecret".to_string()),
            serde_yaml::Value::String(TRUSTEE_SECRET.to_string()),
        );
        spec_map.insert(
            serde_yaml::Value::String("registerServerSecret".to_string()),
            serde_yaml::Value::String(REG_SECRET.to_string()),
        );
        spec_map.insert(
            serde_yaml::Value::String("attestationKeyRegisterSecret".to_string()),
            serde_yaml::Value::String(ATT_REG_SECRET.to_string()),
        );

        if get_virt_provider()? == VirtProvider::Kubevirt {
            let platform = get_k8s_platform(&self.client, &self.test_namespace);
            let port = ATTESTATION_KEY_REGISTER_PORT;
            let address = platform.get_cluster_url(ATTESTATION_KEY_REGISTER_SERVICE, Some(port));
            spec_map.insert(
                serde_yaml::Value::String("publicAttestationKeyRegisterAddr".to_string()),
                serde_yaml::Value::String(address.await?),
            );
        }

        let updated_content = serde_yaml::to_string(&cr_value)?;
        std::fs::write(&cr_manifest_path, updated_content)?;

        let cr_manifest_str = cr_manifest_path.to_str().unwrap();
        kube_apply!(cr_manifest_str, &self.test_name, "Applying CR manifest");

        if self.delayed_approved_image {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        let approved_image_paths = glob(
            manifests_path
                .join("approved_image_cr_*.yaml")
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid ApprovedImage manifest path"))?,
        )?;
        for approved_image_path in approved_image_paths.filter_map(Result::ok) {
            let approved_image_str = approved_image_path.to_str().unwrap();
            kube_apply!(
                approved_image_str,
                &self.test_name,
                "Applying ApprovedImage manifest"
            );
        }

        let depls: Api<Deployment> = Api::namespaced(self.client.clone(), ns);
        for depl in [
            "trusted-cluster-operator",
            REGISTER_SERVER_DEPLOYMENT,
            TRUSTEE_DEPLOYMENT,
            ATTESTATION_KEY_REGISTER_DEPLOYMENT,
        ] {
            self.wait_for_deployment_ready(&depls, depl, scaled_timeout(300))
                .await?;
        }

        let svc = ATTESTATION_KEY_REGISTER_SERVICE;
        let services: Api<Service> = Api::namespaced(self.client.clone(), ns);
        for svc in [REGISTER_SERVER_SERVICE, TRUSTEE_SERVICE, svc] {
            let done = await_condition(services.clone(), svc, |s: Option<&Service>| s.is_some());
            let ctx = format!("waiting for service {svc} to exist");
            timeout(scaled_duration(60), done).await.context(ctx)??;
        }

        let platform = get_k8s_platform(&self.client, &self.test_namespace);
        let svc = REGISTER_SERVER_SERVICE;
        let depl = REGISTER_SERVER_DEPLOYMENT;
        let test_name = &self.test_name;
        platform.expose(svc, depl, REG_CERT, test_name).await?;
        let svc = TRUSTEE_SERVICE;
        let depl = TRUSTEE_DEPLOYMENT;
        platform.expose(svc, depl, TRUSTEE_CERT, test_name).await?;
        let svc = ATTESTATION_KEY_REGISTER_SERVICE;
        let depl = ATTESTATION_KEY_REGISTER_DEPLOYMENT;
        platform.expose(svc, depl, ATT_REG_CERT, test_name).await?;

        let tecs: Api<TrustedExecutionCluster> = Api::namespaced(self.client.clone(), ns);
        let trustee_addr =
            get_cluster_url(&self.client, ns, TRUSTEE_SERVICE, Some(TRUSTEE_PORT)).await?;
        let json = json!({
            "spec": {
                "publicTrusteeAddr": trustee_addr
            }
        });
        let patch = Patch::Merge(&json);
        tecs.patch("trusted-execution-cluster", &Default::default(), &patch)
            .await?;
        let info = format!("Updated TEC resource with publicTrusteeAddr: {trustee_addr}");
        self.info(info);

        let info = format!("Waiting for ApprovedImage {APPROVED_IMAGE_NAME} to be Committed");
        self.info(info);

        let images: Api<ApprovedImage> = Api::namespaced(self.client.clone(), ns);
        let image_ready = |img: Option<&ApprovedImage>| {
            let chk_cond = |c: &Condition| c.type_ == COMMITTED_CONDITION && c.status == "True";
            let chk_status =
                |st: &ApprovedImageStatus| st.conditions.as_ref().map(|cs| cs.iter().any(chk_cond));
            let chk = |img: &ApprovedImage| img.status.as_ref().and_then(chk_status);
            img.and_then(chk).unwrap_or(false)
        };
        let done = await_condition(images.clone(), constants::APPROVED_IMAGE_NAME, image_ready);
        let ctx = format!(
            "waiting for ApprovedImage {} to be Committed",
            constants::APPROVED_IMAGE_NAME
        );
        timeout(scaled_duration(300), done).await.context(ctx)??;
        Ok(())
    }

    pub async fn verify_expected_pcrs(&self, expected_pcrs: &[&[Pcr]]) -> anyhow::Result<()> {
        let client = self.client();
        let namespace = self.namespace();

        let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);

        let poller = Poller::new()
            .with_timeout(scaled_duration(180))
            .with_error_message("Timed out waiting for ApprovedImages to have expected PCR values");

        poller
            .poll_async(|| async {
                let image_list = images
                    .list(&Default::default())
                    .await
                    .map_err(|e| format!("list failed: {e}"))?;
                let committed: Vec<_> = image_list
                    .items
                    .iter()
                    .filter(|img| {
                        img.status
                            .as_ref()
                            .and_then(|s| s.conditions.as_ref())
                            .is_some_and(|cs| {
                                cs.iter()
                                    .any(|c| c.type_ == COMMITTED_CONDITION && c.status == "True")
                            })
                    })
                    .collect();

                if committed.len() != expected_pcrs.len() {
                    return Err(format!(
                        "expected {} committed images, found {}",
                        expected_pcrs.len(),
                        committed.len()
                    ));
                }

                let all_match = committed.iter().all(|img| {
                    let status_pcrs = img.status.as_ref().and_then(|s| s.pcrs.as_ref());
                    let Some(status_pcrs) = status_pcrs else {
                        return false;
                    };
                    let actual_pcrs: Vec<Pcr> = status_pcrs
                        .iter()
                        .filter_map(|sp| {
                            hex::decode(&sp.value).ok().map(|v| Pcr {
                                id: sp.id as u64,
                                value: v,
                                events: vec![],
                            })
                        })
                        .collect();
                    expected_pcrs
                        .iter()
                        .any(|exp| compare_pcrs(&actual_pcrs, exp))
                });

                if all_match {
                    Ok(())
                } else {
                    Err("PCR values didn't match expected".to_string())
                }
            })
            .await
    }
}

#[macro_export]
macro_rules! named_test {
    (async fn $name:ident() -> anyhow::Result<()> { $($body:tt)* }) => {
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            const TEST_NAME: &str = stringify!($name);
            $($body)*
        }
    };
}

// virt_test labels the tests that require virtualization
#[macro_export]
macro_rules! virt_test {
    (async fn $name:ident() -> anyhow::Result<()> { $($body:tt)* }) => {
        #[cfg(feature = "virtualization")]
        #[tokio::test]
        async fn $name() -> anyhow::Result<()> {
            const TEST_NAME: &str = stringify!($name);
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! setup {
    () => {{ $crate::TestContext::new(TEST_NAME, false, &[]) }};
    (delayed_approved_image) => {{ $crate::TestContext::new(TEST_NAME, true, &[]) }};
    ($approved_images:expr) => {{ $crate::TestContext::new(TEST_NAME, false, &$approved_images) }};
    (container_images: $overrides:expr) => {{ $crate::TestContext::new_with_image_overrides(TEST_NAME, false, &[], &$overrides) }};
    ($approved_images:expr, container_images: $overrides:expr) => {{
        $crate::TestContext::new_with_image_overrides(
            TEST_NAME,
            false,
            &$approved_images,
            &$overrides,
        )
    }};
}

async fn setup_test_client() -> Result<Client> {
    let client = Client::try_default().await?;
    Ok(client)
}

fn test_namespace_name() -> String {
    let namespace_prefix = env::var("TEST_NAMESPACE_PREFIX").unwrap_or_default();
    let uuid = &uuid::Uuid::new_v4().to_string()[..8];
    format!("{namespace_prefix}test-{uuid}")
}

pub async fn wait_for_resource_created<K>(
    api: &Api<K>,
    resource_name: &str,
    timeout_secs: u64,
) -> Result<()>
where
    K: kube::Resource<DynamicType = ()> + Clone + std::fmt::Debug + Send + 'static,
    K: k8s_openapi::serde::de::DeserializeOwned,
{
    let created = |r: Option<&K>| r.is_some();
    let done = await_condition(api.clone(), resource_name, created);
    let type_ = std::any::type_name::<K>();
    let ctx = format!("waiting {timeout_secs} for {type_} '{resource_name}' creation");
    let duration = Duration::from_secs(timeout_secs);
    timeout(duration, done).await.context(ctx)??;
    Ok(())
}

// Shared test helpers used across multiple integration test files.

/// Returns the first container's image from a Deployment.
pub fn deployment_image(depl: &Deployment) -> Option<String> {
    depl.spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|ps| ps.containers.first())
        .and_then(|c| c.image.clone())
}

/// Returns a closure that is true when the TEC has the given condition type and status.
pub fn tec_has_condition<'a>(
    type_: &'a str,
    status: &'a str,
) -> impl Fn(Option<&TrustedExecutionCluster>) -> bool + 'a {
    move |tec: Option<&TrustedExecutionCluster>| {
        tec.and_then(|t| t.status.as_ref())
            .and_then(|s| s.conditions.as_ref())
            .is_some_and(|cs| cs.iter().any(|c| c.type_ == type_ && c.status == status))
    }
}

/// Returns a closure that is true when the TEC has the given condition type and reason.
pub fn tec_has_condition_reason<'a>(
    type_: &'a str,
    reason: &'a str,
) -> impl Fn(Option<&TrustedExecutionCluster>) -> bool + 'a {
    move |tec: Option<&TrustedExecutionCluster>| {
        tec.and_then(|t| t.status.as_ref())
            .and_then(|s| s.conditions.as_ref())
            .is_some_and(|cs| cs.iter().any(|c| c.type_ == type_ && c.reason == reason))
    }
}

/// True when the ApprovedImage has a `Committed=True` condition.
pub fn approved_image_is_committed(img: Option<&ApprovedImage>) -> bool {
    img.and_then(|i| i.status.as_ref())
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|cs| {
            cs.iter()
                .any(|c| c.type_ == COMMITTED_CONDITION && c.status == "True")
        })
}

/// True when the ApprovedImage status contains at least one PCR entry.
pub fn approved_image_has_pcrs(img: Option<&ApprovedImage>) -> bool {
    img.and_then(|i| i.status.as_ref())
        .and_then(|s| s.pcrs.as_ref())
        .is_some_and(|pcrs| !pcrs.is_empty())
}

/// Waits up to 120 seconds for the TEC to reach the `Installed=True` condition.
pub async fn wait_for_install(
    tec_api: &Api<TrustedExecutionCluster>,
    name: &str,
) -> anyhow::Result<()> {
    let done = await_condition(
        tec_api.clone(),
        name,
        tec_has_condition(INSTALLED_CONDITION, "True"),
    );
    timeout(scaled_duration(120), done)
        .await
        .context("waiting for initial install")??;
    Ok(())
}

/// Triggers an upgrade by clearing the observedOperatorVersion on the TEC status.
/// The operator will detect a version mismatch and enter the upgrade branch.
pub async fn trigger_upgrade(
    tec_api: &Api<TrustedExecutionCluster>,
    name: &str,
) -> anyhow::Result<()> {
    let patch = json!({ "status": { "observedOperatorVersion": null } });
    tec_api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(patch))
        .await?;
    Ok(())
}

/// Waits up to `secs` seconds for the named ApprovedImage to be committed and have non-empty PCR data in its status.
pub async fn wait_for_committed_with_pcrs(
    images: &Api<ApprovedImage>,
    name: &str,
    secs: u64,
) -> anyhow::Result<()> {
    let done = await_condition(images.clone(), name, |img: Option<&ApprovedImage>| {
        approved_image_is_committed(img) && approved_image_has_pcrs(img)
    });
    timeout(scaled_duration(secs), done)
        .await
        .context(format!("waiting for {name} committed with PCRs"))??;
    Ok(())
}

/// Returns each PCR register's id alongside its events from the ApprovedImage status.
pub fn extract_events(img: &ApprovedImage) -> Vec<(i64, Vec<ApprovedImageStatusPcrsEvents>)> {
    img.status
        .as_ref()
        .and_then(|s| s.pcrs.as_ref())
        .map(|pcrs| {
            pcrs.iter()
                .map(|p| {
                    let events = p.events.clone().unwrap_or_default();
                    (p.id, events)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Returns each PCR register's id alongside its hex-encoded value from the ApprovedImage status.
pub fn extract_pcr_vals(img: &ApprovedImage) -> Vec<(i64, String)> {
    img.status
        .as_ref()
        .and_then(|s| s.pcrs.as_ref())
        .map(|pcrs| pcrs.iter().map(|p| (p.id, p.value.clone())).collect())
        .unwrap_or_default()
}

pub async fn wait_for_resource_deleted<K>(
    api: &Api<K>,
    resource_name: &str,
    timeout_secs: u64,
) -> Result<()>
where
    K: kube::Resource<DynamicType = ()> + Clone + std::fmt::Debug + Send + 'static,
    K: k8s_openapi::serde::de::DeserializeOwned,
{
    let deleted = |r: Option<&K>| r.is_none();
    let done = await_condition(api.clone(), resource_name, deleted);
    let type_ = std::any::type_name::<K>();
    let ctx = format!("waiting {timeout_secs} for {type_} '{resource_name}' deletion");
    let duration = Duration::from_secs(timeout_secs);
    timeout(duration, done).await.context(ctx)??;
    Ok(())
}

pub async fn wait_for_event(
    client: &Client,
    namespace: &str,
    regarding_name: &str,
    reason: &str,
    timeout_secs: u64,
) -> Result<Event> {
    let events_api: Api<Event> = Api::namespaced(client.clone(), namespace);
    Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_error_message(format!(
            "waiting for event reason='{reason}' regarding='{regarding_name}'"
        ))
        .poll_async(|| {
            let api = events_api.clone();
            let name = regarding_name.to_string();
            let rsn = reason.to_string();
            async move {
                let list = api.list(&ListParams::default()).await?;
                list.items
                    .into_iter()
                    .find(|e| {
                        let name_match = e
                            .regarding
                            .as_ref()
                            .and_then(|r| r.name.as_ref())
                            .is_some_and(|n| n == &name);
                        let reason_match = e.reason.as_deref() == Some(&rsn);
                        name_match && reason_match
                    })
                    .ok_or_else(|| anyhow!("not found yet"))
            }
        })
        .await
}
