// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Result, anyhow};
use fs_extra::dir;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
use kube::api::DeleteParams;
use kube::{Api, Client};
use std::path::{Path, PathBuf};
use std::{collections::BTreeMap, env, sync::Once, time::Duration};
use tokio::process::Command;

use trusted_cluster_operator_lib::TrustedExecutionCluster;
use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::openshift_ingresses::Ingress;
use trusted_cluster_operator_lib::routes::Route;

pub mod timer;
pub use timer::Poller;
pub mod mock_client;

#[cfg(feature = "virtualization")]
pub mod virt;

use compute_pcrs_lib::Pcr;

const PLATFORM_ENV: &str = "PLATFORM";
const CLUSTER_URL_ENV: &str = "CLUSTER_URL";
const YELLOW: &str = "\x1b[33m";
const ANSI_RESET: &str = "\x1b[0m";

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

// Large warning frame, e.g. for paid cloud resources that may not have been shut down correctly
pub fn warn_frame(msg: &str) -> String {
    format!("{YELLOW}=== WARNING ===\n{msg}{ANSI_RESET}")
}

#[macro_export]
macro_rules! test_info {
    ($test_name:expr, $($arg:tt)*) => {{
        const GREEN: &str = "\x1b[32m";
        println!("{}INFO{}: {}: {}", GREEN, ANSI_RESET, $test_name, format!($($arg)*));
    }}
}

#[macro_export]
macro_rules! test_warn {
    ($test_name:expr, $($arg:tt)*) => {{
        println!("{YELLOW}WARN{ANSI_RESET}: {}: {}", $test_name, format!($($arg)*));
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
        let apply_output = Command::new("kubectl")
            .args(args)
            .output()
            .await?;
        if !apply_output.status.success() {
            let stderr = String::from_utf8_lossy(&apply_output.stderr);
            return Err(anyhow!("{} failed: {}", $log, stderr));
        }
    }
}

fn get_env(name: &str) -> Result<String> {
    env::var(name).map_err(|e| anyhow!("Environment variable {name} is required: {e}"))
}

pub fn ensure_command(name: &str) -> Result<()> {
    let result = which::which(name).map(|_| ());
    result.map_err(|_| anyhow!("Command {name} not found. Please install {name} first."))
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box)]
trait K8sPlatform: Send + Sync {
    fn add_scc(&self, kustomization: &mut serde_yaml::Value);
    async fn expose(&self, namespace: &str, service: &str, test_name: &str) -> Result<()>;
    async fn get_cluster_url(
        &self,
        client: Client,
        namespace: &str,
        service: &str,
        port: i32,
    ) -> Result<String>;
}

struct Kind {}
struct OpenShift {}
struct OtherK8s {}

fn get_k8s_platform() -> Box<dyn K8sPlatform> {
    match env::var("PLATFORM").as_deref().unwrap_or("kind") {
        "kind" => Box::new(Kind {}),
        "openshift" => Box::new(OpenShift {}),
        _ => Box::new(OtherK8s {}),
    }
}

#[async_trait::async_trait]
impl K8sPlatform for Kind {
    fn add_scc(&self, _: &mut serde_yaml::Value) {}
    async fn expose(&self, _: &str, _: &str, _: &str) -> Result<()> {
        Ok(())
    }

    async fn get_cluster_url(
        &self,
        _: Client,
        namespace: &str,
        service: &str,
        port: i32,
    ) -> Result<String> {
        Ok(format!("{service}.{namespace}.svc.cluster.local:{port}"))
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

    async fn expose(&self, namespace: &str, service: &str, _: &str) -> Result<()> {
        ensure_command("oc")?;
        let args = ["expose", "service", service, "-n", namespace];
        let output = Command::new("oc").args(args).output().await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("oc command failed: {stderr}"));
        }
        Ok(())
    }

    async fn get_cluster_url(
        &self,
        client: Client,
        namespace: &str,
        service: &str,
        _: i32,
    ) -> Result<String> {
        let routes: Api<Route> = Api::namespaced(client.clone(), namespace);
        if let Ok(route) = routes.get(service).await {
            return Ok(route.spec.host.expect("route existed, but had no host"));
        }
        // Fallback when route does not exist yet
        let ingresses: Api<Ingress> = Api::all(client);
        let ingress = ingresses.get("cluster").await?;
        let domain = ingress.spec.domain.unwrap();
        Ok(format!("{service}-{namespace}.{domain}"))
    }
}

#[async_trait::async_trait]
impl K8sPlatform for OtherK8s {
    fn add_scc(&self, _: &mut serde_yaml::Value) {}

    async fn expose(&self, _: &str, _: &str, test_name: &str) -> Result<()> {
        let warn = "You appear to be on an environment that is not Kind or OpenShift. \
                    Ensure operator are services are reachable";
        test_warn!(test_name, "{warn}");
        Ok(())
    }

    async fn get_cluster_url(&self, _: Client, _: &str, _: &str, _: i32) -> Result<String> {
        Err(anyhow!(
            "Set {CLUSTER_URL_ENV} when {PLATFORM_ENV} is not one of: kind, openshift"
        ))
    }
}

pub async fn get_cluster_url(
    client: Client,
    namespace: &str,
    service: &str,
    port: i32,
) -> Result<String> {
    if let Ok(url) = env::var(CLUSTER_URL_ENV) {
        return Ok(format!("{service}.{namespace}.{url}:{port}"));
    }
    get_k8s_platform()
        .get_cluster_url(client, namespace, service, port)
        .await
}

static INIT: Once = Once::new();

pub struct TestContext {
    client: Client,
    test_namespace: String,
    manifests_dir: String,
    test_name: String,
}

impl TestContext {
    pub async fn new(test_name: &str) -> Result<Self> {
        INIT.call_once(|| {
            let _ = env_logger::builder().is_test(true).try_init();
        });

        let client = setup_test_client().await?;
        let namespace = test_namespace_name();

        let ctx = Self {
            client,
            test_namespace: namespace,
            manifests_dir: String::new(),
            test_name: test_name.to_string(),
        };

        let manifests_dir = ctx.create_temp_manifests_dir()?;
        let mut ctx = ctx;
        ctx.manifests_dir = manifests_dir;

        ctx.create_namespace().await?;
        ctx.apply_operator_manifests().await?;

        test_info!(
            &ctx.test_name,
            "Execute test in the namespace {}",
            ctx.test_namespace
        );

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
        self.cleanup_namespace().await?;
        self.cleanup_manifests_dir()?;
        Ok(())
    }

    async fn create_namespace(&self) -> Result<()> {
        test_info!(
            &self.test_name,
            "Creating test namespace: {}",
            self.test_namespace
        );
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

    async fn delete_trusted_execution_cluster(&self) -> Result<()> {
        let tec_api: Api<TrustedExecutionCluster> =
            Api::namespaced(self.client.clone(), &self.test_namespace);
        let dp = DeleteParams::default();

        let tec_list = tec_api.list(&Default::default()).await?;

        for tec in &tec_list.items {
            if let Some(name) = &tec.metadata.name {
                test_info!(
                    &self.test_name,
                    "Deleting TrustedExecutionCluster: {}",
                    name
                );
                tec_api.delete(name, &dp).await?;

                // Wait for the resource to be deleted
                wait_for_resource_deleted(&tec_api, name, 120, 5).await?;
                test_info!(
                    &self.test_name,
                    "TrustedExecutionCluster {} has been deleted",
                    name
                );
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
                test_info!(&self.test_name, "Deleted namespace {}", self.test_namespace);
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                test_info!(&self.test_name, "Namespace already deleted");
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
        test_info!(
            &self.test_name,
            "Created temp manifests directory: {dir_str}",
        );
        Ok(dir_str.to_string())
    }

    fn cleanup_manifests_dir(&self) -> Result<()> {
        if Path::new(&self.manifests_dir).exists() {
            std::fs::remove_dir_all(&self.manifests_dir)?;
            test_info!(
                &self.test_name,
                "Removed manifests directory: {}",
                self.manifests_dir
            );
        }
        Ok(())
    }

    async fn wait_for_deployment_ready(
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
        let poller = Poller::new()
            .with_timeout(Duration::from_secs(timeout_secs))
            .with_interval(Duration::from_secs(5))
            .with_error_message(format!(
                "{deployment_name} deployment does not have 1 available replica after {timeout_secs} seconds"
            ));

        let test_name_owned = self.test_name.clone();
        poller
            .poll_async(move || {
                let api = deployments_api.clone();
                let name = deployment_name.to_string();
                let tn = test_name_owned.clone();
                async move {
                    let deployment = api.get(&name).await?;

                    if let Some(status) = &deployment.status
                        && let Some(available_replicas) = status.available_replicas
                        && available_replicas == 1
                    {
                        test_info!(&tn, "{} deployment has 1 available replica", name);
                        return Ok(());
                    }

                    Err(anyhow!(
                        "{name} deployment does not have 1 available replica yet"
                    ))
                }
            })
            .await
    }

    async fn generate_manifests(&self, workspace_root: &PathBuf) -> Result<(PathBuf, PathBuf)> {
        let ns = self.test_namespace.clone();
        let controller_gen_pattern = workspace_root.join("bin/controller-gen-*");
        let pattern = controller_gen_pattern.to_str().unwrap();
        let err = anyhow!("No controller-gen found in bin/, run `make build-tools` first");
        let controller_gen_path = glob::glob(pattern)?.next().ok_or(err)??;

        test_info!(
            &self.test_name,
            "Generating CRDs and RBAC with controller-gen at: {}",
            controller_gen_path.display()
        );

        let crd_temp_dir = Path::new(&self.manifests_dir).join("crd");
        let rbac_dir = workspace_root.join("config/rbac/");
        let options = dir::CopyOptions::new();
        dir::copy(rbac_dir, &self.manifests_dir, &options)?;
        let rbac_temp_dir = Path::new(&self.manifests_dir).join("rbac");
        std::fs::create_dir_all(&crd_temp_dir)?;

        let crd_temp_dir_str = crd_temp_dir.to_str().unwrap();
        let rbac_temp_dir_str = rbac_temp_dir.to_str().unwrap();

        let role_name = "rbac:roleName=trusted-cluster-operator-role";
        let mut args = vec![&role_name, "crd", "webhook", "paths=./..."];
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

        test_info!(&self.test_name, "CRDs and RBAC generated successfully");

        let trusted_cluster_gen_path = workspace_root.join("trusted-cluster-gen");
        if !trusted_cluster_gen_path.exists() {
            return Err(anyhow!(
                "trusted-cluster-gen not found at {}. Run 'make trusted-cluster-gen' first.",
                trusted_cluster_gen_path.display()
            ));
        }
        let repo = env::var("REGISTRY").unwrap_or_else(|_| "localhost:5000".to_string());
        let tag = env::var("TAG").unwrap_or_else(|_| "latest".to_string());
        let trustee_image = get_env("TRUSTEE_IMAGE")?;
        let approved_image = get_env("APPROVED_IMAGE")?;

        let mut args = vec!["-namespace", &ns, "-output-dir", &self.manifests_dir];
        let operator_img = format!("{repo}/trusted-cluster-operator:{tag}");
        let compute_pcrs_img = format!("{repo}/compute-pcrs:{tag}");
        let reg_srv_img = format!("{repo}/registration-server:{tag}");
        let att_reg_img = format!("{repo}/attestation-key-register:{tag}");
        args.extend(&["-image", &operator_img]);
        args.extend(&["-pcrs-compute-image", &compute_pcrs_img]);
        args.extend(&["-trustee-image", &trustee_image]);
        args.extend(&["-register-server-image", &reg_srv_img]);
        args.extend(&["-attestation-key-register-image", &att_reg_img]);
        args.extend(&["-approved-image", &approved_image]);
        let manifest_gen = Command::new(&trusted_cluster_gen_path).args(args).output();
        let manifest_gen_output = manifest_gen.await?;
        if !manifest_gen_output.status.success() {
            let stderr = String::from_utf8_lossy(&manifest_gen_output.stderr);
            return Err(anyhow!("Failed to generate manifests: {stderr}"));
        }
        Ok((crd_temp_dir, rbac_temp_dir))
    }

    async fn apply_operator_manifests(&self) -> Result<()> {
        let manifests_dir = &self.manifests_dir;
        test_info!(&self.test_name, "Generating manifests in {manifests_dir}");
        let workspace_root = env::current_dir()?.join("..");
        let (crd_temp_dir, rbac_temp_dir) = self.generate_manifests(&workspace_root).await?;
        test_info!(&self.test_name, "Manifests generated successfully");

        let tec = "trustedexecutionclusters.trusted-execution-clusters.io";
        let args = ["get", "crd", tec];
        let crd_check_output = Command::new("kubectl").args(args).output().await?;

        if crd_check_output.status.success() {
            test_info!(
                &self.test_name,
                "TrustedExecutionCluster CRD already exists, skipping CRD creation"
            );
        } else {
            kube_apply!(
                crd_temp_dir.to_str().unwrap(),
                &self.test_name,
                "Applying CRDs",
                fssa = true
            );
        }

        test_info!(&self.test_name, "Preparing RBAC manifests");

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

        test_info!(&self.test_name, "Preparing RBAC kustomization");
        let platform = get_k8s_platform();
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
            kustomize = true
        );

        let manifests_path = Path::new(&self.manifests_dir);
        let operator_manifest_path = manifests_path.join("operator.yaml");
        let operator_manifest_str = operator_manifest_path.to_str().unwrap();
        kube_apply!(
            operator_manifest_str,
            &self.test_name,
            "Applying operator manifest"
        );

        test_info!(
            &self.test_name,
            "Updating CR manifest with publicTrusteeAddr"
        );
        self.apply_operator_manifest(manifests_path).await
    }

    async fn apply_operator_manifest(&self, manifests_path: &Path) -> Result<()> {
        let ns = self.test_namespace.clone();
        let trustee_addr =
            get_cluster_url(self.client.clone(), &ns, TRUSTEE_SERVICE, TRUSTEE_PORT).await?;
        let cr_manifest_path = manifests_path.join("trusted_execution_cluster_cr.yaml");

        let cr_content = std::fs::read_to_string(&cr_manifest_path)?;
        let mut cr_value: serde_yaml::Value = serde_yaml::from_str(&cr_content)?;

        if let Some(spec) = cr_value.get_mut("spec")
            && let Some(spec_map) = spec.as_mapping_mut()
        {
            spec_map.insert(
                serde_yaml::Value::String("publicTrusteeAddr".to_string()),
                serde_yaml::Value::String(trustee_addr.clone()),
            );

            // Set attestationKeyRegistration if environment variable is set
            if let Ok(enable_ak_reg) = env::var("ENABLE_ATTESTATION_KEY_REGISTRATION") {
                let enabled = enable_ak_reg.to_lowercase() == "true"
                    || enable_ak_reg == "1"
                    || enable_ak_reg.to_lowercase() == "yes";
                spec_map.insert(
                    serde_yaml::Value::String("attestationKeyRegistration".to_string()),
                    serde_yaml::Value::Bool(enabled),
                );
            }
        }

        let updated_content = serde_yaml::to_string(&cr_value)?;
        std::fs::write(&cr_manifest_path, updated_content)?;

        test_info!(
            &self.test_name,
            "Updated CR manifest with publicTrusteeAddr: {trustee_addr}",
        );

        let cr_manifest_str = cr_manifest_path.to_str().unwrap();
        kube_apply!(cr_manifest_str, &self.test_name, "Applying CR manifest");

        let approved_image_path = manifests_path.join("approved_image_cr.yaml");
        let approved_image_str = approved_image_path.to_str().unwrap();
        kube_apply!(
            approved_image_str,
            &self.test_name,
            "Applying ApprovedImage manifest"
        );

        let deployments_api: Api<Deployment> = Api::namespaced(self.client.clone(), &ns);

        self.wait_for_deployment_ready(&deployments_api, "trusted-cluster-operator", 120)
            .await?;
        self.wait_for_deployment_ready(&deployments_api, "register-server", 300)
            .await?;
        self.wait_for_deployment_ready(&deployments_api, "trustee-deployment", 180)
            .await?;
        self.wait_for_deployment_ready(&deployments_api, "attestation-key-register", 120)
            .await?;

        let platform = get_k8s_platform();
        for svc in ["kbs-service", "attestation-key-register", "register-server"] {
            platform.expose(&ns, svc, &self.test_name).await?;
        }

        test_info!(
            &self.test_name,
            "Waiting for image-pcrs ConfigMap to be created"
        );
        let configmap_api: Api<ConfigMap> = Api::namespaced(self.client.clone(), &ns);

        let err = format!("image-pcrs ConfigMap in the namespace {ns} not found");
        let poller = Poller::new()
            .with_timeout(Duration::from_secs(60))
            .with_interval(Duration::from_secs(5))
            .with_error_message(err);

        let test_name_owned = self.test_name.clone();
        let check_fn = move || {
            let api = configmap_api.clone();
            let tn = test_name_owned.clone();
            async move {
                let result = api.get("image-pcrs").await;
                if result.is_ok() {
                    test_info!(&tn, "image-pcrs ConfigMap created");
                }
                result
            }
        };
        poller.poll_async(check_fn).await?;

        Ok(())
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
    () => {{ $crate::TestContext::new(TEST_NAME) }};
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

pub async fn wait_for_resource_deleted<K>(
    api: &Api<K>,
    resource_name: &str,
    timeout_secs: u64,
    interval_secs: u64,
) -> Result<()>
where
    K: kube::Resource<DynamicType = ()> + Clone + std::fmt::Debug,
    K: k8s_openapi::serde::de::DeserializeOwned,
{
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_interval(Duration::from_secs(interval_secs))
        .with_error_message(format!("waiting for {resource_name} to be deleted"));

    poller
        .poll_async(|| {
            let api = api.clone();
            let name = resource_name.to_string();
            async move {
                match api.get(&name).await {
                    Ok(_) => Err("{name} still exists, retrying..."),
                    Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
                    Err(e) => {
                        panic!("Unexpected error while fetching {name}: {e:?}");
                    }
                }
            }
        })
        .await
}
