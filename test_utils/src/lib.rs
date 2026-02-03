// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use glob::glob;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
use kube::api::DeleteParams;
use kube::{Api, Client};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Once;
use std::time::Duration;
use tokio::process::Command;
use trusted_cluster_operator_lib::reference_values::ImagePcrs;

pub mod timer;
pub use timer::Poller;
pub mod constants;
pub mod mock_client;

#[cfg(feature = "virtualization")]
pub mod virt;

use compute_pcrs_lib::Pcr;

pub const DEFAULT_TEST_FCOS_IMAGE: &str = "quay.io/trusted-execution-clusters/fedora-coreos@sha256:79a0657399e6c67c7c95b8a09193d18e5675b5aa3cfb4d75ea5c8d4d53b2af74";

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

#[macro_export]
macro_rules! test_info {
    ($test_name:expr, $($arg:tt)*) => {{
        const GREEN: &str = "\x1b[32m";
        const RESET: &str = "\x1b[0m";
        println!("{}INFO{}: {}: {}", GREEN, RESET, $test_name, format!($($arg)*));
    }}
}

macro_rules! kube_apply {
    ($file:expr, $test_name:expr, $log:literal $(, kustomize = $kustomize:literal)? $(, fssa = $fssa:literal)?) => {
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
            return Err(anyhow::anyhow!("{} failed: {}", $log, stderr));
        }
    }
}

static INIT: Once = Once::new();

pub struct TestContext {
    client: Client,
    test_namespace: String,
    manifests_dir: String,
    test_name: String,
}

impl TestContext {
    pub async fn new(test_name: &str, approved_images: &[&str]) -> anyhow::Result<Self> {
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
        ctx.apply_operator_manifests(approved_images).await?;

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

    pub async fn cleanup(&self) -> anyhow::Result<()> {
        self.cleanup_namespace().await?;
        self.cleanup_manifests_dir()?;
        Ok(())
    }

    async fn create_namespace(&self) -> anyhow::Result<()> {
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

    async fn cleanup_namespace(&self) -> anyhow::Result<()> {
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

    fn create_temp_manifests_dir(&self) -> anyhow::Result<String> {
        let temp_dir = std::env::temp_dir();
        let manifests_dir = temp_dir.join(format!("manifests-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&manifests_dir)?;
        let dir_str = manifests_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid temp directory path"))?
            .to_string();
        test_info!(
            &self.test_name,
            "Created temp manifests directory: {}",
            dir_str
        );
        Ok(dir_str)
    }

    fn cleanup_manifests_dir(&self) -> anyhow::Result<()> {
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
    ) -> anyhow::Result<()> {
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

                    Err(anyhow::anyhow!(
                        "{name} deployment does not have 1 available replica yet"
                    ))
                }
            })
            .await
    }

    async fn apply_operator_manifests(&self, approved_images: &[&str]) -> anyhow::Result<()> {
        test_info!(
            &self.test_name,
            "Generating manifests in {}",
            self.manifests_dir
        );

        let ns = self.test_namespace.clone();
        let workspace_root = std::env::current_dir()?.join("..");
        let controller_gen_path = workspace_root.join("bin/controller-gen-v0.19.0");

        test_info!(
            &self.test_name,
            "Generating CRDs and RBAC with controller-gen at: {}",
            controller_gen_path.display()
        );

        let crd_temp_dir = Path::new(&self.manifests_dir).join("crd");
        let rbac_temp_dir = Path::new(&self.manifests_dir).join("rbac");
        std::fs::create_dir_all(&crd_temp_dir)?;
        std::fs::create_dir_all(&rbac_temp_dir)?;

        let crd_temp_dir_str = crd_temp_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid CRD temp directory path"))?;
        let rbac_temp_dir_str = rbac_temp_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid RBAC temp directory path"))?;

        let crd_gen_output = Command::new(&controller_gen_path)
            .args([
                "rbac:roleName=trusted-cluster-operator-role",
                "crd",
                "webhook",
                "paths=./...",
                &format!("output:crd:artifacts:config={crd_temp_dir_str}"),
                &format!("output:rbac:artifacts:config={rbac_temp_dir_str}"),
            ])
            .current_dir(&workspace_root)
            .output()
            .await?;

        if !crd_gen_output.status.success() {
            let stderr = String::from_utf8_lossy(&crd_gen_output.stderr);
            return Err(anyhow::anyhow!(
                "Failed to generate CRDs and RBAC: {stderr}"
            ));
        }

        test_info!(&self.test_name, "CRDs and RBAC generated successfully");

        let trusted_cluster_gen_path = workspace_root.join("trusted-cluster-gen");
        if !trusted_cluster_gen_path.exists() {
            return Err(anyhow::anyhow!(
                "trusted-cluster-gen not found at {}. Run 'make trusted-cluster-gen' first.",
                trusted_cluster_gen_path.display()
            ));
        }

        let mut trusted_cluster_gen_args = vec![
            "-namespace",
            &ns,
            "-output-dir",
            &self.manifests_dir,
            "-image",
            "localhost:5000/trusted-execution-clusters/trusted-cluster-operator:latest",
            "-pcrs-compute-image",
            "localhost:5000/trusted-execution-clusters/compute-pcrs:latest",
            "-trustee-image",
            "quay.io/trusted-execution-clusters/key-broker-service:20260106",
            "-register-server-image",
            "localhost:5000/trusted-execution-clusters/registration-server:latest",
            "-attestation-key-register-image",
            "localhost:5000/trusted-execution-clusters/attestation-key-register:latest",
        ];

        trusted_cluster_gen_args.extend(
            approved_images
                .iter()
                .flat_map(|&i| vec!["-approved-image", i]),
        );

        let manifest_gen_output = Command::new(&trusted_cluster_gen_path)
            .args(trusted_cluster_gen_args)
            .output()
            .await?;

        if !manifest_gen_output.status.success() {
            let stderr = String::from_utf8_lossy(&manifest_gen_output.stderr);
            return Err(anyhow::anyhow!("Failed to generate manifests: {stderr}"));
        }

        test_info!(&self.test_name, "Manifests generated successfully");

        let crd_check_output = Command::new("kubectl")
            .args([
                "get",
                "crd",
                "trustedexecutionclusters.trusted-execution-clusters.io",
            ])
            .output()
            .await?;

        if crd_check_output.status.success() {
            test_info!(
                &self.test_name,
                "TrustedExecutionCluster CRD already exists, skipping CRD creation"
            );
        } else {
            kube_apply!(
                crd_temp_dir_str,
                &self.test_name,
                "Applying CRDs",
                fssa = true
            );
        }

        test_info!(&self.test_name, "Preparing RBAC manifests");

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
        let rb_content = std::fs::read_to_string(&rb_src)?
            .replace(
                "name: manager-rolebinding",
                &format!("name: {ns}-manager-rolebinding"),
            )
            .replace(
                "name: trusted-cluster-operator-role",
                &format!("name: {ns}-trusted-cluster-operator-role"),
            )
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
        let kustomization_content = format!(
            r#"# SPDX-FileCopyrightText: Generated for testing
# SPDX-License-Identifier: CC0-1.0

namespace: {ns}

resources:
  - service_account.yaml
  - role.yaml
  - role_binding.yaml
  - leader_election_role.yaml
  - leader_election_role_binding.yaml
"#
        );

        let temp_kustomization_path = rbac_temp_dir.join("kustomization.yaml");
        std::fs::write(&temp_kustomization_path, kustomization_content)?;

        kube_apply!(
            rbac_temp_dir_str,
            &self.test_name,
            "Applying RBAC",
            kustomize = true
        );

        let manifests_path = Path::new(&self.manifests_dir);
        let operator_manifest_path = manifests_path.join("operator.yaml");
        let operator_manifest_str = operator_manifest_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid operator manifest path"))?;
        kube_apply!(
            operator_manifest_str,
            &self.test_name,
            "Applying operator manifest"
        );

        test_info!(
            &self.test_name,
            "Updating CR manifest with publicTrusteeAddr"
        );
        let trustee_addr = format!("kbs-service.{ns}.svc.cluster.local:8080");
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
        }

        let updated_content = serde_yaml::to_string(&cr_value)?;
        std::fs::write(&cr_manifest_path, updated_content)?;

        test_info!(
            &self.test_name,
            "Updated CR manifest with publicTrusteeAddr: {}",
            trustee_addr
        );

        let cr_manifest_str = cr_manifest_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid CR manifest path"))?;
        kube_apply!(cr_manifest_str, &self.test_name, "Applying CR manifest");

        let approved_image_paths = glob(
            manifests_path
                .join("approved_image_cr_*.yaml")
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid ApprovedImage manifest path"))?,
        )?;
        for approved_image_path in approved_image_paths.filter_map(Result::ok) {
            let approved_image_str = approved_image_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid ApprovedImage manifest path"))?;
            kube_apply!(
                approved_image_str,
                &self.test_name,
                "Applying ApprovedImage manifest"
            );
        }

        let deployments_api: Api<Deployment> = Api::namespaced(self.client.clone(), &ns);

        self.wait_for_deployment_ready(&deployments_api, "trusted-cluster-operator", 120)
            .await?;
        self.wait_for_deployment_ready(&deployments_api, "register-server", 300)
            .await?;
        self.wait_for_deployment_ready(&deployments_api, "trustee-deployment", 180)
            .await?;

        test_info!(
            &self.test_name,
            "Waiting for image-pcrs ConfigMap to be created"
        );
        let configmap_api: Api<ConfigMap> = Api::namespaced(self.client.clone(), &ns);

        let poller = Poller::new()
            .with_timeout(Duration::from_secs(60))
            .with_interval(Duration::from_secs(5))
            .with_error_message(format!(
                "image-pcrs ConfigMap in the namespace {ns} not found"
            ));

        let test_name_owned = self.test_name.clone();
        poller
            .poll_async(move || {
                let api = configmap_api.clone();
                let tn = test_name_owned.clone();
                async move {
                    let result = api.get("image-pcrs").await;
                    if result.is_ok() {
                        test_info!(&tn, "image-pcrs ConfigMap created");
                    }
                    result
                }
            })
            .await?;

        Ok(())
    }

    pub async fn verify_expected_pcrs(&self, expected_pcrs: &[&[Pcr]]) -> anyhow::Result<()> {
        let client = self.client();
        let namespace = self.namespace();

        let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

        let poller = Poller::new()
            .with_timeout(Duration::from_secs(180))
            .with_interval(Duration::from_secs(5))
            .with_error_message("image-pcrs ConfigMap not populated with data".to_string());

        poller
            .poll_async(|| {
                let api = configmap_api.clone();
                async move {
                    let cm = api.get("image-pcrs").await?;

                    if let Some(data) = &cm.data
                        && let Some(image_pcrs_json) = data.get("image-pcrs.json")
                        && let Ok(image_pcrs) = serde_json::from_str::<ImagePcrs>(image_pcrs_json)
                        && image_pcrs.0.len() == expected_pcrs.len()
                    {
                        return Ok(());
                    }

                    Err(anyhow::anyhow!(
                        "image-pcrs ConfigMap not yet populated with image-pcrs.json data"
                    ))
                }
            })
            .await?;

        let image_pcrs_cm = configmap_api.get("image-pcrs").await?;
        assert_eq!(image_pcrs_cm.metadata.name.as_deref(), Some("image-pcrs"));

        let data = image_pcrs_cm
            .data
            .as_ref()
            .expect("image-pcrs ConfigMap should have data field");

        assert!(!data.is_empty(), "image-pcrs ConfigMap should have data");

        let image_pcrs_json = data
            .get("image-pcrs.json")
            .expect("image-pcrs ConfigMap should have image-pcrs.json key");

        assert!(
            !image_pcrs_json.is_empty(),
            "image-pcrs.json should not be empty"
        );

        // Parse the image-pcrs.json using the ImagePcrs structure
        let image_pcrs: ImagePcrs = serde_json::from_str(image_pcrs_json)
            .expect("image-pcrs.json should be valid ImagePcrs JSON");

        assert!(
            !image_pcrs.0.is_empty(),
            "image-pcrs.json should contain at least one image entry"
        );

        test_info!(
            &self.test_name,
            "Checking into {} image results:",
            image_pcrs.0.len()
        );
        let mut found_expected_pcrs = false;

        assert_eq!(
            image_pcrs.0.len(),
            expected_pcrs.len(),
            "image-pcrs.json should contain {} image entries",
            expected_pcrs.len()
        );

        for (i, (_image_ref, image_data)) in image_pcrs.0.iter().enumerate() {
            if compare_pcrs(&image_data.pcrs, expected_pcrs[i]) {
                found_expected_pcrs = true;
                break;
            }
        }

        assert!(
            found_expected_pcrs,
            "At least one image should have the expected PCR values"
        );

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
    () => {{ $crate::TestContext::new(TEST_NAME, &[DEFAULT_TEST_FCOS_IMAGE]) }};

    ($images:expr) => {{ $crate::TestContext::new(TEST_NAME, &$images) }};
}

async fn setup_test_client() -> anyhow::Result<Client> {
    let client = Client::try_default().await?;
    Ok(client)
}

fn test_namespace_name() -> String {
    format!("test-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

pub async fn wait_for_resource_deleted<K>(
    api: &Api<K>,
    resource_name: &str,
    timeout_secs: u64,
    interval_secs: u64,
) -> anyhow::Result<()>
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
