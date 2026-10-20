// SPDX-FileCopyrightText: Chirag Rao <crao@redhat.com>
//
// SPDX-License-Identifier: MIT

use trusted_cluster_operator_test_utils::*;

cfg_if::cfg_if! {
if #[cfg(feature = "virtualization")] {

use anyhow::Context;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Pod, Secret, Service};
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::wait::await_condition;
use kube::{Api, Client};
use serde_json::json;
use tokio::time::timeout;
use trusted_cluster_operator_lib::conditions::*;
use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::images::*;
use trusted_cluster_operator_lib::{ApprovedImage, TrustedExecutionCluster};
use trusted_cluster_operator_test_utils::constants::*;
use trusted_cluster_operator_test_utils::virt::{self, VmBackend};

const TEC_NAME: &str = "trusted-execution-cluster";

// Image component names as they appear in registry paths; no existing constant covers these.
const REGISTRATION_SERVER_COMPONENT: &str = "registration-server";
const COMPUTE_PCRS_COMPONENT: &str = "compute-pcrs";

// Helper functions to get the source and target operator and Trustee versions.
fn source_operator_version() -> anyhow::Result<String> {
    Ok(std::env::var("UPGRADE_OLD_TAG")?)
}

fn source_trustee_version() -> anyhow::Result<String> {
    Ok(std::env::var("UPGRADE_OLD_TRUSTEE_TAG")?)
}

fn target_operator_version() -> String {
    std::env::var("TAG").unwrap_or_else(|_| "latest".into())
}

/// The whole image ref, under the source registry/tag, for the operator or a related image.
fn source_image(component: &str) -> anyhow::Result<String> {
    let registry = std::env::var("UPGRADE_OLD_REGISTRY")?;
    Ok(format!("{registry}/{component}:{}", source_operator_version()?))
}

fn source_trustee_image() -> anyhow::Result<String> {
    let registry = std::env::var("UPGRADE_OLD_REGISTRY")?;
    Ok(format!("{registry}/key-broker-service:{}", source_trustee_version()?))
}

fn target_trustee_image() -> String {
    std::env::var("TRUSTEE_IMAGE")
        .unwrap_or_else(|_| "quay.io/trusted-execution-clusters/key-broker-service:v0.20.0".into())
}

/// Patches the operator Deployment image and RELATED_IMAGE_* env vars in
/// a single strategic merge patch and waits for the rollout.
async fn patch_operator_with_images(
    client: &Client,
    namespace: &str,
    operator_image: &str,
    trustee_image: &str,
    reg_srv_image: &str,
    ak_reg_image: &str,
    compute_pcrs_image: &str,
) -> anyhow::Result<()> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let patch = json!({
        "spec": {
            "template": {
                "spec": {
                    "containers": [{
                        "name": OPERATOR_DEPLOYMENT,
                        "image": operator_image,
                        "env": [
                            {"name": RELATED_IMAGE_TRUSTEE, "value": trustee_image},
                            {"name": RELATED_IMAGE_REGISTRATION_SERVER, "value": reg_srv_image},
                            {"name": RELATED_IMAGE_ATTESTATION_KEY_REGISTER, "value": ak_reg_image},
                            {"name": RELATED_IMAGE_COMPUTE_PCRS, "value": compute_pcrs_image},
                        ]
                    }]
                }
            }
        }
    });
    deployments
        .patch(OPERATOR_DEPLOYMENT, &PatchParams::apply("upgrade-test"), &Patch::Strategic(patch))
        .await?;
    wait_for_deployment_rollout(client, namespace, OPERATOR_DEPLOYMENT, scaled_duration(180))
        .await
        .context("waiting for operator rollout after image patch")?;
    Ok(())
}

}
}

// Real version upgrade end-to-end, single VM boot, three phases:
//   Phase 1: install the source operator + Trustee versions; verify a VM attests.
//   Phase 2: upgrade to the target operator + Trustee versions; verify Trustee is rebuilt from scratch (secret, config, service), ApprovedImage.status.pcrs/events are populated, and the VM re-attests against the target Trustee.
//   Phase 3: a subsequent bad Trustee upgrade must fail (Upgrade=Failed) without disrupting the surviving target Trustee; the VM still attests.
virt_test! {
async fn test_real_version_upgrade() -> anyhow::Result<()> {
    // Phase 1: Deploy with source operator binary and source component images, wait for the install and approved image to be committed.
    let source_operator = source_image(OPERATOR_DEPLOYMENT)?;
    let source_trustee = source_trustee_image()?;
    let source_reg_srv = source_image(REGISTRATION_SERVER_COMPONENT)?;
    let source_ak_reg = source_image(ATTESTATION_KEY_REGISTER_DEPLOYMENT)?;
    let source_compute = source_image(COMPUTE_PCRS_COMPONENT)?;
    let image_overrides = [
        ("OPERATOR_IMAGE", source_operator.as_str()),
        ("TRUSTEE_IMAGE", source_trustee.as_str()),
        (RELATED_IMAGE_REGISTRATION_SERVER, source_reg_srv.as_str()),
        (RELATED_IMAGE_ATTESTATION_KEY_REGISTER, source_ak_reg.as_str()),
        (RELATED_IMAGE_COMPUTE_PCRS, source_compute.as_str()),
    ];
    let test_ctx = setup!(container_images: image_overrides).await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let services: Api<Service> = Api::namespaced(client.clone(), namespace);
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);

    test_ctx.info("Initial install with source operator complete");

    let done = await_condition(images.clone(), APPROVED_IMAGE_NAME, approved_image_has_committed_condition);
    timeout(scaled_duration(60), done)
        .await
        .context("waiting for ApprovedImage to be committed under source version")??;

    // Verify source version images are running.
    let source_trustee_version = source_trustee_version()?;
    let source_operator_version = source_operator_version()?;
    let pre_trustee = deployment_image(&deployments.get(TRUSTEE_DEPLOYMENT).await?).unwrap();
    assert!(pre_trustee.contains(&source_trustee_version), "Trustee should be {source_trustee_version}, got: {pre_trustee}");
    let pre_reg = deployment_image(&deployments.get(REGISTER_SERVER_DEPLOYMENT).await?).unwrap();
    assert!(pre_reg.contains(&source_operator_version), "register-server should be {source_operator_version}, got: {pre_reg}");
    test_ctx.info(format!("Pre-upgrade images: trustee={pre_trustee}, reg={pre_reg}"));

    // Boot a VM and verify attestation with source Trustee version.
    let vm_name = "test-real-upgrade-vm";
    let backend = virt::create_backend(client.clone(), namespace, vm_name).await?;
    backend.create_vm().await?;
    backend.wait_for_running(scaled_timeout(600)).await?;
    backend.wait_for_vm_ssh_ready(scaled_timeout(600), None).await?;

    let root_key = backend.get_root_key(client.clone(), namespace).await?;
    backend.verify_encrypted_root(&root_key).await
        .context("VM should attest with source Trustee")?;
    test_ctx.info("Pre-upgrade attestation verified with source Trustee");

    // Phase 2: Upgrade source -> target (source Trustee -> target Trustee).
    // Patch the operator with the target images, making sure approved images are invalidated, and status contains pcr values and events.
    let target_tag = target_operator_version();
    patch_operator_with_images(
        client,
        namespace,
        &default_image(OPERATOR_DEPLOYMENT),
        &target_trustee_image(),
        &default_image(REGISTRATION_SERVER_COMPONENT),
        &default_image(ATTESTATION_KEY_REGISTER_DEPLOYMENT),
        &default_image(COMPUTE_PCRS_COMPONENT),
    ).await?;
    test_ctx.info(format!("Operator upgraded from {source_operator_version} to {target_tag}"));

    let done = await_condition(
        tec_api.clone(),
        TEC_NAME,
        tec_has_condition_reason(UPGRADE_CONDITION, UPGRADE_COMPLETE),
    );
    timeout(scaled_duration(600), done)
        .await
        .context("waiting for Upgrade=Complete after real version upgrade")??;
    test_ctx.info("Upgrade completed");

    // Verify Trustee upgraded from source to target.
    let target_trustee_version = target_trustee_image()
        .rsplit(':')
        .next()
        .context("TRUSTEE_IMAGE should contain a ':<tag>' suffix")?
        .to_string();
    let post_trustee = deployment_image(&deployments.get(TRUSTEE_DEPLOYMENT).await?).unwrap();
    assert!(post_trustee.contains(&target_trustee_version), "Trustee should be {target_trustee_version}, got: {post_trustee}");
    test_ctx.info(format!("Trustee upgraded: {pre_trustee} -> {post_trustee}"));

    // Verify component images upgraded.
    let post_reg = deployment_image(&deployments.get(REGISTER_SERVER_DEPLOYMENT).await?).unwrap();
    assert!(post_reg.contains(&target_tag),
        "register-server should be {target_tag}, got: {post_reg}");
    let post_ak = deployment_image(&deployments.get(ATTESTATION_KEY_REGISTER_DEPLOYMENT).await?).unwrap();
    assert!(post_ak.contains(&target_tag),
        "ak-register should be {target_tag}, got: {post_ak}");
    test_ctx.info(format!("Post-upgrade images: reg={post_reg}, ak={post_ak}"));

    // ------------------- Trustee rebuilt from scratch: verify all infrastructure -------------------
    // Includes attestation policies, reference values, LUKS keys, and attestation keys, trustee secrets and configmaps and kbs-config.toml.

    // Auth key pair (used by operator to authenticate with KBS API).
    let trustee_secret = secrets.get("trustee-auth").await
        .context("trustee-auth secret should exist after upgrade")?;
    let auth_data = trustee_secret.data.as_ref()
        .expect("trustee-auth secret should have data");
    assert!(auth_data.contains_key("public.pub"),
        "trustee-auth should contain public.pub");
    assert!(auth_data.contains_key("private.key"),
        "trustee-auth should contain private.key");
    test_ctx.info("trustee-auth secret present with public.pub and private.key");

    // KBS configuration.
    let trustee_data_cm = configmaps.get("trustee-data").await
        .context("trustee-data ConfigMap should exist after upgrade")?;
    let cm_data = trustee_data_cm.data.as_ref()
        .expect("trustee-data ConfigMap should have data");
    let kbs_config = cm_data.get("kbs-config.toml")
        .expect("trustee-data should contain kbs-config.toml");
    assert!(!kbs_config.is_empty(), "kbs-config.toml should not be empty");
    test_ctx.info("trustee-data ConfigMap with kbs-config.toml present");

    // KBS service.
    services.get(TRUSTEE_SERVICE).await
        .context("kbs-service should exist after upgrade")?;
    test_ctx.info("kbs-service Service present");

    // Trustee deployment available.
    let trustee_depl = deployments.get(TRUSTEE_DEPLOYMENT).await?;
    assert!(
        deployment_rollout_complete(&trustee_depl),
        "Trustee deployment should be fully rolled out after upgrade"
    );
    test_ctx.info("Trustee deployment Available");

    // ApprovedImage PCRs and events

    wait_for_committed_with_pcrs(&images, APPROVED_IMAGE_NAME, 300).await?;
    let post_image = images.get(APPROVED_IMAGE_NAME).await?;
    let post_pcr_vals = extract_pcr_vals(&post_image);
    assert!(!post_pcr_vals.is_empty(),
        "New operator should populate ApprovedImage.status.pcrs");
    let post_events = extract_events(&post_image);
    assert!(!post_events.is_empty(),
        "New operator should populate ApprovedImage events");
    test_ctx.info("ApprovedImage has status.pcrs and events");

    // Operator version

    let tec = tec_api.get(TEC_NAME).await?;
    let new_version = tec.status.as_ref()
        .and_then(|s| s.observed_operator_version.as_deref());
    assert!(new_version.is_some(), "observedOperatorVersion should be set after upgrade");
    test_ctx.info(format!("observedOperatorVersion: {new_version:?}"));

    // ------------------------------ Post-upgrade attestation ----------------------------------
    // Rebooting the VM forces a fresh attestation cycle against the new
    // Trustee. Success proves that resource policy (resource.rego),
    // attestation policy (tpm.rego), reference values, LUKS keys, and
    // attestation keys were all correctly synced to the KBS API.
    let boot_id = backend.get_boot_id().await?;
    let _reboot = backend.ssh_exec("sudo systemctl reboot").await;
    test_ctx.info("Rebooting VM post-upgrade");

    // verifies attestation policies, reference values, LUKS keys, and attestation keys were all correctly synced to the KBS API.
    backend.wait_for_vm_ssh_ready(scaled_timeout(300), Some(&boot_id)).await?;

    backend.verify_encrypted_root(&root_key).await
        .context("VM should attest against target Trustee after upgrade")?;
    test_ctx.info("Post-upgrade attestation verified");

    // ------------------------------ Phase 3: Bad Trustee upgrade (should result in Upgrade=Failed) ----------------------------------
    // Phase 3: A subsequent bad Trustee upgrade must fail without disrupting the now-target Trustee. Reuses the already-booted VM: no second boot.

    // Shorten the operator's deployment-ready timeout so the expected failure is detected in ~60s instead of the default.
    test_ctx
        .set_operator_related_image(&deployments, "DEPLOYMENT_READY_TIMEOUT_SECS", "60")
        .await?;

    let bad_image = "quay.io/nonexistent/bad-image:v999.999.999";
    test_ctx
        .set_operator_related_image(&deployments, RELATED_IMAGE_TRUSTEE, bad_image)
        .await?;
    trigger_upgrade(&tec_api, TEC_NAME).await?;
    test_ctx.info(format!("Triggered failing upgrade with bad Trustee image {bad_image}"));

    let done = await_condition(
        tec_api.clone(),
        TEC_NAME,
        tec_has_condition_reason(UPGRADE_CONDITION, UPGRADE_FAILED),
    );
    let tec = timeout(scaled_duration(120), done)
        .await
        .context("waiting for Upgrade=Failed after bad Trustee upgrade")??
        .expect("TEC should exist after upgrade failure");

    let upgrade_cond = tec.status.as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == UPGRADE_CONDITION))
        .expect("Upgrade condition should exist after failed upgrade");
    assert_eq!(upgrade_cond.reason, UPGRADE_FAILED);
    assert_eq!(upgrade_cond.status, "False");
    assert!(upgrade_cond.message.contains("Manual intervention required"),
        "got: {}", upgrade_cond.message);
    test_ctx.info(format!("Upgrade=Failed detected: {}", upgrade_cond.message));

    // The Trustee pods must survive the failed upgrade.
    let lp = ListParams::default().labels(&format!("app={TRUSTEE_APP_LABEL}"));
    let surviving = pods_api
        .list(&lp)
        .await?
        .items
        .iter()
        .filter(|p| {
            p.status.as_ref()
                .and_then(|s| s.phase.as_deref())
                .is_some_and(|phase| phase == "Running")
        })
        .any(|_| true);
    assert!(surviving, "Trustee pods should survive the failed upgrade");
    test_ctx.info("Trustee pods survived failed upgrade");

    // Reboot the VM: it must still attest against the surviving target Trustee.
    let boot_id = backend.get_boot_id().await?;
    let _reboot = backend.ssh_exec("sudo systemctl reboot").await;
    backend.wait_for_vm_ssh_ready(scaled_timeout(300), Some(&boot_id)).await?;
    backend.verify_encrypted_root(&root_key).await
        .context("VM should attest against surviving Trustee after failed upgrade")?;
    test_ctx.info("Post-failure attestation verified against surviving Trustee");

    backend.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}
