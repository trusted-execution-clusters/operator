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
use kube::Api;
use serde_json::json;
use tokio::time::timeout;
use trusted_cluster_operator_lib::conditions::*;
use trusted_cluster_operator_lib::endpoints::*;
use trusted_cluster_operator_lib::images::*;
use trusted_cluster_operator_lib::{ApprovedImage, TrustedExecutionCluster};
use trusted_cluster_operator_test_utils::constants::*;
use trusted_cluster_operator_test_utils::virt::{self, VmBackend};

const TEC_NAME: &str = "trusted-execution-cluster";

// Helper functions  to get old and current image tags, to define the to and fro upgrade tags.
fn old_image(component: &str) -> String {
    let registry = std::env::var("UPGRADE_OLD_REGISTRY")
        .unwrap_or_else(|_| "quay.io/trusted-execution-clusters".into());
    let tag = std::env::var("UPGRADE_OLD_TAG").unwrap_or_else(|_| "v0.2.2".into());
    format!("{registry}/{component}:{tag}")
}

fn old_trustee_image() -> String {
    let registry = std::env::var("UPGRADE_OLD_REGISTRY")
        .unwrap_or_else(|_| "quay.io/trusted-execution-clusters".into());
    let tag = std::env::var("UPGRADE_OLD_TRUSTEE_TAG").unwrap_or_else(|_| "v0.17.0".into());
    format!("{registry}/key-broker-service:{tag}")
}

fn current_image(component: &str) -> String {
    let registry = std::env::var("REGISTRY").unwrap_or_else(|_| "localhost:5000".into());
    let tag = std::env::var("TAG").unwrap_or_else(|_| "latest".into());
    format!("{registry}/{component}:{tag}")
}

fn current_tag() -> String {
    std::env::var("TAG").unwrap_or_else(|_| "latest".into())
}

fn current_trustee_image() -> String {
    std::env::var("TRUSTEE_IMAGE")
        .unwrap_or_else(|_| "quay.io/trusted-execution-clusters/key-broker-service:v0.20.0".into())
}

/// Patches the operator Deployment image and RELATED_IMAGE_* env vars in
/// a single strategic merge patch and waits for the rollout.
async fn patch_operator_with_images(
    deployments: &Api<Deployment>,
    operator_image: &str,
    trustee_image: &str,
    reg_srv_image: &str,
    ak_reg_image: &str,
    compute_pcrs_image: &str,
) -> anyhow::Result<()> {
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
    let done = await_condition(
        deployments.clone(),
        OPERATOR_DEPLOYMENT,
        |d: Option<&Deployment>| d.is_some_and(deployment_rollout_complete),
    );
    timeout(scaled_duration(180), done)
        .await
        .context("waiting for operator rollout after image patch")??;
    Ok(())
}

}
}

// TODO: CAN BE COMMENTED OUT UNTIL CI CAN RUN MORE TESTS EFFICIENTLY.
// Test 1: Upgrade failure -- VM still attests against surviving Trustee.
// Injects a bad Trustee image via the operator's env var, triggers upgrade,
// verifies the Upgrade=Failed condition, then confirms the VM can reboot and still attest against the old Trustee pod.
virt_test! {
async fn test_upgrade_failure_vm_still_attests() -> anyhow::Result<()> {
    let cur_operator = current_image("trusted-cluster-operator");
    let cur_trustee = current_trustee_image();
    let cur_reg_srv = current_image("registration-server");
    let cur_ak_reg = current_image("attestation-key-register");
    let cur_compute = current_image("compute-pcrs");
    let image_overrides = [
        ("OPERATOR_IMAGE", cur_operator.as_str()),
        ("TRUSTEE_IMAGE", cur_trustee.as_str()),
        (RELATED_IMAGE_REGISTRATION_SERVER, cur_reg_srv.as_str()),
        (RELATED_IMAGE_ATTESTATION_KEY_REGISTER, cur_ak_reg.as_str()),
        (RELATED_IMAGE_COMPUTE_PCRS, cur_compute.as_str()),
    ];
    let test_ctx = setup!(container_images: image_overrides).await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);

    // Wait for the install of operator and components, and the approved image to be committed.
    wait_for_install(&tec_api, TEC_NAME).await?;
    wait_for_committed_with_pcrs(&images, APPROVED_IMAGE_NAME, 300).await?;
    test_ctx.info("Installed and ApprovedImage committed");

    // Get the good image from the trustee deployment.
    let good_image = deployment_image(&deployments.get(TRUSTEE_DEPLOYMENT).await?)
        .expect("Trustee should have an image");

    // Boot a VM and verify initial attestation, pre upgrade.
    let vm_name = "test-upgrade-fail-vm";
    let backend = virt::create_backend(client.clone(), namespace, vm_name).await?;
    backend.create_vm().await?;
    backend.wait_for_running(scaled_timeout(600)).await?;
    backend.wait_for_vm_ssh_ready(scaled_timeout(600), None).await?;
    let root_key = backend.get_root_key(client.clone(), namespace).await?;
    assert!(backend.verify_encrypted_root(root_key.as_deref()).await?, "VM should attest before failure");
    test_ctx.info("VM attested pre-failure");

    // Shorten the operator's deployment-ready timeout so the expected failure is
    // detected in ~60s instead of the default 300s.
    test_ctx
        .set_operator_related_image(&deployments, "DEPLOYMENT_READY_TIMEOUT_SECS", "60")
        .await?;

    // Patch the operator's desired image to a bad image, then trigger upgrade.
    let bad_image = "quay.io/nonexistent/bad-image:v999.999.999";
    test_ctx
        .set_operator_related_image(&deployments, RELATED_IMAGE_TRUSTEE, bad_image)
        .await?;
    test_ctx.info(format!("Operator RELATED_IMAGE_TRUSTEE set to {bad_image}"));

    trigger_upgrade(&tec_api, TEC_NAME).await?;
    test_ctx.info("Triggered upgrade (expecting failure)");

    // Wait for the upgrade to fail.
    let done = await_condition(
        tec_api.clone(),
        TEC_NAME,
        tec_has_condition_reason(UPGRADE_CONDITION, UPGRADE_FAILED),
    );
    let tec = timeout(scaled_duration(120), done)
        .await
        .context("waiting for Upgrade=Failed")??
        .expect("TEC should exist after upgrade failure");
    test_ctx.info("Upgrade=Failed detected");

    // Verify failure condition.
    let conditions = tec.status.as_ref()
        .and_then(|s| s.conditions.as_ref())
        .expect("TEC should have conditions after failed upgrade");

    let upgrade_cond = conditions.iter().find(|c| c.type_ == UPGRADE_CONDITION).unwrap();
    assert_eq!(upgrade_cond.reason, UPGRADE_FAILED);
    assert_eq!(upgrade_cond.status, "False");
    assert!(upgrade_cond.message.contains("Manual intervention required"),
        "got: {}", upgrade_cond.message);
    test_ctx.info(format!("Failure: {}", upgrade_cond.message));

    // Ensure the observed operator version is cleared.
    let post_version = tec.status.as_ref()
        .and_then(|s| s.observed_operator_version.as_deref());
    assert!(post_version.is_none(),
        "observedOperatorVersion should remain cleared on failed upgrade, got: {post_version:?}");

    assert!(conditions.iter().any(|c| c.type_ == INSTALLED_CONDITION),
        "Installed condition should persist after failed upgrade");

    // Verify old Trustee pods survived.
    let lp = ListParams::default().labels(&format!("app={TRUSTEE_APP_LABEL}"));
    let running: Vec<_> = pods_api
        .list(&lp)
        .await?
        .items
        .iter()
        .filter(|p| {
            p.status.as_ref()
                .and_then(|s| s.phase.as_deref())
                .is_some_and(|phase| phase == "Running")
        })
        .filter_map(|p| p.metadata.name.clone())
        .collect();
    assert!(!running.is_empty(), "Old Trustee pods should survive failed upgrade");
    test_ctx.info(format!("Old Trustee pods running: {running:?}"));

    // Reboot VM -- old Trustee should still serve attestation.
    let boot_id = backend.get_boot_id().await?;
    let _reboot = backend.ssh_exec("sudo systemctl reboot").await;
    backend.wait_for_vm_ssh_ready(scaled_timeout(300), Some(&boot_id)).await?;

    assert!(backend.verify_encrypted_root(root_key.as_deref()).await?,
        "VM should attest against old Trustee after failed upgrade");
    test_ctx.info("Post-failure attestation verified");

    // Recovery: restore good image.
    test_ctx
        .set_operator_related_image(&deployments, RELATED_IMAGE_TRUSTEE, &good_image)
        .await?;
    let good_patch = json!({
        "spec": {"template": {"spec": {"containers": [{"name": "kbs", "image": good_image}]}}}
    });
    deployments
        .patch(TRUSTEE_DEPLOYMENT, &PatchParams::apply("test-upgrade-failure"), &Patch::Strategic(good_patch))
        .await?;
    test_ctx
        .wait_for_deployment_ready(&deployments, TRUSTEE_DEPLOYMENT, scaled_timeout(120))
        .await?;
    test_ctx.info("Trustee recovered");

    backend.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}

// Test 2: Real version upgrade (operator v0.2.2 -> v0.2.3, Trustee v0.17.0 -> v0.20.0).
// v0.2.2 stored PCRs in a ConfigMap; current operator stores them in ApprovedImage status.
// Verifies the ConfigMap approach works pre-upgrade, then after upgrade verifies that Trustee is rebuilt from scratch (secret, config present), ApprovedImage.status.pcrs is populated, and the VM can still attest against the new Trustee after upgrade.
virt_test! {
async fn test_real_version_upgrade() -> anyhow::Result<()> {
    // Phase 1: Deploy with old operator binary and old component images, wait for the install and approved image to be committed.
    // Verify image-pcrs config map is populated by the old operator.
    let old_operator = old_image("trusted-cluster-operator");
    let old_trustee = old_trustee_image();
    let old_reg_srv = old_image("registration-server");
    let old_ak_reg = old_image("attestation-key-register");
    let old_compute = old_image("compute-pcrs");
    let image_overrides = [
        ("OPERATOR_IMAGE", old_operator.as_str()),
        ("TRUSTEE_IMAGE", old_trustee.as_str()),
        (RELATED_IMAGE_REGISTRATION_SERVER, old_reg_srv.as_str()),
        (RELATED_IMAGE_ATTESTATION_KEY_REGISTER, old_ak_reg.as_str()),
        (RELATED_IMAGE_COMPUTE_PCRS, old_compute.as_str()),
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

    wait_for_install(&tec_api, TEC_NAME).await?;
    test_ctx.info("Initial install with v0.2.2 operator complete");

    // v0.2.2 stores PCRs in a ConfigMap, not in ApprovedImage.status.pcrs.
    let cm_exists = await_condition(configmaps.clone(), "image-pcrs", |cm: Option<&ConfigMap>| {
        cm.and_then(|c| c.data.as_ref())
            .and_then(|d| d.get("image-pcrs.json"))
            .is_some_and(|v| !v.is_empty())
    });
    timeout(scaled_duration(300), cm_exists)
        .await
        .context("waiting for image-pcrs ConfigMap to be populated by v0.2.2 operator")??;
    test_ctx.info("image-pcrs ConfigMap present with PCR data (v0.2.2 approach)");

    let done = await_condition(images.clone(), APPROVED_IMAGE_NAME, approved_image_is_committed);
    timeout(scaled_duration(60), done)
        .await
        .context("waiting for ApprovedImage to be committed under v0.2.2")??;
    let pre_image = images.get(APPROVED_IMAGE_NAME).await?;
    let pre_has_status_pcrs = pre_image.status.as_ref()
        .and_then(|s| s.pcrs.as_ref())
        .is_some_and(|p| !p.is_empty());
    assert!(!pre_has_status_pcrs,
        "v0.2.2 should NOT populate ApprovedImage.status.pcrs");
    test_ctx.info("ApprovedImage committed without status.pcrs (expected for v0.2.2)");

    // Verify v0.2.2 images are running.
    let pre_trustee = deployment_image(&deployments.get(TRUSTEE_DEPLOYMENT).await?).unwrap();
    assert!(pre_trustee.contains("v0.17.0"), "Trustee should be v0.17.0, got: {pre_trustee}");
    let pre_reg = deployment_image(&deployments.get(REGISTER_SERVER_DEPLOYMENT).await?).unwrap();
    assert!(pre_reg.contains("v0.2.2"), "register-server should be v0.2.2, got: {pre_reg}");
    test_ctx.info(format!("Pre-upgrade images: trustee={pre_trustee}, reg={pre_reg}"));

    // Boot a VM and verify attestation with Trustee v0.17.0.
    let vm_name = "test-real-upgrade-vm";
    let backend = virt::create_backend(client.clone(), namespace, vm_name).await?;
    backend.create_vm().await?;
    backend.wait_for_running(scaled_timeout(600)).await?;
    backend.wait_for_vm_ssh_ready(scaled_timeout(600), None).await?;

    let root_key = backend.get_root_key(client.clone(), namespace).await?;
    assert!(backend.verify_encrypted_root(root_key.as_deref()).await?,
        "VM should attest with Trustee v0.17.0");
    test_ctx.info("Pre-upgrade attestation verified (Trustee v0.17.0)");

    // Phase 2: Upgrade v0.2.2 -> current (Trustee v0.17.0 -> v0.20.0).
    // Patch the operator with the current images, making sure approved images are invalidated, and status contains pcr values and events.
    let cur_operator = current_image("trusted-cluster-operator");
    let cur_trustee = current_trustee_image();
    let cur_reg_srv = current_image("registration-server");
    let cur_ak_reg = current_image("attestation-key-register");
    let cur_compute = current_image("compute-pcrs");
    let cur_tag = current_tag();
    patch_operator_with_images(
        &deployments,
        &cur_operator,
        &cur_trustee,
        &cur_reg_srv,
        &cur_ak_reg,
        &cur_compute,
    ).await?;
    test_ctx.info("Operator upgraded from v0.2.2 to current");

    let done = await_condition(
        tec_api.clone(),
        TEC_NAME,
        tec_has_condition_reason(UPGRADE_CONDITION, UPGRADE_COMPLETE),
    );
    timeout(scaled_duration(600), done)
        .await
        .context("waiting for Upgrade=Complete after real version upgrade")??;
    test_ctx.info("Upgrade completed");

    // Verify Trustee upgraded from v0.17.0 to v0.20.0.
    let post_trustee = deployment_image(&deployments.get(TRUSTEE_DEPLOYMENT).await?).unwrap();
    assert!(post_trustee.contains("v0.20.0"), "Trustee should be v0.20.0, got: {post_trustee}");
    test_ctx.info(format!("Trustee upgraded: {pre_trustee} -> {post_trustee}"));

    // Verify component images upgraded.
    let post_reg = deployment_image(&deployments.get(REGISTER_SERVER_DEPLOYMENT).await?).unwrap();
    assert!(post_reg.contains(&cur_tag),
        "register-server should be {cur_tag}, got: {post_reg}");
    let post_ak = deployment_image(&deployments.get(ATTESTATION_KEY_REGISTER_DEPLOYMENT).await?).unwrap();
    assert!(post_ak.contains(&cur_tag),
        "ak-register should be {cur_tag}, got: {post_ak}");
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
    let trustee_available = trustee_depl.status.as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|cs| cs.iter().any(|c| c.type_ == "Available" && c.status == "True"));
    assert!(trustee_available, "Trustee deployment should be Available after upgrade");
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

    // --- Post-upgrade attestation ---
    // Rebooting the VM forces a fresh attestation cycle against the new
    // Trustee v0.20.0. Success proves that resource policy (resource.rego),
    // attestation policy (tpm.rego), reference values, LUKS keys, and
    // attestation keys were all correctly synced to the KBS API.
    let boot_id = backend.get_boot_id().await?;
    let _reboot = backend.ssh_exec("sudo systemctl reboot").await;
    test_ctx.info("Rebooting VM post-upgrade");

    // verifies attestation policies, reference values, LUKS keys, and attestation keys were all correctly synced to the KBS API.
    backend.wait_for_vm_ssh_ready(scaled_timeout(300), Some(&boot_id)).await?;

    assert!(backend.verify_encrypted_root(root_key.as_deref()).await?,
        "VM should attest against Trustee v0.20.0 after upgrade");
    test_ctx.info("Post-upgrade attestation verified (Trustee v0.20.0)");

    backend.cleanup().await?;
    test_ctx.cleanup().await?;
    Ok(())
}
}
