// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Context;

use chrono::Utc;
use compute_pcrs_lib::Pcr;
use compute_pcrs_lib::tpmevents::{TPMEvent, TPMEventID};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Pod, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, ObjectMeta, OwnerReference};
use kube::api::{ListParams, LogParams, Patch, PatchParams};
use kube::runtime::wait::await_condition;
use kube::{Api, api::DeleteParams};
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;
use trusted_cluster_operator_lib::conditions::{
    NOT_COMMITTED_REASON_COMPUTING, NOT_COMMITTED_REASON_PENDING, UPGRADE_COMPLETE,
    UPGRADE_CONDITION,
};
use trusted_cluster_operator_lib::endpoints::{REGISTER_SERVER_DEPLOYMENT, TRUSTEE_DEPLOYMENT};
use trusted_cluster_operator_lib::images::RELATED_IMAGE_TRUSTEE;
use trusted_cluster_operator_lib::{
    ApprovedImage, AttestationKey, Machine, TrustedExecutionCluster, generate_owner_reference,
};
use trusted_cluster_operator_test_utils::constants::*;
use trusted_cluster_operator_test_utils::*;
// const EXPECTED_PCR4: &str = "ff2b357be4a4bc66be796d4e7b2f1f27077dc89b96220aae60b443bcf4672525";
const TEC_NAME: &str = "trusted-execution-cluster";
const APPROVED_IMAGE_NAME: &str = "coreos-approved-primary";

fn ak_approved(ak: Option<&AttestationKey>) -> bool {
    let is_approved = |c: &Condition| c.type_ == "Approved" && c.status == "True";
    let cs = ak.and_then(|ak| ak.status.as_ref().and_then(|s| s.conditions.as_ref()));
    cs.map(|cs| cs.iter().any(is_approved)).unwrap_or(false)
}

named_test!(
    async fn test_trusted_execution_cluster_uninstall() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        let client = test_ctx.client();
        let namespace = test_ctx.namespace();

        let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
        let tec = tec_api.get(TEC_NAME).await?;

        let owner_reference = generate_owner_reference(&tec)?;

        // Create a test Machine with TEC as owner reference. We need to set the owner reference
        // manually since the machine is not created directly by the operator.
        let machine_uuid = uuid::Uuid::new_v4().to_string();
        let machine_name = format!("test-machine-{}", &machine_uuid[..8]);

        let machines: Api<Machine> = Api::namespaced(client.clone(), namespace);
        let machine = Machine {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(machine_name.clone()),
                namespace: Some(namespace.to_string()),
                owner_references: Some(vec![owner_reference.clone()]),
                ..Default::default()
            },
            spec: trusted_cluster_operator_lib::MachineSpec {
                id: machine_uuid.clone(),
            },
            status: None,
        };

        machines.create(&Default::default(), &machine).await?;
        test_ctx.info(format!("Created test Machine: {machine_name}"));

        // Create an AttestationKey with the same uuid as the Machine
        let ak_name = format!("test-ak-{}", &machine_uuid[..8]);
        let public_key = "test-public-key-data";

        let attestation_keys: Api<AttestationKey> = Api::namespaced(client.clone(), namespace);
        let attestation_key = AttestationKey {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(ak_name.clone()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: trusted_cluster_operator_lib::AttestationKeySpec {
                public_key: public_key.to_string(),
                uuid: Some(machine_uuid.clone()),
            },
            status: None,
        };

        attestation_keys
            .create(&Default::default(), &attestation_key)
            .await?;
        test_ctx.info(format!(
            "Created test AttestationKey: {ak_name} with uuid: {machine_uuid}",
        ));

        // Wait for the AttestationKey to be approved (operator should match Machine IP and approve it)
        let done = await_condition(attestation_keys.clone(), &ak_name, ak_approved);
        let ctx = format!("waiting for AttestationKey {ak_name} to be approved");
        timeout(scaled_duration(30), done).await.context(ctx)??;

        test_ctx.info("AttestationKey successfully approved");

        // Delete the cluster cr
        let api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
        let dp = DeleteParams::default();
        api.delete(TEC_NAME, &dp).await?;

        // Wait until it disappears
        wait_for_resource_deleted(&api, TEC_NAME, scaled_timeout(120)).await?;

        let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        let timeout = scaled_timeout(120);
        wait_for_resource_deleted(&deployments_api, TRUSTEE_DEPLOYMENT, timeout).await?;
        wait_for_resource_deleted(&deployments_api, REGISTER_SERVER_DEPLOYMENT, timeout).await?;

        let images_api: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
        wait_for_resource_deleted(&images_api, APPROVED_IMAGE_NAME, scaled_timeout(120)).await?;

        wait_for_resource_deleted(&machines, &machine_name, scaled_timeout(120)).await?;
        wait_for_resource_deleted(&attestation_keys, &ak_name, scaled_timeout(120)).await?;
        let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
        wait_for_resource_deleted(&secrets_api, &ak_name, scaled_timeout(120)).await?;

        test_ctx.cleanup().await?;

        Ok(())
    }
);

named_test! {
async fn test_image_pcrs_configmap_updates() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;

    test_ctx.verify_expected_pcrs(&[&primary_pcrs!()]).await?;
    test_ctx.cleanup().await?;

    Ok(())
}
}

named_test! {
async fn test_image_disallow() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
    images.delete(APPROVED_IMAGE_NAME, &DeleteParams::default()).await?;

    wait_for_resource_deleted(&images, APPROVED_IMAGE_NAME, scaled_timeout(180)).await?;

    test_ctx.cleanup().await?;
    Ok(())
}
}

named_test! {
async fn test_attestation_key_lifecycle() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let tec = tec_api.get(TEC_NAME).await?;
    let owner_reference = generate_owner_reference(&tec)?;

    let machine_uuid = uuid::Uuid::new_v4().to_string();

    let ak_name = format!("test-ak-{}", &machine_uuid[..8]);
    let random_public_key = uuid::Uuid::new_v4().to_string();

    let attestation_keys: Api<AttestationKey> = Api::namespaced(client.clone(), namespace);
    let attestation_key = AttestationKey {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(ak_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::AttestationKeySpec {
            public_key: random_public_key,
            uuid: Some(machine_uuid.clone()),
        },
        status: None,
    };

    attestation_keys
        .create(&Default::default(), &attestation_key)
        .await?;
    test_ctx.info(format!(
        "Created test AttestationKey: {ak_name} with uuid: {machine_uuid}",
    ));

    let machine_name = format!("test-machine-{}", &machine_uuid[..8]);
    let machines: Api<Machine> = Api::namespaced(client.clone(), namespace);
    let machine = Machine {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(machine_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::MachineSpec {
            id: machine_uuid.clone(),
        },
        status: None,
    };

    machines.create(&Default::default(), &machine).await?;
    test_ctx.info(format!(
        "Created test Machine: {machine_name} with uuid: {machine_uuid}",
    ));

    // Timeout for the AttestationKey to be approved, have owner reference, and have a Secret created
    let approved = await_condition(attestation_keys.clone(), &ak_name, ak_approved);
    let ctx = format!("waiting for AttestationKey {ak_name} to be approved");
    timeout(scaled_duration(30), approved).await.context(ctx)??;
    let chk_machine_owner = |ak: Option<&AttestationKey>| {
        let chk_owner = |owner: &OwnerReference| owner.kind == "Machine" && owner.name == machine_name;
        let refs = ak.and_then(|ak| ak.metadata.owner_references.as_ref());
        refs.map(|refs| refs.iter().any(chk_owner)).unwrap_or(false)
    };
    let has_machine_owner = await_condition(attestation_keys.clone(), &ak_name, chk_machine_owner);
    let ctx = format!("waiting for AttestationKey {ak_name} to be owned by Machine {machine_name}");
    timeout(scaled_duration(30), has_machine_owner).await.context(ctx)??;
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let chk_ak_owner = |secret: Option<&Secret>| {
        let chk_owner = |owner: &OwnerReference| owner.kind == "AttestationKey" && owner.name == ak_name;
        let refs = secret.and_then(|s| s.metadata.owner_references.as_ref());
        refs.map(|refs| refs.iter().any(chk_owner)).unwrap_or(false)
    };
    let has_ak_owner = await_condition(secrets_api.clone(), &ak_name, chk_ak_owner);
    let ctx = format!("waiting for Secret {ak_name} to be owned by AttestationKey {ak_name}");
    timeout(scaled_duration(30), has_ak_owner).await.context(ctx)??;

    test_ctx.info(format!(
        "AttestationKey successfully approved with owner reference to Machine: {machine_name} and Secret created"
    ));

    // Delete the Machine
    let dp = DeleteParams::default();
    machines.delete(&machine_name, &dp).await?;
    test_ctx.info(format!("Deleted Machine: {machine_name}"));

    wait_for_resource_deleted(&machines, &machine_name, scaled_timeout(120)).await?;
    test_ctx.info("Machine successfully deleted");
    wait_for_resource_deleted(&attestation_keys, &ak_name, scaled_timeout(120)).await?;
    test_ctx.info("AttestationKey successfully deleted");
    wait_for_resource_deleted(&secrets_api, &ak_name, scaled_timeout(120)).await?;
    test_ctx.info("Secret successfully deleted");

    test_ctx.cleanup().await?;

    Ok(())
}
}

named_test! {
async fn test_nonexistent_approved_image() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
    images.create(&Default::default(), &ApprovedImage {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("coreos1".to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::ApprovedImageSpec {
            image: "quay.io/trusted-execution-clusters/fedora-coreos@sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        },
        status: None,
    }).await?;

    let is_pending = |img: Option<&ApprovedImage>| {
        let pending = |c: &Condition| c.reason == NOT_COMMITTED_REASON_PENDING;
        let cs = img.and_then(|img| img.status.as_ref()).and_then(|s| s.conditions.as_ref());
        cs.map(|cs| cs.iter().any(pending)).unwrap_or(false)
    };
    let done = await_condition(images, "coreos1", is_pending);
    let ctx = "waiting for ApprovedImage coreos1 to be PodPending";
    timeout(scaled_duration(30), done).await.context(ctx)??;

     test_ctx.cleanup().await?;
    Ok(())
}
}

named_test! {
async fn test_luks_key_sync() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();
    let tec_name = "trusted-execution-cluster";

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let tec = tec_api.get(tec_name).await?;
    let owner_reference = generate_owner_reference(&tec)?;

    // Create two machines
    let machine1_uuid = uuid::Uuid::new_v4().to_string();
    let machine1_name = format!("test-machine-{}", &machine1_uuid[..8]);
    let machine2_uuid = uuid::Uuid::new_v4().to_string();
    let machine2_name = format!("test-machine-{}", &machine2_uuid[..8]);

    let machines: Api<Machine> = Api::namespaced(client.clone(), namespace);

    let machine1 = Machine {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(machine1_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::MachineSpec {
            id: machine1_uuid.clone(),
        },
        status: None,
    };
    machines.create(&Default::default(), &machine1).await?;
    test_ctx.info(format!("Created Machine 1: {machine1_name}"));

    let machine2 = Machine {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(machine2_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::MachineSpec {
            id: machine2_uuid.clone(),
        },
        status: None,
    };
    machines.create(&Default::default(), &machine2).await?;
    test_ctx.info(format!("Created Machine 2: {machine2_name}"));

    // Wait for both K8s secrets to be created by the keygen controller
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    wait_for_resource_created(&secrets_api, &machine1_uuid, scaled_timeout(60)).await?;
    wait_for_resource_created(&secrets_api, &machine2_uuid, scaled_timeout(60)).await?;
    test_ctx.info("Both machine secrets created");

    // Wait for the operator to send both secrets to the KBS
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let poller = Poller::new()
        .with_timeout(scaled_duration(60))
        .with_interval(scaled_duration(2))
        .with_error_message("Secrets not sent to KBS".to_string());

    poller
        .poll_async(|| {
            let api = pods_api.clone();
            let id1 = machine1_uuid.clone();
            let id2 = machine2_uuid.clone();
            async move {
                let lp = ListParams::default().labels("app=trusted-cluster-operator");
                let operator_pods = api.list(&lp).await?;
                let pod_name = operator_pods
                    .items
                    .first()
                    .and_then(|p| p.metadata.name.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("Operator pod not found"))?
                    .clone();
                let logs = api.logs(&pod_name, &LogParams::default()).await?;
                if logs.contains(&format!("{id1} sent successfully"))
                    && logs.contains(&format!("{id2} sent successfully"))
                {
                    return Ok(());
                }
                Err(anyhow::anyhow!("Not all secrets sent to KBS yet"))
            }
        })
        .await?;
    test_ctx.info("Both secrets sent to KBS");


    let now = Utc::now().to_rfc3339();
    let patch = json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now
                    }
                }
            }
        }
    });

    test_ctx.info(format!("Triggering rollout restart for deployment: {TRUSTEE_DEPLOYMENT}"));
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    // Apply the patch
    deployments
        .patch(
            TRUSTEE_DEPLOYMENT,
            &PatchParams::default(),
            &Patch::Strategic(patch),
        )
        .await?;

    test_ctx.wait_for_deployment_ready(&deployments, TRUSTEE_DEPLOYMENT, 120).await?;

    // Wait for the new pod to be ready
    test_ctx.info("Trustee deployment is ready after restart");

    // Verify both secrets are re-synced to KBS after the trustee restart
    let poller = Poller::new()
        .with_timeout(scaled_duration(60))
        .with_interval(scaled_duration(2))
        .with_error_message("Secrets not re-synced to KBS after restart".to_string());

    poller
        .poll_async(|| {
            let api = pods_api.clone();
            let id1 = machine1_uuid.clone();
            let id2 = machine2_uuid.clone();
            async move {
                let lp = ListParams::default().labels("app=trusted-cluster-operator");
                let operator_pods = api.list(&lp).await?;
                let pod_name = operator_pods
                    .items
                    .first()
                    .and_then(|p| p.metadata.name.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("Operator pod not found"))?
                    .clone();
                let logs = api.logs(&pod_name, &LogParams::default()).await?;
                if logs.contains("Syncing 2 machine luks key to KBS")
                    && logs.matches(&format!("{id1} sent successfully")).count() >= 2
                    && logs.matches(&format!("{id2} sent successfully")).count() >= 2
                {
                    return Ok(());
                }
                Err(anyhow::anyhow!("Secrets not yet re-synced to KBS after restart."))
            }
        })
        .await?;
    test_ctx.info("Both secrets re-synced to KBS after trustee restart");

    // Delete machine1 and verify its secret is removed from both K8s and KBS
    machines
        .delete(&machine1_name, &Default::default())
        .await?;
    test_ctx.info(format!("Deleted Machine 1: {machine1_name}"));

    let poller = Poller::new()
        .with_timeout(scaled_duration(60))
        .with_interval(scaled_duration(2))
        .with_error_message("Machine1 secret not deleted from KBS".to_string());

    poller
        .poll_async(|| {
            let api = pods_api.clone();
            let id1 = machine1_uuid.clone();
            async move {
                let lp = ListParams::default().labels("app=trusted-cluster-operator");
                let operator_pods = api.list(&lp).await?;
                let pod_name = operator_pods
                    .items
                    .first()
                    .and_then(|p| p.metadata.name.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("Operator pod not found"))?
                    .clone();
                let logs = api.logs(&pod_name, &LogParams::default()).await?;
                if logs.contains(&format!("Secret {id1} deleted successfully")) {
                    return Ok(());
                }
                Err(anyhow::anyhow!("Machine1 secret not yet deleted from KBS"))
            }
        })
        .await?;
    test_ctx.info("Machine1 secret deleted from KBS");

    // Verify the K8s Secret for machine1 is also deleted
    wait_for_resource_deleted(&secrets_api, &machine1_uuid, 60).await?;
    test_ctx.info("Machine1 K8s secret deleted");

    test_ctx.cleanup().await?;
    Ok(())
}
}

named_test! {
async fn test_attestation_key_sync() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();
    let tec_name = "trusted-execution-cluster";

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let tec = tec_api.get(tec_name).await?;
    let owner_reference = generate_owner_reference(&tec)?;

    // Create two machines
    let machine1_uuid = uuid::Uuid::new_v4().to_string();
    let machine1_name = format!("test-machine-{}", &machine1_uuid[..8]);
    let machine2_uuid = uuid::Uuid::new_v4().to_string();
    let machine2_name = format!("test-machine-{}", &machine2_uuid[..8]);

    let machines: Api<Machine> = Api::namespaced(client.clone(), namespace);
    let machine1 = Machine {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(machine1_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::MachineSpec {
            id: machine1_uuid.clone(),
        },
        status: None,
    };
    machines.create(&Default::default(), &machine1).await?;
    test_ctx.info(format!("Created Machine 1: {machine1_name}"));

    let machine2 = Machine {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(machine2_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::MachineSpec {
            id: machine2_uuid.clone(),
        },
        status: None,
    };
    machines.create(&Default::default(), &machine2).await?;
    test_ctx.info(format!("Created Machine 2: {machine2_name}"));

    // Create two AttestationKeys with matching UUIDs
    let ak1_name = format!("test-ak-{}", &machine1_uuid[..8]);
    let ak1_public_key = uuid::Uuid::new_v4().to_string();
    let ak2_name = format!("test-ak-{}", &machine2_uuid[..8]);
    let ak2_public_key = uuid::Uuid::new_v4().to_string();

    let attestation_keys: Api<AttestationKey> = Api::namespaced(client.clone(), namespace);

    let ak1 = AttestationKey {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(ak1_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::AttestationKeySpec {
            public_key: ak1_public_key,
            uuid: Some(machine1_uuid.clone()),
        },
        status: None,
    };
    attestation_keys.create(&Default::default(), &ak1).await?;
    test_ctx.info(format!("Created AttestationKey 1: {ak1_name}"));

    let ak2 = AttestationKey {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(ak2_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::AttestationKeySpec {
            public_key: ak2_public_key,
            uuid: Some(machine2_uuid.clone()),
        },
        status: None,
    };
    attestation_keys.create(&Default::default(), &ak2).await?;
    test_ctx.info(format!("Created AttestationKey 2: {ak2_name}"));

    // Wait for both AKs to be approved and have secrets created
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let ak1_done = await_condition(attestation_keys.clone(), &ak1_name, ak_approved);
    let ak2_done = await_condition(attestation_keys.clone(), &ak2_name, ak_approved);
    wait_for_resource_created(&secrets_api, &ak1_name, scaled_timeout(60)).await?;
    wait_for_resource_created(&secrets_api, &ak2_name, scaled_timeout(60)).await?;
    timeout(scaled_duration(60), async {
        tokio::try_join!(ak1_done, ak2_done)
    })
    .await
    .context("waiting for AttestationKeys to be approved with secrets")??;
    test_ctx.info("Both AttestationKeys approved and secrets created");

    // Wait for both AKs to be registered with KBS
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let poller = Poller::new()
        .with_timeout(scaled_duration(60))
        .with_interval(scaled_duration(2))
        .with_error_message("AKs not registered with KBS".to_string());

    poller
        .poll_async(|| {
            let api = pods_api.clone();
            async move {
                let lp = ListParams::default().labels("app=trusted-cluster-operator");
                let operator_pods = api.list(&lp).await?;
                let pod_name = operator_pods
                    .items
                    .first()
                    .and_then(|p| p.metadata.name.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("Operator pod not found"))?
                    .clone();
                let logs = api.logs(&pod_name, &LogParams::default()).await?;
                let count = logs.matches("AK registered successfully").count();
                if count >= 1 {
                    return Ok(());
                }
                Err(anyhow::anyhow!("Only {count} AK registrations found, need at least 1"))
            }
        })
        .await?;
    test_ctx.info("Both AKs registered with KBS");

    // Restart the trustee deployment
    let now = Utc::now().to_rfc3339();
    let patch = json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now
                    }
                }
            }
        }
    });

    test_ctx.info(format!("Triggering rollout restart for deployment: {TRUSTEE_DEPLOYMENT}"));
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    deployments
        .patch(
            TRUSTEE_DEPLOYMENT,
            &PatchParams::default(),
            &Patch::Strategic(patch),
        )
        .await?;

    test_ctx.wait_for_deployment_ready(&deployments, TRUSTEE_DEPLOYMENT, 120).await?;
    test_ctx.info("Trustee deployment is ready after restart");

    // Verify both AKs are re-registered to KBS after the trustee restart
    let poller = Poller::new()
        .with_timeout(scaled_duration(60))
        .with_interval(scaled_duration(2))
        .with_error_message("AKs not re-registered with KBS after restart".to_string());

    poller
        .poll_async(|| {
            let api = pods_api.clone();
            async move {
                let lp = ListParams::default().labels("app=trusted-cluster-operator");
                let operator_pods = api.list(&lp).await?;
                let pod_name = operator_pods
                    .items
                    .first()
                    .and_then(|p| p.metadata.name.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("Operator pod not found"))?
                    .clone();
                let logs = api.logs(&pod_name, &LogParams::default()).await?;
                let count = logs.matches("AK registered successfully").count();
                if count >= 2 {
                    return Ok(());
                }
                Err(anyhow::anyhow!("Only {count} AK registrations after restart, need at least 2"))
            }
        })
        .await?;
    test_ctx.info("Both AKs re-registered with KBS after trustee restart");

    test_ctx.cleanup().await?;
    Ok(())
}
}

named_test! {
async fn test_approved_image_readoption() -> anyhow::Result<()> {
    let test_ctx = setup!(delayed_approved_image).await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let clusters: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);

    let cluster_spec = clusters.get(TEC_NAME).await?.spec;
    let image_spec = images.get(APPROVED_IMAGE_NAME).await?.spec;

    let owned = |img: Option<&ApprovedImage>| {
        let refs = img.and_then(|img| img.metadata.owner_references.as_ref());
        refs.is_some_and(|refs| refs.iter().any(|o| o.kind == "TrustedExecutionCluster"))
    };
    let done = await_condition(images.clone(), APPROVED_IMAGE_NAME, owned);
    let ctx = "waiting for ApprovedImage to be owned by TrustedExecutionCluster";
    timeout(scaled_duration(30), done).await.context(ctx)??;

    test_ctx.info(format!("Deleting TrustedExecutionCluster {TEC_NAME}"));
    clusters.delete(TEC_NAME, &Default::default()).await?;
    wait_for_resource_deleted(&images, APPROVED_IMAGE_NAME, scaled_timeout(60)).await?;
    test_ctx.info("ApprovedImage was removed after TrustedExecutionCluster deletion");

    let image = ApprovedImage {
        spec: image_spec,
        metadata: ObjectMeta {
            name: Some(APPROVED_IMAGE_NAME.to_string()),
            ..Default::default()
        },
        status: None,
    };
    let cluster = TrustedExecutionCluster {
        spec: cluster_spec,
        metadata: ObjectMeta {
            name: Some(TEC_NAME.to_string()),
            ..Default::default()
        },
        status: None,
    };

    test_ctx.info("Creating new ApprovedImage and TrustedExecutionCluster");
    images.create(&Default::default(), &image).await?;
    // Ensure adoption works even when cluster creation was delayed
    tokio::time::sleep(Duration::from_secs(5)).await;
    clusters.create(&Default::default(), &cluster).await?;
    let committed = |img: Option<&ApprovedImage>| {
        img.and_then(|i| i.status.as_ref())
            .and_then(|s| s.conditions.as_ref())
            .is_some_and(|cs| {
                cs.iter()
                    .any(|c| c.type_ == "Committed" && c.status == "True")
            })
    };
    let done = await_condition(images, APPROVED_IMAGE_NAME, committed);
    let ctx = "waiting for ApprovedImage to be committed after recreation";
    timeout(scaled_duration(180), done).await.context(ctx)??;
    test_ctx.info("ApprovedImage committed after recreation");

    test_ctx.cleanup().await?;
    Ok(())
}
}

named_test! {
async fn test_combined_image_pcrs() -> anyhow::Result<()> {
    let test_ctx = setup!([(COMBINE_PCRS_UPDATE_TEST_IMAGE_NAME, COMBINE_PCRS_UPDATE_TEST_IMAGE_REF)]).await?;

    test_ctx.verify_expected_pcrs(&[&primary_pcrs!(), &secondary_pcrs!()]).await?;

    test_ctx.cleanup().await?;
    Ok(())
}
}

fn approved_image_was_invalidated(img: Option<&ApprovedImage>) -> bool {
    img.and_then(|i| i.status.as_ref())
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|cs| {
            cs.iter().any(|c| {
                c.type_ == "Committed"
                    && c.status == "False"
                    && c.reason == NOT_COMMITTED_REASON_COMPUTING
            })
        })
}

named_test! {
async fn test_upgrade_trigger_and_completion() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);

    // Wait for initial install to complete
    wait_for_install(&tec_api, TEC_NAME).await?;
    test_ctx.info("Initial install complete");

    // Record pre-upgrade state
    let tec = tec_api.get(TEC_NAME).await?;
    let pre_upgrade_version = tec
        .status
        .as_ref()
        .and_then(|s| s.observed_operator_version.clone())
        .expect("observedOperatorVersion should be set after install");
    test_ctx.info(format!("Pre-upgrade version: {pre_upgrade_version}"));

    // Record pre-upgrade state of the trustee and register-server deployments.
    let pre_trustee_image = deployment_image(&deployments.get(TRUSTEE_DEPLOYMENT).await?)
        .expect("Trustee should have image");
    let pre_reg_image = deployment_image(&deployments.get(REGISTER_SERVER_DEPLOYMENT).await?)
        .expect("register-server should have image");
    test_ctx.info(format!("Pre-upgrade Trustee image: {pre_trustee_image}"));
    test_ctx.info(format!("Pre-upgrade register-server image: {pre_reg_image}"));

    // Verify ApprovedImage is committed before upgrade
    let done = await_condition(images.clone(), APPROVED_IMAGE_NAME, approved_image_is_committed);
    timeout(scaled_duration(60), done)
        .await
        .context("waiting for ApprovedImage to be committed before upgrade")??;
    test_ctx.info("ApprovedImage is committed pre-upgrade");

    // Trigger upgrade by clearing observedOperatorVersion
    trigger_upgrade(&tec_api, TEC_NAME).await?;
    test_ctx.info("Triggered upgrade by clearing observedOperatorVersion");

    // Wait for upgrade to complete -- the operator should re-stamp the version
    let has_version_again = |tec: Option<&TrustedExecutionCluster>| {
        tec.and_then(|t| t.status.as_ref())
            .and_then(|s| s.observed_operator_version.as_ref())
            .is_some()
    };
    let done = await_condition(tec_api.clone(), TEC_NAME, has_version_again);
    timeout(scaled_duration(180), done)
        .await
        .context("waiting for observedOperatorVersion to be re-stamped after upgrade")??;
    test_ctx.info("observedOperatorVersion re-stamped");

    // Verify Upgrade=Complete condition exists
    let done = await_condition(tec_api.clone(), TEC_NAME, tec_has_condition_reason("Upgrade", "Complete"));
    timeout(scaled_duration(30), done)
        .await
        .context("waiting for Upgrade=Complete condition")??;
    test_ctx.info("Upgrade=Complete condition set");

    // Verify Trustee and register-server images are unchanged (same operator version, as we have manually 'triggered' the operator upgrade path).
    let post_trustee_image = deployment_image(&deployments.get(TRUSTEE_DEPLOYMENT).await?);
    let post_reg_image = deployment_image(&deployments.get(REGISTER_SERVER_DEPLOYMENT).await?);
    assert_eq!(
        Some(pre_trustee_image.as_str()),
        post_trustee_image.as_deref(),
        "Trustee image should remain unchanged when operator version hasn't changed"
    );
    assert_eq!(
        Some(pre_reg_image.as_str()),
        post_reg_image.as_deref(),
        "register-server image should remain unchanged"
    );

    // Verify ApprovedImage PCRs were invalidated and then recommitted
    wait_for_committed_with_pcrs(&images, APPROVED_IMAGE_NAME, 300).await?;
    test_ctx.info("ApprovedImage re-committed with PCRs after upgrade");

    test_ctx.cleanup().await?;
    Ok(())
}
}

named_test! {
async fn test_upgrade_no_downtime() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);

    // Wait for install
    wait_for_install(&tec_api, TEC_NAME).await?;

    // Verify all deployments have at least 1 available replica before upgrade
    for depl_name in [TRUSTEE_DEPLOYMENT, REGISTER_SERVER_DEPLOYMENT] {
        test_ctx.wait_for_deployment_ready(&deployments, depl_name, scaled_timeout(60)).await?;
    }
    test_ctx.info("All deployments ready pre-upgrade");

    // Trigger upgrade
    trigger_upgrade(&tec_api, TEC_NAME).await?;
    test_ctx.info("Triggered upgrade");

    // Poll deployments during upgrade to verify availability is maintained.
    // We check at intervals that availableReplicas >= 1 for all deployments.
    let poller = Poller::new()
        .with_timeout(scaled_duration(180))
        .with_interval(scaled_duration(5))
        .with_error_message("Upgrade did not complete while maintaining availability");

    let depls_api = deployments.clone();
    let tec_api_poll = tec_api.clone();
    poller
        .poll_async(|| {
            let depls = depls_api.clone();
            let tecs = tec_api_poll.clone();
            async move {
                // Check that deployments maintain availability
                for name in [TRUSTEE_DEPLOYMENT, REGISTER_SERVER_DEPLOYMENT] {
                    let depl = depls.get(name).await?;
                    let available = depl
                        .status
                        .as_ref()
                        .and_then(|s| s.available_replicas)
                        .unwrap_or(0);
                    if available < 1 {
                        return Err(anyhow::anyhow!(
                            "Deployment {name} has {available} available replicas during upgrade"
                        ));
                    }
                }

                // Check if upgrade completed
                let tec = tecs.get(TEC_NAME).await?;
                let version_restored = tec
                    .status
                    .as_ref()
                    .and_then(|s| s.observed_operator_version.as_ref())
                    .is_some();
                if version_restored {
                    return Ok(());
                }
                Err(anyhow::anyhow!("Upgrade still in progress"))
            }
        })
        .await?;

    test_ctx.info("Upgrade completed with no deployment downtime");

    test_ctx.cleanup().await?;
    Ok(())
}
}

named_test! {
async fn test_upgrade_combined_pcrs_events() -> anyhow::Result<()> {
    let test_ctx = setup!([(COMBINE_PCRS_UPDATE_TEST_IMAGE_NAME, COMBINE_PCRS_UPDATE_TEST_IMAGE_REF)]).await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);

    wait_for_install(&tec_api, TEC_NAME).await?;

    for name in [APPROVED_IMAGE_NAME, COMBINE_PCRS_UPDATE_TEST_IMAGE_NAME] {
        wait_for_committed_with_pcrs(&images, name, 300).await?;
    }
    test_ctx.info("Both ApprovedImages committed with PCRs");

    let primary = images.get(APPROVED_IMAGE_NAME).await?;
    let primary_events = extract_events(&primary);
    assert!(!primary_events.is_empty(), "Primary image should have events");
    for (pcr_id, events) in &primary_events {
        for ev in events {
            assert!(!ev.name.is_empty(), "PCR {pcr_id} event should have a name");
            assert!(!ev.hash.is_empty(), "PCR {pcr_id} event should have a hash");
            assert!(!ev.id.is_empty(), "PCR {pcr_id} event should have an id");
        }
    }
    test_ctx.info("Primary image events verified");

    let secondary = images.get(COMBINE_PCRS_UPDATE_TEST_IMAGE_NAME).await?;
    let secondary_events = extract_events(&secondary);
    assert!(!secondary_events.is_empty(), "Secondary image should have events");
    test_ctx.info("Secondary image events verified");

    let pre_primary_pcr_vals = extract_pcr_vals(&primary);
    let pre_secondary_pcr_vals = extract_pcr_vals(&secondary);

    trigger_upgrade(&tec_api, TEC_NAME).await?;
    test_ctx.info("Triggered upgrade");

    // Wait for the images to be invalidated.
    for name in [APPROVED_IMAGE_NAME, COMBINE_PCRS_UPDATE_TEST_IMAGE_NAME] {
        let done = await_condition(images.clone(), name, approved_image_was_invalidated);
        timeout(scaled_duration(60), done)
            .await
            .context(format!("{name} should be invalidated during upgrade"))??;
    }
    test_ctx.info("Both images invalidated");

    let done = await_condition(
        tec_api.clone(),
        TEC_NAME,
        tec_has_condition_reason(UPGRADE_CONDITION, UPGRADE_COMPLETE),
    );
    timeout(scaled_duration(300), done)
        .await
        .context("waiting for Upgrade=Complete")??;
    test_ctx.info("Upgrade completed");

    for name in [APPROVED_IMAGE_NAME, COMBINE_PCRS_UPDATE_TEST_IMAGE_NAME] {
        wait_for_committed_with_pcrs(&images, name, 300).await?;
    }
    test_ctx.info("Both images recommitted");

    let post_primary = images.get(APPROVED_IMAGE_NAME).await?;
    let post_primary_events = extract_events(&post_primary);
    assert_eq!(
        primary_events.len(), post_primary_events.len(),
        "Primary image should have same number of PCR entries"
    );
    for (pcr_id, events) in &post_primary_events {
        assert!(!events.is_empty(), "PCR {pcr_id} events should be repopulated");
    }

    let post_secondary = images.get(COMBINE_PCRS_UPDATE_TEST_IMAGE_NAME).await?;
    assert!(!extract_events(&post_secondary).is_empty(), "Secondary events should be repopulated");
    test_ctx.info("Events preserved after upgrade");

    // Verify PCRs are identical.
    // Asserting that the PCRs are identical even after upgrade.
    assert_eq!(pre_primary_pcr_vals, extract_pcr_vals(&post_primary), "Primary PCRs should be identical");
    assert_eq!(pre_secondary_pcr_vals, extract_pcr_vals(&post_secondary), "Secondary PCRs should be identical");

    test_ctx.verify_expected_pcrs(&[&primary_pcrs!(), &secondary_pcrs!()]).await?;
    test_ctx.info("PCR values verified");

    test_ctx.cleanup().await?;
    Ok(())
}
}

// Makes sure that if a upgrade fails, the old pods are still running.
named_test! {
async fn test_upgrade_failure_preserves_old_pods() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), namespace);

    // Wait for install
    wait_for_install(&tec_api, TEC_NAME).await?;

    // Wait for ApprovedImage to be committed
    let done = await_condition(images.clone(), APPROVED_IMAGE_NAME, approved_image_is_committed);
    timeout(scaled_duration(300), done)
        .await
        .context("waiting for ApprovedImage committed")??;

    // Record pre-failure state: Trustee image and pod count
    let pre_trustee_image = deployment_image(&deployments.get(TRUSTEE_DEPLOYMENT).await?)
        .expect("Trustee should have image");
    test_ctx.info(format!("Pre-failure Trustee image: {pre_trustee_image}"));

    let lp = ListParams::default().labels("app=kbs");
    let pre_pods: Vec<_> = pods_api
        .list(&lp)
        .await?
        .items
        .iter()
        .filter_map(|p| p.metadata.name.clone())
        .collect();
    test_ctx.info(format!("Pre-failure Trustee pods: {pre_pods:?}"));

  // Patch the trustee deployment desired image to a bad image.
    let bad_image = "quay.io/nonexistent/bad-image:v999";
    test_ctx
        .set_operator_related_image(&deployments, RELATED_IMAGE_TRUSTEE, bad_image)
        .await?;
    test_ctx.info(format!("Operator RELATED_IMAGE_TRUSTEE set to {bad_image}"));

    trigger_upgrade(&tec_api, TEC_NAME).await?;
    test_ctx.info("Triggered upgrade (Trustee desired image is bad, should fail)");

    // Wait for Upgrade=Failed condition
    let done = await_condition(tec_api.clone(), TEC_NAME, tec_has_condition_reason("Upgrade", "Failed"));
    timeout(scaled_duration(360), done)
        .await
        .context("waiting for Upgrade=Failed condition")??;
    test_ctx.info("Upgrade=Failed condition detected");

    // Verify the TEC status message contains failure detail
    let tec = tec_api.get(TEC_NAME).await?;
    let upgrade_cond = tec
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|cs| cs.iter().find(|c| c.type_ == "Upgrade"));
    assert!(
        upgrade_cond.is_some(),
        "Upgrade condition should exist"
    );
    let msg = &upgrade_cond.unwrap().message;
    assert!(
        msg.contains("Manual intervention required"),
        "Upgrade failure message should indicate manual intervention, got: {msg}"
    );
    test_ctx.info(format!("Upgrade failure message: {msg}"));

    // Verify old Trustee pods are still running (RollingUpdate keeps old pods)
    let post_pods = pods_api.list(&lp).await?;
    let running_pods: Vec<_> = post_pods
        .items
        .iter()
        .filter(|p| {
            p.status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .is_some_and(|phase| phase == "Running")
        })
        .filter_map(|p| p.metadata.name.clone())
        .collect();
    assert!(
        !running_pods.is_empty(),
        "At least one old Trustee pod should still be Running after failed upgrade"
    );
    test_ctx.info(format!("Old Trustee pods still running: {running_pods:?}"));

    // Verify observedOperatorVersion was NOT updated (should be the old version)
    let post_version = tec
        .status
        .as_ref()
        .and_then(|s| s.observed_operator_version.as_deref());
    assert!(
        post_version.is_none() || post_version != Some(""),
        "observedOperatorVersion should not be cleared or updated on failure"
    );
    test_ctx.info("observedOperatorVersion preserved after failure");

    test_ctx.cleanup().await?;
    Ok(())
}
}
