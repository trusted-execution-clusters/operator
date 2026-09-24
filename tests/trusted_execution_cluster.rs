// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Context;

use chrono::Utc;
use compute_pcrs_lib::Pcr;
use compute_pcrs_lib::tpmevents::{TPMEvent, TPMEventID};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Node, NodeSpec, Pod, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, ObjectMeta, OwnerReference};
use kube::api::{ListParams, LogParams, Patch, PatchParams};
use kube::runtime::wait::await_condition;
use kube::{Api, api::DeleteParams};
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;
use trusted_cluster_operator_lib::conditions::{COMMITTED_CONDITION, NOT_COMMITTED_REASON_PENDING};
use trusted_cluster_operator_lib::endpoints::{REGISTER_SERVER_DEPLOYMENT, TRUSTEE_DEPLOYMENT};
use trusted_cluster_operator_lib::{
    ApprovedImage, AttestationKey, Machine, TrustedExecutionCluster, generate_owner_reference,
};
use trusted_cluster_operator_test_utils::constants::*;
use trusted_cluster_operator_test_utils::*;
const NODE_FINALIZER: &str = "trusted-execution-clusters.io/node";

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
                provider_id: None,
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
async fn test_image_pcrs_updates() -> anyhow::Result<()> {
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
            provider_id: None,
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
            provider_id: None,
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
            provider_id: None,
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
            provider_id: None,
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
            provider_id: None,
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
                    .any(|c| c.type_ == COMMITTED_CONDITION && c.status == "True")
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

    // In practical terms it emulates a grub + kernel upgrade
    test_ctx.verify_expected_pcrs(&[&primary_pcrs!(), &secondary_pcrs!()]).await?;

    test_ctx.cleanup().await?;
    Ok(())
}
}

named_test! {
async fn test_node_deletion() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let tec = tec_api.get(TEC_NAME).await?;
    let owner_reference = generate_owner_reference(&tec)?;

    // A unique providerID correlates the Node and the Machine.
    let machine_uuid = uuid::Uuid::new_v4().to_string();
    let machine_name = format!("test-machine-{}", &machine_uuid[..8]);
    let node_name = format!("test-node-{}", &machine_uuid[..8]);
    let provider_id = format!("test:///{machine_uuid}");

    // Create a Machine already bound to the providerID.
    let machines: Api<Machine> = Api::namespaced(client.clone(), namespace);
    let machine = Machine {
        metadata: ObjectMeta {
            name: Some(machine_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner_reference.clone()]),
            ..Default::default()
        },
        spec: trusted_cluster_operator_lib::MachineSpec {
            id: machine_uuid.clone(),
            provider_id: Some(provider_id.clone()),
        },
        status: None,
    };
    machines.create(&Default::default(), &machine).await?;
    test_ctx.info(format!("Created Machine {machine_name} with providerID {provider_id}"));

    // Create a cluster-scoped Node carrying the same providerID.
    let nodes: Api<Node> = Api::all(client.clone());
    let node = Node {
        metadata: ObjectMeta {
            name: Some(node_name.clone()),
            ..Default::default()
        },
        spec: Some(NodeSpec {
            provider_id: Some(provider_id.clone()),
            ..Default::default()
        }),
        ..Default::default()
    };
    nodes.create(&Default::default(), &node).await?;
    test_ctx.info(format!("Created Node {node_name} with providerID {provider_id}"));

    // The finalizer must be attached before we delete the Node, otherwise the
    // deletion completes without ever running the cleanup that deletes the
    // Machine. Wait for the operator to add it.
    let has_finalizer = |n: Option<&Node>| {
        n.and_then(|n| n.metadata.finalizers.as_ref())
            .is_some_and(|f| f.iter().any(|x| x == NODE_FINALIZER))
    };
    let done = await_condition(nodes.clone(), &node_name, has_finalizer);
    let ctx = format!("waiting for the node finalizer on {node_name}");
    timeout(scaled_duration(60), done).await.context(ctx)??;
    test_ctx.info(format!("Finalizer attached to Node {node_name}"));

    // Deleting the Node should trigger the finalizer to delete the matching Machine.
    nodes.delete(&node_name, &DeleteParams::default()).await?;
    test_ctx.info(format!("Deleted Node {node_name}"));

    wait_for_resource_deleted(&machines, &machine_name, scaled_timeout(120)).await?;
    test_ctx.info("Machine deleted after Node deletion");

    // The finalizer must also let the Node itself go.
    wait_for_resource_deleted(&nodes, &node_name, scaled_timeout(120)).await?;

    test_ctx.cleanup().await?;
    Ok(())
}
}
