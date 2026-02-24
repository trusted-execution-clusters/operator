// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use compute_pcrs_lib::Pcr;
use compute_pcrs_lib::tpmevents::{TPMEvent, TPMEventID};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::{Api, api::DeleteParams};
use std::time::Duration;
use trusted_cluster_operator_lib::{
    ApprovedImage, AttestationKey, Machine, TrustedExecutionCluster, generate_owner_reference,
};
use trusted_cluster_operator_test_utils::*;

named_test!(
    async fn test_trusted_execution_cluster_uninstall() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        let client = test_ctx.client();
        let namespace = test_ctx.namespace();
        let name = "trusted-execution-cluster";

        let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

        let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
        let tec = tec_api.get(name).await?;

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
        let poller = Poller::new()
            .with_timeout(Duration::from_secs(30))
            .with_interval(Duration::from_millis(500))
            .with_error_message("AttestationKey was not approved".to_string());

        poller
            .poll_async(|| {
                let ak_api = attestation_keys.clone();
                let ak_name_clone = ak_name.clone();
                async move {
                    let ak = ak_api.get(&ak_name_clone).await?;

                    // Check for Approved condition
                    let has_approved_condition = ak
                        .status
                        .as_ref()
                        .and_then(|s| s.conditions.as_ref())
                        .map(|conditions| {
                            conditions
                                .iter()
                                .any(|c| c.type_ == "Approved" && c.status == "True")
                        })
                        .unwrap_or(false);

                    if !has_approved_condition {
                        return Err(anyhow::anyhow!(
                            "AttestationKey does not have Approved condition yet"
                        ));
                    }

                    Ok(())
                }
            })
            .await?;

        test_ctx.info("AttestationKey successfully approved");

        // Delete the cluster cr
        let api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
        let dp = DeleteParams::default();
        api.delete(name, &dp).await?;

        // Wait until it disappears
        wait_for_resource_deleted(&api, name, 120, 5).await?;

        let deployments_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        wait_for_resource_deleted(&deployments_api, "trustee-deployment", 120, 1).await?;
        wait_for_resource_deleted(&deployments_api, "register-server", 120, 1).await?;
        wait_for_resource_deleted(&configmap_api, "image-pcrs", 120, 1).await?;

        let images_api: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
        wait_for_resource_deleted(&images_api, "coreos", 120, 1).await?;

        wait_for_resource_deleted(&machines, &machine_name, 120, 1).await?;
        wait_for_resource_deleted(&attestation_keys, &ak_name, 120, 1).await?;
        let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
        wait_for_resource_deleted(&secrets_api, &ak_name, 120, 1).await?;

        test_ctx.cleanup().await?;

        Ok(())
    }
);

named_test! {
async fn test_image_pcrs_configmap_updates() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;

    test_ctx.verify_expected_pcrs(&[&expected_base_pcrs!()]).await?;

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
    images.delete("coreos-0", &DeleteParams::default()).await?;

    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(180))
        .with_interval(Duration::from_secs(5))
        .with_error_message("Reference value not removed".to_string());
    poller.poll_async(|| {
        let api = configmap_api.clone();
        async move {
            let cm = api.get("trustee-data").await?;
            if let Some(data) = &cm.data
                && let Some(reference_values_json) = data.get("reference-values.json")
                && !reference_values_json.contains(expected_pcr4_hash!())
            {
                return Ok(());
            }
            Err(anyhow::anyhow!("Reference value not yet removed"))
        }
    }).await?;

    Ok(())
}
}

named_test! {
async fn test_attestation_key_lifecycle() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();
    let tec_name = "trusted-execution-cluster";

    let tec_api: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let tec = tec_api.get(tec_name).await?;
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

    // Poll for the AttestationKey to be approved, have owner reference, and have a Secret created
    let secrets_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(30))
        .with_interval(Duration::from_millis(500))
        .with_error_message("AttestationKey was not approved with owner reference and secret".to_string());

    poller
        .poll_async(|| {
            let ak_api = attestation_keys.clone();
            let secrets = secrets_api.clone();
            let ak_name_clone = ak_name.clone();
            let machine_name_clone = machine_name.clone();
            async move {
                let ak = ak_api.get(&ak_name_clone).await?;

                // Check for Approved condition
                let has_approved_condition = ak
                    .status
                    .as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .map(|conditions| {
                        conditions
                            .iter()
                            .any(|c| c.type_ == "Approved" && c.status == "True")
                    })
                    .unwrap_or(false);

                if !has_approved_condition {
                    return Err(anyhow::anyhow!(
                        "AttestationKey does not have Approved condition yet"
                    ));
                }

                // Check for owner reference to the Machine
                let has_machine_owner_ref = ak
                    .metadata
                    .owner_references
                    .as_ref()
                    .map(|owner_refs| {
                        owner_refs.iter().any(|owner_ref| {
                            owner_ref.kind == "Machine" && owner_ref.name == machine_name_clone
                        })
                    })
                    .unwrap_or(false);

                if !has_machine_owner_ref {
                    return Err(anyhow::anyhow!(
                        "AttestationKey does not have owner reference to Machine yet"
                    ));
                }

                // Check that a Secret with the same name exists and has the AttestationKey as owner
                let secret = secrets.get(&ak_name_clone).await?;
                let has_ak_owner_ref = secret
                    .metadata
                    .owner_references
                    .as_ref()
                    .map(|owner_refs| {
                        owner_refs.iter().any(|owner_ref| {
                            owner_ref.kind == "AttestationKey" && owner_ref.name == ak_name_clone
                        })
                    })
                    .unwrap_or(false);

                if !has_ak_owner_ref {
                    return Err(anyhow::anyhow!(
                        "Secret does not have owner reference to AttestationKey yet"
                    ));
                }

                Ok(())
            }
        })
        .await?;

    test_ctx.info(format!(
        "AttestationKey successfully approved with owner reference to Machine: {machine_name} and Secret created"
    ));

    // Delete the Machine
    let dp = DeleteParams::default();
    machines.delete(&machine_name, &dp).await?;
    test_ctx.info(format!("Deleted Machine: {machine_name}"));

    wait_for_resource_deleted(&machines, &machine_name, 120, 1).await?;
    test_ctx.info("Machine successfully deleted");
    wait_for_resource_deleted(&attestation_keys, &ak_name, 120, 1).await?;
    test_ctx.info("AttestationKey successfully deleted");
    wait_for_resource_deleted(&secrets_api, &ak_name, 120, 1).await?;
    test_ctx.info("Secret successfully deleted");

    test_ctx.cleanup().await?;

    Ok(())
}
}

named_test! {
async fn test_combined_image_pcrs_configmap_updates() -> anyhow::Result<()> {
    let test_ctx = setup!([
        "quay.io/trusted-execution-clusters/fedora-coreos@sha256:372a5db90a8695fafc2869d438bacd7f0ef7fd84f63746a450bfcd4b8b64ae83",
    ]).await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let secondary_expected_pcr4_hash = "37517a1f76c4d5cf615f4690921c732ad31359aac55f3aaf66d65a8ed38655a9";

    test_ctx.verify_expected_pcrs(
        &[&expected_base_pcrs!(),
        // In practical terms it emulates a grub + kernel upgrade
        &[
            Pcr {
                id: 4,
                value: hex::decode(secondary_expected_pcr4_hash).unwrap(),
                events: vec![
                    pcr4_ev_efi_action_event!(),
                    pcr_separator_event!(4, TPMEventID::Pcr4Separator),
                    pcr4_shim_event!(),
                    TPMEvent { pcr: 4, name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(), hash: hex::decode("f45c2c974192366a5391e077c3cbf91e735e86eba2037fd86a1f1501818f73f4").unwrap(), id: TPMEventID::Pcr4Grub },
                    TPMEvent { pcr: 4, name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(), hash: hex::decode("f31e645e5e9ed131eea5dca0a18893a21e5625b4a56314fa39587ddc33a7fa91").unwrap(), id: TPMEventID::Pcr4Vmlinuz },
                ],
            },
            expected_pcr7!(),
            expected_pcr14!(),
        ]]
    ).await?;

    let expected_ref_values = [
        // PCR4
        expected_pcr4_hash!(),
        "0c4e52c0bc5d2fedbf83b2fee82664dbe5347a79cfb2cbcb9a37f64211add6e8",
        "cc5a5360e64b25718be370ca2056645a9ba9e9bae33df08308d6b8e05b8ebb87",
        secondary_expected_pcr4_hash,
        // PCR7
        expected_pcr7_hash!(),
        // PCR14
        expected_pcr14_hash!(),
    ];

    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(180))
        .with_interval(Duration::from_secs(5))
        .with_error_message("Reference value expectations not met".to_string());
    poller.poll_async(|| {
        let api = configmap_api.clone();
        async move {
            let cm = api.get("trustee-data").await?;
            if let Some(data) = &cm.data
                && let Some(reference_values_json) = data.get("reference-values.json")
            {
                    for value in expected_ref_values {
                        if !reference_values_json.contains(value) {
                            return Err(anyhow::anyhow!("Reference value expectations not met"));
                        }
                    }
            }
            Ok(())
        }
    }).await?;

    test_ctx.cleanup().await?;
    Ok(())
}
}
