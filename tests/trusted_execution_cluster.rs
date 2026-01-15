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

const EXPECTED_PCR4: &str = "ff2b357be4a4bc66be796d4e7b2f1f27077dc89b96220aae60b443bcf4672525";

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

    test_ctx.verify_expected_pcrs(
        &[&[
            Pcr {
                id: 4,
                value: hex::decode(EXPECTED_PCR4).unwrap(),
                events: vec![
                    TPMEvent {
                        pcr: 4,
                        name: "EV_EFI_ACTION".to_string(),
                        hash: hex::decode(
                            "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr4EfiCall,
                    },
                    TPMEvent {
                        pcr: 4,
                        name: "EV_SEPARATOR".to_string(),
                        hash: hex::decode(
                            "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr4Separator,
                    },
                    TPMEvent {
                        pcr: 4,
                        name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(),
                        hash: hex::decode(
                            "94896c17d49fc8c8df0cc2836611586edab1615ce7cb58cf13fc5798de56b367",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr4Shim,
                    },
                    TPMEvent {
                        pcr: 4,
                        name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(),
                        hash: hex::decode(
                            "bc6844fc7b59b4f0c7da70a307fc578465411d7a2c34b0f4dc2cc154c873b644",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr4Grub,
                    },
                    TPMEvent {
                        pcr: 4,
                        name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(),
                        hash: hex::decode(
                            "2b1dc59bc61dbbc3db11a6f3b0708c948efd46cceb7f6c8ea2024b8d1b8c829a",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr4Vmlinuz,
                    },
                ],
            },
            Pcr {
                id: 7,
                value: hex::decode(
                    "b3a56a06c03a65277d0a787fcabc1e293eaa5d6dd79398f2dda741f7b874c65d",
                )
                .unwrap(),
                events: vec![
                    TPMEvent {
                        pcr: 7,
                        name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                        hash: hex::decode(
                            "ccfc4bb32888a345bc8aeadaba552b627d99348c767681ab3141f5b01e40a40e",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7SecureBoot,
                    },
                    TPMEvent {
                        pcr: 7,
                        name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                        hash: hex::decode(
                            "adb6fc232943e39c374bf4782b6c697f43c39fca1f4b51dfceda21164e19a893",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7Pk,
                    },
                    TPMEvent {
                        pcr: 7,
                        name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                        hash: hex::decode(
                            "b5432fe20c624811cb0296391bfdf948ebd02f0705ab8229bea09774023f0ebf",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7Kek,
                    },
                    TPMEvent {
                        pcr: 7,
                        name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                        hash: hex::decode(
                            "4313e43de720194a0eabf4d6415d42b5a03a34fdc47bb1fc924cc4e665e6893d",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7Db,
                    },
                    TPMEvent {
                        pcr: 7,
                        name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                        hash: hex::decode(
                            "001004ba58a184f09be6c1f4ec75a246cc2eefa9637b48ee428b6aa9bce48c55",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7Dbx,
                    },
                    TPMEvent {
                        pcr: 7,
                        name: "EV_SEPARATOR".to_string(),
                        hash: hex::decode(
                            "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7Separator,
                    },
                    TPMEvent {
                        pcr: 7,
                        name: "EV_EFI_VARIABLE_AUTHORITY".to_string(),
                        hash: hex::decode(
                            "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7ShimCert,
                    },
                    TPMEvent {
                        pcr: 7,
                        name: "EV_EFI_VARIABLE_AUTHORITY".to_string(),
                        hash: hex::decode(
                            "e8e9578f5951ef16b1c1aa18ef02944b8375ec45ed4b5d8cdb30428db4a31016",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7SbatLevel,
                    },
                    TPMEvent {
                        pcr: 7,
                        name: "EV_EFI_VARIABLE_AUTHORITY".to_string(),
                        hash: hex::decode(
                            "ad5901fd581e6640c742c488083b9ac2c48255bd28a16c106c6f9df52702ee3f",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7GrubMokListCert,
                    },
                ],
            },
            Pcr {
                id: 14,
                value: hex::decode(
                    "17cdefd9548f4383b67a37a901673bf3c8ded6f619d36c8007562de1d93c81cc",
                )
                .unwrap(),
                events: vec![
                    TPMEvent {
                        pcr: 14,
                        name: "EV_IPL".to_string(),
                        hash: hex::decode(
                            "e8e48e3ad10bc243341b4663c0057aef0ec7894ccc9ecb0598f0830fa57f7220",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr14MokList,
                    },
                    TPMEvent {
                        pcr: 14,
                        name: "EV_IPL".to_string(),
                        hash: hex::decode(
                            "8d8a3aae50d5d25838c95c034aadce7b548c9a952eb7925e366eda537c59c3b0",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr14MokListX,
                    },
                    TPMEvent {
                        pcr: 14,
                        name: "EV_IPL".to_string(),
                        hash: hex::decode(
                            "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr14MokListTrusted,
                    },
                ],
            },
        ]]
    ).await?;

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
                && !reference_values_json.contains(EXPECTED_PCR4)
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
