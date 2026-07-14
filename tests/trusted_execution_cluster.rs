// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::Context;
use compute_pcrs_lib::{Part, Pcr};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, OwnerReference};
use kube::api::ObjectMeta;
use kube::runtime::wait::await_condition;
use kube::{Api, api::DeleteParams};
use std::time::Duration;
use tokio::time::timeout;
use trusted_cluster_operator_lib::conditions::NOT_COMMITTED_REASON_PENDING;
use trusted_cluster_operator_lib::endpoints::{REGISTER_SERVER_DEPLOYMENT, TRUSTEE_DEPLOYMENT};
use trusted_cluster_operator_lib::reference_values::ImagePcrs;
use trusted_cluster_operator_lib::{
    ApprovedImage, AttestationKey, Machine, TrustedExecutionCluster, generate_owner_reference,
};
use trusted_cluster_operator_test_utils::*;

const EXPECTED_PCR4: &str = "ff2b357be4a4bc66be796d4e7b2f1f27077dc89b96220aae60b443bcf4672525";
const TEC_NAME: &str = "trusted-execution-cluster";
const TRUSTEE_CONFIG_MAP: &str = "trustee-data";
const RV_JSON_KEY: &str = "reference-values.json";

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
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let populated = |cm: Option<&ConfigMap>| {
        let data = cm.and_then(|cm| cm.data.as_ref());
        let json = data.and_then(|data| data.get("image-pcrs.json"));
        let pcrs = json.and_then(|json| serde_json::from_str::<ImagePcrs>(json).ok());
        pcrs.map(|pcrs| !pcrs.0.is_empty()).unwrap_or(false)
    };
    let done = await_condition(configmap_api.clone(), "image-pcrs", populated);
    let ctx = "waiting for ConfigMap image-pcrs to be populated";
    timeout(scaled_duration(180), done).await.context(ctx)??;

    let image_pcrs_cm = configmap_api.get("image-pcrs").await?;
    assert_eq!(image_pcrs_cm.metadata.name.as_deref(), Some("image-pcrs"));

    let data = image_pcrs_cm.data.as_ref()
        .expect("image-pcrs ConfigMap should have data field");

    assert!(!data.is_empty(), "image-pcrs ConfigMap should have data");

    let image_pcrs_json = data.get("image-pcrs.json")
        .expect("image-pcrs ConfigMap should have image-pcrs.json key");

    assert!(!image_pcrs_json.is_empty(), "image-pcrs.json should not be empty");

    // Parse the image-pcrs.json using the ImagePcrs structure
    let image_pcrs: ImagePcrs = serde_json::from_str(image_pcrs_json)
        .expect("image-pcrs.json should be valid ImagePcrs JSON");

    assert!(!image_pcrs.0.is_empty(), "image-pcrs.json should contain at least one image entry");

    let expected_pcrs = vec![
        Pcr {
            id: 4,
            value: EXPECTED_PCR4.to_string(),
            parts: vec![
                Part { name: "EV_EFI_ACTION".to_string(), hash: "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba".to_string() },
                Part { name: "EV_SEPARATOR".to_string(), hash: "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119".to_string() },
                Part { name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(), hash: "94896c17d49fc8c8df0cc2836611586edab1615ce7cb58cf13fc5798de56b367".to_string() },
                Part { name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(), hash: "bc6844fc7b59b4f0c7da70a307fc578465411d7a2c34b0f4dc2cc154c873b644".to_string() },
                Part { name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(), hash: "72c613f1b4d60dcf51f82f3458cca246580d23150130ec6751ac6fa62c867364".to_string() },
            ],
        },
        Pcr {
            id: 7,
            value: "b3a56a06c03a65277d0a787fcabc1e293eaa5d6dd79398f2dda741f7b874c65d".to_string(),
            parts: vec![
                Part { name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(), hash: "ccfc4bb32888a345bc8aeadaba552b627d99348c767681ab3141f5b01e40a40e".to_string() },
                Part { name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(), hash: "adb6fc232943e39c374bf4782b6c697f43c39fca1f4b51dfceda21164e19a893".to_string() },
                Part { name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(), hash: "b5432fe20c624811cb0296391bfdf948ebd02f0705ab8229bea09774023f0ebf".to_string() },
                Part { name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(), hash: "4313e43de720194a0eabf4d6415d42b5a03a34fdc47bb1fc924cc4e665e6893d".to_string() },
                Part { name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(), hash: "001004ba58a184f09be6c1f4ec75a246cc2eefa9637b48ee428b6aa9bce48c55".to_string() },
                Part { name: "EV_SEPARATOR".to_string(), hash: "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119".to_string() },
                Part { name: "EV_EFI_VARIABLE_AUTHORITY".to_string(), hash: "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9".to_string() },
                Part { name: "EV_EFI_VARIABLE_AUTHORITY".to_string(), hash: "e8e9578f5951ef16b1c1aa18ef02944b8375ec45ed4b5d8cdb30428db4a31016".to_string() },
                Part { name: "EV_EFI_VARIABLE_AUTHORITY".to_string(), hash: "ad5901fd581e6640c742c488083b9ac2c48255bd28a16c106c6f9df52702ee3f".to_string() },
            ],
        },
        Pcr {
            id: 14,
            value: "17cdefd9548f4383b67a37a901673bf3c8ded6f619d36c8007562de1d93c81cc".to_string(),
            parts: vec![
                Part { name: "EV_IPL".to_string(), hash: "e8e48e3ad10bc243341b4663c0057aef0ec7894ccc9ecb0598f0830fa57f7220".to_string() },
                Part { name: "EV_IPL".to_string(), hash: "8d8a3aae50d5d25838c95c034aadce7b548c9a952eb7925e366eda537c59c3b0".to_string() },
                Part { name: "EV_IPL".to_string(), hash: "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a".to_string() },
            ],
        },
    ];

    let mut found_expected_pcrs = false;
    for (_image_ref, image_data) in image_pcrs.0.iter() {
        if compare_pcrs(&image_data.pcrs, &expected_pcrs) {
            found_expected_pcrs = true;
            break;
        }
    }

    assert!(found_expected_pcrs,
        "At least one image should have the expected PCR values");

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

    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let chk_removed = |cm: Option<&ConfigMap>| {
        let data = cm.and_then(|cm| cm.data.as_ref());
        let json = data.and_then(|data| data.get(RV_JSON_KEY));
        json.map(|json| !json.contains(EXPECTED_PCR4)).unwrap_or(false)
    };
    let rv_removed = await_condition(configmap_api, TRUSTEE_CONFIG_MAP, chk_removed);
    let ctx = format!("waiting for ConfigMap {TRUSTEE_CONFIG_MAP} to not contain PCR value");
    timeout(scaled_duration(180), rv_removed).await.context(ctx)??;

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
async fn test_approved_image_readoption() -> anyhow::Result<()> {
    let test_ctx = setup!(delayed_approved_image).await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let clusters: Api<TrustedExecutionCluster> = Api::namespaced(client.clone(), namespace);
    let images: Api<ApprovedImage> = Api::namespaced(client.clone(), namespace);
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

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
    wait_for_resource_deleted(&configmaps, TRUSTEE_CONFIG_MAP, scaled_timeout(60)).await?;
    wait_for_resource_deleted(&images, APPROVED_IMAGE_NAME, scaled_timeout(60)).await?;
    test_ctx.info(format!("Configmap {TRUSTEE_CONFIG_MAP} was removed"));

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
    let chk_added = |cm: Option<&ConfigMap>| {
        let data = cm.and_then(|cm| cm.data.as_ref());
        let json = data.and_then(|data| data.get(RV_JSON_KEY));
        json.map(|json| json.contains(EXPECTED_PCR4)).unwrap_or(false)
    };
    let rv_added = await_condition(configmaps, TRUSTEE_CONFIG_MAP, chk_added);
    let ctx = format!("waiting for ConfigMap {TRUSTEE_CONFIG_MAP} to contain PCR value");
    timeout(scaled_duration(180), rv_added).await.context(ctx)??;
    test_ctx.info("Reference values regenerated");

    test_ctx.cleanup().await?;
    Ok(())
}
}
