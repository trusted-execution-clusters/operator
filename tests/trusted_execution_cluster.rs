// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use compute_pcrs_lib::{Part, Pcr};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{Api, api::DeleteParams};
use std::time::Duration;
use trusted_cluster_operator_lib::reference_values::ImagePcrs;
use trusted_cluster_operator_lib::{ApprovedImage, TrustedExecutionCluster};
use trusted_cluster_operator_test_utils::*;

const EXPECTED_PCR4: &str = "551bbd142a716c67cd78336593c2eb3b547b575e810ced4501d761082b5cd4a8";

named_test!(
    async fn test_trusted_execution_cluster_uninstall() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        let client = test_ctx.client();
        let namespace = test_ctx.namespace();
        let name = "trusted-execution-cluster";

        let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

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

    let poller = Poller::new()
        .with_timeout(Duration::from_secs(180))
        .with_interval(Duration::from_secs(5))
        .with_error_message("image-pcrs ConfigMap not populated with data".to_string());

    poller
        .poll_async(|| {
            let api = configmap_api.clone();
            async move {
                let cm = api.get("image-pcrs").await?;

                if let Some(data) = &cm.data {
                    if let Some(image_pcrs_json) = data.get("image-pcrs.json") {
                        if let Ok(image_pcrs) = serde_json::from_str::<ImagePcrs>(image_pcrs_json) {
                            if !image_pcrs.0.is_empty() {
                                return Ok(());
                            }
                        }
                    }
                }

                Err(anyhow::anyhow!("image-pcrs ConfigMap not yet populated with image-pcrs.json data"))
            }
        })
        .await?;

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
                Part { name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(), hash: "2b1dc59bc61dbbc3db11a6f3b0708c948efd46cceb7f6c8ea2024b8d1b8c829a".to_string() },
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
    images.delete("coreos", &DeleteParams::default()).await?;

    let configmap_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let poller = Poller::new()
        .with_timeout(Duration::from_secs(180))
        .with_interval(Duration::from_secs(5))
        .with_error_message("Reference value not removed".to_string());
    poller.poll_async(|| {
        let api = configmap_api.clone();
        async move {
            let cm = api.get("trustee-data").await?;
            if let Some(data) = &cm.data {
                if let Some(reference_values_json) = data.get("reference-values.json") {
                    if !reference_values_json.contains(EXPECTED_PCR4) {
                        return Ok(());
                    }
                }
            }
            Err(anyhow::anyhow!("Reference value not yet removed"))
        }
    }).await?;

    Ok(())
}
}
