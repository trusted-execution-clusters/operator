// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use compute_pcrs_lib::Pcr;
use futures_util::StreamExt;
use k8s_openapi::{
    api::{
        batch::v1::{Job, JobSpec},
        core::v1::{ConfigMap, Container, ImageVolumeSource, Volume, VolumeMount},
        core::v1::{Pod, PodSpec, PodTemplateSpec},
    },
    jiff::Timestamp,
};
use kube::api::{DeleteParams, ListParams, ObjectMeta, Patch};
use kube::runtime::{
    controller::{Action, Controller},
    finalizer,
    finalizer::Event,
    watcher,
};
use kube::{Api, Client, Resource};
use log::{info, warn};
use oci_client::secrets::RegistryAuth;
use oci_spec::image::ImageConfiguration;
use openssl::hash::{MessageDigest, hash};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use crate::COMPONENT_VERSION;
use crate::trustee::{self, get_image_pcrs};
use operator::{ControllerError, upsert_condition};
use operator::{controller_error_policy, controller_info, create_or_info_if_exists};
use trusted_cluster_operator_lib::{conditions::*, reference_values::*, *};

const JOB_LABEL_KEY: &str = "kind";
const APPROVED_IMAGE_ANNOTATION: &str = "approved-image";
const PCR_COMMAND_NAME: &str = "compute-pcrs";
const PCR_LABEL: &str = "org.coreos.pcrs";
/// Finalizer name to discard reference values when an image is no longer approved
const APPROVED_IMAGE_FINALIZER: &str = "finalizer.approved-image.trusted-execution-clusters.io";

/// Synchronize with compute_pcrs_cli::Output
#[derive(Deserialize)]
struct ComputePcrsOutput {
    pcrs: Vec<Pcr>,
}

pub async fn create_pcrs_config_map(client: Client) -> Result<()> {
    let empty_data = BTreeMap::from([(
        PCR_CONFIG_FILE.to_string(),
        serde_json::to_string(&ImagePcrs::default())?,
    )]);
    let config_map = ConfigMap {
        metadata: ObjectMeta {
            name: Some(PCR_CONFIG_MAP.to_string()),
            ..Default::default()
        },
        data: Some(empty_data),
        ..Default::default()
    };
    create_or_info_if_exists!(client, ConfigMap, config_map);
    Ok(())
}

async fn fetch_pcr_label(image_ref: &oci_client::Reference) -> Result<Option<Vec<Pcr>>> {
    let client = oci_client::Client::new(Default::default());
    let (_, _, raw_config) = client
        .pull_manifest_and_config(image_ref, &RegistryAuth::Anonymous)
        .await?;
    let config: ImageConfiguration = serde_json::from_str(&raw_config)?;
    config
        .labels_of_config()
        .and_then(|m| m.get(PCR_LABEL))
        .map(|l| serde_json::from_str::<ComputePcrsOutput>(l).map(|o| o.pcrs))
        .transpose()
        .map_err(Into::into)
}

fn build_compute_pcrs_pod_spec(
    resource_name: &str,
    boot_image: &str,
    pcrs_compute_image: &str,
) -> PodSpec {
    let image_volume_name = "image";
    let mut cmd = vec![PCR_COMMAND_NAME, "--image", boot_image];
    cmd.extend(&["--resource-name", resource_name]);

    PodSpec {
        service_account_name: Some("trusted-cluster-operator".to_string()),
        containers: vec![Container {
            name: PCR_COMMAND_NAME.to_string(),
            image: Some(pcrs_compute_image.to_string()),
            command: Some(cmd.iter().map(|s| s.to_string()).collect()),
            volume_mounts: Some(vec![VolumeMount {
                name: image_volume_name.to_string(),
                mount_path: IMAGE_VOLUME_MOUNTPOINT.to_string(),
                ..Default::default()
            }]),
            ..Default::default()
        }],
        volumes: Some(vec![Volume {
            name: image_volume_name.to_string(),
            image: Some(ImageVolumeSource {
                reference: Some(boot_image.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        restart_policy: Some("Never".to_string()),
        ..Default::default()
    }
}

async fn job_reconcile(job: Arc<Job>, client: Arc<Client>) -> Result<Action, ControllerError> {
    let err = "Job changed, but had no name";
    let name = &job.metadata.name.clone().context(err)?;
    let err = format!("Job {name} changed, but had no status");
    let status = &job.status.clone().context(err)?;
    let kube_client = Arc::unwrap_or_clone(client);
    if status.completion_time.is_none() {
        info!("Job {name} changed, but had not completed");
        return Ok(Action::requeue(Duration::from_secs(300)));
    }
    let jobs: Api<Job> = Api::default_namespaced(kube_client.clone());
    // Foreground deletion: Delete the pod too
    let delete = jobs.delete(name, &DeleteParams::foreground()).await;
    delete.map_err(Into::<anyhow::Error>::into)?;
    trustee::update_reference_values(kube_client).await?;
    Ok(Action::await_change())
}

pub async fn launch_rv_job_controller(client: Client) {
    let jobs: Api<Job> = Api::default_namespaced(client.clone());
    let watcher = watcher::Config {
        label_selector: Some(format!("{JOB_LABEL_KEY}={PCR_COMMAND_NAME}")),
        ..Default::default()
    };
    tokio::spawn(
        Controller::new(jobs, watcher)
            .run(job_reconcile, controller_error_policy, Arc::new(client))
            .for_each(controller_info),
    );
}

// Name job by sanitized image name, plus a hash to disambiguate
// tags that differed only beyond the truncation limit
fn get_job_name(boot_image: &str) -> Result<String> {
    let rfc1035_boot_image = boot_image.replace(['.', ':', '/', '@', '_'], "-");
    let boot_image_hash = hash(MessageDigest::sha1(), boot_image.as_bytes())?;
    let mut boot_image_hash_str = hex::encode(boot_image_hash);
    boot_image_hash_str.truncate(10);
    let job_name = format!("{PCR_COMMAND_NAME}-{boot_image_hash_str}-{rfc1035_boot_image}");
    let trimmed: String = job_name.chars().take(63).collect();
    let trimmed = trimmed.trim_end_matches('-').to_string();
    Ok(trimmed)
}

async fn compute_fresh_pcrs(client: Client, image: &ApprovedImage) -> anyhow::Result<()> {
    let job_name = get_job_name(&image.spec.image)?;
    let env = "RELATED_IMAGE_COMPUTE_PCRS";
    let default_image =
        format!("quay.io/trusted-execution-clusters/compute-pcrs:{COMPONENT_VERSION}");
    let pcrs_compute_image = std::env::var(env).ok().unwrap_or(default_image);
    let resource_name = image.metadata.name.as_ref().unwrap();
    let pod_spec =
        build_compute_pcrs_pod_spec(resource_name, &image.spec.image, &pcrs_compute_image);
    let job = Job {
        metadata: ObjectMeta {
            name: Some(job_name.clone()),
            labels: Some(BTreeMap::from([(
                JOB_LABEL_KEY.to_string(),
                PCR_COMMAND_NAME.to_string(),
            )])),
            owner_references: Some(vec![generate_owner_reference(image)?]),
            ..Default::default()
        },
        spec: Some(JobSpec {
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(BTreeMap::from([(
                        APPROVED_IMAGE_ANNOTATION.to_string(),
                        resource_name.to_string(),
                    )])),
                    ..Default::default()
                }),
                spec: Some(pod_spec),
            },
            ..Default::default()
        }),
        ..Default::default()
    };
    create_or_info_if_exists!(client, Job, job);
    Ok(())
}

async fn adopt_approved_image(
    client: Client,
    image_name: &str,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let images: Api<ApprovedImage> = Api::default_namespaced(client.clone());
    let default = "<no name>".to_string();
    let cluster_name = cluster.metadata.name.as_ref().unwrap_or(&default);
    info!(
        "Adding owner reference from TrustedExecutionCluster {cluster_name} \
         to ApprovedImage {image_name}"
    );
    let json = json!({
        "metadata": {
            "ownerReferences": [generate_owner_reference(cluster)?],
        }
    });
    let patch = Patch::Merge(&json);
    let params = Default::default();
    images.patch(image_name, &params, &patch).await?;
    Ok(())
}

pub async fn adopt_approved_images(
    client: Client,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let images: Api<ApprovedImage> = Api::default_namespaced(client.clone());
    let images_list = images.list(&Default::default()).await?;
    for image in images_list.items.iter() {
        if image.metadata.deletion_timestamp.is_none()
            && let Some(name) = image.metadata.name.as_ref()
        {
            adopt_approved_image(client.clone(), name, cluster).await?;
        }
    }
    Ok(())
}

async fn image_reconcile(
    image: Arc<ApprovedImage>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    let kube_client = Arc::<Client>::unwrap_or_clone(client);
    let err = "ApprovedImage had no name";
    let name = image.metadata.name.clone().context(err)?;
    let cluster = get_opt_trusted_execution_cluster(kube_client.clone())
        .await
        .map_err(|e| -> ControllerError { e.into() })?;

    let images: Api<ApprovedImage> = Api::default_namespaced(kube_client.clone());
    finalizer(&images, APPROVED_IMAGE_FINALIZER, image, |ev| async {
        match ev {
            Event::Apply(image) => image_add_reconcile(kube_client, &image, cluster)
                .await
                .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into())),
            Event::Cleanup(image) => image_remove_reconcile(kube_client, image, cluster)
                .await
                .map_err(|e| finalizer::Error::<ControllerError>::CleanupFailed(e.into())),
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile on image {name}: {e}").into())
}

async fn image_add_reconcile(
    client: Client,
    image: &ApprovedImage,
    cluster: Option<TrustedExecutionCluster>,
) -> Result<Action> {
    let name = image.metadata.name.as_ref().unwrap();
    let uid_owns = |uid: &String| {
        let refs = image.metadata.owner_references.as_ref();
        refs.map(|os| os.iter().any(|o| o.uid == *uid))
    };
    let cluster_owns = |cluster: &TrustedExecutionCluster| {
        let uid = cluster.metadata.uid.as_ref();
        uid.and_then(uid_owns).unwrap_or(false)
    };
    // Adopt the image by adding TEC as owner reference if not already owned
    if let Some(cluster) = cluster
        && !cluster_owns(&cluster)
    {
        adopt_approved_image(client.clone(), name, &cluster).await?;
    }

    let (action, reason) = match handle_new_image(client.clone(), image).await {
        Ok(reason) => (Action::await_change(), reason),
        Err(e) => {
            warn!("PCR computation for {name} failed: {e}");
            let action = Action::requeue(Duration::from_secs(60));
            (action, NOT_COMMITTED_REASON_FAILED)
        }
    };
    let committed = committed_condition(reason, image.metadata.generation, &image.status);

    // Upserting the committed condition and keeping the existing conditions intact.
    let mut conditions = image.status.as_ref().and_then(|s| s.conditions.clone());
    let changed = upsert_condition(&mut conditions, committed);
    if changed {
        let images: Api<ApprovedImage> = Api::default_namespaced(client);
        update_status!(images, &name, ApprovedImageStatus { conditions })
            .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into()))?;
    }
    Ok(action)
}

async fn image_remove_reconcile(
    client: Client,
    image: Arc<ApprovedImage>,
    cluster: Option<TrustedExecutionCluster>,
) -> Result<Action> {
    let default = "<no name>".to_string();
    let name = image.metadata.name.as_ref().unwrap_or(&default);
    if cluster.is_none() {
        info!("No TrustedExecutionCluster found, skipping disallow_image for {name}");
        return Ok(Action::await_change());
    }
    let cluster = cluster.unwrap();
    let tec_name = cluster.metadata.name.unwrap_or("<no name>".to_string());
    if cluster.metadata.deletion_timestamp.is_some() {
        info!(
            "TrustedExecutionCluster {tec_name} is being deleted, \
             skipping disallow_image for {name}"
        );
        return Ok(Action::await_change());
    }
    disallow_image(client, name).await?;
    Ok(Action::await_change())
}

pub async fn launch_rv_image_controller(client: Client) {
    let images: Api<ApprovedImage> = Api::default_namespaced(client.clone());
    tokio::spawn(
        Controller::new(images, Default::default())
            .run(image_reconcile, controller_error_policy, Arc::new(client))
            .for_each(controller_info),
    );
}

async fn is_pending(client: &Client, resource_name: &str) -> Result<bool> {
    let pods: Api<Pod> = Api::default_namespaced(client.clone());
    let lp = ListParams::default().labels(&format!("{APPROVED_IMAGE_ANNOTATION}={resource_name}"));
    let pod_list = pods.list(&lp).await?;
    Ok(pod_list
        .iter()
        .max_by_key(|pod| pod.metadata.creation_timestamp.as_ref().map(|t| t.0))
        .and_then(|pod| pod.status.as_ref().and_then(|s| s.phase.as_ref()))
        .is_some_and(|phase| phase == "Pending"))
}

pub async fn handle_new_image(client: Client, image: &ApprovedImage) -> Result<&'static str> {
    let resource_name = image.metadata.name.as_ref().unwrap();
    let boot_image = image.spec.image.as_ref();
    let config_maps: Api<ConfigMap> = Api::default_namespaced(client.clone());
    let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let mut image_pcrs = get_image_pcrs(image_pcrs_map.clone())?;
    if let Some(pcr) = image_pcrs.0.get(resource_name)
        && pcr.reference == boot_image
    {
        info!("Image {boot_image} was to be allowed, but already was allowed");
        let res = trustee::update_reference_values(client).await;
        return res.map(|_| COMMITTED_REASON);
    }
    let image_ref: oci_client::Reference = boot_image.parse()?;
    if image_ref.digest().is_none() {
        warn!(
            "Image {boot_image} did not specify a digest. \
             Only images with a digest are supported to avoid ambiguity."
        );
        return Ok(NOT_COMMITTED_REASON_NO_DIGEST);
    }
    let label = fetch_pcr_label(&image_ref).await;

    // Whether to compute pcrs or not.
    let should_compute_pcrs = match label {
        Err(ref e) => {
            warn!("Fetching PCR label for {image_ref} failed: {e}. Falling back to computation.");
            if is_pending(&client, resource_name).await? {
                return Ok(NOT_COMMITTED_REASON_PENDING);
            }
            true
        }
        Ok(None) => {
            info!("No {PCR_LABEL} label present for {image_ref}. Computing.");
            true
        }
        _ => false,
    };
    if should_compute_pcrs {
        let err = NOT_COMMITTED_REASON_COMPUTING;
        return compute_fresh_pcrs(client, image).await.map(|_| err);
    }

    let image_pcr = ImagePcr {
        first_seen: Timestamp::now(),
        pcrs: label.unwrap().unwrap(),
        reference: boot_image.to_string(),
    };
    image_pcrs.0.insert(resource_name.to_string(), image_pcr);
    update_image_pcrs!(config_maps, image_pcrs_map, image_pcrs);
    trustee::update_reference_values(client)
        .await
        .map(|_| COMMITTED_REASON)
}

pub async fn disallow_image(client: Client, resource_name: &str) -> Result<()> {
    let config_maps: Api<ConfigMap> = Api::default_namespaced(client.clone());
    let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let mut image_pcrs = get_image_pcrs(image_pcrs_map.clone())?;
    if image_pcrs.0.remove(resource_name).is_none() {
        info!("Image {resource_name} was to be disallowed, but already was not allowed");
    }
    update_image_pcrs!(config_maps, image_pcrs_map, image_pcrs);
    trustee::update_reference_values(client).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use http::{Method, Request, StatusCode};
    use k8s_openapi::api::batch::v1::JobStatus;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use kube::api::ObjectList;
    use kube::client::Body;
    use trusted_cluster_operator_test_utils::mock_client::*;
    use trusted_cluster_operator_test_utils::test_error_method;

    const DUMMY_IMAGE_REF: &str =
        "quay.io/some-ref@sha256:e71dad00aa0e3d70540e726a0c66407e3004d96e045ab6c253186e327a2419e5";

    #[tokio::test]
    async fn test_create_pcrs_cm_success() {
        let clos = |client| create_pcrs_config_map(client);
        test_create_success::<_, _, ConfigMap>(clos).await;
    }

    #[tokio::test]
    async fn test_create_pcrs_cm_exists() {
        let clos = |client| create_pcrs_config_map(client);
        test_create_already_exists(clos).await;
    }

    #[tokio::test]
    async fn test_create_pcrs_cm_error() {
        let clos = |client| create_pcrs_config_map(client);
        test_error_method!(clos, Method::POST);
    }

    fn dummy_image() -> ApprovedImage {
        ApprovedImage {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                uid: Some("test".to_string()),
                ..Default::default()
            },
            spec: ApprovedImageSpec {
                image: DUMMY_IMAGE_REF.to_string(),
            },
            status: None,
        }
    }

    fn dummy_job() -> Job {
        Job {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            status: Some(JobStatus {
                completion_time: Some(Time(Timestamp::now())),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_job_reconcile_success() {
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::DELETE) => Ok(serde_json::to_string(&Job::default()).unwrap()),
            (1, &Method::GET) => {
                assert!(req.uri().path().contains(PCR_CONFIG_MAP));
                Ok(serde_json::to_string(&dummy_pcrs_map()).unwrap())
            }
            (2, &Method::GET) | (3, &Method::PUT) => {
                assert!(req.uri().path().contains(trustee::TRUSTEE_DATA_MAP));
                Ok(serde_json::to_string(&dummy_trustee_map()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(4, clos, |client| {
            let job = Arc::new(dummy_job());
            let result = job_reconcile(job, Arc::new(client)).await.unwrap();
            assert_eq!(result, Action::await_change());
        });
    }

    #[tokio::test]
    async fn test_job_reconcile_begun_deletion() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let mut job = dummy_job();
            let status = job.status.as_mut().unwrap();
            status.completion_time = None;
            let result = job_reconcile(Arc::new(job), Arc::new(client)).await;
            assert_eq!(result.unwrap(), Action::requeue(Duration::from_secs(300)));
        });
    }

    #[test]
    fn test_get_job_name_trailing_dash() {
        let name = get_job_name("quay.io/some_ref:some-tag-").unwrap();
        assert_eq!(name, "compute-pcrs-105a7802d8-quay-io-some-ref-some-tag");
    }

    #[test]
    fn test_get_job_name_sha() {
        let name = get_job_name(DUMMY_IMAGE_REF).unwrap();
        assert_eq!(
            name,
            "compute-pcrs-6c57e93939-quay-io-some-ref-sha256-e71dad00aa0e3d7"
        );
    }

    #[tokio::test]
    async fn test_compute_fresh_pcrs_success() {
        let image = dummy_image();
        let clos = |client| compute_fresh_pcrs(client, &image);
        test_create_success::<_, _, Job>(clos).await;
    }

    #[tokio::test]
    async fn test_compute_fresh_pcrs_error() {
        let image = dummy_image();
        let clos = |client| compute_fresh_pcrs(client, &image);
        test_error_method!(clos, Method::POST);
    }

    #[tokio::test]
    async fn test_adopt_approved_image() {
        let cluster = dummy_cluster();
        let clos = async |req: Request<Body>, _| {
            assert_body_contains(req, TEST_UID).await;
            Ok(serde_json::to_string(&dummy_image()).unwrap())
        };
        count_check!(1, clos, |client| {
            assert!(adopt_approved_image(client, "test", &cluster).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_adopt_approved_image_error() {
        let cluster = dummy_cluster();
        let clos = |client| adopt_approved_image(client, "test", &cluster);
        test_error_method!(clos, Method::PATCH);
    }

    #[tokio::test]
    async fn test_adopt_approved_images() {
        let cluster = dummy_cluster();
        let clos = async |req: Request<_>, ctr| {
            if ctr == 0 && req.method() == Method::GET {
                let mut deleted = dummy_image();
                deleted.metadata.deletion_timestamp = Some(Time(Timestamp::now()));
                let list = ObjectList {
                    items: vec![dummy_image(), deleted, dummy_image()],
                    types: Default::default(),
                    metadata: Default::default(),
                };
                Ok(serde_json::to_string(&list).unwrap())
            } else if ctr < 3 && req.method() == Method::PATCH {
                Ok(serde_json::to_string(&dummy_image()).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}, counter {ctr}")
            }
        };
        count_check!(3, clos, |client| {
            assert!(adopt_approved_images(client, &cluster).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_adopt_approved_images_error() {
        let cluster = dummy_cluster();
        let clos = |client| adopt_approved_images(client, &cluster);
        test_error_method!(clos, Method::GET);
    }

    // handle_new_image and its caller image_add_reconcile are
    // inherently online functions and not tested here

    #[tokio::test]
    async fn test_image_remove_reconcile() {
        let image = Arc::new(dummy_image());
        let cluster = Some(dummy_cluster());
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            // fetched & updated for removal, then fetched for recomputation
            (0, &Method::GET) | (1, &Method::PUT) | (2, &Method::GET) => {
                assert!(req.uri().path().contains(PCR_CONFIG_MAP));
                Ok(serde_json::to_string(&dummy_pcrs_map()).unwrap())
            }
            (3, &Method::GET) | (4, &Method::PUT) => {
                assert!(req.uri().path().contains(trustee::TRUSTEE_DATA_MAP));
                Ok(serde_json::to_string(&dummy_trustee_map()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(5, clos, |client| {
            assert!(image_remove_reconcile(client, image, cluster).await.is_ok());
        });
    }
}
