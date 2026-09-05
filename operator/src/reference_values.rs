// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use compute_pcrs_lib::Pcr;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::api::{
    batch::v1::{Job, JobSpec},
    core::v1::{Container, ImageVolumeSource, Volume, VolumeMount},
    core::v1::{Pod, PodSpec, PodTemplateSpec},
};
use kube::api::{DeleteParams, ListParams, ObjectMeta, Patch};
use kube::runtime::{
    controller::{Action, Controller},
    events::EventType,
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
use crate::trustee;
use operator::{ControllerError, KIND_LABEL_KEY, LONG_REQUEUE, OperatorContext, upsert_condition};
use operator::{controller_error_policy, controller_info, create_or_info_if_exists};
use trusted_cluster_operator_lib::{conditions::*, record_event, reference_values::*, *};

const APPROVED_IMAGE_ANNOTATION: &str = "approved-image";
const PCR_COMMAND_NAME: &str = "compute-pcrs";
/// Requeue to recheck PCR jobs status.
const PCR_COMPUTING_REQUEUE: Duration = Duration::from_secs(30);
const PCR_LABEL: &str = "org.coreos.pcrs";
/// Finalizer name to discard reference values when an image is no longer approved
const APPROVED_IMAGE_FINALIZER: &str = "finalizer.approved-image.trusted-execution-clusters.io";

/// Synchronize with compute_pcrs_cli::Output
#[derive(Deserialize)]
struct ComputePcrsOutput {
    pcrs: Vec<Pcr>,
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

async fn job_reconcile(
    job: Arc<Job>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let err = "Job changed, but had no name";
    let name = &job.metadata.name.clone().context(err)?;
    let err = format!("Job {name} changed, but had no status");
    let status = &job.status.clone().context(err)?;
    if status.completion_time.is_none() {
        info!("Job {name} changed, but had not completed");
        return Ok(Action::requeue(Duration::from_secs(300)));
    }
    let jobs: Api<Job> = Api::default_namespaced(ctx.client.clone());
    // Foreground deletion: Delete the pod too
    let delete = jobs.delete(name, &DeleteParams::foreground()).await;
    delete.map_err(Into::<anyhow::Error>::into)?;
    trustee::update_reference_values(&ctx).await?;

    if let Some(owner) = job
        .metadata
        .owner_references
        .as_ref()
        .and_then(|refs| refs.iter().find(|r| r.kind == "ApprovedImage"))
    {
        let image_ref = ObjectReference {
            api_version: Some(owner.api_version.clone()),
            kind: Some(owner.kind.clone()),
            name: Some(owner.name.clone()),
            namespace: job.metadata.namespace.clone(),
            uid: Some(owner.uid.clone()),
            ..Default::default()
        };
        record_event(
            &ctx.recorder,
            &image_ref,
            EventType::Normal,
            "ComputationCompleted",
            format!("Reference values computed for {}", owner.name),
            "Computing",
            None,
        )
        .await;
    }
    Ok(LONG_REQUEUE)
}

pub async fn launch_rv_job_controller(ctx: Arc<OperatorContext>) {
    let jobs: Api<Job> = Api::default_namespaced(ctx.client.clone());
    let watcher = watcher::Config {
        label_selector: Some(format!("{KIND_LABEL_KEY}={PCR_COMMAND_NAME}")),
        ..Default::default()
    };
    tokio::spawn(
        Controller::new(jobs, watcher)
            .run(job_reconcile, controller_error_policy, ctx)
            .for_each(controller_info),
    );
}

/// Deletes the compute-pcrs Job for `boot_image`
// 404 is success: the Job may already have been deleted.
pub(crate) async fn delete_compute_pcrs_job(client: &Client, boot_image: &str) -> Result<()> {
    let job_name = get_job_name(boot_image)?;
    let jobs: Api<Job> = Api::default_namespaced(client.clone());
    match jobs.delete(&job_name, &DeleteParams::foreground()).await {
        Ok(_) => info!("Deleted Job {job_name} for PCR recomputation"),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            info!("Job {job_name} already absent");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
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
                KIND_LABEL_KEY.to_string(),
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
    ctx: &OperatorContext,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    for image in ctx.image_store.state() {
        if image.metadata.deletion_timestamp.is_none()
            && let Some(name) = image.metadata.name.as_ref()
        {
            adopt_approved_image(ctx.client.clone(), name, cluster).await?;
        }
    }
    Ok(())
}

async fn image_reconcile(
    image: Arc<ApprovedImage>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let kube_client = ctx.client.clone();
    let err = "ApprovedImage had no name";
    let name = image.metadata.name.clone().context(err)?;
    let map_ctl = |e: anyhow::Error| -> ControllerError { e.into() };
    let cluster = ctx.get_opt_tec().map_err(map_ctl)?;

    let uid_owns = |uid: &String| {
        let refs = image.metadata.owner_references.as_ref();
        refs.map(|os| os.iter().any(|o| o.uid == *uid))
    };
    let cluster_owns = |cluster: &TrustedExecutionCluster| {
        let uid = cluster.metadata.uid.as_ref();
        uid.and_then(uid_owns).unwrap_or(false)
    };

    if let Some(ref cluster) = cluster
        && !cluster_owns(cluster)
    {
        adopt_approved_image(kube_client.clone(), &name, cluster)
            .await
            .map_err(map_ctl)?;
    }

    let images: Api<ApprovedImage> = Api::default_namespaced(kube_client.clone());
    finalizer(&images, APPROVED_IMAGE_FINALIZER, image, |ev| async {
        match ev {
            Event::Apply(image) => image_add_reconcile(&ctx, &image, cluster)
                .await
                .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into())),
            Event::Cleanup(image) => image_remove_reconcile(&ctx, image, cluster)
                .await
                .map_err(|e| finalizer::Error::<ControllerError>::CleanupFailed(e.into())),
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile on image {name}: {e}").into())
}

async fn image_add_reconcile(
    ctx: &OperatorContext,
    image: &ApprovedImage,
    cluster: Option<TrustedExecutionCluster>,
) -> Result<Action> {
    let name = image.metadata.name.as_ref().unwrap();
    let Some(cluster) = cluster else {
        info!("No TrustedExecutionCluster found, deferring image processing for {name}");
        return Ok(Action::requeue(Duration::from_secs(5)));
    };
    // If the cluster is being deleted, defer the image processing
    if cluster.metadata.deletion_timestamp.is_some() {
        info!("TrustedExecutionCluster is being deleted, deferring image processing for {name}");
        return Ok(Action::requeue(Duration::from_secs(5)));
    }
    let image_ref: ObjectReference = image.object_ref(&());
    let (action, reason) = match handle_new_image(ctx, image).await {
        Ok(NOT_COMMITTED_REASON_COMPUTING) => {
            record_event(
                &ctx.recorder,
                &image_ref,
                EventType::Normal,
                "ComputationStarted",
                format!("PCR computation started for {name}"),
                "Computing",
                None,
            )
            .await;
            (
                Action::requeue(PCR_COMPUTING_REQUEUE),
                NOT_COMMITTED_REASON_COMPUTING,
            )
        }
        Ok(reason) => (LONG_REQUEUE, reason),
        Err(e) => {
            warn!("PCR computation for {name} failed: {e}");
            record_event(
                &ctx.recorder,
                &image_ref,
                EventType::Warning,
                "ComputationFailed",
                format!("PCR computation for {name} failed: {e}"),
                "Computing",
                None,
            )
            .await;
            let action = Action::requeue(Duration::from_secs(60));
            (action, NOT_COMMITTED_REASON_FAILED)
        }
    };
    let committed = committed_condition(reason, image.metadata.generation, &image.status);

    // Upserting the committed condition and keeping the existing conditions intact.
    let mut conditions = image.status.as_ref().and_then(|s| s.conditions.clone());
    let changed = upsert_condition(&mut conditions, committed);
    if changed {
        let images: Api<ApprovedImage> = Api::default_namespaced(ctx.client.clone());
        update_status!(
            images,
            &name,
            ApprovedImageStatus {
                conditions,
                pcrs: image.status.as_ref().and_then(|s| s.pcrs.clone()),
                first_seen: image.status.as_ref().and_then(|s| s.first_seen.clone()),
            }
        )
        .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into()))?;
    }
    Ok(action)
}

async fn image_remove_reconcile(
    ctx: &OperatorContext,
    image: Arc<ApprovedImage>,
    cluster: Option<TrustedExecutionCluster>,
) -> Result<Action> {
    let default = "<no name>".to_string();
    let name = image.metadata.name.as_ref().unwrap_or(&default);
    if cluster.is_none() {
        info!("No TrustedExecutionCluster found, skipping disallow_image for {name}");
        return Ok(LONG_REQUEUE);
    }
    let cluster = cluster.unwrap();
    let tec_name = cluster.metadata.name.unwrap_or("<no name>".to_string());
    if cluster.metadata.deletion_timestamp.is_some() {
        info!(
            "TrustedExecutionCluster {tec_name} is being deleted, \
             skipping disallow_image for {name}"
        );
        return Ok(LONG_REQUEUE);
    }
    disallow_image(ctx, name).await?;
    Ok(LONG_REQUEUE)
}

pub async fn launch_rv_image_controller(ctx: Arc<OperatorContext>) {
    let images: Api<ApprovedImage> = Api::default_namespaced(ctx.client.clone());
    let jobs: Api<Job> = Api::default_namespaced(ctx.client.clone());
    let wc = watcher::Config::default().labels(&format!("{KIND_LABEL_KEY}={PCR_COMMAND_NAME}"));
    tokio::spawn(
        Controller::new(images, Default::default())
            .owns(jobs, wc)
            .run(image_reconcile, controller_error_policy, ctx)
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

pub async fn handle_new_image(
    ctx: &OperatorContext,
    image: &ApprovedImage,
) -> Result<&'static str> {
    let resource_name = image.metadata.name.as_ref().unwrap();
    let boot_image: &str = &image.spec.image;

    let is_committed = image
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|cs| {
            cs.iter()
                .any(|c| c.type_ == COMMITTED_CONDITION && c.status == "True")
        });
    if is_committed
        && image
            .status
            .as_ref()
            .and_then(|s| s.pcrs.as_ref())
            .is_some()
    {
        info!("Image {boot_image} was to be allowed, but already was committed");
        // Trustee Deployment reconcile restores RVs after Trustee restarts.
        // New PCRs are pushed from the label path and job_reconcile.
        return Ok(COMMITTED_REASON);
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

    let should_compute_pcrs = match label {
        Err(ref e) => {
            warn!("Fetching PCR label for {image_ref} failed: {e}. Falling back to computation.");
            if is_pending(&ctx.client, resource_name).await? {
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
        return compute_fresh_pcrs(ctx.client.clone(), image)
            .await
            .map(|_| NOT_COMMITTED_REASON_COMPUTING);
    }

    let pcrs = label.unwrap().unwrap();
    let status_pcrs = pcrs_to_status(&pcrs);

    let committed = committed_condition(COMMITTED_REASON, image.metadata.generation, &image.status);
    let conditions = Some(vec![committed]);
    let first_seen = image
        .status
        .as_ref()
        .and_then(|s| s.first_seen.clone())
        .or_else(|| Some(chrono::Utc::now().to_rfc3339()));
    let images: Api<ApprovedImage> = Api::default_namespaced(ctx.client.clone());
    let status = ApprovedImageStatus {
        conditions,
        pcrs: Some(status_pcrs),
        first_seen,
    };
    update_status!(images, resource_name, status)?;

    trustee::update_reference_values(ctx)
        .await
        .map(|_| COMMITTED_REASON)
}

pub async fn disallow_image(ctx: &OperatorContext, resource_name: &str) -> Result<()> {
    info!("Disallowing image {resource_name}, recomputing reference values");
    trustee::update_reference_values(ctx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use http::{Method, Request, StatusCode};
    use k8s_openapi::api::batch::v1::JobStatus;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use k8s_openapi::jiff::Timestamp;
    use kube::api::ObjectList;
    use kube::client::Body;
    use trusted_cluster_operator_test_utils::mock_client::*;
    use trusted_cluster_operator_test_utils::test_error_method;

    fn op_ctx_with_images(client: Client, images: Vec<ApprovedImage>) -> OperatorContext {
        let mut ctx = OperatorContext::new(client);
        ctx.image_store = store_with(images);
        ctx
    }

    const DUMMY_IMAGE_REF: &str =
        "quay.io/some-ref@sha256:e71dad00aa0e3d70540e726a0c66407e3004d96e045ab6c253186e327a2419e5";

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
        let _ = jsonwebtoken_openssl::install_default();
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::DELETE) => Ok(serde_json::to_string(&Job::default()).unwrap()),
            (1, &Method::GET) => {
                let list = ObjectList::<ApprovedImage> {
                    items: vec![],
                    types: Default::default(),
                    metadata: Default::default(),
                };
                Ok(serde_json::to_string(&list).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, clos, |client| {
            let mut auth = dummy_trustee_auth();
            auth.metadata.name = Some("trustee-auth".to_string());
            let mut ctx = OperatorContext::new(client);
            ctx.secret_store = store_with(vec![auth]);
            ctx.tec_store = store_with(vec![dummy_cluster()]);
            let job = Arc::new(dummy_job());
            assert!(job_reconcile(job, Arc::new(ctx)).await.is_err());
        });
    }

    #[tokio::test]
    async fn test_job_reconcile_begun_deletion() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let mut job = dummy_job();
            let status = job.status.as_mut().unwrap();
            status.completion_time = None;
            let ctx = Arc::new(OperatorContext::new(client));
            let result = job_reconcile(Arc::new(job), ctx).await;
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
    async fn test_delete_compute_pcrs_job_not_found() {
        let clos = async |req: Request<_>, _| {
            assert_eq!(req.method(), &Method::DELETE);
            Err(StatusCode::NOT_FOUND)
        };
        count_check!(1, clos, |client| {
            delete_compute_pcrs_job(&client, DUMMY_IMAGE_REF)
                .await
                .unwrap();
        });
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
        let mut deleted = dummy_image();
        deleted.metadata.name = Some("deleted".to_string());
        deleted.metadata.deletion_timestamp = Some(Time(Timestamp::now()));
        let mut second = dummy_image();
        second.metadata.name = Some("second".to_string());
        let clos = async |req: Request<_>, ctr| {
            if ctr < 2 && req.method() == Method::PATCH {
                Ok(serde_json::to_string(&dummy_image()).unwrap())
            } else {
                panic!("unexpected API interaction: {req:?}, counter {ctr}")
            }
        };
        count_check!(2, clos, |client| {
            let ctx = op_ctx_with_images(client, vec![dummy_image(), deleted, second]);
            assert!(adopt_approved_images(&ctx, &cluster).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_adopt_approved_images_error() {
        let cluster = dummy_cluster();
        let clos = async |req: Request<_>, _| match req.method() {
            &Method::PATCH => Err(StatusCode::INTERNAL_SERVER_ERROR),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        count_check!(1, clos, |client| {
            let ctx = op_ctx_with_images(client, vec![dummy_image()]);
            assert!(adopt_approved_images(&ctx, &cluster).await.is_err());
        });
    }

    #[tokio::test]
    async fn test_image_remove_reconcile() {
        let _ = jsonwebtoken_openssl::install_default();
        let image = Arc::new(dummy_image());
        let cluster = Some(dummy_cluster());
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => {
                let list = ObjectList::<ApprovedImage> {
                    items: vec![],
                    types: Default::default(),
                    metadata: Default::default(),
                };
                Ok(serde_json::to_string(&list).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(1, clos, |client| {
            let mut auth = dummy_trustee_auth();
            auth.metadata.name = Some("trustee-auth".to_string());
            let mut ctx = OperatorContext::new(client);
            ctx.secret_store = store_with(vec![auth]);
            ctx.tec_store = store_with(vec![dummy_cluster()]);
            assert!(image_remove_reconcile(&ctx, image, cluster).await.is_err());
        });
    }
}
