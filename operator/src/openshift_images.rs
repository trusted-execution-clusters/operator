// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;
use kube::core::{Expression, Selector, SelectorExt};
use kube::runtime::events::EventType;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::{Controller, controller::Action, reflector::ObjectRef};
use kube::{Api, Resource, ResourceExt, api::ObjectMeta};
use log::warn;
use std::{collections::BTreeMap, sync::Arc};

use operator::*;
use trusted_cluster_operator_lib::machineconfigpools::MachineConfigPool;
use trusted_cluster_operator_lib::machineconfigs::MachineConfig;
use trusted_cluster_operator_lib::{reference_values::*, *};

const MC_LABEL: &str = "trusted-execution-clusters.io/based-on-machineconfig";
const MC_LABEL_PREFIX: &str = "mc";

/// Check if MCP is labelled to autocreate images and MCP's label selectors would select MC
fn is_live(mcp: &MachineConfigPool, mc: &MachineConfig) -> bool {
    let mcp_labels = mcp.metadata.labels.as_ref();
    if mcp_labels.is_none_or(|ls| !ls.contains_key(MCP_APPROVED_IMAGE_LABEL)) {
        return false;
    }
    let mc_labels = mc.metadata.labels.clone().unwrap_or_default();

    let selector = &mcp.spec.machine_config_selector;
    let match_exps = selector.as_ref().and_then(|s| s.match_expressions.clone());
    let match_labels = selector.as_ref().and_then(|s| s.match_labels.clone());
    // Only consider matched when there were any criteria at all
    let match_any = match_exps.is_some() || match_labels.is_some();

    let exp_match = match_exps.is_none_or(|exps| {
        let mut selector = Selector::default();
        for mcp_exp in exps {
            let req = LabelSelectorRequirement {
                key: mcp_exp.key,
                operator: mcp_exp.operator,
                values: mcp_exp.values,
            };
            match Expression::try_from(req) {
                Ok(exp) => selector.extend(exp),
                Err(e) => {
                    let mc_warn = format!("refusing to check liveness of MC {}", mc.name_any());
                    let mcp_warn =
                        format!("failed to parse match expression of MCP {}", mcp.name_any());
                    warn!("{mc_warn}: {mcp_warn}: {e}");
                    return false;
                }
            };
        }
        selector.matches(&mc_labels)
    });

    let label_match =
        match_labels.is_none_or(|ls| ls.iter().all(|(k, v)| mc_labels.get(k) == Some(v)));
    match_any && exp_match && label_match
}

async fn add_approved_image(
    image_name: String,
    labels: BTreeMap<String, String>,
    url: String,
    ctx: &OperatorContext,
) -> Result<ObjectReference> {
    let image = ApprovedImage {
        metadata: ObjectMeta {
            name: Some(image_name),
            labels: Some(labels),
            ..Default::default()
        },
        spec: ApprovedImageSpec { image: url },
        status: None,
    };
    create_or_info_if_exists(ctx.client.clone(), &image).await?;
    Ok(image.object_ref(&()))
}

async fn add_mc_image(mc: &MachineConfig, ctx: &OperatorContext) -> Result<()> {
    let err = "MachineConfig changed, but had no name";
    let mc_name = mc.metadata.name.as_ref().context(err)?;
    let url = match mc.spec.os_image_url.clone() {
        Some(url) if !url.is_empty() => url,
        _ => {
            warn!("Registered MC {mc_name}, but it had no osImageURL");
            return Ok(());
        }
    };

    let image_name = rfc1035(&format!("{mc_name}-{url}"), OSIMAGE_RESOURCE_PREFIX)?;
    let mc_label_value = rfc1035(mc_name, MC_LABEL_PREFIX)?;
    let labels = BTreeMap::from([(MC_LABEL.to_string(), mc_label_value)]);

    let mc_ref = mc.object_ref(&());
    let log = format!(
        "ApprovedImage {image_name}, URL {url} added based on osImageURL of MachineConfig {mc_name}"
    );
    let img_ref = add_approved_image(image_name, labels, url, ctx).await?;
    record_event(
        &ctx.recorder,
        &mc_ref,
        EventType::Normal,
        "MachineconfigImageAdded",
        log,
        "Adding",
        Some(img_ref),
    )
    .await;
    Ok(())
}

async fn mc_reconcile(
    mc: Arc<MachineConfig>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let live = ctx.mcp_store.find(|mcp| is_live(mcp, &mc)).is_some();
    let url = mc.spec.os_image_url.as_ref();
    let is_stored = |i: &ApprovedImage| {
        url.is_some_and(|u| *u == i.spec.image)
            && match (i.metadata.labels.as_ref(), mc.metadata.name.as_ref()) {
                (Some(labels), Some(name)) => labels
                    .get(MC_LABEL)
                    .is_some_and(|m| rfc1035(name, MC_LABEL_PREFIX).ok().is_some_and(|l| l == *m)),
                _ => false,
            }
    };
    if live && ctx.image_store.find(is_stored).is_none() {
        add_mc_image(&mc, &ctx).await.map_err(controller_into)?;
    }
    Ok(LONG_REQUEUE)
}

pub async fn launch_rv_mc_controller(ctx: Arc<OperatorContext>) {
    let mcs: Api<MachineConfig> = Api::all(ctx.client.clone());
    let mcps: Api<MachineConfigPool> = Api::all(ctx.client.clone());
    let mcp_ctx = ctx.clone();
    let wc = WatcherConfig {
        label_selector: Some(MCP_APPROVED_IMAGE_LABEL.to_string()),
        ..Default::default()
    };
    tokio::spawn(
        Controller::new(mcs, Default::default())
            .watches(mcps, wc, move |mcp| {
                // TODO if building removal logic, check against all MCPs
                let mcs = mcp_ctx.mc_store.state_filter(|mc| is_live(&mcp, mc));
                mcs.into_iter()
                    .filter_map(|mc| mc.metadata.name.as_deref().map(ObjectRef::new))
                    .collect::<Vec<_>>()
            })
            .run(mc_reconcile, controller_error_policy, ctx)
            .for_each(controller_info),
    );
}
