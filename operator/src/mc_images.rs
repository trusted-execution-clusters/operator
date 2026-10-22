// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use futures_util::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;
use kube::core::{Expression, Selector, SelectorExt};
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::{Controller, controller::Action, reflector::ObjectRef};
use kube::{Api, ResourceExt, api::ObjectMeta};
use log::warn;
use std::{collections::BTreeMap, sync::Arc};

use operator::*;
use trusted_cluster_operator_lib::machineconfigpools::MachineConfigPool;
use trusted_cluster_operator_lib::machineconfigs::MachineConfig;
use trusted_cluster_operator_lib::{reference_values::*, *};

const MC_LABEL: &str = "trusted-execution-clusters.io/based-on-machineconfig";

/// Check if MCP is labelled to autocreate images and MCP's label selectors would select MC
fn is_live(mcp: &MachineConfigPool, mc: &MachineConfig) -> bool {
    let mcp_labels = mcp.metadata.labels.as_ref();
    if mcp_labels.is_none_or(|ls| !ls.contains_key(MCP_APPROVED_IMAGE_LABEL)) {
        return false;
    }
    let Some(mc_labels) = mc.metadata.labels.as_ref() else {
        return false;
    };

    let selector = &mcp.spec.machine_config_selector;
    let match_exps = selector.as_ref().and_then(|s| s.match_expressions.clone());
    let match_labels = selector.as_ref().and_then(|s| s.match_labels.clone());
    // Only consider matched when there were any criteria at all
    let match_any = match_exps.is_some() || match_labels.is_some();

    let exp_match = match_exps.is_none_or(|exps| {
        let mut selector = Selector::default();
        for mcp_exp in exps {
            let exp = Expression::try_from(LabelSelectorRequirement {
                key: mcp_exp.key,
                operator: mcp_exp.operator,
                values: mcp_exp.values,
            });
            if let Ok(exp) = exp {
                selector.extend(exp);
            } else if let Err(e) = exp {
                let name = mcp.name_any();
                warn!("failed to parse MCP {name}'s match expression: {e}",);
            };
        }
        selector.matches(mc_labels)
    });

    let label_match =
        match_labels.is_none_or(|ls| ls.iter().all(|(k, v)| mc_labels.get(k) == Some(v)));
    match_any && exp_match && label_match
}

fn is_stored(image: &ApprovedImage, mc: &MachineConfig) -> bool {
    match (image.metadata.labels.as_ref(), mc.metadata.name.as_ref()) {
        (Some(labels), Some(name)) => labels.get(MC_LABEL).is_some_and(|m| *m == *name),
        _ => false,
    }
}

async fn add_approved_image(mc: &MachineConfig, ctx: &OperatorContext) -> Result<Action> {
    let err = "MachineConfig changed, but had no name";
    let mc_name = mc.metadata.name.as_ref().context(err)?;
    let url = match mc.spec.os_image_url.clone() {
        Some(url) if !url.is_empty() => url,
        _ => {
            warn!("Registered MC {mc_name}, but it had no osImageURL");
            return Ok(LONG_REQUEUE);
        }
    };

    let image_name = rfc1035(&format!("{mc_name}-{url}"), OSIMAGE_RESOURCE_PREFIX)?;
    let labels = BTreeMap::from([(MC_LABEL.to_string(), mc_name.to_string())]);
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
    Ok(LONG_REQUEUE)
}

async fn mc_reconcile(
    mc: Arc<MachineConfig>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let live = ctx.mcp_store.find(|mcp| is_live(mcp, &mc)).is_some();
    if live && ctx.image_store.find(|i| is_stored(i, &mc)).is_none() {
        let map_ctl = |e: anyhow::Error| -> ControllerError { e.into() };
        return add_approved_image(&mc, &ctx).await.map_err(map_ctl);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{DUMMY_IMAGE_REF, dummy_image, store_with};

    use http::{Method, Request, StatusCode};
    use kube::client::Body;
    use machineconfigpools::MachineConfigPoolMachineConfigSelector;
    use machineconfigpools::MachineConfigPoolMachineConfigSelectorMatchExpressions;
    use trusted_cluster_operator_test_utils::mock_client::*;

    const MAPI_ROLE: &str = "machineconfiguration.openshift.io/role";
    const MC_NAME: &str = "worker-cvm";

    fn match_labels() -> BTreeMap<String, String> {
        BTreeMap::from([(MAPI_ROLE.to_string(), MC_NAME.to_string())])
    }

    fn dummy_mc() -> MachineConfig {
        let mut mc = MachineConfig::default();
        mc.metadata.name = Some(MC_NAME.to_string());
        mc.metadata.labels = Some(match_labels());
        mc.spec.os_image_url = Some(DUMMY_IMAGE_REF.to_string());
        mc
    }

    fn dummy_mcp() -> MachineConfigPool {
        let mut mcp = MachineConfigPool::default();
        mcp.metadata.name = Some(MC_NAME.to_string());
        mcp.metadata.labels = Some(BTreeMap::from([(
            MCP_APPROVED_IMAGE_LABEL.to_string(),
            String::new(),
        )]));
        mcp.spec.machine_config_selector = Some(MachineConfigPoolMachineConfigSelector {
            match_expressions: None,
            match_labels: Some(match_labels()),
        });
        mcp
    }

    #[test]
    fn test_is_live_exp() {
        let mut mcp = dummy_mcp();
        let label_value = match_labels().get(MAPI_ROLE).unwrap().to_string();
        let exp = MachineConfigPoolMachineConfigSelectorMatchExpressions {
            key: MAPI_ROLE.to_string(),
            operator: "In".to_string(),
            values: Some(vec![label_value, "whatever".to_string()]),
        };
        mcp.spec.machine_config_selector = Some(MachineConfigPoolMachineConfigSelector {
            match_expressions: Some(vec![exp]),
            match_labels: None,
        });

        let mut mc = dummy_mc();
        let match_labels = mc.metadata.labels.as_mut().unwrap();
        match_labels.insert("something".to_string(), "else".to_string());
        assert!(is_live(&mcp, &mc));

        let selector = mcp.spec.machine_config_selector.as_mut().unwrap();
        let exps = selector.match_expressions.as_mut().unwrap();
        exps.push(MachineConfigPoolMachineConfigSelectorMatchExpressions {
            key: "foo".to_string(),
            operator: "Exists".to_string(),
            values: None,
        });
        assert!(!is_live(&mcp, &mc));
    }

    #[test]
    fn test_is_live_label() {
        let mut mcp = dummy_mcp();
        let mut mc = dummy_mc();
        let mut labels = match_labels();
        labels.insert("something".to_string(), "else".to_string());
        mc.metadata.labels = Some(labels);
        assert!(is_live(&mcp, &mc));

        let selector = mcp.spec.machine_config_selector.as_mut().unwrap();
        let labels = selector.match_labels.as_mut().unwrap();
        labels.insert("foo".to_string(), "bar".to_string());
        assert!(!is_live(&mcp, &mc));
    }

    #[test]
    fn test_is_live_missing_mcp_label() {
        let mut mcp = dummy_mcp();
        mcp.metadata.labels = Some(BTreeMap::from([("foo".to_string(), String::new())]));

        let mut mc = dummy_mc();
        let mut labels = match_labels();
        labels.insert("something".to_string(), "else".to_string());
        mc.metadata.labels = Some(labels);

        assert!(!is_live(&mcp, &mc));
    }

    #[test]
    fn test_is_live_nothing() {
        assert!(!is_live(&Default::default(), &Default::default()));
    }

    #[tokio::test]
    async fn test_add_approved_image_success() {
        let clos = async |req: Request<Body>, _| match req.method() {
            &Method::POST => {
                let body = get_body_string(req).await;
                assert!(body.contains(DUMMY_IMAGE_REF));
                Ok(serde_json::to_string(&dummy_image()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let mut mc = dummy_mc();
        mc.spec.os_image_url = Some(DUMMY_IMAGE_REF.to_string());
        count_check!(1, clos, |client| {
            let result = add_approved_image(&mc, &OperatorContext::new(client)).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    #[tokio::test]
    async fn test_add_approved_image_no_url() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        let mut mc = dummy_mc();
        mc.spec.os_image_url = None;
        count_check!(0, clos, |client| {
            let result = add_approved_image(&mc, &OperatorContext::new(client)).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    #[tokio::test]
    async fn test_add_approved_image_error() {
        let clos = async |_, _| Err(StatusCode::INTERNAL_SERVER_ERROR);
        count_check!(1, clos, |client| {
            let result = add_approved_image(&dummy_mc(), &OperatorContext::new(client)).await;
            assert!(result.is_err());
        });
    }

    #[tokio::test]
    async fn test_mc_reconcile_new() {
        let clos = async |req: Request<_>, _| match req.method() {
            &Method::POST => Ok(serde_json::to_string(&dummy_image()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };

        count_check!(1, clos, |client| {
            let mut ctx = OperatorContext::new(client);
            ctx.mcp_store = store_with(vec![dummy_mcp()]);
            let result = mc_reconcile(Arc::new(dummy_mc()), Arc::new(ctx)).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }
}
