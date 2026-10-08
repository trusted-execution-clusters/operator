// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;
use kube::Client;
use kube::core::{Expression, Selector, SelectorExt};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, controller::Action};
use kube::runtime::{finalizer, finalizer::Event};
use kube::{Api, ResourceExt, api::ObjectMeta};
use log::warn;
use std::{collections::BTreeMap, sync::Arc};

use operator::*;
use trusted_cluster_operator_lib::machineconfigpools::MachineConfigPool;
use trusted_cluster_operator_lib::machineconfigs::MachineConfig;
use trusted_cluster_operator_lib::reference_values::{OSIMAGE_RESOURCE_PREFIX, rfc1035};
use trusted_cluster_operator_lib::*;

const MC_FINALIZER: &str = "trusted-execution-clusters.io/machineconfig";
const MC_LABEL: &str = "trusted-execution-clusters.io/based-on-machineconfig";

/// Check if MCP's label selectors would select MC
fn is_live(mcp: &MachineConfigPool, mc: &MachineConfig) -> bool {
    let Some(ref labels) = mc.metadata.labels else {
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
        selector.matches(labels)
    });

    let label_match =
        match_labels.is_none_or(|ls| ls.iter().all(|(k, v)| labels.get(k) == Some(v)));
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

async fn delete_approved_image(image: &ApprovedImage, client: Client) -> Result<()> {
    let err = "ApprovedImage for deletion found, but had no name";
    let image_name = image.metadata.name.as_ref().context(err)?;
    let images: Api<ApprovedImage> = Api::default_namespaced(client);
    images.delete(image_name, &Default::default()).await?;
    Ok(())
}

async fn handle_machineconfig(mc: &MachineConfig, ctx: &OperatorContext) -> Result<Action> {
    let live = ctx.mcp_store.find(|mcp| is_live(mcp, mc)).is_some();
    if let Some(stored) = ctx.image_store.find(|i| is_stored(i, mc)) {
        let url = mc.spec.os_image_url.as_ref();
        // Delete if moved out of scope or URL out of date
        if !live || url.is_none_or(|url| *url != stored.spec.image) {
            delete_approved_image(&stored, ctx.client.clone()).await?;
        }
    }
    if !live {
        return Ok(LONG_REQUEUE);
    }
    add_approved_image(mc, ctx).await
}

async fn find_and_delete_approved_image(
    mc: &MachineConfig,
    ctx: &OperatorContext,
) -> Result<Action> {
    let Some(image) = ctx.image_store.find(|i| is_stored(i, mc)) else {
        let mc_name = mc.name_any();
        warn!("MachineConfig {mc_name} deleted, but no associated ApprovedImage found");
        return Ok(LONG_REQUEUE);
    };
    delete_approved_image(&image, ctx.client.clone()).await?;
    Ok(LONG_REQUEUE)
}

async fn mc_reconcile(
    mc: Arc<MachineConfig>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let mcs: Api<MachineConfig> = Api::all(ctx.client.clone());
    finalizer(&mcs, MC_FINALIZER, mc, |ev| async move {
        match ev {
            Event::Apply(mc) => handle_machineconfig(&mc, &ctx)
                .await
                .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into())),
            Event::Cleanup(mc) => find_and_delete_approved_image(&mc, &ctx)
                .await
                .map_err(|e| finalizer::Error::<ControllerError>::CleanupFailed(e.into())),
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile on MachineConfig: {e}").into())
}

pub async fn launch_rv_mc_controller(ctx: Arc<OperatorContext>) {
    let mcs: Api<MachineConfig> = Api::all(ctx.client.clone());
    let mcps: Api<MachineConfigPool> = Api::all(ctx.client.clone());
    let mcp_ctx = ctx.clone();
    tokio::spawn(
        Controller::new(mcs, Default::default())
            .watches(mcps, Default::default(), move |mcp| {
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

    fn image_labels() -> BTreeMap<String, String> {
        BTreeMap::from([(MC_LABEL.to_string(), MC_NAME.to_string())])
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
    async fn test_delete_approved_image() {
        let clos = async |req: Request<_>, _| match req.method() {
            &Method::DELETE => Ok(serde_json::to_string(&dummy_image()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        count_check!(1, clos, |client| {
            let result = delete_approved_image(&dummy_image(), client).await;
            assert_eq!(result.unwrap(), ());
        });
    }

    #[tokio::test]
    async fn test_handle_machineconfig_noop() {
        let clos = async |req: Request<_>, _| panic!("unexpected API interaction: {req:?}");
        count_check!(0, clos, |client| {
            let result = handle_machineconfig(&dummy_mc(), &OperatorContext::new(client)).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    #[tokio::test]
    async fn test_handle_machineconfig_new() {
        let clos = async |req: Request<_>, _| match req.method() {
            &Method::POST => Ok(serde_json::to_string(&dummy_image()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };

        count_check!(1, clos, |client| {
            let mut ctx = OperatorContext::new(client);
            ctx.mcp_store = store_with(vec![dummy_mcp()]);
            let result = handle_machineconfig(&dummy_mc(), &ctx).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    #[tokio::test]
    async fn test_handle_machineconfig_moved_out_of_scope() {
        let clos = async |req: Request<_>, _| match req.method() {
            &Method::DELETE => Ok(serde_json::to_string(&dummy_image()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let mut image = dummy_image();
        image.metadata.labels = Some(image_labels());
        count_check!(1, clos, |client| {
            let mut ctx = OperatorContext::new(client);
            ctx.image_store = store_with(vec![image]);
            let result = handle_machineconfig(&dummy_mc(), &ctx).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    #[tokio::test]
    async fn test_handle_machineconfig_url_changed() {
        let clos = async |req: Request<_>, ctr: u32| match (ctr, req.method()) {
            (0, &Method::DELETE) => Ok(serde_json::to_string(&dummy_image()).unwrap()),
            (1, &Method::POST) => Ok(serde_json::to_string(&dummy_image()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };

        let mut image = dummy_image();
        image.metadata.labels = Some(image_labels());
        let mut mc = dummy_mc();
        mc.spec.os_image_url = Some("something.else".to_string());

        count_check!(2, clos, |client| {
            let mut ctx = OperatorContext::new(client);
            ctx.mcp_store = store_with(vec![dummy_mcp()]);
            ctx.image_store = store_with(vec![image]);
            let result = handle_machineconfig(&mc, &ctx).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }

    #[tokio::test]
    async fn test_find_and_delete_approved_image() {
        let clos = async |req: Request<_>, _| match req.method() {
            &Method::DELETE => Ok(serde_json::to_string(&dummy_image()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}"),
        };
        let mut image = dummy_image();
        image.metadata.labels = Some(image_labels());
        count_check!(1, clos, |client| {
            let mut ctx = OperatorContext::new(client);
            ctx.image_store = store_with(vec![image]);
            let result = find_and_delete_approved_image(&dummy_mc(), &ctx).await;
            assert_eq!(result.unwrap(), LONG_REQUEUE);
        });
    }
}
