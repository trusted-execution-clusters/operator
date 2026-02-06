// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

pub mod conditions;
pub mod endpoints;
pub mod reference_values;

mod kopium;
#[allow(clippy::all)]
mod vendor_kopium;
pub use kopium::approvedimages::*;
pub use kopium::attestationkeys::*;
pub use kopium::ingresses as openshift_ingresses;
pub use kopium::machines::*;
pub use kopium::routes;
pub use kopium::trustedexecutionclusters::*;
pub use vendor_kopium::virtualmachineinstances;
pub use vendor_kopium::virtualmachines;

use conditions::*;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::chrono::Utc;

#[macro_export]
macro_rules! update_status {
    ($api:ident, $name:expr, $status:expr) => {{
        let patch = kube::api::Patch::Merge(serde_json::json!({"status": $status}));
        $api.patch_status($name, &Default::default(), &patch).await
            .map_err(Into::<anyhow::Error>::into)
    }}
}

pub fn condition_status(status: bool) -> String {
    match status {
        true => "True".to_string(),
        false => "False".to_string(),
    }
}

pub fn committed_condition(reason: &str, generation: Option<i64>) -> Condition {
    Condition {
        type_: COMMITTED_CONDITION.to_string(),
        status: condition_status(reason == COMMITTED_REASON),
        reason: reason.to_string(),
        message: match reason {
            NOT_COMMITTED_REASON_COMPUTING => "Computation is ongoing. Check jobs for progress.",
            NOT_COMMITTED_REASON_NO_DIGEST => {
                "Image did not specify a digest. \
                 Only images with a digest are supported to avoid ambiguity."
            }
            NOT_COMMITTED_REASON_FAILED => "Computation failed, check operator log for details",
            _ => "",
        }
        .to_string(),
        last_transition_time: Time(Utc::now()),
        observed_generation: generation,
    }
}
