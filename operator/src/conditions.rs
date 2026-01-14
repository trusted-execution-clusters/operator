// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::chrono::Utc;
use trusted_cluster_operator_lib::{condition_status, conditions::*};

pub fn known_trustee_address_condition(known: bool, generation: Option<i64>) -> Condition {
    let err = "No publicTrusteeAddr specified. Components can deploy, \
               but register-server will not be able to point to Trustee until you add an address";
    let (reason, message) = match known {
        true => (KNOWN_TRUSTEE_ADDRESS_REASON, ""),
        false => (UNKNOWN_TRUSTEE_ADDRESS_REASON, err),
    };
    Condition {
        type_: KNOWN_TRUSTEE_ADDRESS_CONDITION.to_string(),
        status: condition_status(known),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: Time(Utc::now()),
        observed_generation: generation,
    }
}

pub fn installed_condition(reason: &str, generation: Option<i64>) -> Condition {
    Condition {
        type_: INSTALLED_CONDITION.to_string(),
        status: condition_status(reason == INSTALLED_REASON),
        reason: reason.to_string(),
        message: match reason {
            NOT_INSTALLED_REASON_NON_UNIQUE => {
                "Another TrustedExecutionCluster definition was detected. \
                 Only one at a time is supported."
            }
            NOT_INSTALLED_REASON_INSTALLING => "Installation is in progress",
            NOT_INSTALLED_REASON_UNINSTALLING => "Uninstalling",
            _ => "",
        }
        .to_string(),
        last_transition_time: Time(Utc::now()),
        observed_generation: generation,
    }
}

pub fn attestation_key_approved_condition(reason: &str, generation: Option<i64>) -> Condition {
    Condition {
        type_: ATTESTATION_KEY_APPROVED_CONDITION.to_string(),
        status: condition_status(reason == ATTESTATION_KEY_MACHINE_APPROVE),
        reason: reason.to_string(),
        message: match reason {
            ATTESTATION_KEY_MACHINE_APPROVE => {
                "Attestation key approved automatically based on machine registration"
            }
            _ => "",
        }
        .to_string(),
        last_transition_time: Time(Utc::now()),
        observed_generation: generation,
    }
}
