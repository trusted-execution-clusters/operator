// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use trusted_cluster_operator_lib::{
    AttestationKeyStatus, MachineStatus, TrustedExecutionClusterStatus,
};
use trusted_cluster_operator_lib::{condition_status, conditions::*, transition_time};

pub fn known_trustee_address_condition(
    known: bool,
    generation: Option<i64>,
    existing_status: &Option<TrustedExecutionClusterStatus>,
) -> Condition {
    let err = "No publicTrusteeAddr specified. Components can deploy, \
               but register-server will not be able to point to Trustee until you add an address";
    let (reason, message) = match known {
        true => (KNOWN_TRUSTEE_ADDRESS_REASON, ""),
        false => (UNKNOWN_TRUSTEE_ADDRESS_REASON, err),
    };
    let type_ = KNOWN_TRUSTEE_ADDRESS_CONDITION;
    let status = condition_status(known);
    Condition {
        type_: type_.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: transition_time(existing_status, type_, &status),
        status,
        observed_generation: generation,
    }
}

pub fn installed_condition(
    reason: &str,
    generation: Option<i64>,
    existing_status: &Option<TrustedExecutionClusterStatus>,
) -> Condition {
    let status = condition_status(reason == INSTALLED_REASON);
    let type_ = INSTALLED_CONDITION;
    Condition {
        type_: type_.to_string(),
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
        last_transition_time: transition_time(existing_status, type_, &status),
        status,
        observed_generation: generation,
    }
}

pub fn machine_key_provisioned_condition(
    provisioned: bool,
    generation: Option<i64>,
    existing_status: &Option<MachineStatus>,
) -> Condition {
    let (reason, message) = match provisioned {
        true => (
            MACHINE_KEY_PROVISIONED_REASON,
            "LUKS key generated and mounted in Trustee",
        ),
        false => (
            MACHINE_KEY_NOT_PROVISIONED_REASON,
            "Key provisioning failed, check operator logs for details",
        ),
    };
    let type_ = MACHINE_KEY_PROVISIONED_CONDITION;
    let status = condition_status(provisioned);
    Condition {
        type_: type_.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: transition_time(existing_status, type_, &status),
        status,
        observed_generation: generation,
    }
}

pub fn machine_ak_approved_condition(
    approved: bool,
    generation: Option<i64>,
    existing_status: &Option<MachineStatus>,
) -> Condition {
    let (reason, message) = match approved {
        true => (
            MACHINE_AK_APPROVED_REASON,
            "A matching attestation key was found and approved",
        ),
        false => (
            MACHINE_AK_NOT_APPROVED_REASON,
            "No matching attestation key found",
        ),
    };
    let type_ = MACHINE_AK_APPROVED_CONDITION;
    let status = condition_status(approved);
    Condition {
        type_: type_.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        last_transition_time: transition_time(existing_status, type_, &status),
        status,
        observed_generation: generation,
    }
}

pub fn attestation_key_approved_condition(
    reason: &str,
    generation: Option<i64>,
    existing_status: &Option<AttestationKeyStatus>,
) -> Condition {
    let status = condition_status(reason == ATTESTATION_KEY_MACHINE_APPROVE);
    let type_ = ATTESTATION_KEY_APPROVED_CONDITION;
    Condition {
        type_: type_.to_string(),
        reason: reason.to_string(),
        message: match reason {
            ATTESTATION_KEY_MACHINE_APPROVE => {
                "Attestation key approved automatically based on machine registration"
            }
            _ => "",
        }
        .to_string(),
        last_transition_time: transition_time(existing_status, type_, &status),
        status,
        observed_generation: generation,
    }
}

pub fn upgrade_condition(
    type_: &str,
    reason: &str,
    generation: Option<i64>,
    existing_status: &Option<TrustedExecutionClusterStatus>,
    detail: Option<&str>,
) -> Condition {
    let status = condition_status(reason == UPGRADE_COMPLETE);
    let message = match (reason, detail) {
        (UPGRADE_FAILED, Some(d)) => format!("Upgrade failed: {d}. Manual intervention required."),
        (UPGRADE_IN_PROGRESS, _) => "Operator upgrade is in progress".to_string(),
        (UPGRADE_COMPLETE, _) => "Operator upgrade completed successfully".to_string(),
        _ => String::new(),
    };
    Condition {
        type_: type_.to_string(),
        reason: reason.to_string(),
        message,
        last_transition_time: transition_time(existing_status, type_, &status),
        status,
        observed_generation: generation,
    }
}

// Few tests for the various upgrade conditions.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upgrade_condition_in_progress_message() {
        let c = upgrade_condition(UPGRADE_CONDITION, UPGRADE_IN_PROGRESS, None, &None, None);
        assert_eq!(c.type_, UPGRADE_CONDITION);
        assert_eq!(c.reason, UPGRADE_IN_PROGRESS);
        assert_eq!(c.status, "False");
        assert_eq!(c.message, "Operator upgrade is in progress");
    }

    #[test]
    fn test_upgrade_condition_complete_message() {
        let c = upgrade_condition(UPGRADE_CONDITION, UPGRADE_COMPLETE, None, &None, None);
        assert_eq!(c.type_, UPGRADE_CONDITION);
        assert_eq!(c.reason, UPGRADE_COMPLETE);
        assert_eq!(c.status, "True");
        assert_eq!(c.message, "Operator upgrade completed successfully");
    }

    // Trustee upgrade failed message.
    #[test]
    fn test_upgrade_condition_trustee_failed_message() {
        let detail = "Trustee pod failed to become ready";
        let c = upgrade_condition(UPGRADE_CONDITION, UPGRADE_FAILED, None, &None, Some(detail));
        assert_eq!(c.type_, UPGRADE_CONDITION);
        assert_eq!(c.reason, UPGRADE_FAILED);
        assert_eq!(c.status, "False");
        assert_eq!(
            c.message,
            "Upgrade failed: Trustee pod failed to become ready. Manual intervention required."
        );
    }

    // Trustee stage passes, related images stage also passes. Making sure the upgrade condition is set to True.
    #[test]
    fn test_upgrade_stage_conditions() {
        let trustee = upgrade_condition(
            TRUSTEE_UPGRADE_CONDITION,
            UPGRADE_COMPLETE,
            None,
            &None,
            None,
        );
        assert_eq!(trustee.type_, TRUSTEE_UPGRADE_CONDITION);
        assert_eq!(trustee.reason, UPGRADE_COMPLETE);
        assert_eq!(trustee.status, "True");

        let related = upgrade_condition(
            RELATED_IMAGES_UPGRADE_CONDITION,
            UPGRADE_COMPLETE,
            None,
            &None,
            None,
        );
        assert_eq!(related.type_, RELATED_IMAGES_UPGRADE_CONDITION);
        assert_eq!(related.reason, UPGRADE_COMPLETE);
        assert_eq!(related.status, "True");
    }
}
