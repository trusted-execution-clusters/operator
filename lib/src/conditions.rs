// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

pub const INSTALLED_CONDITION: &str = "Installed";
pub const INSTALLED_REASON: &str = "InstallationCompleted";
pub const NOT_INSTALLED_REASON_NON_UNIQUE: &str = "NonUnique";
pub const NOT_INSTALLED_REASON_INSTALLING: &str = "Installing";
pub const NOT_INSTALLED_REASON_UNINSTALLING: &str = "Uninstalling";

pub const KNOWN_TRUSTEE_ADDRESS_CONDITION: &str = "KnownTrusteeAddress";
pub const KNOWN_TRUSTEE_ADDRESS_REASON: &str = "AddressFound";
pub const UNKNOWN_TRUSTEE_ADDRESS_REASON: &str = "NoAddressFound";

pub const COMMITTED_CONDITION: &str = "Committed";
pub const COMMITTED_REASON: &str = "ImageCommitted";
pub const NOT_COMMITTED_REASON_COMPUTING: &str = "Computing";
pub const NOT_COMMITTED_REASON_NO_DIGEST: &str = "NoDigestGiven";
pub const NOT_COMMITTED_REASON_FAILED: &str = "ComputationFailed";
pub const NOT_COMMITTED_REASON_PENDING: &str = "PodPending";

pub const ATTESTATION_KEY_APPROVED_CONDITION: &str = "Approved";
pub const ATTESTATION_KEY_REGISTRATION_REASON: &str = "Registration";
pub const ATTESTATION_KEY_MACHINE_APPROVE: &str = "MachineCreated";

pub const MACHINE_KEY_PROVISIONED_CONDITION: &str = "KeyProvisioned";
pub const MACHINE_KEY_PROVISIONED_REASON: &str = "SecretMounted";
pub const MACHINE_KEY_NOT_PROVISIONED_REASON: &str = "ProvisioningFailed";

pub const MACHINE_AK_APPROVED_CONDITION: &str = "AttestationKeyApproved";
pub const MACHINE_AK_APPROVED_REASON: &str = "KeyApproved";
pub const MACHINE_AK_NOT_APPROVED_REASON: &str = "NoKeyMatched";

// Upgrade conditions
pub const UPGRADE_CONDITION: &str = "Upgrade";
pub const UPGRADE_IN_PROGRESS: &str = "InProgress";
pub const UPGRADE_COMPLETE: &str = "Complete";
pub const UPGRADE_FAILED: &str = "Failed";

// Upgrade conditions for dependencies.
pub const TRUSTEE_UPGRADE_CONDITION: &str = "TrusteeUpgrade";
pub const RELATED_IMAGES_UPGRADE_CONDITION: &str = "RelatedImagesUpgrade";
