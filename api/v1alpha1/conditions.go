// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

package v1alpha1

const (
	InstalledCondition             string = "Installed"
	InstalledReason                string = "InstallationCompleted"
	NotInstalledReasonNonUnique    string = "NonUnique"
	NotInstalledReasonInstalling   string = "Installing"
	NotInstalledReasonUninstalling string = "Uninstalling"

	KnownTrusteeAddressCondition string = "KnownTrusteeAddress"
	KnownTrusteeAddressReason    string = "AddressFound"
	UnknownTrusteeAddressReason  string = "NoAddressFound"

	CommittedCondition          string = "Committed"
	CommittedReason             string = "ImageCommitted"
	NotCommittedReasonComputing string = "Computing"
	NotCommittedReasonNoDigest  string = "NoDigestGiven"
	NotCommittedReasonFailed    string = "ComputationFailed"
	NotCommittedReasonPending   string = "PodPending"

	// Conditions for the AttestationKey
	AttestationKeyApprovedCondition     string = "Approved"
	AttestationKeyRegistrationReason    string = "Registration"
	AttestationKeyMachineApprovedReason string = "MachineCreated"

	// Conditions for the Machine
	MachineKeyProvisionedCondition string = "KeyProvisioned"
	MachineKeyProvisionedReason    string = "SecretMounted"
	MachineKeyNotProvisionedReason string = "ProvisioningFailed"
	MachineAkApprovedCondition     string = "AttestationKeyApproved"
	MachineAkApprovedReason        string = "KeyApproved"
	MachineAkNotApprovedReason     string = "NoKeyMatched"

	// Operator Upgrade conditions
	UpgradeCondition              string = "Upgrade"
	UpgradeInProgress             string = "InProgress"
	UpgradeComplete               string = "Complete"
	UpgradeFailed                 string = "Failed"
	TrusteeUpgradeCondition       string = "TrusteeUpgrade"
	RelatedImagesUpgradeCondition string = "RelatedImagesUpgrade"
)
