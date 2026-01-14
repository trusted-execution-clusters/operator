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

	// Conditions for the AttestationKey
	AttestationKeyApprovedCondition     string = "Approved"
	AttestationKeyRegistrationReason    string = "Registration"
	AttestationKeyMachineApprovedReason string = "MachineCreated"
)
