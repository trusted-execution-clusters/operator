//  SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//  SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
//  SPDX-License-Identifier: MIT

// Package v1alpha1 contains API Schema definitions for the trusted-execution-clusters v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=trusted-execution-clusters.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "trusted-execution-clusters.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// +kubebuilder:rbac:groups="",resources=configmaps;services;secrets,verbs=create;get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=trusted-execution-clusters.io,resources=trustedexecutionclusters;machines;approvedimages,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=trusted-execution-clusters.io,resources=trustedexecutionclusters/finalizers,verbs=update
// +kubebuilder:rbac:groups=trusted-execution-clusters.io,resources=machines/finalizers,verbs=update
// +kubebuilder:rbac:groups=trusted-execution-clusters.io,resources=trustedexecutionclusters/status;machines/status;approvedimages/status,verbs=get;patch;update

// TrustedExecutionClusterSpec defines the desired state of TrustedExecutionCluster
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.publicTrusteeAddr) || has(self.publicTrusteeAddr)", message="Value is required once set"
type TrustedExecutionClusterSpec struct {
	// Image reference to Trustee all-in-one image
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	TrusteeImage string `json:"trusteeImage"`

	// Image reference to trusted-cluster-operator's compute-pcrs image
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	PcrsComputeImage string `json:"pcrsComputeImage"`

	// Image reference to trusted-cluster-operator's register-server image
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	RegisterServerImage string `json:"registerServerImage"`

	// Address where attester can connect to Trustee
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	PublicTrusteeAddr *string `json:"publicTrusteeAddr,omitempty"`

	// Port that Trustee serves on
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	TrusteeKbsPort int32 `json:"trusteeKbsPort,omitempty"`

	// Port that trusted-cluster-operator's register-server serves on
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	RegisterServerPort int32 `json:"registerServerPort,omitempty"`
}

// TrustedExecutionClusterStatus defines the observed state of TrustedExecutionCluster.
type TrustedExecutionClusterStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// TrustedExecutionCluster is the Schema for the trustedexecutionclusters API
type TrustedExecutionCluster struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of TrustedExecutionCluster
	// +required
	Spec TrustedExecutionClusterSpec `json:"spec"`

	// status defines the observed state of TrustedExecutionCluster
	// +optional
	Status TrustedExecutionClusterStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TrustedExecutionClusterList contains a list of TrustedExecutionCluster
type TrustedExecutionClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TrustedExecutionCluster `json:"items"`
}

// MachineSpec defines the desired state of Machine
type MachineSpec struct {
	// Machine ID, typically a UUID
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	Id string `json:"id"`
	// Machine IP address at registration time
	RegistrationAddress *string `json:"registrationAddress"`
}

// MachineStatus defines the observed state of Machine.
type MachineStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Machine is the Schema for the machines API
type Machine struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Machine
	// +required
	Spec MachineSpec `json:"spec"`

	// status defines the observed state of Machine
	// +optional
	Status MachineStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// MachineList contains a list of Machine
type MachineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Machine `json:"items"`
}

// ApprovedImageSpec defines the desired state of ApprovedImage
type ApprovedImageSpec struct {
	// Approved image reference, specified with digest
	// +required
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="Value is immutable"
	// +kubebuilder:validation:XValidation:rule="self.matches(r'.*@sha256:.*')",message="Image must be provided with a digest"
	Reference string `json:"image"`
}

// ApprovedImageStatus defines the observed state of ApprovedImage.
type ApprovedImageStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ApprovedImage is the Schema for the approvedimages API
type ApprovedImage struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of ApprovedImage
	// +required
	Spec ApprovedImageSpec `json:"spec"`

	// status defines the observed state of ApprovedImage
	// +optional
	Status ApprovedImageStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// ApprovedImageList contains a list of ApprovedImage
type ApprovedImageList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApprovedImage `json:"items"`
}
