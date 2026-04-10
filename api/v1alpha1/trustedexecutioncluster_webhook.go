//  SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
//  SPDX-License-Identifier: MIT

package v1alpha1

// +kubebuilder:webhook:path=/validate-trusted-execution-clusters-io-v1alpha1-trustedexecutioncluster,mutating=false,failurePolicy=fail,sideEffects=None,groups=trusted-execution-clusters.io,resources=trustedexecutionclusters,verbs=create,versions=v1alpha1,name=uniquetrustedexecutioncluster.trusted-execution-clusters.io,admissionReviewVersions=v1
