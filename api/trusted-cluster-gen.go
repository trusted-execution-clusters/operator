// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

package main

import (
	"io/trustedexecutioncluster/api/v1alpha1"

	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type Args struct {
	outputDir                   string
	image                       string
	namespace                   string
	trusteeImage                string
	pcrsComputeImage            string
	registerServerImage         string
	attestationKeyRegisterImage string
	approvedImage               string
}

func main() {
	args := Args{}
	flag.StringVar(&args.outputDir, "output-dir", "config/deploy", "Output directory to save rendered YAML")
	flag.StringVar(&args.image, "image", "quay.io/trusted-execution-clusters/trusted-cluster-operator:latest", "Container image to use in the deployment")
	flag.StringVar(&args.namespace, "namespace", "trusted-execution-clusters", "Namespace where to install the operator")
	flag.StringVar(&args.trusteeImage, "trustee-image", "operators", "Container image with all-in-one Trustee")
	flag.StringVar(&args.pcrsComputeImage, "pcrs-compute-image", "quay.io/trusted-execution-clusters/compute-pcrs:latest", "Container image with the Trusted Execution Clusters compute-pcrs binary")
	flag.StringVar(&args.registerServerImage, "register-server-image", "quay.io/trusted-execution-clusters/register-server:latest", "Register server image to use in the deployment")
	flag.StringVar(&args.attestationKeyRegisterImage, "attestation-key-register-image", "quay.io/trusted-execution-clusters/attestation-key-register:latest", "Attestation key register image to use in the deployment")
	flag.StringVar(&args.approvedImage, "approved-image", "", "When set, defines an initial approved image. Must be a bootable container image with SHA reference.")
	flag.Parse()

	log.SetFlags(log.LstdFlags)

	if err := os.MkdirAll(args.outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory %s: %v", args.outputDir, err)
		os.Exit(1)
	}

	if err := generateOperator(&args); err != nil {
		log.Fatalf("Failed to generate operator: %v", err)
	}
	if err := generateTrustedExecutionClusterCR(&args); err != nil {
		log.Fatalf("Failed to generate TrustedExecutionCluster CR: %v", err)
	}
	if err := generateApprovedImageCR(&args); err != nil {
		log.Fatalf("Failed to generate ApprovedImage CR: %v", err)
	}
}

func generateOperator(args *Args) error {
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Namespace",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: args.namespace,
		},
	}
	nsYAML, err := yaml.Marshal(ns)
	if err != nil {
		return fmt.Errorf("failed to marshal namespace: %w", err)
	}

	name := "trusted-cluster-operator"
	labels := map[string]string{"app": name}
	replicas := int32(1)

	templateSpec := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: name,
			Containers: []corev1.Container{
				{
					Name:    name,
					Image:   args.image,
					Command: []string{"/usr/bin/operator"},
				},
			},
		},
	}
	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: args.namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: templateSpec,
		},
	}
	operatorYAML, err := yaml.Marshal(deployment)
	if err != nil {
		return fmt.Errorf("failed to marshal deployment: %w", err)
	}

	outputPath := filepath.Join(args.outputDir, "operator.yaml")
	operatorResources := []string{string(nsYAML), string(operatorYAML)}
	if err := writeResources(outputPath, operatorResources); err != nil {
		return fmt.Errorf("failed to write %s: %v", outputPath, err)
	}

	log.Printf("Generated operator deployment and namespace at %s", outputPath)
	return nil
}

func generateTrustedExecutionClusterCR(args *Args) error {
	cluster := &v1alpha1.TrustedExecutionCluster{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "TrustedExecutionCluster",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trusted-execution-cluster",
			Namespace: args.namespace,
		},
		Spec: v1alpha1.TrustedExecutionClusterSpec{
			TrusteeImage:                     args.trusteeImage,
			PcrsComputeImage:                 args.pcrsComputeImage,
			RegisterServerImage:              args.registerServerImage,
			AttestationKeyRegisterImage:      &args.attestationKeyRegisterImage,
			PublicAttestationKeyRegisterAddr: nil,
			PublicTrusteeAddr:                nil,
			TrusteeKbsPort:                   0,
			RegisterServerPort:               0,
			AttestationKeyRegisterPort:       0,
		},
	}

	clusterYAML, err := yaml.Marshal(cluster)
	if err != nil {
		return fmt.Errorf("failed to marshal TrustedExecutionCluster CR: %w", err)
	}

	outputPath := filepath.Join(args.outputDir, "trusted_execution_cluster_cr.yaml")
	if err := writeResources(outputPath, []string{string(clusterYAML)}); err != nil {
		return fmt.Errorf("failed to write %s: %v", outputPath, err)
	}

	log.Printf("Generated TrustedExecutionCluster CR at %s", outputPath)
	return nil
}

func generateApprovedImageCR(args *Args) error {
	if args.approvedImage == "" {
		return nil
	}

	approvedImage := &v1alpha1.ApprovedImage{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.GroupVersion.String(),
			Kind:       "ApprovedImage",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coreos",
			Namespace: args.namespace,
		},
		Spec: v1alpha1.ApprovedImageSpec{
			Reference: args.approvedImage,
		},
	}

	approvedImageYAML, err := yaml.Marshal(approvedImage)
	if err != nil {
		return fmt.Errorf("failed to marshal ApprovedImage CR: %v", err)
	}

	outputPath := filepath.Join(args.outputDir, "approved_image_cr.yaml")
	if err := writeResources(outputPath, []string{string(approvedImageYAML)}); err != nil {
		return fmt.Errorf("failed to write %s: %v", outputPath, err)
	}
	log.Printf("Generated ApprovedImage CR at %s", outputPath)
	return nil
}

func writeResources(path string, resources []string) error {
	return os.WriteFile(path, []byte(strings.Join(resources, "---\n")), 0644)
}
