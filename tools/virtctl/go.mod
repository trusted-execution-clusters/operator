// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: CC0-1.0

module io/trustedexecutioncluster/tools/virtctl

go 1.25.0

require kubevirt.io/kubevirt v1.7.3

require (
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cheggaaa/pb/v3 v3.1.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-openapi/jsonpointer v0.22.4 // indirect
	github.com/go-openapi/jsonreference v0.21.4 // indirect
	github.com/go-openapi/swag v0.25.4 // indirect
	github.com/go-openapi/swag/cmdutils v0.25.4 // indirect
	github.com/go-openapi/swag/conv v0.25.4 // indirect
	github.com/go-openapi/swag/fileutils v0.25.4 // indirect
	github.com/go-openapi/swag/jsonname v0.25.4 // indirect
	github.com/go-openapi/swag/jsonutils v0.25.4 // indirect
	github.com/go-openapi/swag/loading v0.25.4 // indirect
	github.com/go-openapi/swag/mangling v0.25.4 // indirect
	github.com/go-openapi/swag/netutils v0.25.4 // indirect
	github.com/go-openapi/swag/stringutils v0.25.4 // indirect
	github.com/go-openapi/swag/typeutils v0.25.4 // indirect
	github.com/go-openapi/swag/yamlutils v0.25.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20251007162407-5df77e3f7d1d // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.3.0 // indirect
	github.com/kubernetes-csi/external-snapshotter/client/v4 v4.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/moby/spdystream v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/onsi/ginkgo/v2 v2.27.2 // indirect
	github.com/onsi/gomega v1.38.3 // indirect
	github.com/openshift/api v0.0.0 // indirect
	github.com/openshift/client-go v0.0.0 // indirect
	github.com/openshift/custom-resource-status v1.1.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.80.1 // indirect
	github.com/prometheus/client_golang v1.22.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/spf13/cobra v1.9.1 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/mock v0.5.1 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/oauth2 v0.34.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/term v0.38.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.34.3 // indirect
	k8s.io/apiextensions-apiserver v0.34.3 // indirect
	k8s.io/apimachinery v0.34.3 // indirect
	k8s.io/client-go v12.0.0+incompatible // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-aggregator v0.28.2 // indirect
	k8s.io/kube-openapi v0.31.0 // indirect
	k8s.io/kubectl v0.0.0-00010101000000-000000000000 // indirect
	k8s.io/utils v0.0.0-20251002143259-bc988d571ff4 // indirect
	kubevirt.io/api v1.7.0 // indirect
	kubevirt.io/client-go v0.0.0-00010101000000-000000000000 // indirect
	kubevirt.io/containerized-data-importer-api v1.64.0 // indirect
	kubevirt.io/controller-lifecycle-operator-sdk/api v0.2.4 // indirect
	sigs.k8s.io/controller-runtime v0.22.4 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

replace (
	github.com/nxadm/tail => github.com/nxadm/tail v0.0.0-20211216163028-4472660a31a6
	github.com/openshift/api => github.com/openshift/api v0.0.0-20210105115604-44119421ec6b
	github.com/openshift/client-go => github.com/openshift/client-go v0.0.0-20210112165513-ebc401615f47
	github.com/operator-framework/operator-lifecycle-manager => github.com/operator-framework/operator-lifecycle-manager v0.0.0-20190128024246-5eb7ae5bdb7a
	k8s.io/api => k8s.io/api v0.34.2
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.34.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.34.2
	k8s.io/apiserver => k8s.io/apiserver v0.34.2
	k8s.io/client-go => k8s.io/client-go v0.34.2
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.34.2
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.34.2
	k8s.io/code-generator => k8s.io/code-generator v0.34.2
	k8s.io/component-base => k8s.io/component-base v0.34.2
	k8s.io/cri-api => k8s.io/cri-api v0.34.2
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.34.2
	k8s.io/klog => k8s.io/klog v0.4.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.34.2
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.34.2
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20250710124328-f3f2b991d03b
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.34.2
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.34.2
	k8s.io/kubectl => k8s.io/kubectl v0.34.2
	k8s.io/kubelet => k8s.io/kubelet v0.34.2
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.34.2
	k8s.io/metrics => k8s.io/metrics v0.34.2
	k8s.io/node-api => k8s.io/node-api v0.34.2
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.34.2
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.34.2
	k8s.io/sample-controller => k8s.io/sample-controller v0.34.2
	kubevirt.io/api => kubevirt.io/api v1.8.3
	kubevirt.io/client-go => kubevirt.io/client-go v1.8.3
)
