# Deploying Confidential Workers on Azure OpenShift

This guide explains the deployment of the trusted-execution-clusters operator on an Azure OpenShift cluster and the provisioning of confidential worker nodes with encrypted root volumes and hardware-based attestation.

## Prerequisites

### Repositories

This guide uses artifacts and manifests from three repositories. Clone them and note their local paths:

| Short name | Repository | Contains |
|------------|-----------|----------|
| **operator** | [trusted-execution-clusters/operator](https://github.com/trusted-execution-clusters/operator) | Operator source, CRDs, RBAC, deployment manifests, `make` targets |
| **investigations** | [trusted-execution-clusters/investigations](https://github.com/trusted-execution-clusters/investigations) | Custom RHCOS `Containerfile`, `coreos/justfile` for building the bootable container image and VHD, this documentation |
| **install-operator** | [confidential-clusters/install-operator](https://github.com/confidential-clusters/install-operator) | Install and cleanup scripts |

All `config/` paths in this guide (e.g., `config/crd/`, `config/deploy/`, `config/rbac/`) are relative to the **operator** repository root. All `just` commands are run from the **investigations** repository's `coreos/` directory.

### Requirements

- An Azure OpenShift cluster (OCP 4.21+) with `oc` access
- A container registry accessible from the cluster (e.g., `quay.io/<your-username>`)
- Operator images built and pushed to the registry (from **operator**: `make push-all`)
- A custom RHCOS bootable container image (see [Building the OS image](#building-the-os-image))
- A VHD disk image built from the same container image (see [Building the OS image](#building-the-os-image))
- `make`, `go`, `cargo`, `jq`, `yq`, `kustomize`, `python3`, and `base64` on your workstation
- Azure CLI (`az`) logged in to the subscription that hosts the cluster

### Required information

| Parameter | Example | Description |
|-----------|---------|-------------|
| Registry | `quay.io/myuser` | Container registry for operator images |
| Tag | `v0.2.3` | Operator version (semantic version) |
| Approved image | `quay.io/myuser/rhcos-confidential@sha256:abc...` | Custom RHCOS container image **by digest** |
| VHD resource ID | `/resourceGroups/.../images/.../versions/0.1.0` | Azure Compute Gallery image version |
| Source machineset | `mycluster-worker-westeurope1-abcde` | An existing worker machineset to use as a template |

> The approved image must use a `@sha256:` digest, not a tag. Obtain it with:
> `skopeo inspect docker://<image>:<tag> --format '{{.Digest}}'`

### Building the OS image

The bootable container image and the VHD must originate from the same build. The container image is a custom RHCOS layer that adds `clevis-pin-trustee`, `trustee-attester`, a custom ignition binary, and the dracut modules that include them in the initramfs. The VHD is an Azure disk image produced from that container image.

Both artifacts are built from the **investigations** repository using the `coreos/justfile`:

```sh
# Build the bootable container image
just os=rhcos build

# Export as OCI archive
just os=rhcos oci-archive

# Initialize cosa and build the Azure VHD
just os=rhcos init
just os=rhcos azure
```

The container image must be pushed to a registry by digest. The VHD must be uploaded to an Azure Compute Gallery in the same region as the cluster (or at minimum, the region where the confidential VMs will be provisioned). Azure cannot create a VM from a gallery image in a different region.

If the two artifacts come from different builds, the PCR values computed from the container image will not match the measurements reported by the VHD at boot, and attestation will fail. If the `osImageURL` in the MachineConfig references a different image than the VHD, the MCO will rebase the node after first boot, replacing the custom initramfs and breaking the LUKS unlock on subsequent boots.

## 1. Install cert-manager

All operator services use TLS. cert-manager issues and manages the certificates.

```sh
CRT_MGR_VERSION=$(go list -m -f '{{.Version}}' github.com/cert-manager/cert-manager)
oc apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CRT_MGR_VERSION}/cert-manager.yaml"
oc wait --for=condition=Available deployment/cert-manager -n cert-manager --timeout=120s
oc wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=120s
oc wait --for=condition=Available deployment/cert-manager-cainjector -n cert-manager --timeout=120s
```

> **Wait for the webhook.** The cert-manager webhook validates every Issuer and Certificate resource. If you create certificates immediately after the deployments report Available, the webhook's own TLS certificate may not be injected yet, and requests will fail with `certificate signed by unknown authority`. Verify readiness by applying a dry-run Issuer before proceeding.

## 2. Generate operator manifests

From the **operator** repository root:

```sh
make trusted-cluster-gen
make REGISTRY=<registry> TAG=<tag> NAMESPACE=<namespace> APPROVED_IMAGE=<approved-image> manifests
```

This generates CRD definitions, RBAC manifests, the operator Deployment, the TrustedExecutionCluster CR, and the ApprovedImage CR in `config/deploy/`.

## 3. Create the MachineConfig and MachineConfigPool

The Machine Config Operator (MCO) must know which OS image confidential workers should run. Without a MachineConfig that sets `osImageURL`, the MCO rebases confidential nodes to the stock RHCOS image after they join the cluster, destroying the custom initramfs and its attestation tooling.

Choose a name for the machineset (e.g., `conf-workers`). The MachineConfig, MachineConfigPool, and node role label all derive from this name.

```sh
MACHINESET_NAME=conf-workers

oc apply -f - <<EOF
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 99-${MACHINESET_NAME}
  labels:
    machineconfiguration.openshift.io/role: ${MACHINESET_NAME}
    machine.openshift.io/cluster-api-machineset: ${MACHINESET_NAME}
spec:
  osImageURL: <approved-image>
---
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfigPool
metadata:
  name: ${MACHINESET_NAME}
spec:
  machineConfigSelector:
    matchExpressions:
      - key: machineconfiguration.openshift.io/role
        operator: In
        values:
          - worker
          - ${MACHINESET_NAME}
  nodeSelector:
    matchLabels:
      node-role.kubernetes.io/${MACHINESET_NAME}: ""
EOF
```

The MachineConfigPool selects both `worker` and the machineset-specific role. This ensures confidential workers receive the standard worker configuration plus the custom OS image.

Wait for the MCO to render the configuration:

```sh
# Wait for the MachineConfig to appear in the pool's rendered sources
oc wait mcp/${MACHINESET_NAME} --for=condition=Updated=True --timeout=120s
```

> **The MCO creates a managed user data secret** named `${MACHINESET_NAME}-user-data-managed` in `openshift-machine-api`. This secret contains the ignition config with the rendered MachineConfig, including the custom `osImageURL`. You will extend this secret in step 11 rather than the generic `worker-user-data`.

## 4. Create the namespace and SecurityContextConstraints

```sh
NAMESPACE=trusted-execution-clusters
oc create namespace ${NAMESPACE}
sed "s/<NAMESPACE>/${NAMESPACE}/g" config/openshift/scc.yaml | oc apply -f -
```

## 5. Apply CRDs

```sh
oc apply --server-side --force-conflicts -f config/crd/
```

## 6. Apply RBAC

The operator's RBAC manifests require namespace substitution. Copy the RBAC directory, replace the `system` namespace placeholder, add the SCC, and apply with kustomize:

```sh
RBAC_TMP=$(mktemp -d)
cp -r config/rbac/* "${RBAC_TMP}/"

sed -i "s/namespace: system/namespace: ${NAMESPACE}/g" "${RBAC_TMP}/service_account.yaml"
sed -i "s/namespace: system/namespace: ${NAMESPACE}/g" "${RBAC_TMP}/leader_election_role.yaml"
sed -i "s/namespace: system/namespace: ${NAMESPACE}/g" "${RBAC_TMP}/leader_election_role_binding.yaml"
sed -i "s/name: trusted-cluster-operator-role/name: ${NAMESPACE}-trusted-cluster-operator-role/g" "${RBAC_TMP}/role.yaml"
sed -i "s/name: manager-rolebinding/name: ${NAMESPACE}-manager-rolebinding/g; \
        s/name: trusted-cluster-operator-role/name: ${NAMESPACE}-trusted-cluster-operator-role/g; \
        s/namespace: system/namespace: ${NAMESPACE}/g" "${RBAC_TMP}/role_binding.yaml"

cp config/rbac/kustomization.yaml.in "${RBAC_TMP}/kustomization.yaml"
sed -i "s/namespace: NAMESPACE/namespace: ${NAMESPACE}/g" "${RBAC_TMP}/kustomization.yaml"
cp config/openshift/scc.yaml "${RBAC_TMP}/scc.yaml"
sed -i "s/<NAMESPACE>/${NAMESPACE}/g" "${RBAC_TMP}/scc.yaml"
echo "  - scc.yaml" >> "${RBAC_TMP}/kustomization.yaml"

oc apply --server-side --force-conflicts -k "${RBAC_TMP}"
rm -rf "${RBAC_TMP}"
```

## 7. Deploy the operator

```sh
oc apply -f config/deploy/operator.yaml
oc wait --for=condition=Available deployment/trusted-cluster-operator \
    -n ${NAMESPACE} --timeout=300s
```

## 8. Set up TLS certificates

Create a self-signed CA chain using cert-manager. All three operator services (Trustee/KBS, register-server, attestation-key-register) receive individual certificates.

```sh
oc apply -n ${NAMESPACE} -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: root-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: root-cert
spec:
  secretName: root-secret
  isCA: true
  commonName: selfsigned-ca
  issuerRef:
    name: root-issuer
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: issuer
spec:
  ca:
    secretName: root-secret
EOF
```

Wait for the root CA secret, then create placeholder service certificates. These will be reissued with the correct LoadBalancer addresses in step 10.

```sh
for svc in register-server kbs-service attestation-key-register; do
  oc apply -n ${NAMESPACE} -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ${svc}-cert
spec:
  secretName: ${svc}-secret
  dnsNames: ["${svc}.${NAMESPACE}.svc"]
  issuerRef:
    name: issuer
EOF
done
```

> The secret names used here (`trustee-secret`, `reg-srv-secret`, `att-reg-secret`) must match what the TrustedExecutionCluster CR references in step 10. Adjust the certificate names and secret names to match your CR.

## 9. Expose services via LoadBalancer

The operator's services must be reachable from booting nodes that are not yet part of the cluster network. On Azure, LoadBalancer services provide direct IP access.

> **Do not use OpenShift Routes for these services.** Passthrough routes require DNS resolution of the route hostname. During early boot (when the LUKS root volume is being unlocked), DNS may not be available yet. LoadBalancer services provide direct IP access that works before DNS is configured.

```sh
for svc in kbs-service register-server attestation-key-register; do
  oc patch svc ${svc} -n ${NAMESPACE} --type merge -p '{"spec":{"type":"LoadBalancer"}}'
done
```

Wait for each service to receive an external IP:

```sh
oc get svc -n ${NAMESPACE} -w
```

Record the external IPs for use in steps 10 and 11.

> **Do not create the TrustedExecutionCluster CR before you have the LoadBalancer IPs.** The `publicTrusteeAddr` field is immutable after creation. If you set it to a placeholder or Route hostname and need to change it later, you must delete and recreate the entire TrustedExecutionCluster, which cascade-deletes all operator-managed resources.

## 10. Reissue certificates and create the TrustedExecutionCluster CR

Patch each certificate with the actual LoadBalancer IP address. If the LoadBalancer assigned an IP (not a hostname), use `ipAddresses`; otherwise use `dnsNames`:

```sh
KBS_IP=<kbs-service LoadBalancer IP>

oc patch certificate trustee-cert -n ${NAMESPACE} --type merge \
    -p "{\"spec\":{\"ipAddresses\":[\"${KBS_IP}\"],\"dnsNames\":[]}}"
```

Repeat for `register-server` and `attestation-key-register`. After patching, wait for cert-manager to reissue each certificate (check the revision), then restart each deployment to pick up the new cert:

```sh
oc rollout restart deployment/trustee-deployment -n ${NAMESPACE}
oc rollout status deployment/trustee-deployment -n ${NAMESPACE}
```

Now create the TrustedExecutionCluster CR with the known KBS address:

```sh
oc apply -n ${NAMESPACE} -f - <<EOF
apiVersion: trusted-execution-clusters.io/v1alpha1
kind: TrustedExecutionCluster
metadata:
  name: trusted-execution-cluster
  namespace: ${NAMESPACE}
spec:
  publicTrusteeAddr: ${KBS_IP}:8080
  registerServerPort: 8000
  trusteeKbsPort: 8080
  trusteeSecret: trustee-secret
  registerServerSecret: reg-srv-secret
  attestationKeyRegisterSecret: att-reg-secret
EOF
```

Apply the ApprovedImage and wait for installation:

```sh
oc apply -f config/deploy/approved_image_cr_*.yaml
oc wait --for=condition=Committed approvedimage/<name> -n ${NAMESPACE} --timeout=300s
oc wait --for=condition=Installed trustedexecutioncluster/trusted-execution-cluster \
    -n ${NAMESPACE} --timeout=300s
```

### Azure-specific: do not set publicAttestationKeyRegisterAddr

On Azure, the vTPM does not support the Attestation Key registration flow. The `publicAttestationKeyRegisterAddr` field must **not** be set on the TrustedExecutionCluster CR. This field is for KubeVirt environments only.

> Setting `publicAttestationKeyRegisterAddr` on Azure causes the `trustee-attester` binary to attempt AK creation via `tpm2_createak` as a subprocess. This fails on Azure's vTPM, and the node cannot complete attestation.

### Immutable fields

The following TrustedExecutionCluster fields cannot be changed after creation:

- `publicTrusteeAddr`
- `publicAttestationKeyRegisterAddr`
- `trusteeSecret`
- `registerServerSecret`
- `attestationKeyRegisterSecret`

Set all required values at creation time. To change them, delete and recreate the CR.

## 11. Create the ignition secret

The ignition secret tells booting nodes where to find the register-server and how to verify its TLS certificate. Use the MCO-managed user data secret as the base — it contains the rendered MachineConfig with the correct `osImageURL`.

```sh
MANAGED_SECRET=${MACHINESET_NAME}-user-data-managed
IGNITION_SECRET=${MANAGED_SECRET}-cocl
REG_SERVER_IP=<register-server LoadBalancer IP>
```

Extract the root CA certificate and percent-encode it:

```sh
ROOT_CA_PEM=$(oc get secret root-secret -n ${NAMESPACE} -o jsonpath='{.data.ca\.crt}' | base64 -d)
ROOT_CA_ENCODED=$(python3 -c "
import sys
data = sys.stdin.buffer.read()
print(''.join(chr(b) if chr(b).isascii() and chr(b).isalnum() else f'%{b:02X}' for b in data), end='')
" <<< "${ROOT_CA_PEM}")
```

Extend the managed secret with the register-server merge URL and CA:

```sh
oc get secret ${MANAGED_SECRET} -n openshift-machine-api -o jsonpath='{.data.userData}' \
  | base64 -d \
  | jq --arg url "https://${REG_SERVER_IP}:8000/ignition-clevis-pin-trustee" \
       --arg ca "data:,${ROOT_CA_ENCODED}" \
    '
      .ignition.version = "3.6.0" |
      .ignition.config.merge += [{"source": $url}] |
      .ignition.security.tls.certificateAuthorities += [{"source": $ca}]
    ' > /tmp/ignition.json

oc create secret generic ${IGNITION_SECRET} -n openshift-machine-api \
    --from-file=userData=/tmp/ignition.json
rm /tmp/ignition.json
```

> **Use the MCO-managed secret, not `worker-user-data`.** The generic `worker-user-data` secret does not contain the custom `osImageURL`. Nodes that boot from it will join the cluster, then the MCO will rebase them to stock RHCOS — destroying the custom initramfs and breaking LUKS unlock on the next reboot.

> **Append the merge URL and CA, do not replace.** The base ignition config already contains merge entries for the Machine Config Server and CA entries for the cluster root CA. Replacing them (with `=` instead of `+=`) breaks the MCS connection and the node cannot complete first boot.

> **Set the ignition version to 3.6.0.** The register-server returns an ignition 3.6 config. The base config may use an older version. Setting the version explicitly ensures compatibility.

> **Percent-encode the CA certificate.** Use the `data:,<percent-encoded>` format for the CA data URI. Other formats (`data:;base64,...`, `data:text/plain;charset=utf-8;base64,...`) may not be recognized by all ignition versions.

## 12. Create the confidential machineset

Create a machineset based on an existing worker machineset, modified for confidential VMs:

```sh
SOURCE_MACHINESET=<existing-worker-machineset>

oc get machineset ${SOURCE_MACHINESET} -n openshift-machine-api -o json | \
  jq --arg name "${MACHINESET_NAME}" \
     --arg image "<vhd-resource-id>" \
     --arg user_data "${IGNITION_SECRET}" \
  '
  del(.metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp,
      .metadata.generation, .metadata.managedFields, .status) |
  .metadata.name = $name |
  .metadata.namespace = "openshift-machine-api" |
  .metadata.labels["machine.openshift.io/cluster-api-machineset"] = $name |
  .spec.replicas = 1 |
  .spec.selector.matchLabels["machine.openshift.io/cluster-api-machineset"] = $name |
  .spec.template.metadata.labels["machine.openshift.io/cluster-api-machineset"] = $name |
  .spec.template.spec.metadata.labels["node-role.kubernetes.io/" + $name] = "" |
  .spec.template.spec.providerSpec.value.acceleratedNetworking = false |
  .spec.template.spec.providerSpec.value.image = {"resourceID": $image} |
  .spec.template.spec.providerSpec.value.vmSize = "Standard_DC2as_v5" |
  .spec.template.spec.providerSpec.value.userDataSecret.name = $user_data |
  .spec.template.spec.providerSpec.value.osDisk.managedDisk.securityProfile.securityEncryptionType = "VMGuestStateOnly" |
  .spec.template.spec.providerSpec.value.securityProfile = {
    "settings": {
      "confidentialVM": {
        "uefiSettings": {
          "secureBoot": "Enabled",
          "virtualizedTrustedPlatformModule": "Enabled"
        }
      },
      "securityType": "ConfidentialVM"
    }
  }
  ' | oc apply -f -
```

Key machineset properties:

- **`vmSize`**: Use a DCas or DCads v5 series VM (e.g., `Standard_DC2as_v5`). These are AMD SEV-SNP confidential VMs.
- **`acceleratedNetworking`**: Must be `false` — not supported on DC-series VMs.
- **`securityType`**: `ConfidentialVM` with Secure Boot and vTPM enabled.
- **`securityEncryptionType`**: `VMGuestStateOnly` — the OS disk is not encrypted by the platform; the operator handles root encryption via LUKS.
- **`userDataSecret`**: Points to the extended ignition secret from step 11.
- **Node role label**: `node-role.kubernetes.io/${MACHINESET_NAME}` — matches the MachineConfigPool's nodeSelector from step 3.

> **Check Azure capacity before scaling.** Azure confidential VM SKUs have limited availability per zone. A `ZonalAllocationFailed` error means the zone has the SKU but no physical hosts are available. Try a different availability zone or a smaller VM size. Check availability with:
> `az vm list-skus --location <location> --size Standard_DC --output table`

## Verification

Monitor the machine provisioning:

```sh
oc get machines -n openshift-machine-api \
    -l machine.openshift.io/cluster-api-machineset=${MACHINESET_NAME} -w
```

The machine progresses through: `Provisioning` → `Provisioned` → `Running`.

Once Running, verify the node joined the cluster:

```sh
oc get nodes -l node-role.kubernetes.io/${MACHINESET_NAME}=
```

Check the operator logs for successful attestation:

```sh
oc logs deployment/trustee-deployment -n ${NAMESPACE} --tail=20
```

A successful attestation shows:

```
POST /kbs/v0/attest HTTP/1.1" 200
GET /kbs/v0/resource/default/<uuid>/root HTTP/1.1" 200
```

## Cleanup

To remove the confidential worker setup:

1. Scale the machineset to zero and wait for machines to terminate
2. Delete the machineset
3. Delete the extended ignition secret from `openshift-machine-api`
4. Delete the TrustedExecutionCluster CR (cascade-deletes operator-managed resources)
5. Revert LoadBalancer services to ClusterIP
6. Delete the operator namespace (removes deployments, secrets, RBAC)
7. Delete cluster-scoped RBAC (ClusterRole, ClusterRoleBinding, SCC)
8. Delete the MachineConfig and MachineConfigPool
9. Remove cert-manager (if not used by other components)
