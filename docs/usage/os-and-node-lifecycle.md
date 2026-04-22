# Operating system image and node lifecycle

In Trusted Execution Clusters, every node is attested to run a bootable container image that has been set as an approved image by an administrator.
An example of a bootc-compatible OS is the CoreOS family, which is also what Trusted Execution Clusters is tested with.
Automatically retrieving references to approved images via Cluster API is a planned feature.

# Approving a bootable container image for reference value inclusion

For disambiguation reasons, all images must be referenced with a SHA digest.
With the `ApprovedImage` custom resource, images can be set to be approved.
Their reference values are computed, or taken from the `org.coreos.pcrs` label if present.

```sh
$ kubectl apply -f - <<EOF
apiVersion: trusted-execution-clusters.io/v1alpha1
kind: ApprovedImage
metadata:
  name: coreos
  namespace: trusted-execution-clusters
spec:
  image: quay.io/trusted-execution-clusters/fedora-coreos@sha256:e71dad00aa0e3d70540e726a0c66407e3004d96e045ab6c253186e327a2419e5
EOF

approvedimage.trusted-execution-clusters.io/coreos created
$ kubectl get jobs
NAME                                                              STATUS    COMPLETIONS   DURATION   AGE
compute-pcrs-66c22217c4-quay-io-trusted-execution-clusters-fedo   Running   0/1           19s        19s
$ # Wait for completion, job is auto-deleted upon success
$ kubectl describe approvedimage coreos
Name:         coreos
...
Spec:
  Image:  quay.io/trusted-execution-clusters/fedora-coreos@sha256:e71dad00aa0e3d70540e726a0c66407e3004d96e045ab6c253186e327a2419e5
Status:
  Conditions:
    Last Transition Time:  2025-11-27T18:05:12Z
    Message:               
    Observed Generation:   1
    Reason:                ImageCommitted
    Status:                True
    Type:                  Committed
Events:                    <none>
$ kubectl describe configmap trustee-data
...
reference-values.json:
----
[{"version":"0.1.0","name":"tpm_pcr14","expiration":"2026-11-27T18:05:14Z","value":["17cdefd9548f4383b67a37a901673bf3c8ded6f619d36c8007562de1d93c81cc"]},{"version":"0.1.0","name":"tpm_pcr4","expiration":"2026-11-27T18:05:14Z","value":["551bbd142a716c67cd78336593c2eb3b547b575e810ced4501d761082b5cd4a8"]},{"version":"0.1.0","name":"tpm_pcr7","expiration":"2026-11-27T18:05:14Z","value":["b3a56a06c03a65277d0a787fcabc1e293eaa5d6dd79398f2dda741f7b874c65d"]},{"version":"0.1.0","name":"tpm_svn","expiration":"2026-11-27T18:05:14Z","value":["1"]}]
...
```

Machines booting this image can now register and attest.

**NB:** Updating nodes is not supported yet. Updates incur one intermediary stage of PCR values (assuming no further update on that boot) because kernel update is effective one boot _before_ shim & GRUB update.

**NB:** The TrustedExecutionCluster object adopts ApprovedImages, including those that lived before it.
This ensures that removal of a TrustedExecutionCluster acts as complete uninstallation.

# Disallowing a bootable container image

For the example above:

```sh
$ kubectl delete approvedimage coreos
approvedimage.trusted-execution-clusters.io "coreos" deleted
$ kubectl describe configmap trustee-data
...
reference-values.json:
----
[{"version":"0.1.0","name":"tpm_svn","expiration":"2026-11-27T18:07:46Z","value":["1"]}]
...
```

Subsequent boots on this image will fail.

Ensure that all ApprovedImage objects that reference this image are removed.
If two ApprovedImages approve the same image and only one is deleted, the image is considered approved just the same.

# Registration of machines

New machines register via the [register-server](/register-server), which generates a `Machine` custom resource with a UUID and disk encryption key per machine.
This key can then be provided ("brokered") through Trustee.
Registering machines through direct API interaction is possible, but unsupported.

After such a registration, a Machine might look like:

```sh
$ kubectl get machines
NAME                                           AGE
machine-316809b1-ea29-448c-accb-78c5c6bf5206   88s
$ kubectl describe machine machine-316809b1-ea29-448c-accb-78c5c6bf5206
Name:         machine-316809b1-ea29-448c-accb-78c5c6bf5206
...
Spec:
  Id:                    316809b1-ea29-448c-accb-78c5c6bf5206
  Registration Address:  10.244.82.19
Events:                  <none>
$ kubectl get secrets
NAME                                   TYPE     DATA   AGE
316809b1-ea29-448c-accb-78c5c6bf5206   Opaque   1      2m10s
```

# Deletion of machines

Machines can be deleted if no longer needed:

```sh
$ kubectl delete machine machine-316809b1-ea29-448c-accb-78c5c6bf5206
machine.trusted-execution-clusters.io "machine-316809b1-ea29-448c-accb-78c5c6bf5206" deleted
$ kubectl get secrets
No resources found in test-c54e805f namespace.
```

The secret is owned by the Machine object and thus deleted when the Machine is deleted.
This prevents the node from booting again unless it was configured to re-register by someone controlling the node.
