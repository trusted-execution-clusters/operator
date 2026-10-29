# Rolling out updated TLS credentials to deployments & nodes

In a reconciliation loop watching all secrets in its namespace, the operator computes hashes for all TLS secrets defined in the TEC resource (Trustee, registration server, AK registration server).
To support updating this secret, the loop also watches TEC objects.
To support updating the secrets in nodes that had not yet been associated with a TEC machine, the loop also watches nodes.

## Updating deployments

Each deployment is given the `trusted-execution-clusters.io/tls-hash` annotation to track which TLS certificate's hash it is running with.
When the reconciliation loop detects that a deployment's TLS hash is out of date, it updates this annotation plus the secret mount if the secret name was changed.
Either way, a new pod with the updated secret data is rolled out.

## Updating machines

In their status, the TEC machine objects have the field `TargetTrusteeTLSHash` to track which Trustee TLS certificate's hash the operator has most recently attempted to set.
Upon creation by the registration server, this field is set with the hash of the certificate that registration server distributed at that time.
When the reconciliation loop detects that a machine's Trustee TLS hash is out of date, and has an associated k8s node, it updates this field and creates a k8s job, scoped to this node by the `nodeName` pod spec.
This job is privileged and, in the host namespace, uses `clevis luks edit` to update the certificate that was stored for Trustee.
Upon job creation, the TEC machine's `TrusteeTlsCertUpdated` status condition is set to `Updating`.
An additional reconciliation on these jobs ensures that this status field is updated to `Updated` or `UpdateFailed` accordingly, and that the jobs are cleaned up after successful completion.
The reconciliation loop on nodes ensures that the job gets deleted if the node is deleted.
