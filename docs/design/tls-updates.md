# Rolling out updated TLS credentials to deployments & nodes

In a reconciliation loop watching all secrets in its namespace, the operator computes hashes for all TLS certificates defined in the TEC resource (Trustee, registration server, AK registration server).
To support changing to another secret, the loop also watches TEC objects.
Because the loop must catch when the certificate has propagated to the TEC machines, they are also watched.

The Trustee KBS is not run with a direct mount to the configured certificate secret because machines would lose their ability to attest upon certificate change.
Instead, the operator replicates the content of the secret into an operator-managed secret and only updates that when the machines are ready to use it.

## The `trustee-certs` ConfigMap

The operator describes the target state of nodes' certificates by a ConfigMap called `trustee-certs`.
It includes
- `machine_certs`, a list of certificates to be added to the nodes
- `revoked_certs`, a list of certificates to be removed from the nodes
- `want_cert`, the certificate the Trustee deployment is expected to switch to, if any
- `want_since`, an RFC3339 timestamp of when `want_cert` was updated

## Machine daemon

Nodes backed by operator-managed CVMs are to carry the `trusted-execution-clusters.io/machine` label.
On such nodes, the operator schedules a privileged daemonset with the Rust-based TEC machine daemon.
In a reconciliation loop on the `trustee-certs` ConfigMap, this daemon checks `machine_certs` and `revoked_certs` against its node's disk.
When a discrepancy is detected, the disk's Clevis header is edited accordingly, by adding and removing server configurations with the respective certificates.

The loop also updates its associated Machine's status:
- in the `CertsUpdated` condition field (reasons `Updated`, `Updating`, `Failed`)
- in the `installedCerts` status field (list of hashes)

## Operator reconciliation

The reconciliation loop checks
- if the machine & AK registration secret names are out of date with these deployments, in which case the deployments are updated directly
- if the Trustee certificate is out of date with the Trustee deployment (through name or content change)

In the latter case, if the certificate is not already listed as `want_cert`, `want_cert` is updated alongside `want_since`.
Furthermore, if
- the certificate is missing in any `installedCerts` of the machines, and
- `want_since` has not passed longer than `certUpdateGracePeriod`, configurable in the TEC resource, ago,

then
- the certificate is added to `machine_certs`, and
- the TEC object gets the `CertsUpdated` condition set to `AddingNew`.

Otherwise,
- the new certificate can be updated in the secret used by the Trustee deployment
- the old certificate can be added to `revoked_certs`
- the TEC object gets the `CertsUpdated` condition set to `RevokingOld`

If the Trustee certificate is not out of date, the TEC object gets the `CertsUpdated` condition set to `Updated`
