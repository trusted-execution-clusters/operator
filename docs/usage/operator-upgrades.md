# Upgrading the Operator

What end users deploying the operator need to know and do when a new version is released. For how upgrades are implemented internally, see the [design doc](../design/operator_upgrades.md).

## How an upgrade is triggered

The operator upgrades are triggered manually or via OLM, by applying manifests; there is no separate upgrade command to run against the cluster.

1. You deploy a newer operator image/bundle (e.g. via `kubectl apply -f operator.yaml` with the new image tag, or by approving the next CSV in an OLM `Subscription`).
2. Once the new operator Pod starts and takes over reconciliation of the existing `TrustedExecutionCluster` resource, it compares its own compiled-in version against `status.observedOperatorVersion` on the resource.
3. If they differ, the operator automatically starts the upgrade flow described below. You do not need to create or apply any additional resource.

> There is no concept of upgrading only part of the deployment or part of the related component microservices. One operator Pod manages one `TrustedExecutionCluster`, and the upgrade applies to Trustee and all operator-managed component images together. The operator and related components (attestation_key_register, registration_server, trustee), are all bundled together in the TEC.

## What happens automatically during an upgrade

1. The `Upgrade` condition on the `TrustedExecutionCluster` is set to `InProgress`.
2. Trustee is **reinstalled from scratch**: its ConfigMaps (`trustee-data`, attestation policy), Secret (`trustee-auth`), Service, and Deployment are recreated/patched. All previously registered LUKS keys and attestation keys are resynced from Kubernetes Secrets, so no manual key re-entry is required. This causes **at least one Trustee Pod restart**, during which there is a brief moment where attestation requests will fail until the new Pod is ready.
3. Every `ApprovedImage` is invalidated and its PCR reference values are recomputed (`compute-pcrs` is re-run for each image, including combination PCRs), even if the image itself hasn't changed. This is required because the new operator/Trustee version may compute or interpret PCRs differently, and because compute-pcrs version also bumps (even if there is not change in it) when operator image bumps as both are bundled together.
4. The register-server and attestation-key-register Deployments are updated to the new component images.
5. Once every stage succeeds, `status.observedOperatorVersion` is set to the new version and the `Upgrade` condition is set to `Complete`.

## Monitoring an upgrade

Watch the conditions on the resource:

```bash
kubectl get trustedexecutioncluster <name> -o jsonpath='{.status.conditions}' | jq
```

Relevant condition types:

| Condition              | Meaning                                                                                 |
| ---------------------- | --------------------------------------------------------------------------------------- |
| `Upgrade`              | Overall upgrade status: `InProgress`, `Complete`, or `Failed`.                          |
| `TrusteeUpgrade`       | Set to `Complete` once Trustee has been fully reinstalled.                              |
| `RelatedImagesUpgrade` | Set to `Complete` once register-server and attestation-key-register have been upgraded. |

Also check that PCR recomputation finished for every image:

```bash
kubectl get approvedimage -o jsonpath='{range .items[*]}{.metadata.name}{": "}{.status.conditions[?(@.type=="Committed")].reason}{"\n"}{end}' -n <namespace>
```

Until an image shows `Committed`, its PCR values may be stale or missing, and any VM relying on it may fail attestation.

## Pre-upgrade checklist

- Read the release notes for the new version; any breaking change to the `TrustedExecutionCluster` CRD or `ApprovedImage` CRD spec will be called out there (see [Limitations](#limitations) below for the general compatibility promise).
- Make sure you have a recent backup/export of your `TrustedExecutionCluster`, `ApprovedImage`, and `Machine` resources (`kubectl get <kind> -o yaml`). There is no automated rollback (see below), so this is your fallback if something goes wrong.
- Plan for a short attestation outage while Trustee restarts. Nodes that are already attested and booted are not affected, but any node attesting *during* the restart window will need to retry.
- Do not run two operator replicas/versions pointed at the same cluster/namespace at once; only one `TrustedExecutionCluster` per namespace is supported, and only one version should ever be reconciling it.

## Recovering from a failed upgrade

If a stage fails (e.g. a bad image reference, Trustee failing to become ready), the operator sets:

```yaml
status:
  conditions:
    - type: Upgrade
      status: "False"
      reason: Failed
      message: "Upgrade failed: <detail>. Manual intervention required."
```

Important: **the operator will not retry automatically** once `Upgrade=Failed` is set, even on the next reconcile loop. This is intentional, to avoid repeatedly disrupting a cluster that is already in a bad state. The previously-working component versions are left running, so the cluster should remain usable while you investigate.

To recover:

1. Diagnose and fix the root cause (check operator logs and events, the message in the `Upgrade` condition, and the state of the `trustee` Deployment/Pod).
2. Fix the underlying issue, for example by correcting a `RELATED_IMAGE_*` environment variable on the operator Deployment, or rolling back to a known-good operator image.
3. Clear the failure state so the operator will try again.
  ```bash
   kubectl edit trustedexecutioncluster <name> --subresource=status -n <namespace>
  ```
   Manually delete the `- type: Upgrade` entry from `status.conditions`, save, and exit. This drops the `Upgrade=Failed` entry while leaving every other condition (e.g. `Installed`) untouched. On the next reconcile the operator no longer sees `Upgrade=Failed` and retries `run_upgrade` from the top. There is no dedicated CLI/API for this yet (see [Limitations](#limitations)); it is a manual status edit today.
4. Re-check the conditions as described in [Monitoring an upgrade](#monitoring-an-upgrade) to confirm the retried upgrade completes.

## Limitations

Keep these in mind when planning an upgrade:

1. **No automated rollback.** Downgrading the operator image is not tested or supported; the CRD and status format are only guaranteed to move forward. Always have an export of your resources before upgrading (see checklist above).
2. **Single served CRD version, no conversion webhook.** The CRD stays at `v1alpha1` and only one version is ever served. In practice this means the operator project commits to additive, backwards-compatible CRD changes across releases, but you should still read release notes for any field deprecations.
3. **No dedicated upgrade/migration component.** Upgrades run inside the normal reconciliation loop; there are no separate migration Jobs. This keeps the upgrade self-contained, but also means an upgrade can only make progress while the operator Pod itself is healthy and scheduled.
4. **PCR recomputation happens on every upgrade, for every image.** Expect `compute-pcrs` Jobs to run again for all `ApprovedImage` resources, even unchanged ones, immediately after an upgrade. On clusters with many approved images this adds load and delays attestation-readiness for all of them, not just new ones.
5. **A failed upgrade requires manual intervention and does not auto-retry.** See [Recovering from a failed upgrade](#recovering-from-a-failed-upgrade).
6. **Trustee attestation has a brief outage during upgrade.** Trustee is rebuilt (not just patched in place) on every upgrade, so expect a short window where attestation requests fail while the new Trustee Pod comes up.
