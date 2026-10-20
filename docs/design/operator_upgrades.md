# Operator Upgrades: Design

This section outlines How upgrades are implemented internally. For what end users depoying the operator need to know and do when a new version is released, see the [Upgrading the Operator](../usage/operator-upgrades.md) guide.

## How does the operator handle upgrades?

1. No CRD or operator rollbacks are supported. The CRD version remains at `v1alpha1`. CRD changes do not bump the CRD's or the operator's version.
  - Extra care must be taken to make sure subsequent CRD changes are backwards compatible, since there is no migration path for incompatible changes.
2. No conversion webhooks: only one version of the CRD is served.
  - Subsequent CRD changes must be additive/optional and must not break existing functionality.
3. Everything is handled in the operator's reconciliation loop (`handle_upgrade` in `operator/src/main.rs`): no separate `UpgradeManager`/`UpgradeController` component, no migration Jobs.
4. Already-approved images remain in place after an operator upgrade, but PCR values for every image are recomputed on each upgrade (`invalidate_all_approved_images`), including combination PCRs.
5. The operator tracks each stage of the upgrade via the `Upgrade`, `TrusteeUpgrade`, and `RelatedImagesUpgrade` conditions.

What do these decisions mean for someone operating a cluster (no automated rollback, mandatory PCR recomputation cost, manual recovery from a failed upgrade) is covered in [Limitations](../usage/operator-upgrades.md#limitations) in the user guide.

An upgrade is detected by comparing `status.observedOperatorVersion` on the `TrustedExecutionCluster` against the operator's own compiled-in `COMPONENT_VERSION`. On a mismatch, `handle_upgrade`:

1. Sets `Upgrade=InProgress`.
2. Runs `run_upgrade`, which reinstalls Trustee from scratch (`converge_trustee`) and then upgrades the related component images (`converge_related_images`), setting `TrusteeUpgrade=Complete` and `RelatedImagesUpgrade=Complete` respectively as each stage finishes.
3. On success, sets `Upgrade=Complete` and updates `observedOperatorVersion` to the new version.
4. On failure, sets `Upgrade=Failed` with a detail message and leaves `observedOperatorVersion` unchanged (still the old version). The retry gate on the next reconcile is the `Upgrade=Failed` condition itself (checked via `has_condition`), not `observedOperatorVersion` — the version check only short-circuits when the cluster is already fully up to date, which it is not after a failure. Retrying therefore requires removing/changing the `Upgrade` condition, not touching `observedOperatorVersion`.

Integration coverage lives in `tests/upgrade.rs` (`test_real_version_upgrade`), which exercises a real upgrade from a previously released operator/Trustee version to the current one, including a subsequent failing upgrade that must leave the cluster in a working, attested state with the older components still running.

## Diagram

Refer to the [operator_upgrades.png](../pics/operator_upgrades.png) file for the diagram.