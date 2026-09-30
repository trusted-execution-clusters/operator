## How does the operator handle upgrades currently?

1. No CRD or operator rollbacks supported. CRD version remains at v1alpha1. CRD changes do not bump its or the operator’s version.
  a. Extra care will have to be taken to make sure subsequent CRD changes are backwards compatible.
2. No conversion webhooks, i.e only 1 version of CRD will be served
  a. Which means subsequent CRD changes must be additive/optional and not break existing functionality.
3. Everything is handled in the operator's reconciliation loop
  a. No seperate UpgradeManager or UpgradeController component.
    b. No migration jobs.
4. Already existing approved images will remain as is after operator upgrades, computation of PCR values for each image will be triggered on each upgrade. This includes combination PCRs.
5. Operator tracks each stages of upgrades. However, for now, the operator will not restart from scratch in case of a failure. It would require manual intervention. Status is set to Upgrade=Failed.



## Diagram:
Refer to the [operator_upgrades.png](../pics/operator_upgrades.png) file for the diagram.