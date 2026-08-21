---
description: Download Prow azure-integration-test artifacts for a PR to logs/azure-integration-test-<branch>
user_invocable: true
---

# Download azure-integration-test artifacts

Given a PR number (from user input or current branch context), download the full artifacts tree from the Prow azure-integration-test job.

## Steps

1. Get the PR number. If not provided, infer from the current branch:
   ```
   gh pr view --json number -q .number
   ```

2. Get the head branch name and the Prow link in one step:
   ```
   gh pr view <PR> --json headRefName -q .headRefName
   gh pr checks <PR>
   ```
   From the `gh pr checks` output, find the line starting with `ci/prow/azure-integration-test`. The fourth column (tab-separated) is the Prow URL.

3. Derive the GCS path from the Prow URL — no need to fetch any web pages:
   - The Prow URL has the form `https://prow.ci.openshift.org/view/gs/<GCS_PATH>`
   - Strip the prefix `https://prow.ci.openshift.org/view/gs/` to get `<GCS_PATH>`
   - The gsutil source is `gs://<GCS_PATH>/artifacts/`

4. Create the destination directory and download:
   ```
   mkdir -p logs/azure-integration-test-<headRefName>
   gsutil -m cp -r gs://<GCS_PATH>/artifacts/ logs/azure-integration-test-<headRefName>/
   ```

   If `gsutil` is not available, try `gcloud storage cp -r` with the same paths.

## Fallback

If the URL pattern has changed (e.g. `gh pr checks` no longer returns a `prow.ci.openshift.org/view/gs/` URL for that check), fetch the Prow page with WebFetch and look for the Artifacts link. On the gcsweb artifacts page, look for the `gsutil` or `gcloud storage` command near the top.
