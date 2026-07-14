- Use `cargo fmt`. Always perform `make lint clippy` before publishing when code is changed.
  - Use an extra binding if this saves more than one (formatted) LOC, e.g.
```rust
let svc = ATTESTATION_KEY_REGISTER_SERVICE;
self.create_certificate(svc, ATT_REG_CERT, ATT_REG_SECRET, issuer_name)
    .await?;
```
over
```rust
self.create_certificate(
    ATTESTATION_KEY_REGISTER_SERVICE,
    ATT_REG_CERT,
    ATT_REG_SECRET,
    issuer_name,
)
.await?;
```
- Use [REUSE](https://reuse.software) comments for new files, or exclude in [REUSE.toml](./REUSE.toml) when not possible.
- Follow [k8s API conventions](https://github.com/kubernetes/community/blob/main/contributors/devel/sig-architecture/api-conventions.md)
  - Use [reflector-backed caches](https://github.com/trusted-execution-clusters/operator/pull/267) where possible
- Add design documents for large features
- When functionality is changed, perform `make test`, and [integration test](./tests/README.md) at least with basic attestation.
- Test with the infrastructure a test needs -- unit with mocked API server, cluster test with a cluster, and attestation test with VMs. Preferably, add a test when
  - adding a feature
  - fixing a bug, with a test that you verify isolates this bug
- For members
  - Set membership to public so GHA runs integration tests without requiring the ok-to-test label
  - Merge when you have approval, passing tests, and are happy with your PR.

# Committing

- [Sign commits cryptographically](https://git-scm.com/docs/git-commit#Documentation/git-commit.txt---gpg-signkey-id)
- Limit commit subjects to 50 and messages to 72 characters. Leave an empty line between subject and message.
- Add small changes to larger PRs in separate commits to ease review burden, but do not add them to already open PRs
- Commit subjects
  - Prepend your commit subject with a short focus area. Omit this when making general operator changes. Examples are `tests`, `tests/azure`, `rvs` (reference values)
  - Most subjects should start with a verb in infinitive form, e.g. `Add reference value removal test`
- Explain what you did, and why you did it when it isn't obvious
- Commit trailers
  - [Sign off commits](https://git-scm.com/docs/git-commit#Documentation/git-commit.txt---signoff)
  - Mark AI use in the commit trailer, such as `Assisted-by: AI`
- Put separate changes in separate commits, but bisects should stay intact
  - Linting should pass, so a new definition must be used in the same commit.
  - When a change requires a change to a test, the changes should be in the same commit. On the contrary, a larger new test can be in a separate commit for easier review.

# AI use

- Do not raise PRs that you do not understand. Review changes with your own eyes before raising.
- Do not respond to review inquiries with replies that you do not understand
- Nontrivial use of AI must be included in the commit message trailer
