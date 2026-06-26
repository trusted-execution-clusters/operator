# Project objective

See [README](./README.md#trusted-execution-cluster-operator-trusted-cluster-operator).

- **Success looks like**: With the operator deployed, all nodes in the cluster are attested from hardware to software.
- **Non-goals**: Rely on OpenShift, see the [confidential-clusters](https://github.com/confidential-clusters/operator) downstream.

# Architecture

- Entry points: see [README](./README.md#repository-structure).
- Integrations: [Trustee](https://github.com/confidential-containers/trustee), [compute-pcrs](https://github.com/trusted-execution-clusters/compute-pcrs), [clevis-pin-trustee](https://github.com/latchset/clevis-pin-trustee)

# Conventions

- See [CONTRIBUTING](./CONTRIBUTING.md).
- Use `Assisted-by:` or `Generated-by`: in commit messages for AI-supported contributions.
- Never commit real credentials; use env vars and local `.env` (gitignored) with synthetic values in docs.

# Things that human users of agents should do

and agents should suggest when they detect

- Have a coherent goal per session
- Read architecture, security-sensitive paths, performance-critical design, ambiguous product trade-offs

# Things agents should do, but can get wrong

- The operator's crate name is `operator`.
- Use MCPs when available
  - Prefer the MCP LSP over `grep`
  - Prefer the k8s LSP over `kubectl`.
- Reuse, and check for other uses of a similar pattern. When functionality can be moved out of a function for reuse, commit the generalization before the new use.
- Include lint-compatible code style when writing, not as an afterthought.
