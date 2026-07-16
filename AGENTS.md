# Project objective

See [README](./README.md#trusted-execution-cluster-operator-trusted-cluster-operator).

- **Success looks like**: With the operator deployed, all nodes in the cluster are attested from hardware to software.
- **Non-goals**: Rely on OpenShift, see the [confidential-clusters](https://github.com/confidential-clusters/operator) downstream.

# Architecture

- Entry points: see [README](./README.md#repository-structure).
- Integrations
  - [Trustee](https://github.com/confidential-containers/trustee)
    - The deployment of Trustee should be restart-stable with respect to configurations, reference values, and brokered keys
  - [compute-pcrs](https://github.com/trusted-execution-clusters/compute-pcrs)
  - [clevis-pin-trustee](https://github.com/latchset/clevis-pin-trustee)

# Conventions

- See [CONTRIBUTING](./CONTRIBUTING.md).
- Use ASCII characters, except where needed for proper nouns
- Never commit real credentials; use env vars and local `.env` (gitignored) with synthetic values in docs.

# Things that human users of agents should do

and agents should suggest when they detect

- Have a coherent goal per session
- Read architecture, security-sensitive paths, performance-critical design, ambiguous product trade-offs

# Things agents should do, but can get wrong

- The operator's crate name is `operator`, test_utils's crate name is `trusted-cluster-operator-test-utils`.
- Use MCPs when available
  - Prefer the LSP MCP over `grep`
  - Prefer the k8s MCP over `kubectl`.
- Reuse, and check for other uses of a similar pattern. When functionality can be moved out of a function for reuse, commit the generalization before the new use.
- Include lint-compatible code style when writing, not as an afterthought.
