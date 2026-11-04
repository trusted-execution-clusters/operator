// SPDX-FileCopyrightText: Roy Kaufman <rkaufman@redhat.com>
//
// SPDX-License-Identifier: MIT

use trusted_cluster_operator_test_utils::*;

named_test! {
    #[ignore = "run with make install-operator"]
    async fn install_operator() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        test_ctx.info(format!("Operator installed successfully in {}", test_ctx.namespace()));
        test_ctx.info(format!("To remove it, run make cluster-cleanup NAMESPACE={}", test_ctx.namespace()));
        Ok(())
    }
}
