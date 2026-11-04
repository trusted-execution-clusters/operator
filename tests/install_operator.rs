// SPDX-FileCopyrightText: Roy Kaufman <rkaufman@redhat.com>
//
// SPDX-License-Identifier: MIT

use trusted_cluster_operator_test_utils::*;

named_test! {
    async fn install_operator() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        let namespace = test_ctx.namespace();
        test_ctx.info("Operatoer installed successfully");
        test_ctx.info(format!("To remove kubectl delete namespace {namespace}"));
        Ok(())
    }
}
