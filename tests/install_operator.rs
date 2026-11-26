// SPDX-FileCopyrightText: Roy Kaufman <rkaufman@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::path::Path;

use anyhow::Context;
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

named_test! {
    #[ignore = "run with make cluster-cleanup"]
    async fn cleanup_operator() -> anyhow::Result<()> {
        // Set TEST_NAMESPACE when running this test directly, or NAMESPACE when using make cluster-cleanup.
        let namespace = std::env::var("TEST_NAMESPACE")
            .ok()
            .filter(|namespace| !namespace.is_empty())
            .context("Set NAMESPACE to the namespace printed by make install-operator")?;
        let ctx =
            TestContext::new_with_existing_namespace(TEST_NAME, &namespace, Path::new(""), false).await?;
        ctx.cleanup().await
    }
}
