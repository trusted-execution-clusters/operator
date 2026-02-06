// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::time::Duration;

pub struct Poller {
    timeout: Duration,
    interval: Duration,
    error_message: Option<String>,
}

impl Default for Poller {
    fn default() -> Self {
        Self::new()
    }
}

impl Poller {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            interval: Duration::from_secs(5),
            error_message: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_error_message<S: Into<String>>(mut self, message: S) -> Self {
        self.error_message = Some(message.into());
        self
    }

    pub async fn poll_async<F, Fut, T, E>(&self, mut check_fn: F) -> anyhow::Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let start_time = std::time::Instant::now();

        loop {
            match check_fn().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if start_time.elapsed() >= self.timeout {
                        let error_msg = self.error_message.as_ref().cloned().unwrap_or_else(|| {
                            format!("Polling timed out after {:?}", self.timeout)
                        });
                        return Err(anyhow::anyhow!("{error_msg}, last error was: {e:?}"));
                    }
                    tokio::time::sleep(self.interval).await;
                }
            }
        }
    }
}
