//! JeanGrey end-to-end integration tests.

mod address_lifecycle;
mod messaging;
mod persistence;
mod stale_rediscovery;

use std::sync::OnceLock;

pub(crate) fn init_tracing() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_env("JEANGREY_TEST_LOG")
            .unwrap_or_else(|_| "jeangrey=info".into());
        if std::env::var("JEANGREY_TEST_LOG").is_ok() {
            // Explicit log request: print to stderr unconditionally (the
            // test writer would otherwise swallow output on success).
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .try_init();
        } else {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_test_writer()
                .try_init();
        }
    });
}
