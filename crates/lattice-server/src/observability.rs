//! Tracing initialization. JSON output in production, pretty in development.

use anyhow::Context;
use tracing_subscriber::{prelude::*, EnvFilter};

/// Initialize the global tracing subscriber.
///
/// Reads `RUST_LOG` for filter directives. Defaults to
/// `lattice=debug,tower_http=debug,sqlx=warn` if unset.
///
/// # Errors
///
/// Returns an error if the global subscriber has already been set.
pub fn init_tracing() -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("lattice=debug,tower_http=debug,sqlx=warn"));

    let env = std::env::var("LATTICE__ENVIRONMENT").unwrap_or_else(|_| "development".into());

    let registry = tracing_subscriber::registry().with(env_filter);

    if env == "development" {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .with_file(false)
                    .with_line_number(false)
                    .compact(),
            )
            .try_init()
            .context("failed to install dev tracing subscriber")
    } else {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_current_span(true)
                    .with_span_list(false),
            )
            .try_init()
            .context("failed to install JSON tracing subscriber")
    }
}
