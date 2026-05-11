//! `lattice-server` binary entrypoint.
//!
//! Initialization order is **strict**:
//! 1. Load `.env`
//! 2. Initialize tracing (nothing emits logs before this)
//! 3. Initialize crypto subsystem
//! 4. Load typed config
//! 5. Open database pool
//! 6. Start HTTP/QUIC listener with graceful shutdown
//!
//! Anything that fails between 1 and 5 aborts the process with a logged
//! error and a non-zero exit code.

#![forbid(unsafe_code)]

use anyhow::Context;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Environment
    let _ = dotenvy::dotenv();

    // 2. Tracing
    lattice_server::observability::init_tracing()
        .context("failed to initialize tracing")?;

    info!(version = env!("CARGO_PKG_VERSION"), "starting lattice-server");

    // 3. Crypto
    lattice_crypto::init().context("crypto init failed")?;

    // 4. Config
    let cfg = lattice_server::config::AppConfig::load()
        .context("failed to load configuration")?;
    info!(
        bind_addr = %cfg.server.bind_addr,
        environment = %cfg.environment,
        "configuration loaded"
    );

    // 5. Database
    // TODO: open sqlx pool against cfg.database_url

    // 6. HTTP listener
    let app = lattice_server::app();
    let listener = tokio::net::TcpListener::bind(&cfg.server.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", cfg.server.bind_addr))?;
    info!(bind_addr = %cfg.server.bind_addr, "HTTP listener bound");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    info!("server shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!(error = %e, "failed to install ctrl-c handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => warn!(error = %e, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("received ctrl-c, shutting down"),
        () = terminate => info!("received SIGTERM, shutting down"),
    }
}
