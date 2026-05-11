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

use std::path::PathBuf;

use anyhow::Context;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand_core::RngCore;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Environment
    let _ = dotenvy::dotenv();

    // 2. Tracing
    lattice_server::observability::init_tracing().context("failed to initialize tracing")?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting lattice-server"
    );

    // 3. Crypto
    lattice_crypto::init().context("crypto init failed")?;

    // 4. Config
    let cfg = lattice_server::config::AppConfig::load().context("failed to load configuration")?;
    info!(
        bind_addr = %cfg.server.bind_addr,
        environment = %cfg.environment,
        "configuration loaded"
    );

    // 5. Federation key + in-memory state
    let federation_sk = load_or_generate_federation_key(&cfg.federation_key_path)
        .context("failed to load or generate federation signing key")?;
    let state = lattice_server::state::ServerState::new_with_federation_key(federation_sk);
    info!(
        federation_pubkey = %state.federation_pubkey_b64,
        "federation identity loaded"
    );

    // 5.b. Database (sqlx) — deferred to follow-up commit.

    // 6. HTTP listener
    let app = lattice_server::app(state);
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

/// Load the federation signing key from `path` if the file exists;
/// otherwise generate a fresh one with `OsRng` and persist it. The
/// file format is the 32-byte raw seed.
///
/// Pass an empty path to use an ephemeral in-memory key (warning is
/// logged — federation peers will see a new pubkey on every restart).
fn load_or_generate_federation_key(path: &str) -> anyhow::Result<SigningKey> {
    let p = if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    };
    if let Some(p) = &p {
        if p.exists() {
            let bytes = std::fs::read(p)
                .with_context(|| format!("read federation key from {}", p.display()))?;
            let seed: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("federation key file is not exactly 32 bytes"))?;
            info!(path = %p.display(), "loaded federation key from disk");
            return Ok(SigningKey::from_bytes(&seed));
        }
    }
    let mut seed = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .context("OsRng failed to fill 32 bytes")?;
    let sk = SigningKey::from_bytes(&seed);
    if let Some(p) = p {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        std::fs::write(&p, sk.to_bytes())
            .with_context(|| format!("write federation key to {}", p.display()))?;
        info!(path = %p.display(), "wrote freshly-generated federation key");
    } else {
        warn!(
            "federation_key_path is empty; using ephemeral in-memory key — \
             federation peers will see a new pubkey on every restart"
        );
    }
    Ok(sk)
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
