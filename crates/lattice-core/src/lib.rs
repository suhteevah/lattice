//! # lattice-core
//!
//! Client core for Lattice. Handles session management, group operations,
//! message routing, and local-first state reconciliation.
//!
//! This crate is the **only** code in the workspace that compiles to
//! `wasm32-unknown-unknown` for the V1 browser client. Server-only
//! dependencies must not appear in this crate's tree.
//!
//! ## Module map (planned)
//!
//! - `session` — connection lifecycle, reconnect logic
//! - `group` — high-level group operations atop `lattice-crypto::mls`
//! - `message` — send/receive pipeline, padding + sealed sender wrapping
//! - `sync` — local-first state reconciliation (CRDT-based)
//! - `storage` — façade over `lattice-storage` backends
//!
//! ## Status
//!
//! Stub — see `docs/HANDOFF.md §6`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Library version surfaced for diagnostic UI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the client core. Sets up logging (panic-hook in WASM) and
/// verifies all underlying subsystems.
///
/// # Errors
///
/// Returns an error if subsystem initialization fails.
pub fn init() -> Result<(), Error> {
    #[cfg(target_arch = "wasm32")]
    {
        // Browser-friendly panic messages.
        std::panic::set_hook(Box::new(|info| {
            web_sys::console::error_1(&format!("[lattice-core panic] {info}").into());
        }));
    }

    lattice_crypto::init().map_err(|e| Error::Init(e.to_string()))?;
    tracing::info!(version = VERSION, "lattice-core initialized");
    Ok(())
}

/// Errors from the client core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Initialization failed.
    #[error("init failure: {0}")]
    Init(String),
    /// Operation propagated from `lattice-crypto`.
    #[error(transparent)]
    Crypto(#[from] lattice_crypto::Error),
    /// Operation propagated from `lattice-protocol`.
    #[error(transparent)]
    Protocol(#[from] lattice_protocol::Error),
}
