//! Lattice desktop shell — M7 Phase F.
//!
//! Wraps the Leptos `lattice-web` UI in a Tauri 2 WebView and exposes
//! `lattice-media`'s voice/video pipeline over IPC. The browser tab and
//! the desktop shell run the **same** Leptos code; the desktop just
//! lights up extra `#[tauri::command]` surfaces that the browser cannot
//! reach (in particular, the native `lattice-media` PQ-DTLS-SRTP
//! pipeline that depends on UDP / Tokio runtime semantics unavailable
//! to wasm32).
//!
//! ## Runtime split
//!
//! - Leptos UI calls `window.__TAURI_INTERNALS__.invoke(cmd, args)` to
//!   talk to this binary. Detection lives in
//!   `apps/lattice-web/src/tauri.rs`.
//! - IPC commands are defined in [`commands`]; they spawn the
//!   `lattice-media` orchestrator on the Tokio runtime Tauri provides.
//! - The shell holds [`state::DesktopState`] inside a `Mutex` for the
//!   small amount of per-call lifecycle it tracks (M7 follow-ups will
//!   evolve this into a proper call registry).
//!
//! ## What is **not** here yet
//!
//! - Cross-machine signaling. `start_call` currently runs the Phase
//!   E.2 loopback in-process — the cryptographic smoke proof that the
//!   IPC bridge can drive `lattice-media` end-to-end. Real MLS-routed
//!   call invites land in a later M7 phase.
//! - Hardware-backed keys (Phase G).
//! - Mobile shells (Phase H).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod commands;
pub mod state;

use tracing_subscriber::EnvFilter;

/// Boot the Tauri app, register IPC commands, hand off to the runtime.
///
/// Exposed as a library function so Tauri Mobile (Phase H) can call
/// it later without changing the desktop entry point.
///
/// # Panics
///
/// Panics if Tauri's `run` returns an error during startup — at that
/// point the desktop app has nothing useful to do, so abort rather
/// than continue with a broken state.
pub fn run() {
    init_tracing();
    // Install the rustls `ring` crypto provider before any IPC command
    // can trigger a DTLS handshake. lattice-server's transitive rustls
    // feature set would otherwise race the auto-pick at first use.
    lattice_media::ensure_crypto_provider();
    tracing::info!(
        version = lattice_core::VERSION,
        media = lattice_media::crate_version(),
        "lattice-desktop booting"
    );

    let state = state::DesktopState::new();

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::start_call,
            commands::accept_call,
            commands::end_call,
            commands::call_status,
            commands::desktop_info,
        ])
        .run(tauri::generate_context!())
        .expect("tauri run");
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,lattice=debug,lattice_media=debug"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}
