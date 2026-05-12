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
//! - Hardware-backed keys via TPM 2.0 / Windows Hello (Phase G.3).
//!   Phase G.1 ships the [`lattice_media::keystore`] trait and a
//!   DPAPI-backed Windows implementation; G.2 lands macOS Secure
//!   Enclave and Linux Secret Service; G.3 swaps the Windows seal
//!   primitive from DPAPI to NCrypt-via-TPM.
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

    let keystore: std::sync::Arc<dyn lattice_media::keystore::Keystore> = build_keystore();
    let state = state::DesktopState::new(keystore);

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::start_call,
            commands::accept_call,
            commands::end_call,
            commands::call_status,
            commands::desktop_info,
            commands::keystore_generate,
            commands::keystore_pubkey,
            commands::keystore_sign,
            commands::keystore_delete,
            commands::keystore_list,
        ])
        .run(tauri::generate_context!())
        .expect("tauri run");
}

/// Construct the platform-default keystore. Boot fails if the OS-keychain
/// directory cannot be created — there is no useful degraded mode.
///
/// Selection matrix:
///
/// | OS | Backend | Phase |
/// |---|---|---|
/// | Windows | DPAPI seal under `%LOCALAPPDATA%\Lattice\keystore\` | G.1 |
/// | Linux | FreeDesktop Secret Service (GNOME Keyring / KWallet) | G.2a |
/// | macOS | Login Keychain (`SecItemAdd` generic password) | G.2b |
/// | _other_ | `MemoryKeystore` (volatile; not for production) | — |
///
/// TPM 2.0 (Windows) and Secure-Enclave-bound wrap (macOS) are the
/// G.3 upgrade — same trait, different seal primitive, no caller-side
/// change.
fn build_keystore() -> std::sync::Arc<dyn lattice_media::keystore::Keystore> {
    #[cfg(target_os = "windows")]
    {
        let ks = lattice_media::keystore::windows::WindowsKeystore::at_default_location()
            .expect("WindowsKeystore::at_default_location");
        tracing::info!("keystore: WindowsKeystore (DPAPI) at default location");
        std::sync::Arc::new(ks)
    }
    #[cfg(target_os = "linux")]
    {
        let ks = lattice_media::keystore::linux::LinuxKeystore::at_default_location()
            .expect("LinuxKeystore::at_default_location");
        tracing::info!("keystore: LinuxKeystore (Secret Service) at default location");
        std::sync::Arc::new(ks)
    }
    #[cfg(target_os = "macos")]
    {
        let ks = lattice_media::keystore::macos::MacosKeystore::at_default_location()
            .expect("MacosKeystore::at_default_location");
        tracing::info!("keystore: MacosKeystore (Keychain) at default location");
        std::sync::Arc::new(ks)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        tracing::warn!(
            "keystore: MemoryKeystore (volatile) — no platform keystore impl for this OS"
        );
        std::sync::Arc::new(lattice_media::keystore::memory::MemoryKeystore::new())
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,lattice=debug,lattice_media=debug"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}
