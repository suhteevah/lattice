//! Tauri 2 IPC commands exposed to the Leptos UI.
//!
//! Phase F surface: voice/video lifecycle + a small `desktop_info`
//! handshake so the UI can show the user that they're running inside
//! the desktop shell.
//!
//! ## Threading
//!
//! All commands are `async` — Tauri runs them on its tokio runtime, so
//! `lattice_media::call::run_loopback_call` (which spawns subordinate
//! tasks) is callable directly. Long-running work does **not** block
//! the UI thread.
//!
//! ## Error mapping
//!
//! Tauri serializes `Result<T, String>` cleanly across IPC; we render
//! [`MediaError`] via `Display`. The Leptos side parses the string for
//! presentation. Replace with a structured error enum once the UI
//! needs branching on error variant.

use lattice_media::call::{CallId, CallOutcome, run_loopback_call};
use lattice_media::error::MediaError;
use serde::{Deserialize, Serialize};
use tauri::State;
use tracing::{info, instrument, warn};

use crate::state::DesktopState;

/// Sentinel echoed back to the Leptos UI on boot so it can show "you
/// are running the desktop shell, native voice/video is available."
#[derive(Debug, Serialize, Deserialize)]
pub struct DesktopInfo {
    /// Sentence describing the shell ("Lattice desktop shell — M7
    /// Phase F" or similar). The UI surfaces this verbatim.
    pub greeting: String,
    /// `lattice-core` semver. Reported alongside the version Leptos
    /// fetches from its own `lattice_core::VERSION` so a mismatch is
    /// debuggable from the UI.
    pub core_version: String,
    /// `lattice-media` semver — proves which crate version is wired
    /// into the IPC bridge.
    pub media_version: String,
}

/// Boot-time handshake. Cheap; safe to invoke repeatedly.
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "debug")]
#[allow(clippy::unused_async)] // Tauri requires `async` for commands that return data
pub async fn desktop_info() -> Result<DesktopInfo, String> {
    Ok(DesktopInfo {
        greeting: "Lattice desktop shell — M7 Phase F.".to_string(),
        core_version: lattice_core::VERSION.to_string(),
        media_version: lattice_media::crate_version().to_string(),
    })
}

/// Spec for a call the caller wants to start.
///
/// `peer_user_id` and `group_id` arrive hex-encoded from the UI so the
/// IPC payload stays JSON-friendly. They're not used by the Phase F
/// loopback path — kept on the wire so the cross-machine flow (later
/// M7 phase) doesn't need a breaking IPC change.
#[derive(Debug, Serialize, Deserialize)]
pub struct StartCallRequest {
    /// 32-byte BLAKE3 user_id of the peer, hex-encoded.
    pub peer_user_id_hex: Option<String>,
    /// 32-byte group id, hex-encoded. Same shape as `lattice-protocol`
    /// uses on the wire today.
    pub group_id_hex: Option<String>,
}

/// Result of a `start_call` invocation. Mirrors
/// [`lattice_media::call::CallOutcome`] with serializable fields and an
/// extra `call_id_hex` so the UI can copy/paste the identifier.
#[derive(Debug, Serialize, Deserialize)]
pub struct StartCallReport {
    /// 16-byte CallId, hex-encoded.
    pub call_id_hex: String,
    /// Caller-side ICE host candidates that crossed the in-process
    /// signaling channel.
    pub caller_candidates_seen: usize,
    /// Same for the callee.
    pub callee_candidates_seen: usize,
    /// First four bytes of the PQ-folded SRTP master, hex-encoded.
    /// **Not a key** — only useful as a cross-side equality check.
    pub srtp_master_prefix: String,
    /// Length of the plain RTP packet round-tripped through the
    /// SRTP contexts.
    pub plain_rtp_len: usize,
    /// Length of the protected (encrypted + auth-tagged) RTP packet.
    pub protected_rtp_len: usize,
    /// Length recovered after the callee unwraps the SRTP packet.
    /// MUST equal `plain_rtp_len`.
    pub recovered_rtp_len: usize,
}

/// Start a call. Phase F runs the same Phase E.2 loopback the
/// `run_loopback_call` orchestrator drives — proves IPC + lattice-media
/// can carry the full cryptographic pipeline; cross-machine signaling
/// lands in a later phase.
///
/// # Errors
///
/// Returns the stringified [`MediaError`] if any stage fails (ICE,
/// DTLS, ML-KEM, SRTP).
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "info", skip(state))]
pub async fn start_call(
    request: StartCallRequest,
    state: State<'_, DesktopState>,
) -> Result<StartCallReport, String> {
    let call_id = generate_call_id();
    info!(call_id = ?call_id, request = ?request, "start_call IPC invocation");

    let outcome = run_loopback_call(call_id)
        .await
        .map_err(|e: MediaError| e.to_string())?;

    state.calls.lock().await.insert(call_id, outcome.clone());

    Ok(StartCallReport {
        call_id_hex: hex::encode(call_id.0),
        caller_candidates_seen: outcome.caller_candidates_seen,
        callee_candidates_seen: outcome.callee_candidates_seen,
        srtp_master_prefix: outcome.srtp_master_prefix,
        plain_rtp_len: outcome.plain_rtp_len,
        protected_rtp_len: outcome.protected_rtp_len,
        recovered_rtp_len: outcome.recovered_rtp_len,
    })
}

/// Accept an incoming call. Phase F placeholder — there is no remote
/// invite to consume yet because cross-machine signaling is deferred.
/// Returns the matching loopback outcome when the call_id is known,
/// otherwise an error.
///
/// # Errors
///
/// Returns an error string if the call_id is not registered (no
/// `start_call` has produced it yet) or the hex parse fails.
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "info", skip(state))]
pub async fn accept_call(
    call_id_hex: String,
    state: State<'_, DesktopState>,
) -> Result<StartCallReport, String> {
    let call_id = parse_call_id(&call_id_hex)?;
    let calls = state.calls.lock().await;
    let outcome = calls
        .get(&call_id)
        .cloned()
        .ok_or_else(|| format!("no call registered for id {call_id_hex}"))?;
    Ok(outcome_to_report(call_id, outcome))
}

/// Tear down a call. Removes it from the registry; returns whether the
/// call_id was actually present.
///
/// # Errors
///
/// Returns an error if the hex parse fails.
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "info", skip(state))]
pub async fn end_call(
    call_id_hex: String,
    state: State<'_, DesktopState>,
) -> Result<bool, String> {
    let call_id = parse_call_id(&call_id_hex)?;
    let was_present = state.calls.lock().await.remove(&call_id).is_some();
    if !was_present {
        warn!(call_id = ?call_id, "end_call: id not in registry");
    }
    Ok(was_present)
}

/// Look up the outcome for a previously-started call. Used by the UI
/// to re-render call status after a window reload.
///
/// # Errors
///
/// Returns an error if the hex parse fails or the call_id isn't known.
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "debug", skip(state))]
pub async fn call_status(
    call_id_hex: String,
    state: State<'_, DesktopState>,
) -> Result<StartCallReport, String> {
    let call_id = parse_call_id(&call_id_hex)?;
    let calls = state.calls.lock().await;
    let outcome = calls
        .get(&call_id)
        .cloned()
        .ok_or_else(|| format!("no call registered for id {call_id_hex}"))?;
    Ok(outcome_to_report(call_id, outcome))
}

fn generate_call_id() -> CallId {
    // Phase F uses random bytes; cross-machine signaling will derive
    // the CallId from the inviter's MLS application message instead.
    let mut bytes = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    CallId(bytes)
}

fn parse_call_id(hex_str: &str) -> Result<CallId, String> {
    let raw = hex::decode(hex_str).map_err(|e| format!("call_id hex decode: {e}"))?;
    if raw.len() != CallId::LEN {
        return Err(format!(
            "call_id wrong length: got {}, want {}",
            raw.len(),
            CallId::LEN
        ));
    }
    let mut bytes = [0u8; CallId::LEN];
    bytes.copy_from_slice(&raw);
    Ok(CallId(bytes))
}

fn outcome_to_report(call_id: CallId, outcome: CallOutcome) -> StartCallReport {
    StartCallReport {
        call_id_hex: hex::encode(call_id.0),
        caller_candidates_seen: outcome.caller_candidates_seen,
        callee_candidates_seen: outcome.callee_candidates_seen,
        srtp_master_prefix: outcome.srtp_master_prefix,
        plain_rtp_len: outcome.plain_rtp_len,
        protected_rtp_len: outcome.protected_rtp_len,
        recovered_rtp_len: outcome.recovered_rtp_len,
    }
}
