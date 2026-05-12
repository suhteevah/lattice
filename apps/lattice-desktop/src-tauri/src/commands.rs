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

use std::sync::Arc;

use lattice_media::call::{CallId, CallOutcome, run_loopback_call};
use lattice_media::error::MediaError;
use lattice_media::keystore::{KeyHandle, Keystore, StoredKey};
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

// ──────────────────────────────────────────────────────────────────
// Phase G — keystore IPC commands
// ──────────────────────────────────────────────────────────────────

/// JSON-friendly mirror of a [`StoredKey`] for IPC. All bytes hex-
/// encoded; `created_at_unix` is seconds-since-epoch.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeystoreEntryReport {
    /// Hex-encoded 16-byte [`KeyHandle`].
    pub handle_hex: String,
    /// Hex-encoded ML-DSA-65 verifying key (1952 bytes raw).
    pub ml_dsa_pk_hex: String,
    /// Hex-encoded Ed25519 verifying key (32 bytes raw).
    pub ed25519_pk_hex: String,
    /// User-supplied label.
    pub label: String,
    /// Seconds since UNIX epoch when the key was generated.
    pub created_at_unix: u64,
}

impl KeystoreEntryReport {
    fn from_stored(stored: &StoredKey) -> Self {
        Self {
            handle_hex: stored.handle.to_hex(),
            ml_dsa_pk_hex: hex::encode(&stored.public.ml_dsa_pk),
            ed25519_pk_hex: hex::encode(stored.public.ed25519_pk),
            label: stored.label.clone(),
            created_at_unix: stored
                .created_at
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
        }
    }
}

/// JSON-friendly mirror of a [`lattice_crypto::identity::HybridSignature`].
#[derive(Debug, Serialize, Deserialize)]
pub struct HybridSignatureReport {
    /// Hex-encoded ML-DSA-65 signature (3309 bytes raw).
    pub ml_dsa_sig_hex: String,
    /// Hex-encoded Ed25519 signature (64 bytes raw).
    pub ed25519_sig_hex: String,
}

/// Generate a fresh hybrid identity keypair and seal it via the
/// platform keystore.
///
/// # Errors
///
/// Returns the stringified [`lattice_media::keystore::KeystoreError`]
/// if generation, sealing, or disk IO fails.
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "info", skip(state))]
pub async fn keystore_generate(
    label: String,
    state: State<'_, DesktopState>,
) -> Result<KeystoreEntryReport, String> {
    let keystore: Arc<dyn Keystore> = state.keystore.clone();
    let stored = tokio::task::spawn_blocking(move || keystore.generate(&label))
        .await
        .map_err(|e| format!("join: {e}"))?
        .map_err(|e| e.to_string())?;
    info!(handle = %stored.handle, label = %stored.label, "keystore_generate complete");
    Ok(KeystoreEntryReport::from_stored(&stored))
}

/// Fetch the public-key bundle for a stored handle without unsealing
/// the secret bytes.
///
/// # Errors
///
/// Returns an error if the hex parse fails, the handle is unknown,
/// or the sidecar can't be read.
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "debug", skip(state))]
pub async fn keystore_pubkey(
    handle_hex: String,
    state: State<'_, DesktopState>,
) -> Result<KeystoreEntryReport, String> {
    let handle = KeyHandle::from_hex(&handle_hex).map_err(|e| e.to_string())?;
    let keystore: Arc<dyn Keystore> = state.keystore.clone();
    // pubkey() doesn't unseal, but it still hits the disk on Windows —
    // route through spawn_blocking so a slow disk can't block the
    // Tokio worker.
    let public = tokio::task::spawn_blocking(move || keystore.pubkey(&handle))
        .await
        .map_err(|e| format!("join: {e}"))?
        .map_err(|e| e.to_string())?;
    Ok(KeystoreEntryReport {
        handle_hex,
        ml_dsa_pk_hex: hex::encode(&public.ml_dsa_pk),
        ed25519_pk_hex: hex::encode(public.ed25519_pk),
        // Label / created_at aren't on the public bundle alone; the UI
        // calls `keystore_list` when it wants those. Leave them empty
        // rather than re-reading the sidecar a second time.
        label: String::new(),
        created_at_unix: 0,
    })
}

/// Unseal, sign, zeroize. The `message_hex` payload is hex-decoded by
/// this command — Tauri's JSON layer doesn't preserve raw bytes
/// cleanly, and the UI already handles base64/hex.
///
/// # Errors
///
/// Returns an error if the hex parse fails for either input, the
/// handle is unknown, the OS unseal primitive fails (corrupted blob,
/// wrong user, …), or the signing operation itself fails.
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "info", skip(state, message_hex))]
pub async fn keystore_sign(
    handle_hex: String,
    message_hex: String,
    state: State<'_, DesktopState>,
) -> Result<HybridSignatureReport, String> {
    let handle = KeyHandle::from_hex(&handle_hex).map_err(|e| e.to_string())?;
    let message = hex::decode(&message_hex).map_err(|e| format!("message hex decode: {e}"))?;
    let keystore: Arc<dyn Keystore> = state.keystore.clone();
    let signature = tokio::task::spawn_blocking(move || keystore.sign(&handle, &message))
        .await
        .map_err(|e| format!("join: {e}"))?
        .map_err(|e| e.to_string())?;
    Ok(HybridSignatureReport {
        ml_dsa_sig_hex: hex::encode(&signature.ml_dsa_sig),
        ed25519_sig_hex: hex::encode(signature.ed25519_sig),
    })
}

/// Delete a stored keypair. Returns whether the handle was present.
///
/// # Errors
///
/// Returns an error if the hex parse fails or a disk IO operation
/// fails partway through (one file deleted but not the other).
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "info", skip(state))]
pub async fn keystore_delete(
    handle_hex: String,
    state: State<'_, DesktopState>,
) -> Result<bool, String> {
    let handle = KeyHandle::from_hex(&handle_hex).map_err(|e| e.to_string())?;
    let keystore: Arc<dyn Keystore> = state.keystore.clone();
    let was_present = tokio::task::spawn_blocking(move || keystore.delete(&handle))
        .await
        .map_err(|e| format!("join: {e}"))?
        .map_err(|e| e.to_string())?;
    Ok(was_present)
}

/// Enumerate all stored keys.
///
/// # Errors
///
/// Returns an error if the keystore directory cannot be read or a
/// sidecar file is malformed.
#[tauri::command(rename_all = "snake_case")]
#[instrument(level = "debug", skip(state))]
pub async fn keystore_list(
    state: State<'_, DesktopState>,
) -> Result<Vec<KeystoreEntryReport>, String> {
    let keystore: Arc<dyn Keystore> = state.keystore.clone();
    let entries = tokio::task::spawn_blocking(move || keystore.list())
        .await
        .map_err(|e| format!("join: {e}"))?
        .map_err(|e| e.to_string())?;
    Ok(entries.iter().map(KeystoreEntryReport::from_stored).collect())
}
