//! High-level call lifecycle types.
//!
//! A call is a sequence of MLS application messages (carrying call
//! signaling) layered with a media plane (DTLS-SRTP). This module owns
//! the state machine; the actual signaling payloads live in
//! `lattice-protocol::wire` (added in Phase C) and the media plane
//! lives in [`crate::handshake`] + [`crate::srtp`].
//!
//! Phase F additions: [`run_loopback_call`] drives the entire Phase
//! E.2 pipeline + a real `webrtc-srtp::Context` RTP round trip through
//! [`crate::srtp::PqSrtpEndpoint`]. Returns a [`CallOutcome`] suitable
//! for IPC across the Tauri command boundary.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, instrument};

use crate::error::MediaError;
use crate::handshake::{
    decapsulate, default_dtls_config, encapsulate, extract_dtls_exporter, generate_keypair,
    negotiate_dtls,
};
use crate::ice::IceAgent;
use crate::srtp::{
    PqSrtpEndpoint, SRTP_MASTER_KEY_LEN, derive_srtp_master, split_srtp_master,
};

/// Stable identifier for a single call.
///
/// Generated at invite time by the caller and echoed in every
/// subsequent signaling message + the SRTP `info` parameter so all
/// derived material is bound to the same call.
///
/// 16 bytes is chosen to match UUID v4 wire size; the bytes themselves
/// are just `rand::random()` for now — switching to v7 (time-ordered)
/// is a Phase C polish item if it makes call-log ordering easier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallId(pub [u8; 16]);

impl CallId {
    /// Length, in bytes, of the wire encoding.
    pub const LEN: usize = 16;
}

/// Direction relative to the local participant. Used by SRTP to pick
/// between the client-write / server-write key pair derived from the
/// PQ-folded master.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Local participant initiated the call (DTLS client role).
    Caller,
    /// Local participant accepted the call (DTLS server role).
    Callee,
}

/// Call state machine. Transitions are driven by signaling messages
/// from the remote side and by local user actions (accept / decline /
/// hang up). Phase B captures the surface; Phase C wires it up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallState {
    /// Local side has sent `CallInvite`; waiting for `CallAccept` or
    /// `CallDecline`.
    Inviting,
    /// Remote `CallInvite` received; awaiting local accept decision.
    Ringing,
    /// Both sides accepted; ICE candidate exchange in flight.
    Connecting,
    /// DTLS handshake complete, PQ shared secret derived, SRTP keys
    /// installed; media is flowing.
    Active,
    /// Either side hung up, or the connection dropped.
    Ended(EndReason),
}

/// Reason a call ended, surfaced in the `CallEnd` wire payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// Remote side hung up explicitly.
    RemoteHangup,
    /// Local side hung up explicitly.
    LocalHangup,
    /// Remote declined the invite.
    Declined,
    /// ICE failed to find a working candidate pair within the timeout.
    IceFailed,
    /// DTLS handshake failed.
    DtlsFailed,
    /// PQ key exchange failed (encap / decap error).
    PqKexFailed,
}

/// Summary of a completed call setup. Returned by [`run_loopback_call`]
/// and reused by the Tauri `start_call` IPC command so the desktop UI
/// can display non-secret diagnostics (key prefixes, byte counts) to
/// the user without exposing any actual key material.
///
/// **Logging discipline:** none of these fields carry full key material.
/// `srtp_master_prefix` is the first 4 bytes of the 60-byte master, used
/// only for cross-side equality smoke checks at the UI level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallOutcome {
    /// The call this outcome describes. Echoed verbatim from the input.
    pub call_id: CallId,
    /// Number of host ICE candidates the caller saw before the pair
    /// converged. Useful as a "we actually exchanged stuff" signal in
    /// the UI.
    pub caller_candidates_seen: usize,
    /// Same for the callee side.
    pub callee_candidates_seen: usize,
    /// First 4 bytes of the agreed SRTP master, hex-encoded. Both sides
    /// MUST report the same prefix; the orchestrator asserts this
    /// before returning.
    pub srtp_master_prefix: String,
    /// Length of the SRTP-protected RTP packet the caller produced.
    /// Plain RTP was 12 (header) + N (payload); SRTP appends a 10-byte
    /// auth tag for the pinned profile.
    pub protected_rtp_len: usize,
    /// Length of the RTP packet the callee recovered after SRTP unwrap.
    /// MUST equal the plain RTP length the caller fed in.
    pub recovered_rtp_len: usize,
    /// Original plain-RTP packet length the caller encoded. Bundled
    /// alongside [`Self::recovered_rtp_len`] so the UI can render the
    /// pair as "12+N → 12+N".
    pub plain_rtp_len: usize,
}

/// Default per-stage timeout used by [`run_loopback_call`].
///
/// 20 s is generous enough for ICE host-only loopback on a sleepy CI
/// box and short enough that a CLI hang surfaces during interactive
/// use. Tauri callers wanting a different cap should call
/// [`run_loopback_call_with_timeout`] instead.
pub const LOOPBACK_CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Run the full Phase E pipeline plus a real SRTP RTP packet round
/// trip in a single process. Both halves of the call run on the same
/// host; ICE host candidates connect over loopback, DTLS completes,
/// the PQ KEM round-trips through an in-process channel (no MLS
/// transport — this is the smoke proof, not the production signaling
/// path), and a single RTP packet is encrypted by the caller endpoint
/// and decrypted by the callee endpoint.
///
/// Used by:
/// - the `tests/orchestrator_loopback.rs` integration test
/// - the desktop shell's `start_call` Tauri command (Phase F smoke
///   surface — proves the IPC + lattice-media stack are wired up
///   end-to-end; cross-machine signaling lives in later phases).
///
/// # Errors
///
/// Surfaces [`MediaError`] from any stage. The error variant identifies
/// which phase failed (ICE / DTLS / PQ KEX / SRTP).
#[instrument(level = "info", skip_all, fields(call_id = ?call_id))]
pub async fn run_loopback_call(call_id: CallId) -> Result<CallOutcome, MediaError> {
    run_loopback_call_with_timeout(call_id, LOOPBACK_CALL_TIMEOUT).await
}

/// Same as [`run_loopback_call`] but caller controls the per-stage
/// timeout. Useful in tests and in the Tauri command where the UI
/// already has its own progress indicator.
///
/// # Errors
///
/// Same as [`run_loopback_call`].
#[allow(clippy::too_many_lines)] // single-purpose orchestration; splitting hurts readability
#[instrument(level = "info", skip_all, fields(call_id = ?call_id))]
pub async fn run_loopback_call_with_timeout(
    call_id: CallId,
    per_stage_timeout: Duration,
) -> Result<CallOutcome, MediaError> {
    info!("loopback call starting");

    // Defend against rustls feature unification: ensure a default
    // CryptoProvider is installed before any DTLS handshake starts.
    // See `crate::ensure_crypto_provider` doc-comment for context.
    crate::ensure_crypto_provider();

    // -- ICE agents -----------------------------------------------------
    let caller_ice = Arc::new(IceAgent::new(vec![], true).await?);
    let callee_ice = Arc::new(IceAgent::new(vec![], false).await?);

    let caller_creds = caller_ice.local_credentials().await;
    let callee_creds = callee_ice.local_credentials().await;
    caller_ice.set_remote_credentials(callee_creds.clone()).await?;
    callee_ice.set_remote_credentials(caller_creds.clone()).await?;

    // Mirror Phase E.2: each side forwards every gathered local candidate
    // into the other side's `add_remote_candidate`. Real signaling rides
    // MLS; here we short-circuit it through in-process Arcs.
    let caller_seen = Arc::new(Mutex::new(0usize));
    let callee_seen = Arc::new(Mutex::new(0usize));

    {
        let callee_for_caller = Arc::clone(&callee_ice);
        let seen = Arc::clone(&caller_seen);
        caller_ice.on_local_candidate(move |maybe_line| {
            if let Some(sdp) = maybe_line {
                let callee = Arc::clone(&callee_for_caller);
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    *seen.lock().await += 1;
                    if let Err(e) = callee.add_remote_candidate(&sdp) {
                        debug!(error = %e, "callee.add_remote_candidate dropped");
                    }
                });
            }
        });
    }
    {
        let caller_for_callee = Arc::clone(&caller_ice);
        let seen = Arc::clone(&callee_seen);
        callee_ice.on_local_candidate(move |maybe_line| {
            if let Some(sdp) = maybe_line {
                let caller = Arc::clone(&caller_for_callee);
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    *seen.lock().await += 1;
                    if let Err(e) = caller.add_remote_candidate(&sdp) {
                        debug!(error = %e, "caller.add_remote_candidate dropped");
                    }
                });
            }
        });
    }

    caller_ice.gather_candidates()?;
    callee_ice.gather_candidates()?;

    let caller_dial = {
        let ice = Arc::clone(&caller_ice);
        let creds = callee_creds.clone();
        tokio::spawn(async move { ice.dial(creds).await })
    };
    let callee_accept = {
        let ice = Arc::clone(&callee_ice);
        let creds = caller_creds.clone();
        tokio::spawn(async move { ice.accept(creds).await })
    };

    let (caller_conn, callee_conn) = timeout(per_stage_timeout, async {
        let caller_conn = caller_dial
            .await
            .map_err(|e| MediaError::IceGathering(format!("dial join: {e}")))??;
        let callee_conn = callee_accept
            .await
            .map_err(|e| MediaError::IceGathering(format!("accept join: {e}")))??;
        Ok::<_, MediaError>((caller_conn, callee_conn))
    })
    .await
    .map_err(|_| MediaError::IceGathering("ice pair-up timed out".into()))??;
    debug!("ice paired");

    // -- DTLS handshake (both sides concurrent) ------------------------
    let caller_dtls = {
        let cfg = default_dtls_config()?;
        let conn = Arc::clone(&caller_conn);
        tokio::spawn(async move { negotiate_dtls(conn, Role::Caller, cfg).await })
    };
    let callee_dtls = {
        let cfg = default_dtls_config()?;
        let conn = Arc::clone(&callee_conn);
        tokio::spawn(async move { negotiate_dtls(conn, Role::Callee, cfg).await })
    };
    let (caller_dtls, callee_dtls) = timeout(per_stage_timeout, async {
        let a = caller_dtls
            .await
            .map_err(|e| MediaError::DtlsHandshake(format!("caller join: {e}")))??;
        let b = callee_dtls
            .await
            .map_err(|e| MediaError::DtlsHandshake(format!("callee join: {e}")))??;
        Ok::<_, MediaError>((a, b))
    })
    .await
    .map_err(|_| MediaError::DtlsHandshake("dtls handshake timed out".into()))??;
    debug!("dtls handshakes complete");

    // -- DTLS exporter -------------------------------------------------
    let caller_state = caller_dtls.connection_state().await;
    let callee_state = callee_dtls.connection_state().await;
    let caller_exporter = extract_dtls_exporter(&caller_state).await?;
    let callee_exporter = extract_dtls_exporter(&callee_state).await?;
    if caller_exporter.as_bytes() != callee_exporter.as_bytes() {
        return Err(MediaError::DtlsHandshake(
            "dtls exporters diverged — handshake didn't converge".into(),
        ));
    }

    // -- PQ KEM round trip --------------------------------------------
    let caller_kp = generate_keypair()?;
    let callee_encap = encapsulate(&caller_kp.encapsulation_key)?;
    let caller_pq = decapsulate(&caller_kp.decapsulation_key, &callee_encap.ciphertext)?;
    if caller_pq.expose() != callee_encap.shared_secret.expose() {
        return Err(MediaError::PqKex(
            "ml-kem round trip didn't converge".into(),
        ));
    }
    debug!("pq kem agreed");

    // -- PQ-folded SRTP master ----------------------------------------
    let caller_master =
        derive_srtp_master(caller_exporter.as_bytes(), &caller_pq, call_id, 0)?;
    let callee_master = derive_srtp_master(
        callee_exporter.as_bytes(),
        &callee_encap.shared_secret,
        call_id,
        0,
    )?;
    if caller_master.expose() != callee_master.expose() {
        return Err(MediaError::Srtp(
            "pq-folded srtp masters disagree".into(),
        ));
    }
    let srtp_master_prefix = hex_prefix(caller_master.expose(), 4);

    // -- SRTP context build + RTP packet round trip -------------------
    let caller_keys = split_srtp_master(&caller_master, Role::Caller);
    let callee_keys = split_srtp_master(&callee_master, Role::Callee);
    debug_assert_eq!(caller_keys.local.master_key.len(), SRTP_MASTER_KEY_LEN);
    let mut caller_srtp = PqSrtpEndpoint::from_session_keys(caller_keys)?;
    let mut callee_srtp = PqSrtpEndpoint::from_session_keys(callee_keys)?;

    let rtp = build_loopback_rtp_packet(b"lattice phase F smoke");
    let plain_rtp_len = rtp.len();
    let protected = caller_srtp.protect_rtp(&rtp)?;
    let recovered = callee_srtp.unprotect_rtp(&protected)?;
    if recovered.as_ref() != rtp.as_slice() {
        return Err(MediaError::Srtp(
            "callee recovered RTP differs from caller plain RTP".into(),
        ));
    }

    let caller_candidates_seen = *caller_seen.lock().await;
    let callee_candidates_seen = *callee_seen.lock().await;

    // Best-effort teardown; loopback ICE close errors don't fail the
    // call result.
    if let Err(e) = caller_ice.close().await {
        debug!(error = %e, "caller ice close error");
    }
    if let Err(e) = callee_ice.close().await {
        debug!(error = %e, "callee ice close error");
    }

    info!(
        caller_candidates_seen,
        callee_candidates_seen,
        protected_len = protected.len(),
        recovered_len = recovered.len(),
        "loopback call green"
    );

    Ok(CallOutcome {
        call_id,
        caller_candidates_seen,
        callee_candidates_seen,
        srtp_master_prefix,
        protected_rtp_len: protected.len(),
        recovered_rtp_len: recovered.len(),
        plain_rtp_len,
    })
}

/// Minimal RTP/2 packet: 12-byte fixed header (V=2, no padding, no
/// extension, no CSRC, PT=96 dynamic, fixed SSRC) plus the payload.
fn build_loopback_rtp_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12 + payload.len());
    packet.push(0x80); // V=2, P=0, X=0, CC=0
    packet.push(96);   // M=0, PT=96 (dynamic)
    packet.extend_from_slice(&1u16.to_be_bytes()); // sequence_number
    packet.extend_from_slice(&0u32.to_be_bytes()); // timestamp
    packet.extend_from_slice(&0x0c0f_fee0u32.to_be_bytes()); // ssrc
    packet.extend_from_slice(payload);
    packet
}

/// Hex-encode the first `n` bytes of `bytes`. Bounded helper so callers
/// can't accidentally hex the full key material.
fn hex_prefix(bytes: &[u8], n: usize) -> String {
    let take = bytes.len().min(n);
    let mut out = String::with_capacity(take * 2);
    for b in &bytes[..take] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
