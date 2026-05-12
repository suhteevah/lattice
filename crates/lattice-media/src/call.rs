//! High-level call lifecycle types.
//!
//! A call is a sequence of MLS application messages (carrying call
//! signaling) layered with a media plane (DTLS-SRTP). This module owns
//! the state machine; the actual signaling payloads live in
//! `lattice-protocol::wire` (added in Phase C) and the media plane
//! lives in [`crate::handshake`] + [`crate::srtp`].
//!
//! Phase B scope: types only. No state-machine transitions yet.

use serde::{Deserialize, Serialize};

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
