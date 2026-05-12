//! # lattice-protocol
//!
//! Wire schemas, framing, and envelope types for Lattice.
//!
//! This crate is the **wire contract**. Any breaking change requires a
//! protocol version bump in [`WIRE_VERSION`] and a migration plan documented
//! in `docs/ARCHITECTURE.md`.
//!
//! Schemas start as Rust structs serialized with Prost (Protocol Buffers
//! over the wire). Migration to Cap'n Proto is tracked as a follow-up; the
//! type surface here is designed to translate cleanly.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Test code legitimately uses expect()/unwrap()/panic per HANDOFF §7.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod lattice_capnp;
pub mod sealed_sender;
pub mod sig;
pub mod wire;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Current wire protocol version. Bump on any breaking schema change.
///
/// * v1 (M2): initial scaffolding — single-joiner PqWelcomePayload
///   {epoch, ml_kem_ct}, no AEAD wrap. Prost wire types.
/// * v2 (M5): multi-joiner support — PqWelcomePayload gains
///   `joiner_idx`, `wrap_nonce`, `wrap_ct` so one shared PSK secret
///   can be sealed to N joiners in a single commit. Prost wire types.
/// * v3 (M5): Prost → Cap'n Proto wire types. Schema at
///   `crates/lattice-protocol/schema/lattice.capnp`; binary encoding
///   is Cap'n Proto packed format. Identity claims, membership
///   certs, sealed envelopes, KeyPackage / Welcome / Commit /
///   ApplicationMessage all changed framing but kept logical
///   structure. Internal TBS encodings in `sealed_sender` +
///   `routes::federation` still use Prost — those are signing-
///   transcript helpers, not wire-format types, and live in a
///   future polish pass.
/// * v4 (M7 Phase C): M7 call signaling — `CallInvite`,
///   `CallAccept`, `CallIceCandidate`, `CallEnd`, and the
///   discriminated `CallSignal` wrapper. The new types live inside
///   MLS-encrypted `ApplicationMessage` payloads — wire envelope is
///   unchanged, but a decoder that recognizes the new variants
///   needs v4-aware code, hence the bump.
pub const WIRE_VERSION: u32 = 4;

/// Identifier for a Lattice user. UUIDv7 — embeds timestamp for
/// natural ordering and debuggability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

/// Identifier for a Lattice group (MLS group ID, mirrored here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub Uuid);

/// Identifier for a single device of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub Uuid);

/// Outer envelope sent on every Lattice wire operation.
///
/// The server inspects only `version`, `recipient`, and routing metadata.
/// `payload_ct` is opaque ciphertext — usually a sealed-sender envelope or
/// an MLS commit/application message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version. Must match [`WIRE_VERSION`].
    pub version: u32,
    /// Recipient (user or group). Server uses this for routing.
    pub recipient: Recipient,
    /// Padded, encrypted payload.
    #[serde(with = "serde_bytes")]
    pub payload_ct: Vec<u8>,
    /// Wire timestamp (RFC 3339, UTC). Informational only — never used in
    /// MLS state.
    pub sent_at: chrono::DateTime<chrono::Utc>,
}

/// Who the envelope is addressed to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Recipient {
    /// 1:1 message to a user. May use sealed sender.
    User {
        /// Recipient user ID.
        id: UserId,
    },
    /// Group message. Always MLS-framed.
    Group {
        /// Target group ID.
        id: GroupId,
    },
}

/// Protocol-level errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The wire version field did not match [`WIRE_VERSION`].
    #[error("wire version mismatch: peer={peer}, ours={ours}")]
    VersionMismatch {
        /// Version sent by the peer.
        peer: u32,
        /// Version we support.
        ours: u32,
    },
    /// Generic decoding failure.
    #[error("decode failure: {0}")]
    Decode(String),
    /// Generic encoding failure.
    #[error("encode failure: {0}")]
    Encode(String),
}

/// `Result` alias for protocol operations.
pub type Result<T> = std::result::Result<T, Error>;
