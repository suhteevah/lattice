//! Error type for the media plane.
//!
//! Domain errors via `thiserror` per workspace convention. Infra
//! errors (tokio, IO, vendored-webrtc) surface through `anyhow` at
//! the boundary call sites rather than leaking into this enum.

use thiserror::Error;

/// Errors emitted by `lattice-media`.
///
/// Variants are intentionally coarse for the scaffold — Phase C and
/// onwards will subdivide as concrete failure modes show up.
#[derive(Debug, Error)]
pub enum MediaError {
    /// The call invite wire payload was malformed or failed signature
    /// validation.
    #[error("invalid call invite: {0}")]
    InvalidInvite(String),

    /// ICE candidate gathering failed.
    #[error("ice gathering failed: {0}")]
    IceGathering(String),

    /// STUN / TURN connectivity failed.
    #[error("rendezvous unreachable: {0}")]
    Rendezvous(String),

    /// DTLS handshake failed or did not produce the expected exporter
    /// material.
    #[error("dtls handshake failed: {0}")]
    DtlsHandshake(String),

    /// ML-KEM-768 encap / decap failed. Should not happen with
    /// well-formed inputs; if it does, the call is aborted.
    #[error("pq key exchange failed: {0}")]
    PqKex(String),

    /// SRTP key derivation or context construction failed.
    #[error("srtp construction failed: {0}")]
    Srtp(String),

    /// Call ended for an unexpected reason.
    #[error("call ended unexpectedly: {0}")]
    CallEnded(String),
}
