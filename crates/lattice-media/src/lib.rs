//! # lattice-media
//!
//! M7 — voice/video for Lattice. This crate is the home for everything
//! that drives a 1:1 audio/video call: PQ-hybrid DTLS-SRTP, ICE/STUN/TURN
//! candidate gathering, call signaling, and (later) hardware-backed key
//! integration on Tauri shells.
//!
//! **Status:** Phase B scaffold. Module skeletons + types in place; no
//! behavior yet. See `scratch/m7-build-plan.md` for the phased plan and
//! `docs/HANDOFF.md` §14 for the in-progress notes.
//!
//! ## Cryptographic posture
//!
//! Voice/video ships PQ-hybrid from day one. The DTLS-SRTP handshake
//! itself remains classical (X25519 + ECDSA) because no shipping DTLS
//! stack implements ML-KEM yet, but the SRTP master key is derived as
//!
//! ```text
//! srtp_master = HKDF-SHA-256(
//!     ikm  = dtls_exporter || ml_kem_768_shared_secret,
//!     salt = b"lattice/srtp/v1",
//!     info = call_id || epoch_id,
//!     length = 60,
//! )
//! ```
//!
//! The ML-KEM-768 ciphertext is exchanged inside MLS application
//! messages alongside the call invite, so an attacker who breaks
//! X25519/ECDSA in 20 years still cannot recover SRTP keys without
//! also breaking ML-KEM-768.
//!
//! ## What lives here vs. elsewhere
//!
//! - **`lattice-crypto`** owns MLS, identity, and the primitives. We
//!   re-use its hybrid KEM helpers; we don't duplicate them.
//! - **`lattice-protocol`** owns the wire types. Call-signaling
//!   payloads (`CallInvite`, `CallAccept`, `CallIceCandidate`,
//!   `CallEnd`) are MLS `ApplicationMessage` payload variants
//!   defined there.
//! - **`lattice-media`** (this crate) is where the media plane —
//!   DTLS-SRTP, ICE, RTP framing — actually runs. Once Phase D
//!   lands, the `vendor/` subdirectory carries patched copies of
//!   `webrtc-dtls` and `webrtc-srtp` with the surgical hooks that
//!   accept externally-derived SRTP keys.
//!
//! ## Non-goals
//!
//! No classical-only fallback path. The "tonight shortcut" path
//! (plain WebRTC + MLS-encrypted signaling, no PQ overlay) was
//! considered and rejected on 2026-05-11. Voice/video ships PQ-hybrid
//! or it doesn't ship.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod call;
pub mod constants;
pub mod error;
pub mod handshake;
pub mod ice;
pub mod rendezvous;
pub mod srtp;

pub use error::MediaError;

/// Identifier reported by [`crate_version`] — sanity-check that the
/// scaffold is reachable from downstream tests / dependents.
///
/// This is intentionally a function, not a `const`, so that future
/// phases can fold in build-time provenance (git short hash, vendored-
/// webrtc-rs upstream tag) without breaking callers.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_version_is_non_empty() {
        assert!(!crate_version().is_empty());
    }
}
