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

use std::sync::Once;

static INSTALL_CRYPTO: Once = Once::new();

/// Install rustls's `ring` `CryptoProvider` as the process-wide default,
/// at most once per process.
///
/// `dtls` depends on rustls 0.23 for the TLS 1.2 cipher suite
/// implementations. When the same workspace also depends on rustls via
/// `lattice-server` (which inherits the rustls `default` features and
/// therefore enables `aws-lc-rs`), Cargo's feature unification produces
/// a rustls build with BOTH crypto providers enabled. In that state,
/// `CryptoProvider::get_default()` panics with "Could not automatically
/// determine the process-level CryptoProvider".
///
/// Call this at every public entry point that drives a DTLS handshake
/// (the [`call::run_loopback_call`] orchestrator does so internally;
/// the `lattice-desktop` shell does so in `main`). The `Once` makes
/// repeated calls cheap.
///
/// Pinning `ring` here matches the workspace's explicit
/// `rustls = { features = ["ring"] }` declaration; we don't want
/// `aws-lc-rs` because it pulls in a vendored C build that pads
/// compile times and shifts the cryptographic posture sideways.
pub fn ensure_crypto_provider() {
    INSTALL_CRYPTO.call_once(|| {
        // `install_default` returns `Err` if a provider was already
        // installed by some other code path in this process — that's a
        // soft success for our purposes, so we discard the result.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

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
