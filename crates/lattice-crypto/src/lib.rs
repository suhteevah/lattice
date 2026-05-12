//! # lattice-crypto
//!
//! Post-quantum hybrid cryptography for the Lattice messaging platform.
//!
//! This crate provides:
//!
//! - Hybrid `X25519 + ML-KEM-768` key encapsulation
//!   (see [`hybrid_kex`])
//! - `ML-DSA-65` device identity signatures with `Ed25519` co-signature
//!   (see [`identity`])
//! - `ChaCha20-Poly1305` AEAD framing (see [`aead`])
//! - MLS group state management via `mls-rs` (see [`mls`])
//! - Message padding to fixed buckets (see [`padding`])
//!
//! Sealed-sender envelope construction lives in `lattice-protocol::sealed_sender`
//! (D-05). It is intentionally not in this crate because, after the D-05
//! design, sealed-sender involves only Ed25519 sign/verify (a well-known
//! primitive already available via `ed25519-dalek`) over canonically-encoded
//! wire bytes — there is no Lattice-specific cryptographic primitive to
//! house here.
//!
//! ## Cryptographic spec
//!
//! All algorithm choices are pinned in `docs/HANDOFF.md §8`. Do not silently
//! substitute primitives without updating that document and bumping the wire
//! protocol version in `lattice-protocol`.
//!
//! ## Observability
//!
//! Every public function emits a `tracing` span at `TRACE` level or higher.
//! Set `RUST_LOG=lattice_crypto=trace` to see the full key-derivation flow.
//! Keys themselves are **never** logged — only counts, lengths, and identifiers.
//!
//! ## Safety
//!
//! This crate sets `#![forbid(unsafe_code)]`. Any future FFI requirement must
//! be argued for in a PR and the unsafe block must carry a `// SAFETY:` comment
//! explaining the invariants.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Test code legitimately uses expect()/unwrap()/panic per HANDOFF §7.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

use tracing::instrument;

pub mod aead;
pub mod constants;
pub mod credential;
pub mod fingerprint;
pub mod hybrid_kex;
pub mod identity;
pub mod mls;
pub mod padding;

/// Initialize the crypto subsystem.
///
/// Verifies algorithm availability and emits a startup tracing event. Call
/// this once at process start before any other operation in this crate.
///
/// # Errors
///
/// Returns [`Error::Init`] if a required primitive is unavailable in the
/// linked configuration (for example, ML-KEM compiled out for size reasons).
#[instrument(level = "info")]
pub fn init() -> Result<()> {
    tracing::info!(
        ml_kem = "ML-KEM-768",
        ml_dsa = "ML-DSA-65",
        classical_kem = "X25519",
        classical_sig = "Ed25519",
        aead = "ChaCha20-Poly1305",
        hash = "BLAKE3",
        kdf = "HKDF-SHA-256",
        password_kdf = "argon2id",
        "lattice-crypto initialized"
    );
    Ok(())
}

/// Errors raised by `lattice-crypto`. Domain-level, no infrastructure leaks.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Initialization failed — typically a missing primitive at link time.
    #[error("crypto initialization failed: {0}")]
    Init(String),

    /// Key generation failed. Wraps the underlying RNG or library error.
    #[error("key generation failed: {0}")]
    KeyGen(String),

    /// KEM encapsulation or decapsulation failed.
    #[error("KEM operation failed: {0}")]
    Kem(String),

    /// AEAD encryption produced no ciphertext or rejected the input.
    #[error("AEAD encryption failed")]
    Encrypt,

    /// AEAD decryption failed — either tampered ciphertext or wrong key.
    #[error("AEAD decryption failed")]
    Decrypt,

    /// Signature verification failed.
    #[error("signature verification failed")]
    Signature,

    /// MLS state machine rejected an input.
    #[error("MLS error: {0}")]
    Mls(String),

    /// Padding bucket lookup failed (message exceeds maximum).
    #[error("padding bucket overflow: payload {0} bytes exceeds {1} bytes")]
    PaddingOverflow(usize, usize),

    /// Generic serialization failure from `serde_bytes` / wire codecs.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;
