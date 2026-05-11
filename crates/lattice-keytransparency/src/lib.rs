//! # lattice-keytransparency
//!
//! Append-only Merkle-log of user identity keys, CONIKS-style.
//!
//! Reserved for V1.5. See `docs/ROADMAP.md`. This crate exists as a
//! placeholder so dependent crates can reference its types without
//! workspace churn when the implementation lands.
//!
//! Planned interface:
//!
//! - `Log` — append-only structure; each leaf is `(user_id, identity_pk,
//!   epoch)`.
//! - `InclusionProof` — Merkle path from a leaf to the current root.
//! - `ConsistencyProof` — proof that root R₂ extends root R₁.
//! - Third-party `Auditor` — verifies log monotonicity over time.
//!
//! ## Status
//!
//! Empty crate. Do not depend on it for V1 code paths.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Placeholder errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not yet implemented.
    #[error("not implemented")]
    NotImplemented,
}
