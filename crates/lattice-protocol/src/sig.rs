//! Re-exports of crypto-layer signature types for wire-format consumers
//! (D-03).
//!
//! The hybrid signature **type** lives in `lattice_crypto::identity` (the
//! crate that actually produces and validates it). This module re-exports
//! it so wire-format callers can refer to a single canonical name, and
//! also exposes [`wire::HybridSignatureWire`] for Prost-encoded use.

pub use crate::wire::HybridSignatureWire;
pub use lattice_crypto::identity::HybridSignature;
