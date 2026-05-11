//! Sealed sender envelopes.
//!
//! For 1:1 DMs, the server does not need to know the sender identity to
//! route a message — only the recipient. Sealed sender wraps the ciphertext
//! in an envelope encrypted to the recipient's long-term key, with the
//! sender's identity inside the envelope.
//!
//! The server sees: `{ recipient_id, opaque_blob }`. The recipient unwraps
//! and discovers: `{ sender_id, application_payload, sender_signature }`.
//!
//! ## Construction
//!
//! Following Signal's sealed sender pattern, adapted for hybrid PQ:
//!
//! 1. Sender derives an ephemeral hybrid keypair `(eph_pk, eph_sk)`.
//! 2. Sender encapsulates to the recipient's long-term hybrid pubkey,
//!    producing a shared secret `SS_envelope`.
//! 3. Sender constructs `inner = sender_id || timestamp || ciphertext`.
//! 4. Sender signs `inner` with their hybrid identity key.
//! 5. AEAD-encrypts `inner || signature` under `SS_envelope`.
//! 6. Wire form: `eph_pk || ml_kem_ct || aead_ciphertext`.
//!
//! ## Status
//!
//! Stub — see `docs/HANDOFF.md §6`. Defers to [`crate::hybrid_kex`] and
//! [`crate::aead`] once those land.

use tracing::instrument;

use crate::{Error, Result};

/// Wrap a payload in a sealed sender envelope addressed to `recipient_pk`.
///
/// # Errors
///
/// Returns [`Error::SealedSender`] on KEX or AEAD failure.
#[instrument(level = "debug", skip(sender_sk, sender_id, recipient_pk, payload), fields(pt_len = payload.len()))]
pub fn seal(
    sender_sk: &crate::identity::IdentitySecretKey,
    sender_id: &[u8],
    recipient_pk: &crate::hybrid_kex::HybridPublicKey,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let _ = (sender_sk, sender_id, recipient_pk, payload);
    tracing::debug!("sealed_sender::seal — TODO");
    Err(Error::SealedSender("sealed_sender::seal not implemented".into()))
}

/// Unwrap a sealed sender envelope using the recipient's long-term key.
///
/// Returns the discovered sender ID and the inner payload. The sender's
/// signature inside the envelope is verified before returning.
///
/// # Errors
///
/// Returns [`Error::SealedSender`] on any integrity or signature failure.
#[instrument(level = "debug", skip(recipient_sk, envelope), fields(env_len = envelope.len()))]
pub fn open(
    recipient_sk: &crate::hybrid_kex::HybridSecretKey,
    envelope: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let _ = (recipient_sk, envelope);
    tracing::debug!("sealed_sender::open — TODO");
    Err(Error::SealedSender("sealed_sender::open not implemented".into()))
}
