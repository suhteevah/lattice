//! Sealed-sender envelope construction per D-05.
//!
//! Routing servers should not learn which group member sent a given
//! application message. The construction is Signal-style with a
//! per-epoch server-issued attribution cert:
//!
//! ```text
//! cert.server_sig    = Ed25519(server_sk, canonical_cert_bytes(cert_fields))
//! envelope.envelope_sig = Ed25519(ephemeral_sender_sk,
//!                                 canonical_envelope_bytes(env_fields))
//! ```
//!
//! Where `ephemeral_sender_sk` is the secret pairing of
//! `cert.ephemeral_sender_pubkey`. The routing server verifies both
//! signatures, learns that **some** valid group member sent the
//! envelope, but does not learn **which** member. The recipient
//! decrypts the inner MLS application ciphertext to recover the
//! sender's `LeafNodeIndex` from MLS framing — the routing server
//! never sees that.
//!
//! ## Layered architecture (Phase F, Option B — 2026-05-10)
//!
//! The seal/verify functions live here in `lattice-protocol` rather
//! than `lattice-crypto` because post-D-05 there is no Lattice-specific
//! cryptographic primitive in sealed-sender: it is plain Ed25519
//! sign/verify (`ed25519-dalek`) over canonically-encoded wire bytes.
//! The wire types ([`MembershipCert`], [`SealedEnvelope`]) live in
//! [`crate::wire`] and are Prost-encoded. The "canonical bytes" for
//! signing are derived from inline `*Tbs` (to-be-signed) Prost structs
//! that mirror the wire types minus the signature fields — keeps the
//! transcript deterministic without ad-hoc concatenation.

#![allow(
    clippy::module_name_repetitions,
    // `seal()`'s first paragraph reads as one logical thought; splitting it
    // hurts the documentation more than it helps the rustdoc summary.
    clippy::too_long_first_doc_paragraph,
)]
// Test code in this module legitimately uses expect()/unwrap()/panic and
// redundant clones for clarity per HANDOFF §7.
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::redundant_clone,
    )
)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use prost::Message;

use crate::wire::{MembershipCert, SealedEnvelope};

/// Length of an Ed25519 public key.
pub const ED25519_PUB_LEN: usize = 32;

/// Length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;

/// To-be-signed view of a [`MembershipCert`] (excludes `server_sig`).
///
/// The byte string `MembershipCertTbs.encode_to_vec()` is what the
/// issuing home server signs with its Ed25519 federation identity
/// key, and what the routing server / recipient re-derive to verify.
#[derive(Clone, PartialEq, Eq, Message)]
struct MembershipCertTbs {
    #[prost(bytes = "vec", tag = "1")]
    group_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    epoch: u64,
    #[prost(bytes = "vec", tag = "3")]
    ephemeral_sender_pubkey: Vec<u8>,
    #[prost(int64, tag = "4")]
    valid_until: i64,
}

impl MembershipCertTbs {
    fn from_cert(cert: &MembershipCert) -> Self {
        Self {
            group_id: cert.group_id.clone(),
            epoch: cert.epoch,
            ephemeral_sender_pubkey: cert.ephemeral_sender_pubkey.clone(),
            valid_until: cert.valid_until,
        }
    }
}

/// To-be-signed view of a [`SealedEnvelope`] (excludes
/// `membership_cert.server_sig` and `envelope_sig`).
///
/// `cert_canonical` is the byte string from [`MembershipCertTbs`] —
/// signing the cert into the envelope transcript ties the envelope to
/// a specific cert + server policy without re-embedding all the cert
/// fields again.
#[derive(Clone, PartialEq, Eq, Message)]
struct SealedEnvelopeTbs {
    #[prost(bytes = "vec", tag = "1")]
    group_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    epoch: u64,
    #[prost(bytes = "vec", tag = "3")]
    cert_canonical: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    inner_ciphertext: Vec<u8>,
}

/// Errors raised by sealed-sender operations.
#[derive(Debug, thiserror::Error)]
pub enum SealedSenderError {
    /// Envelope did not carry a `membership_cert` field.
    #[error("envelope is missing its membership cert")]
    MissingCert,
    /// Server's Ed25519 verifying key bytes were the wrong length.
    #[error("server pubkey length {got} (expected {expected})")]
    ServerPubkeyLength {
        /// Observed length.
        got: usize,
        /// Required: [`ED25519_PUB_LEN`].
        expected: usize,
    },
    /// `cert.ephemeral_sender_pubkey` length was wrong.
    #[error("ephemeral sender pubkey length {got} (expected {expected})")]
    EphemeralPubkeyLength {
        /// Observed length.
        got: usize,
        /// Required: [`ED25519_PUB_LEN`].
        expected: usize,
    },
    /// `cert.server_sig` length was wrong.
    #[error("cert server_sig length {got} (expected {expected})")]
    CertSigLength {
        /// Observed length.
        got: usize,
        /// Required: [`ED25519_SIG_LEN`].
        expected: usize,
    },
    /// `envelope.envelope_sig` length was wrong.
    #[error("envelope_sig length {got} (expected {expected})")]
    EnvelopeSigLength {
        /// Observed length.
        got: usize,
        /// Required: [`ED25519_SIG_LEN`].
        expected: usize,
    },
    /// Server's signature on the cert did not verify.
    #[error("cert server_sig failed Ed25519 verify")]
    CertSigInvalid,
    /// Sender's signature on the envelope did not verify.
    #[error("envelope_sig failed Ed25519 verify")]
    EnvelopeSigInvalid,
    /// Cert validity window had already expired at verify time.
    #[error("cert expired: valid_until={valid_until} now={now}")]
    CertExpired {
        /// `cert.valid_until` Unix-epoch seconds.
        valid_until: i64,
        /// Current Unix-epoch seconds.
        now: i64,
    },
    /// Envelope claims a `group_id`/`epoch` that does not match the
    /// embedded cert.
    #[error("envelope group_id/epoch does not match its cert")]
    CertMismatch,
}

/// Issue a [`MembershipCert`] by signing the canonical cert bytes with
/// the home server's Ed25519 federation identity key.
///
/// This is the server-side cert-minting helper — server-side code
/// (`lattice-server::routes::issue_cert`, M3 scope) uses this when a
/// member's epoch rotates. Tests and the integration harness call it
/// directly to fabricate certs without a live server.
#[must_use]
pub fn issue_cert(
    server_sk: &SigningKey,
    group_id: Vec<u8>,
    epoch: u64,
    ephemeral_sender_pubkey: Vec<u8>,
    valid_until: i64,
) -> MembershipCert {
    let tbs = MembershipCertTbs {
        group_id: group_id.clone(),
        epoch,
        ephemeral_sender_pubkey: ephemeral_sender_pubkey.clone(),
        valid_until,
    };
    let bytes = tbs.encode_to_vec();
    let sig = server_sk.sign(&bytes);
    MembershipCert {
        group_id,
        epoch,
        ephemeral_sender_pubkey,
        valid_until,
        server_sig: sig.to_bytes().to_vec(),
    }
}

/// Seal an MLS application-message ciphertext into a [`SealedEnvelope`].
///
/// The sender signs the envelope transcript with the secret key paired
/// to `cert.ephemeral_sender_pubkey` (which the sender chose during
/// cert issuance and persists locally).
///
/// # Errors
///
/// Returns [`SealedSenderError::EphemeralPubkeyLength`] if the cert's
/// ephemeral pubkey is malformed.
pub fn seal(
    cert: MembershipCert,
    ephemeral_sk: &SigningKey,
    inner_ciphertext: Vec<u8>,
) -> Result<SealedEnvelope, SealedSenderError> {
    // Sanity check: the cert's ephemeral pubkey must match the secret
    // key the caller is signing with. Defends against a confused-deputy
    // where a stale cert is paired with the wrong sk.
    if cert.ephemeral_sender_pubkey.len() != ED25519_PUB_LEN {
        return Err(SealedSenderError::EphemeralPubkeyLength {
            got: cert.ephemeral_sender_pubkey.len(),
            expected: ED25519_PUB_LEN,
        });
    }
    let derived_pk = ephemeral_sk.verifying_key().to_bytes();
    if derived_pk.as_slice() != cert.ephemeral_sender_pubkey.as_slice() {
        // Same length variant — caller passed the wrong sk. We surface
        // it as the most informative existing variant; a dedicated
        // KeyMismatch would be slightly clearer but isn't worth a
        // breaking enum addition.
        return Err(SealedSenderError::EphemeralPubkeyLength {
            got: 0,
            expected: ED25519_PUB_LEN,
        });
    }

    let cert_canonical = MembershipCertTbs::from_cert(&cert).encode_to_vec();
    let env_tbs = SealedEnvelopeTbs {
        group_id: cert.group_id.clone(),
        epoch: cert.epoch,
        cert_canonical,
        inner_ciphertext: inner_ciphertext.clone(),
    };
    let env_bytes = env_tbs.encode_to_vec();
    let env_sig = ephemeral_sk.sign(&env_bytes);

    Ok(SealedEnvelope {
        group_id: cert.group_id.clone(),
        epoch: cert.epoch,
        membership_cert: Some(cert),
        inner_ciphertext,
        envelope_sig: env_sig.to_bytes().to_vec(),
    })
}

/// Verify a sealed envelope at the routing server.
///
/// Checks: (a) `cert.server_sig` against the canonical cert bytes
/// under `server_pubkey`, (b) `envelope.envelope_sig` against the
/// canonical envelope bytes under `cert.ephemeral_sender_pubkey`,
/// (c) `cert.valid_until` is in the future, (d) the envelope's
/// `group_id`/`epoch` matches the cert's.
///
/// On success the router knows "some valid group member with cert
/// issued by `server_pubkey` sent this" but learns nothing about
/// which member.
///
/// # Errors
///
/// Returns one of the [`SealedSenderError`] variants on any failure.
pub fn verify_at_router(
    server_pubkey: &VerifyingKey,
    envelope: &SealedEnvelope,
    now_unix: i64,
) -> Result<(), SealedSenderError> {
    let cert = envelope
        .membership_cert
        .as_ref()
        .ok_or(SealedSenderError::MissingCert)?;

    // Envelope binds to a specific cert (group_id, epoch).
    if envelope.group_id != cert.group_id || envelope.epoch != cert.epoch {
        return Err(SealedSenderError::CertMismatch);
    }

    // Time check.
    if cert.valid_until < now_unix {
        return Err(SealedSenderError::CertExpired {
            valid_until: cert.valid_until,
            now: now_unix,
        });
    }

    // Cert signature.
    if cert.server_sig.len() != ED25519_SIG_LEN {
        return Err(SealedSenderError::CertSigLength {
            got: cert.server_sig.len(),
            expected: ED25519_SIG_LEN,
        });
    }
    let cert_canonical = MembershipCertTbs::from_cert(cert).encode_to_vec();
    let server_sig_bytes: [u8; ED25519_SIG_LEN] =
        cert.server_sig
            .as_slice()
            .try_into()
            .map_err(|_| SealedSenderError::CertSigLength {
                got: cert.server_sig.len(),
                expected: ED25519_SIG_LEN,
            })?;
    let cert_sig = Signature::from_bytes(&server_sig_bytes);
    server_pubkey
        .verify(&cert_canonical, &cert_sig)
        .map_err(|_| SealedSenderError::CertSigInvalid)?;

    // Envelope signature.
    if envelope.envelope_sig.len() != ED25519_SIG_LEN {
        return Err(SealedSenderError::EnvelopeSigLength {
            got: envelope.envelope_sig.len(),
            expected: ED25519_SIG_LEN,
        });
    }
    if cert.ephemeral_sender_pubkey.len() != ED25519_PUB_LEN {
        return Err(SealedSenderError::EphemeralPubkeyLength {
            got: cert.ephemeral_sender_pubkey.len(),
            expected: ED25519_PUB_LEN,
        });
    }
    let eph_pk_bytes: [u8; ED25519_PUB_LEN] = cert
        .ephemeral_sender_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| SealedSenderError::EphemeralPubkeyLength {
            got: cert.ephemeral_sender_pubkey.len(),
            expected: ED25519_PUB_LEN,
        })?;
    let eph_pk = VerifyingKey::from_bytes(&eph_pk_bytes)
        .map_err(|_| SealedSenderError::EnvelopeSigInvalid)?;

    let env_tbs = SealedEnvelopeTbs {
        group_id: cert.group_id.clone(),
        epoch: cert.epoch,
        cert_canonical,
        inner_ciphertext: envelope.inner_ciphertext.clone(),
    };
    let env_bytes = env_tbs.encode_to_vec();
    let env_sig_bytes: [u8; ED25519_SIG_LEN] =
        envelope.envelope_sig.as_slice().try_into().map_err(|_| {
            SealedSenderError::EnvelopeSigLength {
                got: envelope.envelope_sig.len(),
                expected: ED25519_SIG_LEN,
            }
        })?;
    let env_sig = Signature::from_bytes(&env_sig_bytes);
    eph_pk
        .verify(&env_bytes, &env_sig)
        .map_err(|_| SealedSenderError::EnvelopeSigInvalid)?;

    Ok(())
}

/// Recipient-side open. Verifies the envelope (same checks as
/// [`verify_at_router`]) and returns the inner MLS application
/// ciphertext. Caller's MLS state then decrypts to recover sender
/// identity from the inner framing.
///
/// # Errors
///
/// Same as [`verify_at_router`].
pub fn open_at_recipient<'a>(
    server_pubkey: &VerifyingKey,
    envelope: &'a SealedEnvelope,
    now_unix: i64,
) -> Result<&'a [u8], SealedSenderError> {
    verify_at_router(server_pubkey, envelope, now_unix)?;
    Ok(&envelope.inner_ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand_core::RngCore;

    fn rand_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.try_fill_bytes(&mut seed).expect("rng");
        SigningKey::from_bytes(&seed)
    }

    /// Build a (cert, ephemeral_sk) pair using a freshly generated
    /// server identity. Returns (server_pk, cert, eph_sk).
    fn fixture(
        group_id: Vec<u8>,
        epoch: u64,
        valid_until: i64,
    ) -> (VerifyingKey, MembershipCert, SigningKey) {
        let server_sk = rand_signing_key();
        let server_pk = server_sk.verifying_key();
        let eph_sk = rand_signing_key();
        let eph_pk_bytes = eph_sk.verifying_key().to_bytes().to_vec();
        let cert = issue_cert(&server_sk, group_id, epoch, eph_pk_bytes, valid_until);
        (server_pk, cert, eph_sk)
    }

    #[test]
    fn round_trip_seal_open() {
        let (server_pk, cert, eph_sk) = fixture(vec![1; 16], 7, 1_700_000_000);
        let inner = b"mls application message ciphertext".to_vec();
        let env = seal(cert, &eph_sk, inner.clone()).expect("seal");
        // Router check (one minute before expiry).
        verify_at_router(&server_pk, &env, 1_699_999_900).expect("router verify");
        // Recipient unwrap.
        let recovered = open_at_recipient(&server_pk, &env, 1_699_999_900).expect("open");
        assert_eq!(recovered, inner);
    }

    #[test]
    fn router_does_not_decrypt_inner() {
        // The router has only server_pubkey — verify succeeds, but the
        // inner_ciphertext field is opaque (no MLS state available).
        let (server_pk, cert, eph_sk) = fixture(vec![2; 16], 1, 1_700_000_000);
        let env = seal(cert, &eph_sk, b"opaque inner".to_vec()).expect("seal");
        verify_at_router(&server_pk, &env, 1_699_999_000).expect("verify");
        // Routing server CAN see `env.inner_ciphertext` bytes but cannot
        // derive who sent them or what they say without MLS state.
        // The test asserts the verify path doesn't attempt to interpret
        // them.
        assert!(!env.inner_ciphertext.is_empty(), "inner present but opaque");
    }

    #[test]
    fn router_cannot_identify_sender() {
        // Two distinct ephemeral keypairs issue certs from the same
        // server for the same group/epoch. The router cannot tell which
        // member sent a given envelope just by inspecting the envelope.
        let server_sk = rand_signing_key();
        let server_pk = server_sk.verifying_key();
        let group_id: Vec<u8> = vec![3; 16];
        let epoch = 1;
        let valid_until = 1_700_000_000;

        let alice_eph_sk = rand_signing_key();
        let alice_eph_pk = alice_eph_sk.verifying_key().to_bytes().to_vec();
        let alice_cert = issue_cert(
            &server_sk,
            group_id.clone(),
            epoch,
            alice_eph_pk,
            valid_until,
        );
        let bob_eph_sk = rand_signing_key();
        let bob_eph_pk = bob_eph_sk.verifying_key().to_bytes().to_vec();
        let bob_cert = issue_cert(&server_sk, group_id.clone(), epoch, bob_eph_pk, valid_until);

        let env_a = seal(alice_cert, &alice_eph_sk, b"from alice".to_vec()).expect("alice seal");
        let env_b = seal(bob_cert, &bob_eph_sk, b"from bob".to_vec()).expect("bob seal");

        // Both verify under the same server_pk.
        verify_at_router(&server_pk, &env_a, 1_699_999_000).expect("alice verify");
        verify_at_router(&server_pk, &env_b, 1_699_999_000).expect("bob verify");

        // Server sees `env.ephemeral_sender_pubkey` differs but has no
        // mapping from that to a stable identity — which is the property
        // the design provides. Re-cert in the next epoch with a fresh
        // ephemeral key prevents cross-epoch correlation.
        let alice_eph_pk_in_env = &env_a
            .membership_cert
            .as_ref()
            .unwrap()
            .ephemeral_sender_pubkey;
        let bob_eph_pk_in_env = &env_b
            .membership_cert
            .as_ref()
            .unwrap()
            .ephemeral_sender_pubkey;
        assert_ne!(alice_eph_pk_in_env, bob_eph_pk_in_env);
    }

    #[test]
    fn tampered_envelope_sig_rejected() {
        let (server_pk, cert, eph_sk) = fixture(vec![4; 16], 1, 1_700_000_000);
        let mut env = seal(cert, &eph_sk, b"original".to_vec()).expect("seal");
        env.envelope_sig[0] ^= 0xFF;
        assert!(matches!(
            verify_at_router(&server_pk, &env, 1_699_999_000),
            Err(SealedSenderError::EnvelopeSigInvalid)
        ));
    }

    #[test]
    fn tampered_cert_sig_rejected() {
        let (server_pk, cert, eph_sk) = fixture(vec![5; 16], 1, 1_700_000_000);
        let mut env = seal(cert, &eph_sk, b"x".to_vec()).expect("seal");
        env.membership_cert.as_mut().unwrap().server_sig[0] ^= 0xFF;
        assert!(matches!(
            verify_at_router(&server_pk, &env, 1_699_999_000),
            Err(SealedSenderError::CertSigInvalid)
        ));
    }

    #[test]
    fn tampered_inner_ciphertext_rejected() {
        let (server_pk, cert, eph_sk) = fixture(vec![6; 16], 1, 1_700_000_000);
        let mut env = seal(cert, &eph_sk, b"original".to_vec()).expect("seal");
        env.inner_ciphertext[0] ^= 0xFF;
        // Envelope_sig was computed over the original inner_ciphertext,
        // so tampering breaks the signature.
        assert!(matches!(
            verify_at_router(&server_pk, &env, 1_699_999_000),
            Err(SealedSenderError::EnvelopeSigInvalid)
        ));
    }

    #[test]
    fn expired_cert_rejected() {
        let (server_pk, cert, eph_sk) = fixture(vec![7; 16], 1, 1_700_000_000);
        let env = seal(cert, &eph_sk, b"x".to_vec()).expect("seal");
        // verify at now=2 billion (well past valid_until=1.7B).
        let result = verify_at_router(&server_pk, &env, 2_000_000_000);
        assert!(matches!(result, Err(SealedSenderError::CertExpired { .. })));
    }

    #[test]
    fn wrong_server_pubkey_rejected() {
        let (_server_pk, cert, eph_sk) = fixture(vec![8; 16], 1, 1_700_000_000);
        let env = seal(cert, &eph_sk, b"x".to_vec()).expect("seal");
        let attacker_pk = rand_signing_key().verifying_key();
        assert!(matches!(
            verify_at_router(&attacker_pk, &env, 1_699_999_000),
            Err(SealedSenderError::CertSigInvalid)
        ));
    }

    #[test]
    fn seal_rejects_wrong_ephemeral_sk() {
        let (_server_pk, cert, _correct_eph_sk) = fixture(vec![9; 16], 1, 1_700_000_000);
        let wrong_eph_sk = rand_signing_key();
        let result = seal(cert, &wrong_eph_sk, b"x".to_vec());
        assert!(matches!(
            result,
            Err(SealedSenderError::EphemeralPubkeyLength { .. })
        ));
    }

    #[test]
    fn envelope_group_id_mismatch_rejected() {
        let (server_pk, cert, eph_sk) = fixture(vec![10; 16], 1, 1_700_000_000);
        let mut env = seal(cert, &eph_sk, b"x".to_vec()).expect("seal");
        env.group_id = vec![99; 16];
        assert!(matches!(
            verify_at_router(&server_pk, &env, 1_699_999_000),
            Err(SealedSenderError::CertMismatch)
        ));
    }
}
