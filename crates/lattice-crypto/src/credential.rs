//! Lattice's custom MLS credential carrying a user ID + a hybrid identity
//! public key (Ed25519 + ML-DSA-65).
//!
//! Wraps the same key material as [`crate::identity::IdentityPublicKey`] but
//! adds a `user_id` and serializes via `mls-rs-codec` (TLS-style
//! length-prefixed binary) so it can be embedded in
//! `mls_rs_core::identity::Credential::Custom`. The credential type id is
//! [`CREDENTIAL_TYPE_LATTICE`] (`0xF001`).
//!
//! The user-level vs device-level identity split: a `LatticeCredential`
//! published by a user's device carries that user's *user* `user_id` (a
//! BLAKE3 hash of the canonical handle, e.g. `alice@home.example.com`).
//! Two devices owned by the same user share `user_id` but have distinct
//! `ed25519_pub` + `ml_dsa_pub`. The MLS `IdentityProvider` reports
//! `user_id` as the MLS identity (see [`crate::mls`]), so device rotation
//! within a user is permitted via MLS's `valid_successor` mechanism.

#![allow(clippy::module_name_repetitions)]

// Note: avoid `use crate::{Error, Result}` here — the `mls-rs-codec` derive
// macros generate code that references an unqualified `Error` and expects
// it to be `mls_rs_codec::Error`. Shadowing that with our crate `Error`
// breaks the derive expansion. Use fully-qualified `crate::Error` /
// `crate::Result` instead.
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

/// MLS `CredentialType` value reserved for Lattice's hybrid credential.
///
/// Lives in the private-use range `0xF000..=0xFFFF` per RFC 9420 §17.1.
/// Lattice ciphersuite `LATTICE_HYBRID_V1` is `0xF000`; we use `0xF001` for
/// the credential so the two id spaces don't collide.
pub const CREDENTIAL_TYPE_LATTICE: u16 = 0xF001;

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PK_LEN: usize = 32;

/// Length of an ML-DSA-65 verifying key in bytes (FIPS 204).
pub const ML_DSA_65_PK_LEN: usize = 1952;

/// Length of a user_id in bytes (BLAKE3-256 over a canonical handle).
pub const USER_ID_LEN: usize = 32;

/// A Lattice custom MLS credential.
///
/// Serializes via `mls-rs-codec` to a TLS-style length-prefixed byte string.
/// The resulting bytes go into `mls_rs_core::identity::CustomCredential.data`
/// with `credential_type = CREDENTIAL_TYPE_LATTICE`.
///
/// See [`crate::mls`] for how the credential is bound to an MLS
/// `SigningIdentity` and validated by `LatticeIdentityProvider`.
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct LatticeCredential {
    /// User identifier — BLAKE3-256 over a canonical handle string.
    ///
    /// Two devices owned by the same user share this field.
    pub user_id: [u8; USER_ID_LEN],
    /// Ed25519 verifying key bytes.
    pub ed25519_pub: [u8; ED25519_PK_LEN],
    /// ML-DSA-65 verifying key bytes (1952 bytes per FIPS 204).
    pub ml_dsa_pub: Vec<u8>,
}

impl LatticeCredential {
    /// Construct a credential from the parts. Validates lengths.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if `ml_dsa_pub` is not exactly
    /// [`ML_DSA_65_PK_LEN`] bytes.
    pub fn new(
        user_id: [u8; USER_ID_LEN],
        ed25519_pub: [u8; ED25519_PK_LEN],
        ml_dsa_pub: Vec<u8>,
    ) -> crate::Result<Self> {
        if ml_dsa_pub.len() != ML_DSA_65_PK_LEN {
            return Err(crate::Error::Serialization(format!(
                "ml_dsa_pub length {} (expected {ML_DSA_65_PK_LEN})",
                ml_dsa_pub.len()
            )));
        }
        Ok(Self {
            user_id,
            ed25519_pub,
            ml_dsa_pub,
        })
    }

    /// Encode the credential to wire bytes for embedding in MLS
    /// `CustomCredential.data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if `mls-rs-codec` rejects the value.
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        self.mls_encode_to_vec()
            .map_err(|e| crate::Error::Serialization(format!("encode: {e}")))
    }

    /// Decode a credential from wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] on malformed input or wrong-length
    /// fields after decoding.
    pub fn decode(mut bytes: &[u8]) -> crate::Result<Self> {
        let cred = <Self as MlsDecode>::mls_decode(&mut bytes)
            .map_err(|e| crate::Error::Serialization(format!("decode: {e}")))?;
        if cred.ml_dsa_pub.len() != ML_DSA_65_PK_LEN {
            return Err(crate::Error::Serialization(format!(
                "decoded ml_dsa_pub length {} (expected {ML_DSA_65_PK_LEN})",
                cred.ml_dsa_pub.len()
            )));
        }
        Ok(cred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LatticeCredential {
        LatticeCredential {
            user_id: [0xAA; USER_ID_LEN],
            ed25519_pub: [0xBB; ED25519_PK_LEN],
            ml_dsa_pub: vec![0xCC; ML_DSA_65_PK_LEN],
        }
    }

    #[test]
    fn new_validates_ml_dsa_length() {
        // Right length: OK
        assert!(LatticeCredential::new([0; 32], [0; 32], vec![0; ML_DSA_65_PK_LEN]).is_ok());
        // Wrong length: error
        assert!(matches!(
            LatticeCredential::new([0; 32], [0; 32], vec![0; ML_DSA_65_PK_LEN - 1]),
            Err(crate::Error::Serialization(_))
        ));
        assert!(matches!(
            LatticeCredential::new([0; 32], [0; 32], vec![0; ML_DSA_65_PK_LEN + 1]),
            Err(crate::Error::Serialization(_))
        ));
    }

    #[test]
    fn encode_decode_round_trip() {
        let original = sample();
        let bytes = original.encode().expect("encode");
        let decoded = LatticeCredential::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_rejects_wrong_ml_dsa_length() {
        // Hand-build a credential with a too-short ml_dsa_pub, bypass `new`.
        let bad = LatticeCredential {
            user_id: [0xAA; USER_ID_LEN],
            ed25519_pub: [0xBB; ED25519_PK_LEN],
            ml_dsa_pub: vec![0xCC; ML_DSA_65_PK_LEN - 1],
        };
        let bytes = bad.mls_encode_to_vec().expect("encode");
        let result = LatticeCredential::decode(&bytes);
        assert!(matches!(result, Err(crate::Error::Serialization(_))));
    }

    #[test]
    fn decode_rejects_truncated_bytes() {
        let original = sample();
        let mut bytes = original.encode().expect("encode");
        bytes.truncate(bytes.len() / 2);
        let result = LatticeCredential::decode(&bytes);
        assert!(matches!(result, Err(crate::Error::Serialization(_))));
    }

    #[test]
    fn credential_type_id_is_f001() {
        assert_eq!(CREDENTIAL_TYPE_LATTICE, 0xF001);
    }

    #[test]
    fn constant_lengths_match_fips() {
        assert_eq!(ED25519_PK_LEN, 32);
        assert_eq!(ML_DSA_65_PK_LEN, 1952);
        assert_eq!(USER_ID_LEN, 32);
    }
}
