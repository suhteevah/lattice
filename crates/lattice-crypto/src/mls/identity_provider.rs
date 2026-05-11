//! `mls-rs` [`IdentityProvider`] implementation for Lattice's hybrid
//! credential.
//!
//! Decodes [`crate::credential::LatticeCredential`] from each member's
//! MLS `SigningIdentity` and enforces:
//!
//! - The credential's `credential_type` is `CREDENTIAL_TYPE_LATTICE`
//!   (`0xF001`).
//! - The `signing_identity.signature_key` byte layout matches the
//!   credential's `ed25519_pub` and `ml_dsa_pub` (catches confused-deputy
//!   attacks where a member presents one credential and signs with
//!   another's key).
//! - The MLS-level identity is the credential's `user_id`, not the
//!   per-device key. This lets a user rotate devices inside the same
//!   group without leaving and rejoining: any sibling device with the
//!   same `user_id` is a [`valid_successor`].
//!
//! [`IdentityProvider`]: mls_rs_core::identity::IdentityProvider
//! [`valid_successor`]: mls_rs_core::identity::IdentityProvider::valid_successor

use mls_rs_core::{
    extension::ExtensionList,
    identity::{
        Credential, CredentialType, IdentityProvider, MemberValidationContext, SigningIdentity,
    },
    time::MlsTime,
};

use crate::credential::{
    CREDENTIAL_TYPE_LATTICE, ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN,
};

/// Layout of the `SigningIdentity::signature_key` byte string for the
/// Lattice hybrid suite: `ed25519_pub(32) || ml_dsa_pub(1952)`.
///
/// `LatticeHybridCipherSuite::sign` and `::verify` use this layout to
/// produce/check hybrid signatures, and `LatticeIdentityProvider` checks
/// that the credential's individual key fields agree with this packed
/// representation.
pub const SIGNATURE_KEY_LEN: usize = ED25519_PK_LEN + ML_DSA_65_PK_LEN;

/// `mls-rs` [`IdentityProvider`] for Lattice.
///
/// Stateless — clone freely. Validation does not require external state;
/// optional cross-checks against a key-transparency log (M6) will live in
/// a separate validator that runs upstream of this provider.
#[derive(Clone, Debug, Default)]
pub struct LatticeIdentityProvider;

impl LatticeIdentityProvider {
    /// Construct a fresh provider. The provider is stateless, so any two
    /// instances behave identically.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Decode the embedded Lattice credential, or fail with an error
    /// describing why this signing identity is not acceptable.
    fn extract_credential(
        signing_identity: &SigningIdentity,
    ) -> Result<LatticeCredential, IdentityProviderError> {
        let Credential::Custom(custom) = &signing_identity.credential else {
            return Err(IdentityProviderError::NotLatticeCredential);
        };
        if custom.credential_type != CredentialType::new(CREDENTIAL_TYPE_LATTICE) {
            return Err(IdentityProviderError::WrongCredentialType(
                custom.credential_type.raw_value(),
            ));
        }
        LatticeCredential::decode(&custom.data)
            .map_err(|e| IdentityProviderError::Decode(format!("credential decode: {e}")))
    }

    /// Check that `signing_identity.signature_key` byte layout matches the
    /// credential's `ed25519_pub` and `ml_dsa_pub` fields.
    fn check_signature_key_binding(
        signing_identity: &SigningIdentity,
        cred: &LatticeCredential,
    ) -> Result<(), IdentityProviderError> {
        let key_bytes: &[u8] = signing_identity.signature_key.as_bytes();
        if key_bytes.len() != SIGNATURE_KEY_LEN {
            return Err(IdentityProviderError::SignatureKeyLength {
                got: key_bytes.len(),
                expected: SIGNATURE_KEY_LEN,
            });
        }
        let (ed_part, ml_part) = key_bytes.split_at(ED25519_PK_LEN);
        if ed_part != cred.ed25519_pub {
            return Err(IdentityProviderError::Ed25519Mismatch);
        }
        if ml_part != cred.ml_dsa_pub {
            return Err(IdentityProviderError::MlDsaMismatch);
        }
        Ok(())
    }
}

impl IdentityProvider for LatticeIdentityProvider {
    type Error = IdentityProviderError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        let cred = Self::extract_credential(signing_identity)?;
        Self::check_signature_key_binding(signing_identity, &cred)?;
        Ok(())
    }

    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        // Lattice does not use MLS external senders in V1: every commit
        // originates from a group member. Refuse outright so a confused
        // policy does not silently allow them.
        Err(IdentityProviderError::ExternalSenderUnsupported)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        let cred = Self::extract_credential(signing_identity)?;
        // MLS-level identity is the user, not the device. Same user_id
        // across two devices ⇒ MLS treats them as the same identity, so
        // the rotation flow does not need a Remove + Add commit cycle.
        Ok(cred.user_id.to_vec())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        let pre = Self::extract_credential(predecessor)?;
        let suc = Self::extract_credential(successor)?;
        Ok(pre.user_id == suc.user_id)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::new(CREDENTIAL_TYPE_LATTICE)]
    }
}

/// Errors raised by [`LatticeIdentityProvider`].
#[derive(Debug, thiserror::Error)]
pub enum IdentityProviderError {
    /// `signing_identity.credential` was not a `Credential::Custom(_)`.
    #[error("signing identity does not carry a custom credential")]
    NotLatticeCredential,
    /// Credential type id did not match `CREDENTIAL_TYPE_LATTICE`.
    #[error("custom credential type {0:#06x} does not match Lattice ({expected:#06x})", expected = CREDENTIAL_TYPE_LATTICE)]
    WrongCredentialType(u16),
    /// Embedded `LatticeCredential` bytes failed to decode.
    #[error("{0}")]
    Decode(String),
    /// `signing_identity.signature_key` byte length is wrong for the
    /// hybrid suite.
    #[error("signature key length {got} (expected {expected})")]
    SignatureKeyLength {
        /// Observed length.
        got: usize,
        /// Required length: `ED25519_PK_LEN + ML_DSA_65_PK_LEN`.
        expected: usize,
    },
    /// `signing_identity.signature_key[..32]` did not match
    /// `credential.ed25519_pub`.
    #[error("ed25519 portion of signature_key does not match credential")]
    Ed25519Mismatch,
    /// `signing_identity.signature_key[32..]` did not match
    /// `credential.ml_dsa_pub`.
    #[error("ml-dsa portion of signature_key does not match credential")]
    MlDsaMismatch,
    /// `validate_external_sender` called — refused by design (V1).
    #[error("external senders are not supported in Lattice V1")]
    ExternalSenderUnsupported,
}

impl mls_rs_core::error::IntoAnyError for IdentityProviderError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mls_rs_core::{
        crypto::SignaturePublicKey,
        identity::{Credential, CustomCredential, SigningIdentity},
    };

    fn sample_credential(user_id_byte: u8) -> LatticeCredential {
        LatticeCredential {
            user_id: [user_id_byte; 32],
            ed25519_pub: [0xBB; ED25519_PK_LEN],
            ml_dsa_pub: vec![0xCC; ML_DSA_65_PK_LEN],
        }
    }

    /// Build a SigningIdentity whose signature_key is the canonical
    /// `ed25519_pub || ml_dsa_pub` byte layout for the given credential.
    fn matched_signing_identity(cred: &LatticeCredential) -> SigningIdentity {
        let mut signature_key_bytes = Vec::with_capacity(ED25519_PK_LEN + ML_DSA_65_PK_LEN);
        signature_key_bytes.extend_from_slice(&cred.ed25519_pub);
        signature_key_bytes.extend_from_slice(&cred.ml_dsa_pub);
        SigningIdentity {
            credential: Credential::Custom(CustomCredential {
                credential_type: CredentialType::new(CREDENTIAL_TYPE_LATTICE),
                data: cred.encode().expect("encode"),
            }),
            signature_key: SignaturePublicKey::from(signature_key_bytes),
        }
    }

    #[test]
    fn validate_member_accepts_matched_keys() {
        let cred = sample_credential(0x11);
        let ident = matched_signing_identity(&cred);
        let provider = LatticeIdentityProvider::new();
        provider
            .validate_member(&ident, None, MemberValidationContext::None)
            .expect("validate");
    }

    #[test]
    fn validate_member_rejects_non_lattice_credential() {
        let provider = LatticeIdentityProvider::new();
        let ident = SigningIdentity {
            credential: Credential::Basic(mls_rs_core::identity::BasicCredential::new(
                b"alice".to_vec(),
            )),
            signature_key: SignaturePublicKey::from(vec![0; SIGNATURE_KEY_LEN]),
        };
        assert!(matches!(
            provider.validate_member(&ident, None, MemberValidationContext::None),
            Err(IdentityProviderError::NotLatticeCredential)
        ));
    }

    #[test]
    fn validate_member_rejects_wrong_credential_type() {
        let provider = LatticeIdentityProvider::new();
        let cred = sample_credential(0x22);
        let ident = SigningIdentity {
            credential: Credential::Custom(CustomCredential {
                credential_type: CredentialType::new(0xF099), // not Lattice
                data: cred.encode().expect("encode"),
            }),
            signature_key: SignaturePublicKey::from(vec![0; SIGNATURE_KEY_LEN]),
        };
        assert!(matches!(
            provider.validate_member(&ident, None, MemberValidationContext::None),
            Err(IdentityProviderError::WrongCredentialType(0xF099))
        ));
    }

    #[test]
    fn validate_member_rejects_signature_key_length() {
        let provider = LatticeIdentityProvider::new();
        let cred = sample_credential(0x33);
        let mut ident = matched_signing_identity(&cred);
        // Truncate signature_key by one byte.
        let mut bytes = ident.signature_key.as_bytes().to_vec();
        bytes.pop();
        ident.signature_key = SignaturePublicKey::from(bytes);
        assert!(matches!(
            provider.validate_member(&ident, None, MemberValidationContext::None),
            Err(IdentityProviderError::SignatureKeyLength { .. })
        ));
    }

    #[test]
    fn validate_member_rejects_ed25519_mismatch() {
        let provider = LatticeIdentityProvider::new();
        let cred = sample_credential(0x44);
        let mut ident = matched_signing_identity(&cred);
        let mut bytes = ident.signature_key.as_bytes().to_vec();
        bytes[0] ^= 0xFF; // flip a bit in the ed25519 portion
        ident.signature_key = SignaturePublicKey::from(bytes);
        assert!(matches!(
            provider.validate_member(&ident, None, MemberValidationContext::None),
            Err(IdentityProviderError::Ed25519Mismatch)
        ));
    }

    #[test]
    fn validate_member_rejects_ml_dsa_mismatch() {
        let provider = LatticeIdentityProvider::new();
        let cred = sample_credential(0x55);
        let mut ident = matched_signing_identity(&cred);
        let mut bytes = ident.signature_key.as_bytes().to_vec();
        bytes[ED25519_PK_LEN] ^= 0xFF; // flip first byte of the ml-dsa portion
        ident.signature_key = SignaturePublicKey::from(bytes);
        assert!(matches!(
            provider.validate_member(&ident, None, MemberValidationContext::None),
            Err(IdentityProviderError::MlDsaMismatch)
        ));
    }

    #[test]
    fn identity_returns_user_id() {
        let provider = LatticeIdentityProvider::new();
        let cred = sample_credential(0x66);
        let ident = matched_signing_identity(&cred);
        let id = provider
            .identity(&ident, &ExtensionList::default())
            .expect("identity");
        assert_eq!(id, cred.user_id.to_vec());
    }

    #[test]
    fn valid_successor_allows_same_user_id() {
        let provider = LatticeIdentityProvider::new();
        let pre_cred = sample_credential(0x77);
        // Successor has same user_id but distinct ed25519/ml_dsa material —
        // this is the device-rotation case.
        let suc_cred = LatticeCredential {
            user_id: pre_cred.user_id,
            ed25519_pub: [0xEE; ED25519_PK_LEN],
            ml_dsa_pub: vec![0xFF; ML_DSA_65_PK_LEN],
        };
        let pre = matched_signing_identity(&pre_cred);
        let suc = matched_signing_identity(&suc_cred);
        assert!(
            provider
                .valid_successor(&pre, &suc, &ExtensionList::default())
                .expect("valid_successor")
        );
    }

    #[test]
    fn valid_successor_rejects_different_user_id() {
        let provider = LatticeIdentityProvider::new();
        let pre = matched_signing_identity(&sample_credential(0x88));
        let suc = matched_signing_identity(&sample_credential(0x89));
        assert!(
            !provider
                .valid_successor(&pre, &suc, &ExtensionList::default())
                .expect("valid_successor")
        );
    }

    #[test]
    fn external_sender_is_unsupported() {
        let provider = LatticeIdentityProvider::new();
        let ident = matched_signing_identity(&sample_credential(0x99));
        assert!(matches!(
            provider.validate_external_sender(&ident, None, None),
            Err(IdentityProviderError::ExternalSenderUnsupported)
        ));
    }

    #[test]
    fn supported_types_advertises_only_lattice() {
        let provider = LatticeIdentityProvider::new();
        assert_eq!(
            provider.supported_types(),
            vec![CredentialType::new(CREDENTIAL_TYPE_LATTICE)]
        );
    }
}
