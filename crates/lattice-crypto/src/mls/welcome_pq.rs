//! Welcome-side custom extension that carries an ML-KEM-768 ciphertext
//! addressed to a single joiner, plus seal / open helpers.
//!
//! This is the receive-path side of the D-04 PSK injection flow. When
//! Alice adds Bob via [`super::add_member`] (M2 Phase D), she:
//!
//! 1. Reads Bob's [`super::leaf_node_kem::LatticeKemPubkey`] from his
//!    KeyPackage LeafNode extensions.
//! 2. Calls [`seal_pq_secret`] which ML-KEM-encapsulates a fresh
//!    per-commit shared secret to Bob's encapsulation key.
//! 3. Stores the resulting secret in her [`super::psk::LatticePskStorage`]
//!    under [`super::psk::psk_id_for_epoch`]`(next_epoch)`.
//! 4. Attaches a [`PqWelcomePayload`] (this module's extension) to the
//!    Welcome message that mls-rs produces.
//! 5. References the PSK in the commit via `add_psk(psk_id)`.
//!
//! Bob's [`super::process_welcome`]:
//!
//! 1. Reads the [`PqWelcomePayload`] from the Welcome's extensions.
//! 2. Calls [`open_pq_secret`] with his own
//!    [`super::leaf_node_kem::KemKeyPair`] to recover the shared secret.
//! 3. Stores it in his own [`super::psk::LatticePskStorage`] under the
//!    same epoch-derived id — **before** calling `Client::join_group`,
//!    because mls-rs looks up the PSK synchronously during join.
//!
//! ## Extension id
//!
//! `0xF003` — RFC 9420 §17.4 private-use range. Sibling to
//! [`super::leaf_node_kem::LATTICE_KEM_PUBKEY_EXTENSION`] (`0xF002`).
//!
//! ## Wire format
//!
//! ```text
//! PqWelcomePayload {
//!     epoch:    u64                    // little-endian
//!     ml_kem_ct: opaque<1088 bytes>    // length-prefixed by MLS codec
//! }
//! ```
//!
//! The `epoch` field redundantly carries the target epoch so the joiner
//! can derive the same [`super::psk::psk_id_for_epoch`] id Alice used
//! without trusting their own group-context computation (which won't
//! exist yet during a Welcome).

#![allow(clippy::module_name_repetitions)]

use ml_kem::{kem::Encapsulate, EncodedSizeUser, KemCore, MlKem768};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::extension::{ExtensionType, MlsCodecExtension};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::leaf_node_kem::{
    KemKeyPair, LatticeKemPubkey, ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN, ML_KEM_768_SS_LEN,
};

/// Reserved `ExtensionType` for the Lattice ML-KEM Welcome extension.
pub const LATTICE_WELCOME_PQ_EXTENSION: ExtensionType = ExtensionType::new(0xF003);

/// MLS Welcome extension carrying the per-joiner ML-KEM-768 ciphertext
/// plus the target epoch number.
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct PqWelcomePayload {
    /// MLS epoch this payload's PSK is keyed to. Joiner uses this to
    /// derive `psk_id_for_epoch(epoch)` for local PSK storage.
    pub epoch: u64,
    /// ML-KEM-768 ciphertext (1088 bytes per FIPS 203).
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub ml_kem_ct: Vec<u8>,
}

impl MlsCodecExtension for PqWelcomePayload {
    fn extension_type() -> ExtensionType {
        LATTICE_WELCOME_PQ_EXTENSION
    }
}

/// Encapsulate a fresh ML-KEM-768 shared secret to a joiner's pubkey
/// using [`OsRng`].
///
/// Returns the wire payload (for the Welcome message) and the shared
/// secret (to be stored locally under
/// [`super::psk::psk_id_for_epoch`]`(epoch)`).
///
/// # Errors
///
/// Returns [`WelcomePqError`] on a malformed pubkey or an internal
/// ML-KEM encapsulation failure.
pub fn seal_pq_secret(
    joiner_kem_pk: &LatticeKemPubkey,
    epoch: u64,
) -> Result<(PqWelcomePayload, Zeroizing<[u8; ML_KEM_768_SS_LEN]>), WelcomePqError> {
    seal_pq_secret_with_rng(joiner_kem_pk, epoch, &mut OsRng)
}

/// Encapsulate using an explicit RNG. Useful for tests with seeded RNGs.
///
/// # Errors
///
/// Same as [`seal_pq_secret`].
pub fn seal_pq_secret_with_rng<R: CryptoRng + RngCore>(
    joiner_kem_pk: &LatticeKemPubkey,
    epoch: u64,
    rng: &mut R,
) -> Result<(PqWelcomePayload, Zeroizing<[u8; ML_KEM_768_SS_LEN]>), WelcomePqError> {
    if joiner_kem_pk.encapsulation_key.len() != ML_KEM_768_EK_LEN {
        return Err(WelcomePqError::EncapsulationKeyLength {
            got: joiner_kem_pk.encapsulation_key.len(),
            expected: ML_KEM_768_EK_LEN,
        });
    }
    let ek_bytes: &ml_kem::Encoded<<MlKem768 as KemCore>::EncapsulationKey> = joiner_kem_pk
        .encapsulation_key
        .as_slice()
        .try_into()
        .map_err(|_| WelcomePqError::EncapsulationKeyLength {
            got: joiner_kem_pk.encapsulation_key.len(),
            expected: ML_KEM_768_EK_LEN,
        })?;
    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(ek_bytes);
    let (ct, ss) = ek
        .encapsulate(rng)
        .map_err(|e| WelcomePqError::Encapsulate(format!("{e:?}")))?;

    let mut ss_arr = [0u8; ML_KEM_768_SS_LEN];
    ss_arr.copy_from_slice(&ss);

    let payload = PqWelcomePayload {
        epoch,
        ml_kem_ct: ct.to_vec(),
    };
    debug_assert_eq!(payload.ml_kem_ct.len(), ML_KEM_768_CT_LEN);

    Ok((payload, Zeroizing::new(ss_arr)))
}

/// Decapsulate a [`PqWelcomePayload`] using the joiner's
/// [`KemKeyPair`] to recover the shared secret.
///
/// The caller should store the returned secret under
/// [`super::psk::psk_id_for_epoch`]`(payload.epoch)` before invoking
/// `Client::join_group` — mls-rs's join path looks up the PSK
/// synchronously and any later insertion will be too late.
///
/// # Errors
///
/// Returns [`WelcomePqError`] on malformed ciphertext or a decapsulation
/// failure.
pub fn open_pq_secret(
    our_kp: &KemKeyPair,
    payload: &PqWelcomePayload,
) -> Result<Zeroizing<[u8; ML_KEM_768_SS_LEN]>, WelcomePqError> {
    our_kp
        .decapsulate(&payload.ml_kem_ct)
        .map_err(WelcomePqError::from)
}

/// Errors raised by Welcome-PQ helpers.
#[derive(Debug, thiserror::Error)]
pub enum WelcomePqError {
    /// Joiner's encapsulation key bytes were the wrong length.
    #[error("ml-kem-768 encapsulation key length {got} (expected {expected})")]
    EncapsulationKeyLength {
        /// Observed length.
        got: usize,
        /// Required length: [`ML_KEM_768_EK_LEN`].
        expected: usize,
    },
    /// ML-KEM encapsulation failed (essentially impossible with `OsRng`).
    #[error("ml-kem-768 encapsulate: {0}")]
    Encapsulate(String),
    /// ML-KEM decapsulation or related key validation failed.
    #[error(transparent)]
    Decap(#[from] super::leaf_node_kem::KemKeyError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_type_is_f003() {
        assert_eq!(LATTICE_WELCOME_PQ_EXTENSION.raw_value(), 0xF003);
        assert_eq!(
            <PqWelcomePayload as MlsCodecExtension>::extension_type(),
            LATTICE_WELCOME_PQ_EXTENSION,
        );
    }

    #[test]
    fn seal_open_round_trip() {
        // Bob's KeyPackage carries his LatticeKemPubkey extension.
        let bob = KemKeyPair::generate().expect("bob");
        let bob_pk = bob.pubkey();

        // Alice seals against Bob's pubkey for epoch 7.
        let (payload, ss_alice) = seal_pq_secret(&bob_pk, 7).expect("seal");
        assert_eq!(payload.epoch, 7);
        assert_eq!(payload.ml_kem_ct.len(), ML_KEM_768_CT_LEN);

        // Bob opens.
        let ss_bob = open_pq_secret(&bob, &payload).expect("open");
        assert_eq!(&ss_alice[..], &ss_bob[..]);
    }

    #[test]
    fn payload_round_trips_through_mls_codec() {
        let bob = KemKeyPair::generate().expect("bob");
        let (payload, _ss) = seal_pq_secret(&bob.pubkey(), 99).expect("seal");
        let bytes = payload.mls_encode_to_vec().expect("encode");
        let decoded = PqWelcomePayload::mls_decode(&mut &*bytes).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn seal_rejects_malformed_pubkey() {
        let bad_pk = LatticeKemPubkey {
            encapsulation_key: vec![0u8; ML_KEM_768_EK_LEN - 1],
        };
        assert!(matches!(
            seal_pq_secret(&bad_pk, 0),
            Err(WelcomePqError::EncapsulationKeyLength { .. })
        ));
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let bob = KemKeyPair::generate().expect("bob");
        let (mut payload, ss_alice) = seal_pq_secret(&bob.pubkey(), 11).expect("seal");
        // Flip one byte of the ciphertext.
        payload.ml_kem_ct[0] ^= 0xFF;
        match open_pq_secret(&bob, &payload) {
            // ml-kem-768 has implicit rejection — a tampered ct decapsulates
            // to a different secret (not an error). Verify the secret differs.
            Ok(ss_bob) => assert_ne!(&ss_alice[..], &ss_bob[..]),
            // If the underlying impl strict-rejects (some versions do), that
            // also satisfies the security goal.
            Err(_) => {}
        }
    }

    #[test]
    fn open_rejects_wrong_length_ciphertext() {
        let bob = KemKeyPair::generate().expect("bob");
        let payload = PqWelcomePayload {
            epoch: 0,
            ml_kem_ct: vec![0u8; ML_KEM_768_CT_LEN - 1],
        };
        let result = open_pq_secret(&bob, &payload);
        assert!(matches!(
            result,
            Err(WelcomePqError::Decap(super::super::leaf_node_kem::KemKeyError::CiphertextLength { .. }))
        ));
    }

    #[test]
    fn distinct_seals_produce_distinct_ciphertexts() {
        // Same recipient, two encapsulations — fresh randomness should yield
        // distinct ciphertexts and distinct shared secrets.
        let bob = KemKeyPair::generate().expect("bob");
        let (p1, ss1) = seal_pq_secret(&bob.pubkey(), 0).expect("seal1");
        let (p2, ss2) = seal_pq_secret(&bob.pubkey(), 0).expect("seal2");
        assert_ne!(p1.ml_kem_ct, p2.ml_kem_ct);
        assert_ne!(&ss1[..], &ss2[..]);
    }

    #[test]
    fn distinct_recipients_yield_distinct_secrets() {
        let bob = KemKeyPair::generate().expect("bob");
        let carol = KemKeyPair::generate().expect("carol");
        let (_p1, ss_bob) = seal_pq_secret(&bob.pubkey(), 0).expect("seal bob");
        let (_p2, ss_carol) = seal_pq_secret(&carol.pubkey(), 0).expect("seal carol");
        assert_ne!(&ss_bob[..], &ss_carol[..]);
    }

    #[test]
    fn epoch_carried_in_payload() {
        let bob = KemKeyPair::generate().expect("bob");
        let (p, _ss) = seal_pq_secret(&bob.pubkey(), 0x1234_5678_9ABC_DEF0).expect("seal");
        assert_eq!(p.epoch, 0x1234_5678_9ABC_DEF0);
    }
}
