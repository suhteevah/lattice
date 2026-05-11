//! Custom MLS `LeafNode` extension carrying a per-leaf ML-KEM-768
//! encapsulation key.
//!
//! mls-rs's standard `LeafNode` carries an X25519 HPKE init key (for the
//! base `0x0003` ciphersuite Lattice wraps). This module adds an
//! ML-KEM-768 encapsulation key alongside it as a custom extension —
//! that's the public-key side of the D-04 PSK injection flow. When
//! Alice adds Bob to a group she fetches Bob's `LatticeKemPubkey`
//! extension from his `LeafNode` and ML-KEM-encapsulates a fresh
//! per-epoch shared secret to it. Bob decapsulates with his stored
//! ML-KEM secret key (held outside MLS — see
//! [`generate_kem_keypair`]) and stores the PSK before processing the
//! Welcome (see [`super::welcome_pq`] for the receive path).
//!
//! ## Extension id
//!
//! `0xF002` — RFC 9420 §17.4 private-use range. Lattice reserves:
//! `0xF000` (ciphersuite), `0xF001` (credential type), `0xF002`
//! (this extension), `0xF003` (Welcome PQ payload, see
//! [`super::welcome_pq`]).
//!
//! ## Where the secret key lives
//!
//! The ML-KEM-768 *decapsulation* key is NOT part of MLS state. It is
//! sibling material to the LeafNode init secret: per-device, generated
//! at KeyPackage creation, stored locally in the same encrypted store
//! that holds the leaf init secret. Callers manage it through
//! [`KemKeyPair`] which holds both halves and zeroizes on drop.

#![allow(clippy::module_name_repetitions)]

use ml_kem::{kem::Decapsulate, EncodedSizeUser, KemCore, MlKem768};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::extension::{ExtensionType, MlsCodecExtension};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// Reserved `ExtensionType` for the Lattice ML-KEM-768 LeafNode extension.
pub const LATTICE_KEM_PUBKEY_EXTENSION: ExtensionType = ExtensionType::new(0xF002);

/// Length of an ML-KEM-768 encapsulation key in bytes (FIPS 203).
pub const ML_KEM_768_EK_LEN: usize = 1184;

/// Length of an ML-KEM-768 decapsulation key in bytes (FIPS 203).
pub const ML_KEM_768_DK_LEN: usize = 2400;

/// Length of an ML-KEM-768 ciphertext in bytes (FIPS 203).
pub const ML_KEM_768_CT_LEN: usize = 1088;

/// Length of an ML-KEM-768 shared secret in bytes.
pub const ML_KEM_768_SS_LEN: usize = 32;

/// `LeafNode` extension carrying an ML-KEM-768 encapsulation key.
///
/// Wire form (MLS-codec): single length-prefixed opaque byte string
/// `encapsulation_key`. Inner length always [`ML_KEM_768_EK_LEN`]
/// (1184 bytes). The codec layer carries the length so future
/// algorithm variants can be detected.
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct LatticeKemPubkey {
    /// ML-KEM-768 encapsulation key bytes (1184 bytes per FIPS 203).
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub encapsulation_key: Vec<u8>,
}

impl LatticeKemPubkey {
    /// Construct from raw bytes. Validates length.
    ///
    /// # Errors
    ///
    /// Returns [`KemKeyError::EncapsulationKeyLength`] if `bytes` is not
    /// exactly [`ML_KEM_768_EK_LEN`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, KemKeyError> {
        if bytes.len() != ML_KEM_768_EK_LEN {
            return Err(KemKeyError::EncapsulationKeyLength {
                got: bytes.len(),
                expected: ML_KEM_768_EK_LEN,
            });
        }
        Ok(Self {
            encapsulation_key: bytes,
        })
    }
}

impl MlsCodecExtension for LatticeKemPubkey {
    fn extension_type() -> ExtensionType {
        LATTICE_KEM_PUBKEY_EXTENSION
    }
}

/// Per-device ML-KEM-768 keypair. Holds both encapsulation key (public)
/// and decapsulation key (secret). Zeroize on drop covers the secret
/// portion.
///
/// Callers persist this in their identity store next to the leaf init
/// secret; on KeyPackage publication, the [`pubkey()`] portion becomes
/// the `LatticeKemPubkey` LeafNode extension. The secret never leaves
/// the device.
///
/// [`pubkey()`]: KemKeyPair::pubkey
pub struct KemKeyPair {
    /// ML-KEM-768 encapsulation key bytes (1184 bytes).
    encapsulation_key: Vec<u8>,
    /// ML-KEM-768 decapsulation key bytes (2400 bytes), wrapped to zeroize on drop.
    decapsulation_key: Zeroizing<Vec<u8>>,
}

impl KemKeyPair {
    /// Generate a fresh ML-KEM-768 keypair using [`OsRng`].
    ///
    /// # Errors
    ///
    /// Practically infallible — `OsRng` does not error in normal
    /// operation. The `Result` is here for forward compatibility.
    pub fn generate() -> Result<Self, KemKeyError> {
        Self::generate_from_rng(&mut OsRng)
    }

    /// Generate a fresh ML-KEM-768 keypair from an explicit RNG.
    ///
    /// # Errors
    ///
    /// Returns [`KemKeyError::Generation`] only on unexpected internal
    /// failure of the `ml-kem` crate.
    pub fn generate_from_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, KemKeyError> {
        let (dk, ek) = MlKem768::generate(rng);
        Ok(Self {
            encapsulation_key: ek.as_bytes().to_vec(),
            decapsulation_key: Zeroizing::new(dk.as_bytes().to_vec()),
        })
    }

    /// Borrow the encapsulation key bytes for publication.
    #[must_use]
    pub fn encapsulation_key_bytes(&self) -> &[u8] {
        &self.encapsulation_key
    }

    /// Project to the public-key half as a wire extension value.
    #[must_use]
    pub fn pubkey(&self) -> LatticeKemPubkey {
        LatticeKemPubkey {
            encapsulation_key: self.encapsulation_key.clone(),
        }
    }

    /// Decapsulate a ciphertext from a peer using our secret half.
    ///
    /// # Errors
    ///
    /// Returns [`KemKeyError::CiphertextLength`] if `ciphertext` is the
    /// wrong size, or [`KemKeyError::Decapsulate`] if the underlying
    /// ML-KEM decapsulation fails.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; ML_KEM_768_SS_LEN]>, KemKeyError> {
        if ciphertext.len() != ML_KEM_768_CT_LEN {
            return Err(KemKeyError::CiphertextLength {
                got: ciphertext.len(),
                expected: ML_KEM_768_CT_LEN,
            });
        }
        let dk_bytes: &ml_kem::Encoded<<MlKem768 as KemCore>::DecapsulationKey> = self
            .decapsulation_key
            .as_slice()
            .try_into()
            .map_err(|_| KemKeyError::DecapsulationKeyLength {
                got: self.decapsulation_key.len(),
                expected: ML_KEM_768_DK_LEN,
            })?;
        let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(dk_bytes);
        let ct: &ml_kem::Ciphertext<MlKem768> = ciphertext
            .try_into()
            .map_err(|_| KemKeyError::CiphertextLength {
                got: ciphertext.len(),
                expected: ML_KEM_768_CT_LEN,
            })?;
        let ss = dk
            .decapsulate(ct)
            .map_err(|e| KemKeyError::Decapsulate(format!("{e:?}")))?;
        let mut out = [0u8; ML_KEM_768_SS_LEN];
        out.copy_from_slice(&ss);
        Ok(Zeroizing::new(out))
    }
}

impl KemKeyPair {
    /// `pub(crate)` accessor for the raw decapsulation key bytes. Used
    /// by [`super::KemKeyPair::duplicate`] inside this crate; not part
    /// of the public API because exposing the secret bytes by reference
    /// invites accidental copying past the `Zeroizing` wrapper.
    pub(crate) fn decapsulation_key_inner(&self) -> &[u8] {
        &self.decapsulation_key
    }

    /// `pub(crate)` raw-bytes constructor. Used by
    /// [`super::KemKeyPair::duplicate`]; bypasses RNG so the caller
    /// must have obtained the bytes from a previous `generate` call.
    pub(crate) fn from_raw_bytes_inner(ek: Vec<u8>, dk: Vec<u8>) -> Self {
        Self {
            encapsulation_key: ek,
            decapsulation_key: Zeroizing::new(dk),
        }
    }
}

impl Drop for KemKeyPair {
    fn drop(&mut self) {
        // `decapsulation_key: Zeroizing<Vec<u8>>` zeroes itself.
        // The encapsulation key is public material — no need to zero it.
        self.encapsulation_key.zeroize();
    }
}

/// Errors raised by [`LatticeKemPubkey`] and [`KemKeyPair`].
#[derive(Debug, thiserror::Error)]
pub enum KemKeyError {
    /// Encapsulation key bytes were the wrong length.
    #[error("ml-kem-768 encapsulation key length {got} (expected {expected})")]
    EncapsulationKeyLength {
        /// Observed length.
        got: usize,
        /// Required length: [`ML_KEM_768_EK_LEN`].
        expected: usize,
    },
    /// Decapsulation key bytes were the wrong length.
    #[error("ml-kem-768 decapsulation key length {got} (expected {expected})")]
    DecapsulationKeyLength {
        /// Observed length.
        got: usize,
        /// Required length: [`ML_KEM_768_DK_LEN`].
        expected: usize,
    },
    /// Ciphertext bytes were the wrong length.
    #[error("ml-kem-768 ciphertext length {got} (expected {expected})")]
    CiphertextLength {
        /// Observed length.
        got: usize,
        /// Required length: [`ML_KEM_768_CT_LEN`].
        expected: usize,
    },
    /// Keypair generation failed (essentially impossible with `OsRng`).
    #[error("ml-kem-768 key generation: {0}")]
    Generation(String),
    /// Decapsulation failed (corrupted ciphertext or mismatched key).
    #[error("ml-kem-768 decapsulate: {0}")]
    Decapsulate(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::Encapsulate;

    #[test]
    fn extension_type_is_f002() {
        assert_eq!(
            LATTICE_KEM_PUBKEY_EXTENSION.raw_value(),
            0xF002,
        );
        assert_eq!(
            <LatticeKemPubkey as MlsCodecExtension>::extension_type(),
            LATTICE_KEM_PUBKEY_EXTENSION,
        );
    }

    #[test]
    fn keypair_generate_yields_correct_sizes() {
        let kp = KemKeyPair::generate().expect("generate");
        assert_eq!(kp.encapsulation_key_bytes().len(), ML_KEM_768_EK_LEN);
        assert_eq!(kp.pubkey().encapsulation_key.len(), ML_KEM_768_EK_LEN);
    }

    #[test]
    fn lattice_kem_pubkey_round_trip_codec() {
        let kp = KemKeyPair::generate().expect("generate");
        let pk = kp.pubkey();
        let bytes = pk.mls_encode_to_vec().expect("encode");
        let decoded = LatticeKemPubkey::mls_decode(&mut &*bytes).expect("decode");
        assert_eq!(decoded, pk);
    }

    #[test]
    fn from_bytes_validates_length() {
        assert!(LatticeKemPubkey::from_bytes(vec![0u8; ML_KEM_768_EK_LEN]).is_ok());
        assert!(matches!(
            LatticeKemPubkey::from_bytes(vec![0u8; ML_KEM_768_EK_LEN - 1]),
            Err(KemKeyError::EncapsulationKeyLength { .. })
        ));
    }

    #[test]
    fn encap_decap_round_trip() {
        // Alice generates a keypair, publishes the pubkey.
        let alice = KemKeyPair::generate().expect("alice");
        let alice_pk_bytes = alice.encapsulation_key_bytes().to_vec();

        // Bob encapsulates against Alice's pubkey.
        let alice_ek_bytes: &ml_kem::Encoded<<MlKem768 as KemCore>::EncapsulationKey> =
            alice_pk_bytes.as_slice().try_into().expect("ek bytes");
        let alice_ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(alice_ek_bytes);
        let (ct, ss_bob) = alice_ek.encapsulate(&mut OsRng).expect("encap");

        // Alice decapsulates.
        let ss_alice = alice.decapsulate(ct.as_slice()).expect("decap");

        assert_eq!(&ss_alice[..], &ss_bob[..]);
    }

    #[test]
    fn decapsulate_rejects_wrong_length_ciphertext() {
        let kp = KemKeyPair::generate().expect("generate");
        let result = kp.decapsulate(&vec![0u8; ML_KEM_768_CT_LEN - 1]);
        assert!(matches!(result, Err(KemKeyError::CiphertextLength { .. })));
    }

    #[test]
    fn distinct_keypairs_produce_distinct_pubkeys() {
        let a = KemKeyPair::generate().expect("a");
        let b = KemKeyPair::generate().expect("b");
        assert_ne!(a.encapsulation_key_bytes(), b.encapsulation_key_bytes());
    }
}
