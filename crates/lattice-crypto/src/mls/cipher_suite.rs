//! Lattice's custom MLS `CipherSuiteProvider`.
//!
//! Wraps the base `mls-rs-crypto-rustcrypto` suite for MLS ciphersuite
//! `0x0003` (`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`) per
//! D-04. All KDF / AEAD / hash / HPKE / KEM methods delegate to the
//! inner suite unchanged. The four signature methods are overridden to
//! produce and verify hybrid Ed25519 + ML-DSA-65 signatures (D-03).
//!
//! ## Public-use ID
//!
//! Lattice's full custom ciphersuite is named `LATTICE_HYBRID_V1` and
//! advertised with ID `0xF000` (RFC 9420 §17.1 private-use range). The
//! actual binding of the ML-KEM-768 secret into the MLS key schedule
//! happens **above** this trait via PSK injection — see
//! [`super::psk`] and the D-04 2026-05-10 re-open in `docs/DECISIONS.md`.
//! The cipher-suite provider here only needs to handle hybrid sigs; it
//! is **not** the place to fold in the PQ secret.
//!
//! ## Signature key / signature byte layout
//!
//! ```text
//! signature_public_key  bytes = ed25519_pub (32)  || ml_dsa_pub (1952)
//! signature_secret_key  bytes = ed25519_sk_seed(32) || ml_dsa_sk_seed(32)
//! signature             bytes = ed25519_sig (64)  || ml_dsa_sig (3309)
//! ```
//!
//! `LatticeIdentityProvider` enforces that the credential's individual
//! `ed25519_pub` / `ml_dsa_pub` fields agree with this packed layout
//! (see [`super::identity_provider`]). Mixing layouts is a
//! confused-deputy vulnerability — keep this comment in sync if the
//! layout ever changes.

#![allow(clippy::module_name_repetitions)]

use ed25519_dalek::{
    Signature as EdSignature, Signer as EdSigner, SigningKey as EdSigningKey,
    Verifier as EdVerifier, VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::{Keypair as MlKeypair, Signer as MlSigner, Verifier as MlVerifier};
use ml_dsa::{
    EncodedVerifyingKey, MlDsa65, Seed, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use mls_rs_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePsk, HpkePublicKey,
    HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_crypto_rustcrypto::{RustCryptoError, RustCryptoProvider};
use rand::rngs::OsRng;
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::identity::{ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};

// Re-exported lengths from crate::credential for the trait impl.
use crate::credential::{ED25519_PK_LEN, ML_DSA_65_PK_LEN};

/// MLS ciphersuite identifier reserved for Lattice (`0xF000`).
pub const LATTICE_HYBRID_V1: CipherSuite = CipherSuite::new(0xF000);

/// Combined hybrid signature-public-key length in bytes.
pub const HYBRID_SIG_PK_LEN: usize = ED25519_PK_LEN + ML_DSA_65_PK_LEN;

/// Combined hybrid signature-secret-key length in bytes: two 32-byte seeds.
pub const HYBRID_SIG_SK_LEN: usize = 32 + 32;

/// Combined hybrid signature length in bytes.
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;

/// Lattice's `CryptoProvider` — advertises only `LATTICE_HYBRID_V1`.
///
/// Wraps the standard `RustCryptoProvider` to do the actual primitive
/// work. The wrapper is needed because we need to lie to `mls-rs` about
/// which ciphersuite we're implementing (we say `0xF000`, the inner
/// suite says `0x0003`).
#[derive(Clone, Debug, Default)]
pub struct LatticeCryptoProvider {
    inner: RustCryptoProvider,
}

impl LatticeCryptoProvider {
    /// Construct a provider whose only supported suite is `LATTICE_HYBRID_V1`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RustCryptoProvider::with_enabled_cipher_suites(vec![
                CipherSuite::CURVE25519_CHACHA,
            ]),
        }
    }
}

impl CryptoProvider for LatticeCryptoProvider {
    type CipherSuiteProvider = LatticeHybridCipherSuite;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        vec![LATTICE_HYBRID_V1]
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if cipher_suite != LATTICE_HYBRID_V1 {
            return None;
        }
        // Borrow the inner suite from the base ciphersuite (0x0003) — that's
        // the ciphersuite whose HPKE / AEAD / KDF / hash primitives we use.
        self.inner
            .cipher_suite_provider(CipherSuite::CURVE25519_CHACHA)
            .map(|inner| LatticeHybridCipherSuite { inner })
    }
}

/// Lattice's hybrid `CipherSuiteProvider`.
///
/// Delegates 18 of 22 trait methods to the wrapped `RustCryptoCipherSuite`
/// for the base 0x0003 ciphersuite. Overrides:
///
/// - `cipher_suite()` to advertise `LATTICE_HYBRID_V1` (`0xF000`).
/// - `signature_key_generate`, `signature_key_derive_public`, `sign`,
///   `verify` to handle Ed25519 + ML-DSA-65 packed key/signature material
///   per the byte layout documented at the module top.
#[derive(Clone)]
pub struct LatticeHybridCipherSuite {
    inner: <RustCryptoProvider as CryptoProvider>::CipherSuiteProvider,
}

/// Errors raised by `LatticeHybridCipherSuite`.
#[derive(Debug, thiserror::Error)]
pub enum LatticeHybridError {
    /// Underlying `mls-rs-crypto-rustcrypto` operation failed.
    #[error(transparent)]
    Inner(#[from] RustCryptoError),
    /// `SignaturePublicKey` byte length did not match the hybrid layout.
    #[error("hybrid signature public key length {got} (expected {expected})")]
    SigPkLength {
        /// Observed length.
        got: usize,
        /// Expected length.
        expected: usize,
    },
    /// `SignatureSecretKey` byte length did not match the hybrid layout.
    #[error("hybrid signature secret key length {got} (expected {expected})")]
    SigSkLength {
        /// Observed length.
        got: usize,
        /// Expected length.
        expected: usize,
    },
    /// Signature byte length did not match the hybrid layout.
    #[error("hybrid signature length {got} (expected {expected})")]
    SigLength {
        /// Observed length.
        got: usize,
        /// Expected length.
        expected: usize,
    },
    /// RNG failure during signature-key generation.
    #[error("hybrid signature key generation: {0}")]
    KeyGen(String),
    /// Hybrid signing failed.
    #[error("hybrid sign: {0}")]
    Sign(String),
    /// Hybrid verification failed.
    #[error("hybrid signature verification failed")]
    Verify,
}

impl mls_rs_core::error::IntoAnyError for LatticeHybridError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl CipherSuiteProvider for LatticeHybridCipherSuite {
    type Error = LatticeHybridError;
    type HpkeContextS = <<RustCryptoProvider as CryptoProvider>::CipherSuiteProvider as CipherSuiteProvider>::HpkeContextS;
    type HpkeContextR = <<RustCryptoProvider as CryptoProvider>::CipherSuiteProvider as CipherSuiteProvider>::HpkeContextR;

    fn cipher_suite(&self) -> CipherSuite {
        LATTICE_HYBRID_V1
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.inner.hash(data)?)
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.inner.mac(key, data)?)
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.inner.aead_seal(key, data, aad, nonce)?)
    }

    fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self.inner.aead_open(key, ciphertext, aad, nonce)?)
    }

    fn aead_key_size(&self) -> usize {
        self.inner.aead_key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.inner.aead_nonce_size()
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self.inner.kdf_extract(salt, ikm)?)
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self.inner.kdf_expand(prk, info, len)?)
    }

    fn kdf_extract_size(&self) -> usize {
        self.inner.kdf_extract_size()
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.inner.hpke_seal(remote_key, info, aad, pt)?)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .inner
            .hpke_open(ciphertext, local_secret, local_public, info, aad)?)
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.inner.hpke_seal_psk(remote_key, info, aad, pt, psk)?)
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .inner
            .hpke_open_psk(ciphertext, local_secret, local_public, info, aad, psk)?)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        Ok(self.inner.hpke_setup_s(remote_key, info)?)
    }

    fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        Ok(self
            .inner
            .hpke_setup_r(kem_output, local_secret, local_public, info)?)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.inner.kem_derive(ikm)?)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.inner.kem_generate()?)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(self.inner.kem_public_key_validate(key)?)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        Ok(self.inner.random_bytes(out)?)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        let mut rng = OsRng;

        // ML-DSA-65 seed
        let mut ml_dsa_seed = [0u8; 32];
        rng.try_fill_bytes(&mut ml_dsa_seed)
            .map_err(|e| LatticeHybridError::KeyGen(format!("ml-dsa seed: {e}")))?;
        let seed: Seed = ml_dsa_seed.into();
        let ml_dsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&seed);
        let ml_dsa_pk = ml_dsa_sk.verifying_key();

        // Ed25519
        let ed_sk = EdSigningKey::generate(&mut rng);
        let ed_pk = ed_sk.verifying_key();

        // Pack
        let mut sk_bytes = Vec::with_capacity(HYBRID_SIG_SK_LEN);
        sk_bytes.extend_from_slice(&ed_sk.to_bytes()); // 32
        sk_bytes.extend_from_slice(&ml_dsa_seed); // 32
        debug_assert_eq!(sk_bytes.len(), HYBRID_SIG_SK_LEN);

        let mut pk_bytes = Vec::with_capacity(HYBRID_SIG_PK_LEN);
        pk_bytes.extend_from_slice(&ed_pk.to_bytes()); // 32
        pk_bytes.extend_from_slice(&ml_dsa_pk.encode()); // 1952
        debug_assert_eq!(pk_bytes.len(), HYBRID_SIG_PK_LEN);

        Ok((
            SignatureSecretKey::from(sk_bytes),
            SignaturePublicKey::from(pk_bytes),
        ))
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        let sk_bytes = secret_key.as_bytes();
        if sk_bytes.len() != HYBRID_SIG_SK_LEN {
            return Err(LatticeHybridError::SigSkLength {
                got: sk_bytes.len(),
                expected: HYBRID_SIG_SK_LEN,
            });
        }
        let (ed_sk_bytes, ml_dsa_seed_bytes) = sk_bytes.split_at(32);

        let ed_sk = EdSigningKey::from_bytes(ed_sk_bytes.try_into().map_err(|_| {
            LatticeHybridError::SigSkLength {
                got: ed_sk_bytes.len(),
                expected: 32,
            }
        })?);
        let ed_pk = ed_sk.verifying_key();

        let seed_arr: [u8; 32] =
            ml_dsa_seed_bytes
                .try_into()
                .map_err(|_| LatticeHybridError::SigSkLength {
                    got: ml_dsa_seed_bytes.len(),
                    expected: 32,
                })?;
        let seed: Seed = seed_arr.into();
        let ml_dsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&seed);
        let ml_dsa_pk = ml_dsa_sk.verifying_key();

        let mut pk_bytes = Vec::with_capacity(HYBRID_SIG_PK_LEN);
        pk_bytes.extend_from_slice(&ed_pk.to_bytes());
        pk_bytes.extend_from_slice(&ml_dsa_pk.encode());
        Ok(SignaturePublicKey::from(pk_bytes))
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let sk_bytes = secret_key.as_bytes();
        if sk_bytes.len() != HYBRID_SIG_SK_LEN {
            return Err(LatticeHybridError::SigSkLength {
                got: sk_bytes.len(),
                expected: HYBRID_SIG_SK_LEN,
            });
        }
        let (ed_sk_bytes, ml_dsa_seed_bytes) = sk_bytes.split_at(32);

        let ed_sk = EdSigningKey::from_bytes(ed_sk_bytes.try_into().map_err(|_| {
            LatticeHybridError::SigSkLength {
                got: ed_sk_bytes.len(),
                expected: 32,
            }
        })?);
        let ed_sig = ed_sk.sign(data);

        let seed_arr: [u8; 32] =
            ml_dsa_seed_bytes
                .try_into()
                .map_err(|_| LatticeHybridError::SigSkLength {
                    got: ml_dsa_seed_bytes.len(),
                    expected: 32,
                })?;
        let seed: Seed = seed_arr.into();
        let ml_dsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&seed);
        let ml_dsa_sig: MlDsaSignature<MlDsa65> = ml_dsa_sk
            .try_sign(data)
            .map_err(|e| LatticeHybridError::Sign(format!("ml-dsa: {e}")))?;

        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&ed_sig.to_bytes()); // 64
        out.extend_from_slice(&ml_dsa_sig.encode()); // 3309
        debug_assert_eq!(out.len(), HYBRID_SIG_LEN);
        Ok(out)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        let pk_bytes = public_key.as_bytes();
        if pk_bytes.len() != HYBRID_SIG_PK_LEN {
            return Err(LatticeHybridError::SigPkLength {
                got: pk_bytes.len(),
                expected: HYBRID_SIG_PK_LEN,
            });
        }
        if signature.len() != HYBRID_SIG_LEN {
            return Err(LatticeHybridError::SigLength {
                got: signature.len(),
                expected: HYBRID_SIG_LEN,
            });
        }
        let (ed_pk_bytes, ml_dsa_pk_bytes) = pk_bytes.split_at(ED25519_PK_LEN);
        let (ed_sig_bytes, ml_dsa_sig_bytes) = signature.split_at(ED25519_SIG_LEN);

        // Ed25519
        let ed_pk_arr: [u8; ED25519_PK_LEN] = ed_pk_bytes
            .try_into()
            .map_err(|_| LatticeHybridError::Verify)?;
        let ed_pk =
            EdVerifyingKey::from_bytes(&ed_pk_arr).map_err(|_| LatticeHybridError::Verify)?;
        let ed_sig_arr: [u8; ED25519_SIG_LEN] = ed_sig_bytes
            .try_into()
            .map_err(|_| LatticeHybridError::Verify)?;
        let ed_sig = EdSignature::from_bytes(&ed_sig_arr);
        ed_pk
            .verify(data, &ed_sig)
            .map_err(|_| LatticeHybridError::Verify)?;

        // ML-DSA-65
        let ml_dsa_pk_enc: &EncodedVerifyingKey<MlDsa65> = ml_dsa_pk_bytes
            .try_into()
            .map_err(|_| LatticeHybridError::Verify)?;
        let ml_dsa_pk = MlDsaVerifyingKey::<MlDsa65>::decode(ml_dsa_pk_enc);
        let ml_dsa_sig = MlDsaSignature::<MlDsa65>::try_from(ml_dsa_sig_bytes)
            .map_err(|_| LatticeHybridError::Verify)?;
        ml_dsa_pk
            .verify(data, &ml_dsa_sig)
            .map_err(|_| LatticeHybridError::Verify)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> LatticeHybridCipherSuite {
        LatticeCryptoProvider::new()
            .cipher_suite_provider(LATTICE_HYBRID_V1)
            .expect("cipher suite present")
    }

    #[test]
    fn cipher_suite_id_is_f000() {
        assert_eq!(provider().cipher_suite(), LATTICE_HYBRID_V1);
        assert_eq!(u16::from(LATTICE_HYBRID_V1), 0xF000_u16);
    }

    #[test]
    fn provider_advertises_only_lattice_suite() {
        let p = LatticeCryptoProvider::new();
        assert_eq!(p.supported_cipher_suites(), vec![LATTICE_HYBRID_V1]);
        assert!(
            p.cipher_suite_provider(CipherSuite::CURVE25519_CHACHA)
                .is_none()
        );
        assert!(p.cipher_suite_provider(CipherSuite::P256_AES128).is_none());
    }

    #[test]
    fn signature_round_trip() {
        let p = provider();
        let (sk, pk) = p.signature_key_generate().expect("keygen");
        assert_eq!(sk.as_bytes().len(), HYBRID_SIG_SK_LEN);
        assert_eq!(pk.as_bytes().len(), HYBRID_SIG_PK_LEN);

        let msg = b"hello, hybrid signature";
        let sig = p.sign(&sk, msg).expect("sign");
        assert_eq!(sig.len(), HYBRID_SIG_LEN);
        p.verify(&pk, &sig, msg).expect("verify");
    }

    #[test]
    fn signature_rejects_tampered_message() {
        let p = provider();
        let (sk, pk) = p.signature_key_generate().expect("keygen");
        let sig = p.sign(&sk, b"original").expect("sign");
        assert!(matches!(
            p.verify(&pk, &sig, b"tampered"),
            Err(LatticeHybridError::Verify)
        ));
    }

    #[test]
    fn signature_rejects_tampered_ed25519_half() {
        let p = provider();
        let (sk, pk) = p.signature_key_generate().expect("keygen");
        let mut sig = p.sign(&sk, b"msg").expect("sign");
        sig[0] ^= 0xFF; // first byte is ed25519 portion
        assert!(matches!(
            p.verify(&pk, &sig, b"msg"),
            Err(LatticeHybridError::Verify)
        ));
    }

    #[test]
    fn signature_rejects_tampered_ml_dsa_half() {
        let p = provider();
        let (sk, pk) = p.signature_key_generate().expect("keygen");
        let mut sig = p.sign(&sk, b"msg").expect("sign");
        sig[ED25519_SIG_LEN] ^= 0xFF; // first byte of the ml-dsa portion
        assert!(matches!(
            p.verify(&pk, &sig, b"msg"),
            Err(LatticeHybridError::Verify)
        ));
    }

    #[test]
    fn signature_rejects_wrong_pk() {
        let p = provider();
        let (sk_a, _pk_a) = p.signature_key_generate().expect("keygen a");
        let (_sk_b, pk_b) = p.signature_key_generate().expect("keygen b");
        let sig = p.sign(&sk_a, b"msg").expect("sign");
        assert!(matches!(
            p.verify(&pk_b, &sig, b"msg"),
            Err(LatticeHybridError::Verify)
        ));
    }

    #[test]
    fn signature_rejects_wrong_length_pk() {
        let p = provider();
        let sig = vec![0u8; HYBRID_SIG_LEN];
        let pk = SignaturePublicKey::from(vec![0u8; HYBRID_SIG_PK_LEN - 1]);
        assert!(matches!(
            p.verify(&pk, &sig, b"msg"),
            Err(LatticeHybridError::SigPkLength { .. })
        ));
    }

    #[test]
    fn signature_rejects_wrong_length_sig() {
        let p = provider();
        let (_sk, pk) = p.signature_key_generate().expect("keygen");
        let bogus_sig = vec![0u8; HYBRID_SIG_LEN + 1];
        assert!(matches!(
            p.verify(&pk, &bogus_sig, b"msg"),
            Err(LatticeHybridError::SigLength { .. })
        ));
    }

    #[test]
    fn signature_key_derive_public_matches_generate() {
        let p = provider();
        let (sk, pk) = p.signature_key_generate().expect("keygen");
        let derived = p.signature_key_derive_public(&sk).expect("derive");
        assert_eq!(derived.as_bytes(), pk.as_bytes());
    }

    #[test]
    fn delegated_aead_round_trip() {
        let p = provider();
        let mut key = vec![0u8; p.aead_key_size()];
        p.random_bytes(&mut key).expect("rng");
        let mut nonce = vec![0u8; p.aead_nonce_size()];
        p.random_bytes(&mut nonce).expect("rng");
        let plaintext = b"delegated to chacha20-poly1305";
        let ct = p
            .aead_seal(&key, plaintext, Some(b"aad"), &nonce)
            .expect("seal");
        let pt = p.aead_open(&key, &ct, Some(b"aad"), &nonce).expect("open");
        assert_eq!(pt.as_slice(), plaintext);
    }

    #[test]
    fn delegated_kdf_extract_expand_works() {
        let p = provider();
        let prk = p.kdf_extract(b"salt", b"ikm").expect("extract");
        assert_eq!(prk.len(), p.kdf_extract_size());
        let okm = p.kdf_expand(&prk, b"info", 64).expect("expand");
        assert_eq!(okm.len(), 64);
    }
}
