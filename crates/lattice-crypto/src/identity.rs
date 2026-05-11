//! Device identity: ML-DSA-65 post-quantum signatures with Ed25519
//! co-signature for hybrid security (D-03).
//!
//! Every Lattice device holds two long-term signing keypairs. Identity
//! claims, prekey bundles, and federation events are signed by **both**
//! keys independently; verifiers require both signatures to validate.
//!
//! This survives:
//! - A future cryptanalytic break of Ed25519 — PQ side still valid.
//! - A future cryptanalytic break of ML-DSA-65 — classical side still valid.
//!
//! Single-side success on verify is treated as failure; there is no
//! "degrade to classical" path.

// Crypto convention uses short paired names like pk/sk; clippy's
// `similar_names` complains, but renaming them to dissimilar identifiers
// hurts readability for anyone reading the cryptographic literature.
#![allow(clippy::similar_names)]

use ed25519_dalek::{
    Signature as EdSignature, Signer as EdSigner, SigningKey as EdSigningKey,
    Verifier as EdVerifier, VerifyingKey as EdVerifyingKey,
};
use ml_dsa::signature::{Keypair as MlKeypair, Signer as MlSigner, Verifier as MlVerifier};
use ml_dsa::{
    EncodedVerifyingKey, MlDsa65, Seed, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use tracing::instrument;
use zeroize::Zeroize;

use crate::{Error, Result};

/// Length of an Ed25519 signature in bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// Length of an ML-DSA-65 signature in bytes (FIPS 204).
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// Public identity bundle published to the home server's key directory.
#[derive(Clone, Debug)]
pub struct IdentityPublicKey {
    /// ML-DSA-65 verifying key bytes (1952 bytes per FIPS 204).
    pub ml_dsa_pk: Vec<u8>,
    /// Ed25519 verifying key (32 bytes).
    pub ed25519_pk: [u8; 32],
}

/// Long-term identity secret.
///
/// Stored in WebAuthn-derived encrypted storage on V1, hardware-backed
/// enclave on V2. Zeroized on drop.
///
/// For ML-DSA-65 we persist the 32-byte seed rather than the expanded
/// signing-key bytes — the expanded form is deterministically rederived
/// from the seed via `SigningKey::from_seed`. This matches FIPS 204's
/// recommended storage format and keeps the at-rest footprint small.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct IdentitySecretKey {
    /// ML-DSA-65 32-byte seed (the FIPS 204 `xi` value).
    pub ml_dsa_seed: [u8; 32],
    /// Ed25519 signing key (32 bytes).
    pub ed25519_sk: [u8; 32],
}

/// Hybrid signature: both ML-DSA-65 and Ed25519 over the same message
/// (D-03). Both must verify for the hybrid signature to be valid.
#[derive(Clone, Debug)]
pub struct HybridSignature {
    /// ML-DSA-65 signature bytes (3309 bytes per FIPS 204).
    pub ml_dsa_sig: Vec<u8>,
    /// Ed25519 signature (64 bytes).
    pub ed25519_sig: [u8; 64],
}

/// Generate a fresh hybrid identity keypair using [`OsRng`].
///
/// # Errors
///
/// Returns [`Error::KeyGen`] if the seed RNG reports failure. In practice
/// `OsRng` does not fail; we surface the abstract failure mode so callers
/// can react.
#[instrument(level = "debug")]
pub fn generate_identity() -> Result<(IdentityPublicKey, IdentitySecretKey)> {
    generate_identity_from_rng(&mut OsRng)
}

/// Generate an identity keypair from an explicit RNG. Useful for tests and
/// for callers that hold a domain-specific RNG.
///
/// # Errors
///
/// Returns [`Error::KeyGen`] on impossible RNG failures.
#[instrument(level = "debug", skip(rng))]
pub fn generate_identity_from_rng<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(IdentityPublicKey, IdentitySecretKey)> {
    // ML-DSA-65: deterministic from a 32-byte seed
    let mut ml_dsa_seed_bytes = [0u8; 32];
    rng.try_fill_bytes(&mut ml_dsa_seed_bytes)
        .map_err(|e| Error::KeyGen(format!("ml-dsa seed sampling: {e}")))?;
    let seed: Seed = ml_dsa_seed_bytes.into();
    let ml_dsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&seed);
    let ml_dsa_pk = ml_dsa_sk.verifying_key();

    // Ed25519
    let ed_signing = EdSigningKey::generate(rng);
    let ed_verifying = ed_signing.verifying_key();

    let pk = IdentityPublicKey {
        ml_dsa_pk: ml_dsa_pk.encode().to_vec(),
        ed25519_pk: ed_verifying.to_bytes(),
    };
    let sk = IdentitySecretKey {
        ml_dsa_seed: ml_dsa_seed_bytes,
        ed25519_sk: ed_signing.to_bytes(),
    };

    tracing::debug!(
        ml_dsa_pk_len = pk.ml_dsa_pk.len(),
        ed25519_pk_len = pk.ed25519_pk.len(),
        "identity generated"
    );
    Ok((pk, sk))
}

/// Produce a hybrid signature over `message`. Both component signatures
/// are produced over the **same** message bytes (D-03).
///
/// # Errors
///
/// Returns [`Error::Signature`] if either underlying signer fails. A
/// half-signed claim is never released — both signatures must succeed
/// before this function returns.
#[instrument(level = "debug", skip(sk, message), fields(msg_len = message.len()))]
pub fn sign(sk: &IdentitySecretKey, message: &[u8]) -> Result<HybridSignature> {
    // ML-DSA sign
    let seed: Seed = sk.ml_dsa_seed.into();
    let ml_dsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&seed);
    let ml_dsa_sig: MlDsaSignature<MlDsa65> = ml_dsa_sk
        .try_sign(message)
        .map_err(|_| Error::Signature)?;

    // Ed25519 sign
    let ed_signing = EdSigningKey::from_bytes(&sk.ed25519_sk);
    let ed_sig: EdSignature = ed_signing.sign(message);

    Ok(HybridSignature {
        ml_dsa_sig: ml_dsa_sig.encode().to_vec(),
        ed25519_sig: ed_sig.to_bytes(),
    })
}

/// Verify a hybrid signature. Both component signatures must verify;
/// a single-side success is treated as failure.
///
/// # Errors
///
/// Returns [`Error::Signature`] if either component fails to verify, if
/// either signature has the wrong length, or if either public key can't be
/// decoded.
#[instrument(level = "debug", skip(pk, message, sig), fields(msg_len = message.len()))]
pub fn verify(
    pk: &IdentityPublicKey,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<()> {
    // ML-DSA verify
    let ml_dsa_pk_enc: &EncodedVerifyingKey<MlDsa65> = pk
        .ml_dsa_pk
        .as_slice()
        .try_into()
        .map_err(|_| Error::Signature)?;
    let ml_dsa_pk = MlDsaVerifyingKey::<MlDsa65>::decode(ml_dsa_pk_enc);
    let ml_dsa_sig = MlDsaSignature::<MlDsa65>::try_from(sig.ml_dsa_sig.as_slice())
        .map_err(|_| Error::Signature)?;
    ml_dsa_pk
        .verify(message, &ml_dsa_sig)
        .map_err(|_| Error::Signature)?;

    // Ed25519 verify
    let ed_verifying = EdVerifyingKey::from_bytes(&pk.ed25519_pk).map_err(|_| Error::Signature)?;
    let ed_sig = EdSignature::from_bytes(&sig.ed25519_sig);
    ed_verifying
        .verify(message, &ed_sig)
        .map_err(|_| Error::Signature)?;

    tracing::debug!("hybrid signature verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_sign_verify() {
        let (pk, sk) = generate_identity().expect("generate");
        let msg = b"identity claim payload";
        let sig = sign(&sk, msg).expect("sign");
        verify(&pk, msg, &sig).expect("verify");
    }

    #[test]
    fn rejects_tampered_message() {
        let (pk, sk) = generate_identity().expect("generate");
        let sig = sign(&sk, b"original").expect("sign");
        assert!(matches!(
            verify(&pk, b"tampered", &sig),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let (pk_a, sk_a) = generate_identity().expect("generate a");
        let (_pk_b, sk_b) = generate_identity().expect("generate b");
        let sig_b = sign(&sk_b, b"msg").expect("sign b");
        assert!(matches!(verify(&pk_a, b"msg", &sig_b), Err(Error::Signature)));
        let sig_a = sign(&sk_a, b"msg").expect("sign a");
        verify(&pk_a, b"msg", &sig_a).expect("verify a");
    }

    #[test]
    fn rejects_swapped_ed25519_only() {
        let (pk_a, sk_a) = generate_identity().expect("gen a");
        let (pk_b, sk_b) = generate_identity().expect("gen b");
        let sig_a = sign(&sk_a, b"msg").expect("sign a");
        let sig_b = sign(&sk_b, b"msg").expect("sign b");

        // Frankenstein: A's ML-DSA portion + B's Ed25519 portion
        let franken = HybridSignature {
            ml_dsa_sig: sig_a.ml_dsa_sig,
            ed25519_sig: sig_b.ed25519_sig,
        };
        // Against A's pk: Ed25519 portion was signed by B's key → fail
        assert!(matches!(verify(&pk_a, b"msg", &franken), Err(Error::Signature)));
        // Against B's pk: ML-DSA portion was signed by A's key → fail
        assert!(matches!(verify(&pk_b, b"msg", &franken), Err(Error::Signature)));
    }

    #[test]
    fn rejects_malformed_ml_dsa_sig_length() {
        let (pk, sk) = generate_identity().expect("gen");
        let mut sig = sign(&sk, b"msg").expect("sign");
        sig.ml_dsa_sig.truncate(sig.ml_dsa_sig.len() - 1);
        assert!(matches!(verify(&pk, b"msg", &sig), Err(Error::Signature)));
    }

    #[test]
    fn rejects_corrupted_ed25519_sig() {
        let (pk, sk) = generate_identity().expect("gen");
        let mut sig = sign(&sk, b"msg").expect("sign");
        sig.ed25519_sig[0] ^= 0xFF;
        assert!(matches!(verify(&pk, b"msg", &sig), Err(Error::Signature)));
    }

    #[test]
    fn signature_sizes_match_fips_204() {
        let (_pk, sk) = generate_identity().expect("gen");
        let sig = sign(&sk, b"size check").expect("sign");
        assert_eq!(sig.ml_dsa_sig.len(), 3309, "ML-DSA-65 sig is 3309 bytes");
        assert_eq!(sig.ed25519_sig.len(), 64, "Ed25519 sig is 64 bytes");
    }

    #[test]
    fn pubkey_sizes_match_fips_204() {
        let (pk, _sk) = generate_identity().expect("gen");
        assert_eq!(pk.ml_dsa_pk.len(), 1952, "ML-DSA-65 pk is 1952 bytes");
        assert_eq!(pk.ed25519_pk.len(), 32, "Ed25519 pk is 32 bytes");
    }

    /// Deterministic generation from a seeded RNG. Same seed → same keypair,
    /// proving the wrapper introduces no non-determinism.
    #[test]
    fn deterministic_from_seeded_rng() {
        use rand::SeedableRng;
        let mut rng1 = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
        let mut rng2 = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);
        let (pk1, _sk1) = generate_identity_from_rng(&mut rng1).expect("gen1");
        let (pk2, _sk2) = generate_identity_from_rng(&mut rng2).expect("gen2");
        assert_eq!(pk1.ml_dsa_pk, pk2.ml_dsa_pk);
        assert_eq!(pk1.ed25519_pk, pk2.ed25519_pk);
    }
}
