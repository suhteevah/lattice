//! Hybrid key encapsulation: classical X25519 combined with ML-KEM-768.
//!
//! The combiner concatenates both shared secrets and runs them through
//! HKDF-SHA-256 with a caller-supplied info string. An attacker must
//! break **both** primitives to recover the resulting session secret.
//!
//! ## Construction
//!
//! Follows the spirit of `draft-mahy-mls-xwing`:
//!
//! ```text
//! K_classical  = X25519(eph_sk, peer_pk)
//! K_pq         = ML-KEM-768.Decaps(ml_kem_ct, ml_kem_sk)
//! SS           = HKDF-SHA-256(salt=&[], ikm=K_classical || K_pq, info=info, L=64)
//! ```
//!
//! The 64-byte output is split into a 32-byte session key and a 32-byte
//! confirmation tag. Callers typically use the session key for AEAD
//! framing and the confirmation tag for transcript binding.
//!
//! ## Info string convention
//!
//! Pass [`HKDF_INIT`](crate::constants::HKDF_INIT) for the initial
//! session-secret derivation that seeds an MLS group's `init_secret`.
//! Other purposes use the appropriate constant from `crate::constants`.

// Crypto convention uses short paired names like pk/sk and ek/dk; clippy's
// `similar_names` complains, but renaming them to dissimilar identifiers
// hurts readability for anyone reading the cryptographic literature.
#![allow(clippy::similar_names)]

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use tracing::instrument;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

/// Output of a hybrid KEX: 32-byte session key + 32-byte confirmation tag.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct HybridSharedSecret {
    /// Derived 32-byte session key. Treat as opaque; feed to AEAD or KDF.
    pub session_key: [u8; 32],
    /// 32-byte confirmation tag for transcript binding.
    pub confirmation: [u8; 32],
}

/// Public component of a hybrid keypair: both classical and PQ public keys.
#[derive(Clone, Debug)]
pub struct HybridPublicKey {
    /// X25519 public key (32 bytes).
    pub x25519: [u8; 32],
    /// ML-KEM-768 encapsulation key bytes (1184 bytes).
    pub ml_kem: Vec<u8>,
}

/// Private component of a hybrid keypair. Zeroized on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct HybridSecretKey {
    /// X25519 secret key (32 bytes).
    pub x25519: [u8; 32],
    /// ML-KEM-768 decapsulation key bytes (2400 bytes).
    pub ml_kem: Vec<u8>,
}

/// Wire-shaped ciphertext bundle for a hybrid encapsulation.
#[derive(Clone, Debug)]
pub struct HybridCiphertext {
    /// X25519 ephemeral public key acting as the classical ciphertext (32 bytes).
    pub x25519_eph_pk: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub ml_kem_ct: Vec<u8>,
}

/// Generate a fresh hybrid keypair using [`OsRng`].
///
/// # Errors
///
/// Returns [`Error::KeyGen`] only on impossible RNG failure.
#[instrument(level = "debug")]
pub fn generate_keypair() -> Result<(HybridPublicKey, HybridSecretKey)> {
    generate_keypair_from_rng(&mut OsRng)
}

/// Generate a hybrid keypair from an explicit RNG.
///
/// # Errors
///
/// Returns [`Error::KeyGen`] on impossible underlying RNG failures.
#[instrument(level = "debug", skip(rng))]
pub fn generate_keypair_from_rng<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(HybridPublicKey, HybridSecretKey)> {
    // X25519
    let x_static = XStaticSecret::random_from_rng(&mut *rng);
    let x_public = XPublicKey::from(&x_static);

    // ML-KEM-768
    let (decap_key, encap_key) = MlKem768::generate(rng);

    let pk = HybridPublicKey {
        x25519: x_public.to_bytes(),
        ml_kem: encap_key.as_bytes().to_vec(),
    };
    let sk = HybridSecretKey {
        x25519: x_static.to_bytes(),
        ml_kem: decap_key.as_bytes().to_vec(),
    };

    tracing::debug!(
        x25519_pk_len = pk.x25519.len(),
        ml_kem_pk_len = pk.ml_kem.len(),
        "hybrid keypair generated"
    );
    Ok((pk, sk))
}

/// Encapsulate to a peer's hybrid public key. Produces a wire-shaped
/// ciphertext bundle and a 64-byte shared secret (split into 32-byte
/// session key and 32-byte confirmation tag).
///
/// # Errors
///
/// Returns [`Error::Kem`] if the peer's ML-KEM key is malformed or if
/// either layer's underlying operation fails.
#[instrument(level = "debug", skip(peer_pk, info), fields(info_len = info.len()))]
pub fn encapsulate(
    peer_pk: &HybridPublicKey,
    info: &[u8],
) -> Result<(HybridCiphertext, HybridSharedSecret)> {
    encapsulate_with_rng(peer_pk, info, &mut OsRng)
}

/// Encapsulate using an explicit RNG. Useful for testing with a seeded RNG.
///
/// # Errors
///
/// Same as [`encapsulate`].
#[instrument(level = "debug", skip(peer_pk, info, rng), fields(info_len = info.len()))]
pub fn encapsulate_with_rng<R: CryptoRng + RngCore>(
    peer_pk: &HybridPublicKey,
    info: &[u8],
    rng: &mut R,
) -> Result<(HybridCiphertext, HybridSharedSecret)> {
    // Classical: ephemeral X25519 → DH against peer's x25519 prekey
    let eph_sk = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pk = XPublicKey::from(&eph_sk);
    let peer_x = XPublicKey::from(peer_pk.x25519);
    let k_classical = eph_sk.diffie_hellman(&peer_x);

    // PQ: ML-KEM-768 encap to peer's ml-kem prekey
    let peer_ek_bytes: &ml_kem::Encoded<<MlKem768 as KemCore>::EncapsulationKey> = peer_pk
        .ml_kem
        .as_slice()
        .try_into()
        .map_err(|_| Error::Kem("peer ml-kem public key wrong length".into()))?;
    let peer_ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(peer_ek_bytes);
    let (ct_pq, k_pq) = peer_ek
        .encapsulate(rng)
        .map_err(|e| Error::Kem(format!("ml-kem encapsulate: {e:?}")))?;

    let shared = combine(k_classical.as_bytes(), &k_pq, info)?;

    let ciphertext = HybridCiphertext {
        x25519_eph_pk: eph_pk.to_bytes(),
        ml_kem_ct: ct_pq.to_vec(),
    };
    Ok((ciphertext, shared))
}

/// Decapsulate a peer's ciphertext bundle to recover the shared secret.
///
/// # Errors
///
/// Returns [`Error::Kem`] on any input-validation or decapsulation failure.
#[instrument(level = "debug", skip(sk, ct, info), fields(info_len = info.len()))]
pub fn decapsulate(
    sk: &HybridSecretKey,
    ct: &HybridCiphertext,
    info: &[u8],
) -> Result<HybridSharedSecret> {
    // Classical: DH against the peer's ephemeral pubkey using our static x25519 sk
    let static_sk = XStaticSecret::from(sk.x25519);
    let peer_eph = XPublicKey::from(ct.x25519_eph_pk);
    let k_classical = static_sk.diffie_hellman(&peer_eph);

    // PQ: ML-KEM-768 decap
    let dk_bytes: &ml_kem::Encoded<<MlKem768 as KemCore>::DecapsulationKey> = sk
        .ml_kem
        .as_slice()
        .try_into()
        .map_err(|_| Error::Kem("decapsulation key wrong length".into()))?;
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(dk_bytes);

    let ct_bytes: &ml_kem::Ciphertext<MlKem768> = ct
        .ml_kem_ct
        .as_slice()
        .try_into()
        .map_err(|_| Error::Kem("ciphertext wrong length".into()))?;
    let k_pq = dk
        .decapsulate(ct_bytes)
        .map_err(|e| Error::Kem(format!("ml-kem decapsulate: {e:?}")))?;

    combine(k_classical.as_bytes(), &k_pq, info)
}

/// HKDF-SHA-256 combiner over `K_classical || K_pq`.
fn combine(
    k_classical: &[u8; 32],
    k_pq: &ml_kem::SharedKey<MlKem768>,
    info: &[u8],
) -> Result<HybridSharedSecret> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(k_classical);
    ikm.extend_from_slice(k_pq);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(info, okm.as_mut())
        .map_err(|e| Error::Kem(format!("hkdf expand: {e}")))?;

    let mut session_key = [0u8; 32];
    let mut confirmation = [0u8; 32];
    session_key.copy_from_slice(&okm[..32]);
    confirmation.copy_from_slice(&okm[32..]);

    Ok(HybridSharedSecret {
        session_key,
        confirmation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::HKDF_INIT;

    #[test]
    fn round_trip_encap_decap() {
        let (pk, sk) = generate_keypair().expect("gen");
        let (ct, ss_sender) = encapsulate(&pk, HKDF_INIT).expect("encap");
        let ss_recipient = decapsulate(&sk, &ct, HKDF_INIT).expect("decap");
        assert_eq!(ss_sender.session_key, ss_recipient.session_key);
        assert_eq!(ss_sender.confirmation, ss_recipient.confirmation);
    }

    #[test]
    fn different_info_yields_different_secret() {
        let (pk, _sk) = generate_keypair().expect("gen");
        let (_ct1, ss1) = encapsulate(&pk, b"lattice/init/v1").expect("encap 1");
        let (_ct2, ss2) = encapsulate(&pk, b"lattice/mls-init/v1").expect("encap 2");
        // Different info → different shared secret even with same keypair
        // (and a fresh ephemeral each time the rng moves anyway, so this is
        // mostly a sanity check on the info-string binding)
        assert_ne!(ss1.session_key, ss2.session_key);
    }

    #[test]
    fn key_sizes_match_fips_203() {
        let (pk, sk) = generate_keypair().expect("gen");
        assert_eq!(pk.x25519.len(), 32, "X25519 pk is 32 bytes");
        assert_eq!(pk.ml_kem.len(), 1184, "ML-KEM-768 ek is 1184 bytes");
        assert_eq!(sk.x25519.len(), 32, "X25519 sk is 32 bytes");
        assert_eq!(sk.ml_kem.len(), 2400, "ML-KEM-768 dk is 2400 bytes");

        let (ct, _ss) = encapsulate(&pk, HKDF_INIT).expect("encap");
        assert_eq!(ct.x25519_eph_pk.len(), 32, "ephemeral X25519 pk is 32 bytes");
        assert_eq!(ct.ml_kem_ct.len(), 1088, "ML-KEM-768 ct is 1088 bytes");
    }

    #[test]
    fn shared_secret_is_64_bytes() {
        let (pk, sk) = generate_keypair().expect("gen");
        let (ct, ss) = encapsulate(&pk, HKDF_INIT).expect("encap");
        assert_eq!(ss.session_key.len(), 32);
        assert_eq!(ss.confirmation.len(), 32);
        let ss_d = decapsulate(&sk, &ct, HKDF_INIT).expect("decap");
        assert_eq!(ss_d.session_key.len(), 32);
        assert_eq!(ss_d.confirmation.len(), 32);
    }

    #[test]
    fn rejects_mismatched_decap_key() {
        let (pk_a, _sk_a) = generate_keypair().expect("gen a");
        let (_pk_b, sk_b) = generate_keypair().expect("gen b");
        let (ct, ss_sender) = encapsulate(&pk_a, HKDF_INIT).expect("encap to a");

        // Decap with B's secret key produces a *different* secret (ML-KEM
        // implicit rejection: decap with wrong key still succeeds but
        // yields garbage). What we verify here is that the resulting
        // shared secret does NOT match the sender's.
        let ss_wrong = decapsulate(&sk_b, &ct, HKDF_INIT).expect("decap with wrong key");
        assert_ne!(ss_sender.session_key, ss_wrong.session_key);
    }

    #[test]
    fn rejects_malformed_peer_pubkey() {
        let bad_pk = HybridPublicKey {
            x25519: [0u8; 32],
            ml_kem: vec![0u8; 100], // wrong length
        };
        assert!(matches!(encapsulate(&bad_pk, HKDF_INIT), Err(Error::Kem(_))));
    }

    #[test]
    fn deterministic_from_seeded_rng() {
        use rand::SeedableRng;
        let mut rng1 = rand_chacha::ChaCha20Rng::from_seed([11u8; 32]);
        let mut rng2 = rand_chacha::ChaCha20Rng::from_seed([11u8; 32]);
        let (pk1, _sk1) = generate_keypair_from_rng(&mut rng1).expect("gen 1");
        let (pk2, _sk2) = generate_keypair_from_rng(&mut rng2).expect("gen 2");
        assert_eq!(pk1.x25519, pk2.x25519);
        assert_eq!(pk1.ml_kem, pk2.ml_kem);
    }
}
