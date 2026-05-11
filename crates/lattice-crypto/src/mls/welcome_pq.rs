//! Welcome-side custom extension that carries an ML-KEM-768 ciphertext
//! plus an HKDF-wrap of the shared PSK secret, addressed to a single
//! joiner. Multiple joiners in the same commit each receive their own
//! [`PqWelcomePayload`] with a distinct `ml_kem_ct` + `wrap_nonce` +
//! `wrap_ct`, but all unwrap to the **same** 32-byte `W` — that's what
//! lets the commit reference a single external PSK.
//!
//! This is the receive-path side of the D-04 PSK injection flow.
//! When Alice adds Bob (1:1) or Alice adds {Bob, Carol} (multi-member,
//! M5):
//!
//! 1. Alice generates one random 32-byte `W` (the shared PSK secret).
//! 2. For each joiner she reads their `LatticeKemPubkey` and calls
//!    [`seal_pq_secret_multi`] which:
//!    a. ML-KEM-encapsulates to the joiner's pubkey → `(ct_i, ss_i)`.
//!    b. Derives a wrap key `K_i = HKDF-SHA-256(salt=epoch||i,
//!       ikm=ss_i, info="lattice/wrap/v2", L=32)`.
//!    c. ChaCha20-Poly1305-seals `W` under `K_i` with a fresh random
//!       nonce; AAD = `epoch || i` so a swapped payload from a
//!       different joiner index would fail authentication.
//! 3. Alice stores `W` in her PSK store under
//!    `psk_id_for_epoch(next_epoch)`.
//! 4. Attaches each [`PqWelcomePayload`] to the corresponding joiner's
//!    Welcome message.
//! 5. References the PSK in the commit via `add_external_psk(psk_id)`.
//!
//! On the receive side, each joiner runs [`open_pq_secret`] with the
//! payload directed at them:
//!
//! 1. Decapsulates `ml_kem_ct` with their KEM secret → `ss_i`.
//! 2. Derives the same `K_i`.
//! 3. ChaCha20-Poly1305-opens `wrap_ct` with `wrap_nonce` and AAD →
//!    recovers `W`.
//! 4. Stores `W` under the same epoch-derived PSK id Alice used —
//!    **before** calling `Client::join_group`, because mls-rs looks
//!    up the PSK synchronously during join.
//!
//! ## Extension id
//!
//! `0xF003` — RFC 9420 §17.4 private-use range. Sibling to
//! [`super::leaf_node_kem::LATTICE_KEM_PUBKEY_EXTENSION`] (`0xF002`).
//!
//! ## Wire format (v2 — bumped from M2's v1 when M5 multi-member
//! landed)
//!
//! ```text
//! PqWelcomePayload {
//!     epoch:      u64                 // little-endian
//!     joiner_idx: u32                 // 0 for solo / 1:1; 0..N for multi
//!     ml_kem_ct:  opaque<1088 bytes>  // length-prefixed by MLS codec
//!     wrap_nonce: opaque<12 bytes>    // ChaCha20-Poly1305 nonce
//!     wrap_ct:    opaque<48 bytes>    // 32-byte W + 16-byte tag
//! }
//! ```
//!
//! `joiner_idx` is the position of this joiner in the commit's add
//! list. It feeds the HKDF salt + the AEAD AAD so a per-joiner payload
//! can't be replayed against a different joiner who would otherwise
//! derive the same `K`.

#![allow(clippy::module_name_repetitions)]

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, kem::Encapsulate};
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use mls_rs_core::extension::{ExtensionType, MlsCodecExtension};
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::leaf_node_kem::{KemKeyPair, LatticeKemPubkey, ML_KEM_768_EK_LEN, ML_KEM_768_SS_LEN};
#[cfg(test)]
use super::leaf_node_kem::ML_KEM_768_CT_LEN;

/// Reserved `ExtensionType` for the Lattice ML-KEM Welcome extension.
pub const LATTICE_WELCOME_PQ_EXTENSION: ExtensionType = ExtensionType::new(0xF003);

/// HKDF info string for deriving the per-joiner wrap key.
const HKDF_WRAP_INFO: &[u8] = b"lattice/wrap/v2";

/// MLS Welcome extension carrying the per-joiner ML-KEM-768 ciphertext
/// plus the target epoch + the AEAD-sealed shared PSK secret.
#[derive(Clone, Debug, PartialEq, Eq, MlsSize, MlsEncode, MlsDecode)]
pub struct PqWelcomePayload {
    /// MLS epoch this payload's PSK is keyed to. Joiner uses this to
    /// derive `psk_id_for_epoch(epoch)` for local PSK storage.
    pub epoch: u64,
    /// Joiner index within the commit's add list (0 for solo / 1:1,
    /// 0..N for multi). Mixed into the HKDF salt + AEAD AAD so a
    /// payload meant for joiner A can't be unwrapped by joiner B even
    /// if they share a credential (e.g. the same user re-adding a
    /// second device).
    pub joiner_idx: u32,
    /// ML-KEM-768 ciphertext (1088 bytes per FIPS 203).
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub ml_kem_ct: Vec<u8>,
    /// ChaCha20-Poly1305 nonce for the wrap (12 random bytes).
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub wrap_nonce: Vec<u8>,
    /// ChaCha20-Poly1305 ciphertext + Poly1305 tag (32 + 16 bytes).
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    pub wrap_ct: Vec<u8>,
}

impl MlsCodecExtension for PqWelcomePayload {
    fn extension_type() -> ExtensionType {
        LATTICE_WELCOME_PQ_EXTENSION
    }
}

/// Encapsulate a fresh ML-KEM-768 shared secret to a single joiner's
/// pubkey using [`OsRng`] and seal a fresh 32-byte `W` under it.
///
/// Returns the wire payload (for the Welcome message) and `W` (to be
/// stored locally under `psk_id_for_epoch(epoch)`).
///
/// Internally calls [`seal_pq_secret_multi`] with a single-element
/// slice — the 1:1 path and the multi-member path share one
/// implementation.
///
/// # Errors
///
/// Returns [`WelcomePqError`] on a malformed pubkey or an internal
/// ML-KEM encapsulation / AEAD failure.
pub fn seal_pq_secret(
    joiner_kem_pk: &LatticeKemPubkey,
    epoch: u64,
) -> Result<(PqWelcomePayload, Zeroizing<[u8; ML_KEM_768_SS_LEN]>), WelcomePqError> {
    let (mut payloads, w) = seal_pq_secret_multi(&[joiner_kem_pk], epoch)?;
    let payload = payloads.pop().expect("multi seal produced a payload for a single joiner");
    Ok((payload, w))
}

/// Encapsulate one fresh 32-byte shared PSK secret `W` to N joiners.
///
/// Returns one [`PqWelcomePayload`] per joiner (in input order, each
/// tagged with its `joiner_idx`) plus the shared `W` that every
/// joiner will recover. The caller stores `W` under
/// `psk_id_for_epoch(epoch)`.
///
/// # Errors
///
/// Returns [`WelcomePqError`] on a malformed pubkey, ML-KEM
/// encapsulation failure, HKDF expand error, or AEAD encrypt error.
/// A `joiners.len()` of zero is rejected as `EncapsulationKeyLength
/// { got: 0, expected: ML_KEM_768_EK_LEN }` — that's not a "fits the
/// existing variant" call but it's the closest signal to "you asked
/// to encrypt to nobody".
pub fn seal_pq_secret_multi(
    joiners: &[&LatticeKemPubkey],
    epoch: u64,
) -> Result<(Vec<PqWelcomePayload>, Zeroizing<[u8; ML_KEM_768_SS_LEN]>), WelcomePqError> {
    seal_pq_secret_multi_with_rng(joiners, epoch, &mut OsRng)
}

/// Same as [`seal_pq_secret_multi`] but with an explicit RNG for
/// tests that need reproducibility.
///
/// # Errors
///
/// Same as [`seal_pq_secret_multi`].
pub fn seal_pq_secret_multi_with_rng<R: CryptoRng + RngCore>(
    joiners: &[&LatticeKemPubkey],
    epoch: u64,
    rng: &mut R,
) -> Result<(Vec<PqWelcomePayload>, Zeroizing<[u8; ML_KEM_768_SS_LEN]>), WelcomePqError> {
    if joiners.is_empty() {
        return Err(WelcomePqError::EncapsulationKeyLength {
            got: 0,
            expected: ML_KEM_768_EK_LEN,
        });
    }

    // 1. Generate the shared PSK secret W.
    let mut w_bytes = [0u8; ML_KEM_768_SS_LEN];
    rng.fill_bytes(&mut w_bytes);
    let w = Zeroizing::new(w_bytes);

    let mut out = Vec::with_capacity(joiners.len());
    for (idx_usize, joiner_pk) in joiners.iter().enumerate() {
        let idx = u32::try_from(idx_usize).map_err(|_| WelcomePqError::JoinerIndexOverflow)?;
        let payload = seal_single_to_joiner(joiner_pk, epoch, idx, w.as_slice(), rng)?;
        out.push(payload);
    }
    Ok((out, w))
}

/// Original single-joiner helper. Kept exported (as
/// [`seal_pq_secret_with_rng`]) for tests + callers that want a
/// reproducible RNG.
///
/// # Errors
///
/// Same as [`seal_pq_secret`].
pub fn seal_pq_secret_with_rng<R: CryptoRng + RngCore>(
    joiner_kem_pk: &LatticeKemPubkey,
    epoch: u64,
    rng: &mut R,
) -> Result<(PqWelcomePayload, Zeroizing<[u8; ML_KEM_768_SS_LEN]>), WelcomePqError> {
    let (mut payloads, w) = seal_pq_secret_multi_with_rng(&[joiner_kem_pk], epoch, rng)?;
    let payload = payloads
        .pop()
        .expect("multi seal produced a payload for a single joiner");
    Ok((payload, w))
}

fn seal_single_to_joiner<R: CryptoRng + RngCore>(
    joiner_kem_pk: &LatticeKemPubkey,
    epoch: u64,
    joiner_idx: u32,
    w: &[u8],
    rng: &mut R,
) -> Result<PqWelcomePayload, WelcomePqError> {
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

    // Derive the per-joiner wrap key from the encapsulated ss + epoch + idx.
    let wrap_key = derive_wrap_key(&ss, epoch, joiner_idx)?;

    // AEAD-seal W under the wrap key with a fresh random nonce.
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(&wrap_key.into());
    let aad = aead_aad(epoch, joiner_idx);
    let wrap_ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload { msg: w, aad: &aad },
        )
        .map_err(|e| WelcomePqError::Aead(format!("seal: {e}")))?;

    Ok(PqWelcomePayload {
        epoch,
        joiner_idx,
        ml_kem_ct: ct.to_vec(),
        wrap_nonce: nonce_bytes.to_vec(),
        wrap_ct,
    })
}

/// Decapsulate a [`PqWelcomePayload`] using the joiner's
/// [`KemKeyPair`] to recover the shared secret `W`.
///
/// The caller should store `W` under
/// `psk_id_for_epoch(payload.epoch)` before invoking
/// `Client::join_group` — mls-rs's join path looks up the PSK
/// synchronously and any later insertion will be too late.
///
/// # Errors
///
/// Returns [`WelcomePqError`] on malformed ciphertext, a decapsulation
/// failure, HKDF expand error, or AEAD authentication failure (which
/// catches both tampered payloads and payloads addressed to a
/// different joiner index).
pub fn open_pq_secret(
    our_kp: &KemKeyPair,
    payload: &PqWelcomePayload,
) -> Result<Zeroizing<[u8; ML_KEM_768_SS_LEN]>, WelcomePqError> {
    let ss = our_kp
        .decapsulate(&payload.ml_kem_ct)
        .map_err(WelcomePqError::from)?;
    let wrap_key = derive_wrap_key(ss.as_slice(), payload.epoch, payload.joiner_idx)?;
    if payload.wrap_nonce.len() != 12 {
        return Err(WelcomePqError::Aead(format!(
            "wrap_nonce length {} (expected 12)",
            payload.wrap_nonce.len()
        )));
    }
    let cipher = ChaCha20Poly1305::new(&wrap_key.into());
    let aad = aead_aad(payload.epoch, payload.joiner_idx);
    let opened = cipher
        .decrypt(
            Nonce::from_slice(&payload.wrap_nonce),
            chacha20poly1305::aead::Payload {
                msg: &payload.wrap_ct,
                aad: &aad,
            },
        )
        .map_err(|e| WelcomePqError::Aead(format!("open: {e}")))?;
    if opened.len() != ML_KEM_768_SS_LEN {
        return Err(WelcomePqError::Aead(format!(
            "unwrapped W length {} (expected {})",
            opened.len(),
            ML_KEM_768_SS_LEN
        )));
    }
    let mut out = [0u8; ML_KEM_768_SS_LEN];
    out.copy_from_slice(&opened);
    Ok(Zeroizing::new(out))
}

/// HKDF-SHA-256 expand the encapsulated `ss` into a 32-byte wrap key,
/// keyed on `epoch || joiner_idx` so per-joiner keys differ even if
/// `ss` somehow collided.
fn derive_wrap_key(
    ss: &[u8],
    epoch: u64,
    joiner_idx: u32,
) -> Result<[u8; 32], WelcomePqError> {
    let mut salt = Vec::with_capacity(8 + 4);
    salt.extend_from_slice(&epoch.to_le_bytes());
    salt.extend_from_slice(&joiner_idx.to_le_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), ss);
    let mut out = [0u8; 32];
    hk.expand(HKDF_WRAP_INFO, &mut out)
        .map_err(|e| WelcomePqError::Hkdf(format!("expand wrap key: {e}")))?;
    Ok(out)
}

fn aead_aad(epoch: u64, joiner_idx: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 4);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad.extend_from_slice(&joiner_idx.to_le_bytes());
    aad
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
    /// HKDF expand failed (shouldn't happen for a 32-byte output).
    #[error("hkdf: {0}")]
    Hkdf(String),
    /// ChaCha20-Poly1305 AEAD seal / open failed. Open failures are
    /// the typical "wrong joiner index" / "tampered payload" signal.
    #[error("aead: {0}")]
    Aead(String),
    /// More than 2^32 joiners requested in one commit. Realistically
    /// impossible for human groups but the type system insists.
    #[error("joiner index would overflow u32")]
    JoinerIndexOverflow,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::mls::leaf_node_kem::KemKeyPair;

    fn fresh_pubkey() -> (KemKeyPair, LatticeKemPubkey) {
        let kp = KemKeyPair::generate();
        let pk = kp.pubkey();
        (kp, pk)
    }

    #[test]
    fn extension_type_is_f003() {
        assert_eq!(
            <PqWelcomePayload as MlsCodecExtension>::extension_type(),
            ExtensionType::new(0xF003)
        );
    }

    #[test]
    fn seal_open_round_trip_single_joiner() {
        let (bob, bob_pk) = fresh_pubkey();
        let (payload, ss_alice) = seal_pq_secret(&bob_pk, 7).expect("seal");
        assert_eq!(payload.epoch, 7);
        assert_eq!(payload.joiner_idx, 0);
        assert_eq!(payload.ml_kem_ct.len(), ML_KEM_768_CT_LEN);
        assert_eq!(payload.wrap_nonce.len(), 12);
        assert_eq!(payload.wrap_ct.len(), ML_KEM_768_SS_LEN + 16);
        let ss_bob = open_pq_secret(&bob, &payload).expect("open");
        assert_eq!(ss_alice.as_slice(), ss_bob.as_slice());
    }

    #[test]
    fn seal_open_round_trip_multi_joiner() {
        let (bob_kp, bob_pk) = fresh_pubkey();
        let (carol_kp, carol_pk) = fresh_pubkey();
        let (payloads, ss_alice) =
            seal_pq_secret_multi(&[&bob_pk, &carol_pk], 42).expect("seal multi");
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].joiner_idx, 0);
        assert_eq!(payloads[1].joiner_idx, 1);
        // Both joiners should recover the SAME W as Alice generated.
        let ss_bob = open_pq_secret(&bob_kp, &payloads[0]).expect("open bob");
        let ss_carol = open_pq_secret(&carol_kp, &payloads[1]).expect("open carol");
        assert_eq!(ss_alice.as_slice(), ss_bob.as_slice());
        assert_eq!(ss_alice.as_slice(), ss_carol.as_slice());
    }

    #[test]
    fn cross_joiner_payload_fails_open() {
        let (bob_kp, bob_pk) = fresh_pubkey();
        let (_carol_kp, carol_pk) = fresh_pubkey();
        let (payloads, _ss) =
            seal_pq_secret_multi(&[&bob_pk, &carol_pk], 99).expect("seal");
        // Bob tries to open Carol's payload — ml_kem_ct was
        // encapsulated to Carol's pubkey, so Bob's decap fails
        // outright (KEM-level rejection).
        assert!(open_pq_secret(&bob_kp, &payloads[1]).is_err());
    }

    #[test]
    fn tampered_joiner_idx_fails_open() {
        let (bob, bob_pk) = fresh_pubkey();
        let (mut payload, _ss) = seal_pq_secret(&bob_pk, 11).expect("seal");
        // Flip the joiner_idx — AEAD AAD includes it, so open should
        // reject with an Aead error.
        payload.joiner_idx = 1;
        assert!(matches!(
            open_pq_secret(&bob, &payload),
            Err(WelcomePqError::Aead(_))
        ));
    }

    #[test]
    fn payload_round_trips_through_mls_codec() {
        let (_bob, bob_pk) = fresh_pubkey();
        let (payload, _ss) = seal_pq_secret(&bob_pk, 99).expect("seal");
        let bytes = payload.mls_encode_to_vec().expect("encode");
        let decoded = PqWelcomePayload::mls_decode(&mut &bytes[..]).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn seal_rejects_malformed_pubkey() {
        let bad_pk = LatticeKemPubkey {
            encapsulation_key: vec![0u8; 99],
        };
        assert!(matches!(
            seal_pq_secret(&bad_pk, 0),
            Err(WelcomePqError::EncapsulationKeyLength { got: 99, .. })
        ));
    }

    #[test]
    fn seal_rejects_empty_joiner_list() {
        assert!(matches!(
            seal_pq_secret_multi(&[], 0),
            Err(WelcomePqError::EncapsulationKeyLength { got: 0, .. })
        ));
    }

    #[test]
    fn open_rejects_tampered_ml_kem_ct() {
        let (bob, bob_pk) = fresh_pubkey();
        let (mut payload, _ss) = seal_pq_secret(&bob_pk, 11).expect("seal");
        payload.ml_kem_ct[0] ^= 1;
        assert!(open_pq_secret(&bob, &payload).is_err());
    }

    #[test]
    fn open_rejects_tampered_wrap_ct() {
        let (bob, bob_pk) = fresh_pubkey();
        let (mut payload, _ss) = seal_pq_secret(&bob_pk, 11).expect("seal");
        let last = payload.wrap_ct.len() - 1;
        payload.wrap_ct[last] ^= 1;
        assert!(matches!(
            open_pq_secret(&bob, &payload),
            Err(WelcomePqError::Aead(_))
        ));
    }

    #[test]
    fn open_rejects_wrong_length_ciphertext() {
        let (bob, _) = fresh_pubkey();
        let payload = PqWelcomePayload {
            epoch: 0,
            joiner_idx: 0,
            ml_kem_ct: vec![0u8; 99],
            wrap_nonce: vec![0u8; 12],
            wrap_ct: vec![0u8; 48],
        };
        assert!(open_pq_secret(&bob, &payload).is_err());
    }
}
