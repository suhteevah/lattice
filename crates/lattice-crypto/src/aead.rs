//! ChaCha20-Poly1305 AEAD framing.
//!
//! All Lattice ciphertext payloads — MLS application messages, sealed sender
//! envelopes, federation transport frames — use ChaCha20-Poly1305 with a
//! 12-byte nonce.
//!
//! Nonce construction is **always** deterministic from a session counter
//! XOR'd with a session-derived IV. We never use a random nonce — at the
//! message volumes we expect, birthday collisions are a real concern.
//!
//! The IV itself is derived from the session secret plus a direction label
//! via HKDF-SHA-256 (info: [`HKDF_AEAD_NONCE_PREFIX`]) so two parties
//! sharing an AEAD key but transmitting in opposite directions never reuse
//! a (key, nonce) pair.
//!
//! Tag verification failures and decryption failures are reported with the
//! same error variant ([`Error::Decrypt`]) to avoid leaking which one
//! happened.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::instrument;
use zeroize::Zeroize;

use crate::constants::HKDF_AEAD_NONCE_PREFIX;
use crate::{Error, Result};

/// 32-byte AEAD key. Zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct AeadKey(pub [u8; 32]);

impl AeadKey {
    /// Construct from a 32-byte array. Caller owns provenance.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// 12-byte AEAD nonce.
#[derive(Clone, Copy, Debug)]
pub struct AeadNonce(pub [u8; 12]);

impl AeadNonce {
    /// Build a deterministic nonce from a session IV and a 64-bit counter.
    ///
    /// The counter MUST be monotonically increasing within a session. The
    /// IV's top 4 bytes are preserved; the bottom 8 bytes are XOR'd with
    /// the counter's big-endian representation. This matches the standard
    /// ChaCha20-Poly1305 nonce layout used by IETF QUIC and TLS 1.3.
    #[must_use]
    pub fn from_counter(iv: [u8; 12], counter: u64) -> Self {
        let mut nonce = iv;
        let ctr_bytes = counter.to_be_bytes();
        for (i, b) in ctr_bytes.iter().enumerate() {
            nonce[4 + i] ^= *b;
        }
        Self(nonce)
    }
}

/// Derive a 12-byte AEAD IV from a session secret + direction label.
///
/// The direction label distinguishes streams sharing a key — for example,
/// `b"a2b"` and `b"b2a"` for the two halves of a bidirectional channel.
/// Without this, two endpoints with the same AEAD key and counter would
/// produce identical (key, nonce) pairs.
///
/// # Errors
///
/// Returns [`Error::KeyGen`] only if HKDF expand fails, which is
/// impossible for a 12-byte output. The signature returns `Result` to keep
/// callers honest about the abstract failure mode.
#[instrument(level = "trace", skip(session_secret, direction), fields(direction_len = direction.len()))]
pub fn derive_iv(session_secret: &[u8], direction: &[u8]) -> Result<[u8; 12]> {
    let hk = Hkdf::<Sha256>::new(None, session_secret);
    let mut info = Vec::with_capacity(HKDF_AEAD_NONCE_PREFIX.len() + 1 + direction.len());
    info.extend_from_slice(HKDF_AEAD_NONCE_PREFIX);
    info.push(b'/');
    info.extend_from_slice(direction);
    let mut iv = [0u8; 12];
    hk.expand(&info, &mut iv)
        .map_err(|e| Error::KeyGen(format!("hkdf expand for aead iv: {e}")))?;
    Ok(iv)
}

/// Encrypt `plaintext` with optional `aad` (additional authenticated data).
///
/// # Errors
///
/// Returns [`Error::Encrypt`] if the underlying AEAD reports failure. The
/// only realistic cause is plaintext exceeding the per-nonce length limit
/// (~256 GiB); we surface it uniformly.
#[instrument(level = "trace", skip(key, plaintext, aad), fields(pt_len = plaintext.len(), aad_len = aad.len()))]
pub fn encrypt(key: &AeadKey, nonce: AeadNonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce.0), payload)
        .map_err(|_| Error::Encrypt)?;
    tracing::trace!(ct_len = ciphertext.len(), "aead::encrypt ok");
    Ok(ciphertext)
}

/// Decrypt `ciphertext`. Authenticity of `aad` is verified as part of the
/// AEAD construction.
///
/// # Errors
///
/// Returns [`Error::Decrypt`] on any authentication or decryption failure.
/// The two are not distinguished externally to avoid leaking which one
/// happened.
#[instrument(level = "trace", skip(key, ciphertext, aad), fields(ct_len = ciphertext.len(), aad_len = aad.len()))]
pub fn decrypt(key: &AeadKey, nonce: AeadNonce, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0));
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce.0), payload)
        .map_err(|_| Error::Decrypt)?;
    tracing::trace!(pt_len = plaintext.len(), "aead::decrypt ok");
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> AeadKey {
        AeadKey::from_bytes([0x42; 32])
    }

    #[test]
    fn round_trip_simple() {
        let key = fixed_key();
        let nonce = AeadNonce([0xAB; 12]);
        let pt = b"hello, lattice";
        let ct = encrypt(&key, nonce, b"", pt).expect("encrypt");
        let recovered = decrypt(&key, nonce, b"", &ct).expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn round_trip_with_aad() {
        let key = fixed_key();
        let nonce = AeadNonce([0xCD; 12]);
        let pt = b"payload";
        let aad = b"associated data";
        let ct = encrypt(&key, nonce, aad, pt).expect("encrypt");
        let recovered = decrypt(&key, nonce, aad, &ct).expect("decrypt");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = fixed_key();
        let nonce = AeadNonce([0; 12]);
        let pt = b"important message";
        let mut ct = encrypt(&key, nonce, b"", pt).expect("encrypt");
        // flip a bit in the ciphertext body (skip the leading 0 of length-zero AAD)
        ct[0] ^= 0x01;
        assert!(matches!(
            decrypt(&key, nonce, b"", &ct),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn tampered_aad_rejected() {
        let key = fixed_key();
        let nonce = AeadNonce([0; 12]);
        let ct = encrypt(&key, nonce, b"aad1", b"pt").expect("encrypt");
        assert!(matches!(
            decrypt(&key, nonce, b"aad2", &ct),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let key1 = AeadKey::from_bytes([0x01; 32]);
        let key2 = AeadKey::from_bytes([0x02; 32]);
        let nonce = AeadNonce([0; 12]);
        let ct = encrypt(&key1, nonce, b"", b"secret").expect("encrypt");
        assert!(matches!(
            decrypt(&key2, nonce, b"", &ct),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn nonce_from_counter_is_deterministic() {
        let iv = [0xAA; 12];
        let n0 = AeadNonce::from_counter(iv, 0);
        let n1 = AeadNonce::from_counter(iv, 1);
        assert_ne!(n0.0, n1.0);
        // top 4 bytes of IV preserved
        assert_eq!(&n0.0[..4], &iv[..4]);
        // counter=0 leaves IV unchanged
        assert_eq!(n0.0, iv);
    }

    #[test]
    fn derive_iv_differs_per_direction() {
        let secret = b"shared session secret material";
        let iv_a2b = derive_iv(secret, b"a2b").expect("derive a2b");
        let iv_b2a = derive_iv(secret, b"b2a").expect("derive b2a");
        assert_ne!(iv_a2b, iv_b2a);
    }

    #[test]
    fn derive_iv_is_deterministic() {
        let secret = b"shared session secret material";
        let iv1 = derive_iv(secret, b"a2b").expect("derive 1");
        let iv2 = derive_iv(secret, b"a2b").expect("derive 2");
        assert_eq!(iv1, iv2);
    }

    /// End-to-end smoke test: derive direction-specific IVs, encrypt a
    /// message with counter-derived nonces, decrypt the other direction.
    #[test]
    fn directional_session_smoke() {
        let key = fixed_key();
        let secret = b"shared session secret";
        let iv_a2b = derive_iv(secret, b"a2b").expect("derive a2b");
        let iv_b2a = derive_iv(secret, b"b2a").expect("derive b2a");

        // Alice sends counter=0
        let nonce_alice = AeadNonce::from_counter(iv_a2b, 0);
        let ct_a = encrypt(&key, nonce_alice, b"", b"from alice").expect("encrypt a");

        // Bob sends counter=0 (same counter, different direction)
        let nonce_bob = AeadNonce::from_counter(iv_b2a, 0);
        let ct_b = encrypt(&key, nonce_bob, b"", b"from bob").expect("encrypt b");

        // Different ciphertexts despite same counter
        assert_ne!(ct_a, ct_b);

        // Bob decrypts Alice's message
        let recv_at_bob = decrypt(&key, nonce_alice, b"", &ct_a).expect("decrypt at bob");
        assert_eq!(recv_at_bob, b"from alice");

        // Alice decrypts Bob's message
        let recv_at_alice = decrypt(&key, nonce_bob, b"", &ct_b).expect("decrypt at alice");
        assert_eq!(recv_at_alice, b"from bob");
    }
}
