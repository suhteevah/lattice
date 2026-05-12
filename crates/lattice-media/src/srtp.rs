//! PQ-hybrid SRTP context.
//!
//! Wraps the vendored `webrtc-srtp` `Context` (landing in Phase D) so
//! that the master key is derived from
//!
//! ```text
//! HKDF-SHA-256(
//!     ikm  = dtls_exporter || ml_kem_shared_secret,
//!     salt = empty,
//!     info = PQ_DTLS_SRTP_INFO_PREFIX
//!         || call_id
//!         || epoch_id.to_be_bytes(),
//!     length = SRTP_MASTER_OKM_LEN,
//! )
//! ```
//!
//! instead of being derived directly from the DTLS exporter. The
//! vendored `webrtc-srtp::Context::new` gets a sibling constructor in
//! Phase D that accepts pre-derived key material, which is what this
//! type wraps.
//!
//! Pinned by `docs/DECISIONS.md` §D-18. The construction matches the
//! M2 PSK injection pattern (D-04 amendment) — both fold an ML-KEM-768
//! secret into an HKDF derivation alongside a classical exporter, so
//! the security argument is identical: the PQ secret enters the KDF
//! under HKDF-SHA-256 before any subkey is derived.
//!
//! Phase B scope: type definitions + the HKDF derivation helper. No
//! `encrypt_rtp` / `decrypt_rtp` yet — those land in Phase E once the
//! vendored Context is wired up.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::call::{CallId, Role};
use crate::constants::{PQ_DTLS_SRTP_INFO_PREFIX, SRTP_MASTER_OKM_LEN};
use crate::error::MediaError;
use crate::handshake::PqSharedSecret;

/// Length of a single SRTP master key, in bytes.
///
/// Fixed at 16 for both AES-CM-128 (`SRTP_AES128_CM_HMAC_SHA1_80`)
/// and AES-GCM-128 (`SRTP_AEAD_AES_128_GCM`). Higher-entropy AES-256
/// profiles aren't currently negotiated by webrtc-rs (Phase D punts
/// that decision).
pub const SRTP_MASTER_KEY_LEN: usize = 16;

/// Length of a single SRTP master salt, in bytes. Fixed at 14 for
/// the same reason as [`SRTP_MASTER_KEY_LEN`].
pub const SRTP_MASTER_SALT_LEN: usize = 14;

/// Output of the SRTP key derivation. 60 bytes laid out as
/// `(client_key[16], server_key[16], client_salt[14], server_salt[14])`
/// per the standard webrtc-srtp expectation.
///
/// Zeroized on drop. Callers that need to hand bytes to the vendored
/// SRTP context use [`SrtpMasterKey::expose`].
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SrtpMasterKey([u8; SRTP_MASTER_OKM_LEN]);

impl SrtpMasterKey {
    /// Output length, in bytes.
    pub const LEN: usize = SRTP_MASTER_OKM_LEN;

    /// Expose the raw bytes for handoff to the vendored
    /// `webrtc-srtp::Context` constructor.
    #[must_use]
    pub const fn expose(&self) -> &[u8; SRTP_MASTER_OKM_LEN] {
        &self.0
    }
}

/// Derive the 60-byte SRTP master from the DTLS exporter and the PQ
/// shared secret.
///
/// `dtls_exporter` is the output of the RFC 5705 exporter call with
/// label `b"EXTRACTOR-dtls_srtp"`. `pq_secret` is the ML-KEM-768
/// shared secret resolved during the call-invite / call-accept
/// round trip. `call_id` and `epoch_id` are the HKDF `info` binding so
/// each call has fresh material even if (somehow) the inputs collide.
///
/// # Errors
///
/// Returns [`MediaError::Srtp`] if the HKDF expansion fails. With
/// valid inputs and the constant output length this should never
/// happen, but we propagate the error rather than panicking.
pub fn derive_srtp_master(
    dtls_exporter: &[u8],
    pq_secret: &PqSharedSecret,
    call_id: CallId,
    epoch_id: u64,
) -> Result<SrtpMasterKey, MediaError> {
    let mut ikm = Vec::with_capacity(dtls_exporter.len() + PqSharedSecret::LEN);
    ikm.extend_from_slice(dtls_exporter);
    ikm.extend_from_slice(pq_secret.expose());

    let mut info = Vec::with_capacity(PQ_DTLS_SRTP_INFO_PREFIX.len() + CallId::LEN + 8);
    info.extend_from_slice(PQ_DTLS_SRTP_INFO_PREFIX);
    info.extend_from_slice(&call_id.0);
    info.extend_from_slice(&epoch_id.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; SRTP_MASTER_OKM_LEN];
    hk.expand(&info, &mut okm)
        .map_err(|e| MediaError::Srtp(format!("hkdf expand: {e}")))?;

    // Best-effort zeroize of the staging IKM. The Vec heap allocation
    // means zeroize-on-drop is not automatic; do it here explicitly.
    ikm.zeroize();

    Ok(SrtpMasterKey(okm))
}

/// SRTP key + salt for one direction. Either local-write (we encrypt
/// outgoing RTP with these) or remote-write (we decrypt incoming
/// RTP with these).
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SrtpKeyPair {
    /// 16-byte master key fed to `webrtc-srtp::Context::new` as the
    /// `master_key` argument for the matching direction.
    pub master_key: [u8; SRTP_MASTER_KEY_LEN],
    /// 14-byte master salt fed to `webrtc-srtp::Context::new` as the
    /// `master_salt` argument for the matching direction.
    pub master_salt: [u8; SRTP_MASTER_SALT_LEN],
}

/// Both directions of an SRTP session, as they get handed to
/// `webrtc-srtp`.
///
/// Per RFC 5764 §4.2 the 60-byte DTLS-SRTP exporter is laid out as
/// `(client_write_key, server_write_key, client_write_salt,
/// server_write_salt)`. Which of those is "local" depends on the
/// DTLS role: the DTLS client uses `client_write_*` as its outgoing
/// keys, the DTLS server uses `server_write_*`. [`split_srtp_master`]
/// does that mapping based on the [`Role`] of the local participant.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SrtpSessionKeys {
    /// Outgoing direction (what we encrypt with).
    pub local: SrtpKeyPair,
    /// Incoming direction (what we decrypt with).
    pub remote: SrtpKeyPair,
}

/// Split a 60-byte PQ-folded SRTP master into the local/remote
/// key pairs, mapped by DTLS role.
///
/// The byte layout matches webrtc-srtp's
/// `extract_session_keys_from_dtls` exactly (its 60-byte exporter
/// output is `(client_key_16 || server_key_16 || client_salt_14 ||
/// server_salt_14)`). We reproduce that layout so a real
/// `webrtc-srtp::Context::new` call accepts our output without
/// further translation.
///
/// The 60-byte input must come from [`derive_srtp_master`] — feeding
/// the raw DTLS exporter here defeats the point of the PQ fold.
#[must_use]
pub fn split_srtp_master(master: &SrtpMasterKey, role: Role) -> SrtpSessionKeys {
    let bytes = master.expose();
    let mut client_key = [0u8; SRTP_MASTER_KEY_LEN];
    let mut server_key = [0u8; SRTP_MASTER_KEY_LEN];
    let mut client_salt = [0u8; SRTP_MASTER_SALT_LEN];
    let mut server_salt = [0u8; SRTP_MASTER_SALT_LEN];

    let mut cursor = 0;
    client_key.copy_from_slice(&bytes[cursor..cursor + SRTP_MASTER_KEY_LEN]);
    cursor += SRTP_MASTER_KEY_LEN;
    server_key.copy_from_slice(&bytes[cursor..cursor + SRTP_MASTER_KEY_LEN]);
    cursor += SRTP_MASTER_KEY_LEN;
    client_salt.copy_from_slice(&bytes[cursor..cursor + SRTP_MASTER_SALT_LEN]);
    cursor += SRTP_MASTER_SALT_LEN;
    server_salt.copy_from_slice(&bytes[cursor..cursor + SRTP_MASTER_SALT_LEN]);

    let client_pair = SrtpKeyPair {
        master_key: client_key,
        master_salt: client_salt,
    };
    let server_pair = SrtpKeyPair {
        master_key: server_key,
        master_salt: server_salt,
    };

    match role {
        Role::Caller => SrtpSessionKeys {
            local: client_pair,
            remote: server_pair,
        },
        Role::Callee => SrtpSessionKeys {
            local: server_pair,
            remote: client_pair,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_srtp_master_is_deterministic() {
        let exporter = [7u8; 60];
        let pq = PqSharedSecret::from_bytes([3u8; 32]);
        let call = CallId([9u8; 16]);
        let a = derive_srtp_master(&exporter, &pq, call, 0).expect("derive");
        let b = derive_srtp_master(&exporter, &pq, call, 0).expect("derive");
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn derive_srtp_master_differs_per_call_id() {
        let exporter = [7u8; 60];
        let pq = PqSharedSecret::from_bytes([3u8; 32]);
        let a = derive_srtp_master(&exporter, &pq, CallId([1u8; 16]), 0).expect("derive");
        let b = derive_srtp_master(&exporter, &pq, CallId([2u8; 16]), 0).expect("derive");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn derive_srtp_master_differs_per_epoch() {
        let exporter = [7u8; 60];
        let pq = PqSharedSecret::from_bytes([3u8; 32]);
        let call = CallId([9u8; 16]);
        let a = derive_srtp_master(&exporter, &pq, call, 0).expect("derive");
        let b = derive_srtp_master(&exporter, &pq, call, 1).expect("derive");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn derive_srtp_master_differs_when_pq_secret_differs() {
        let exporter = [7u8; 60];
        let call = CallId([9u8; 16]);
        let pq_a = PqSharedSecret::from_bytes([3u8; 32]);
        let pq_b = PqSharedSecret::from_bytes([4u8; 32]);
        let a = derive_srtp_master(&exporter, &pq_a, call, 0).expect("derive");
        let b = derive_srtp_master(&exporter, &pq_b, call, 0).expect("derive");
        // This is the key PQ property: changing the ML-KEM secret
        // changes the SRTP master, even if the DTLS exporter is
        // identical. Defends against harvest-now-decrypt-later on the
        // classical DTLS handshake.
        assert_ne!(a.expose(), b.expose());
    }

    /// Build a recognizable 60-byte master and assert the split lays
    /// out the four 30-byte halves exactly the way RFC 5764 §4.2
    /// specifies. Caller and callee see the same client/server pair
    /// but with `local` and `remote` swapped.
    #[test]
    #[allow(clippy::cast_possible_truncation)] // i ∈ 0..60 always fits u8
    fn split_srtp_master_lays_out_session_keys_correctly() {
        // Construct a master with distinguishable byte ranges so we
        // can byte-match each slice after the split.
        let mut bytes = [0u8; SRTP_MASTER_OKM_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        // Bypass derive_srtp_master to inject our recognizable bytes
        // directly into a SrtpMasterKey.
        let master = unsafe_construct_master(bytes);

        let caller_keys = split_srtp_master(&master, Role::Caller);
        // Caller is DTLS client → local = client_write_*
        assert_eq!(&caller_keys.local.master_key, &bytes[0..16]);
        assert_eq!(&caller_keys.remote.master_key, &bytes[16..32]);
        assert_eq!(&caller_keys.local.master_salt, &bytes[32..46]);
        assert_eq!(&caller_keys.remote.master_salt, &bytes[46..60]);

        let callee_keys = split_srtp_master(&master, Role::Callee);
        // Callee is DTLS server → local = server_write_*
        assert_eq!(&callee_keys.local.master_key, &bytes[16..32]);
        assert_eq!(&callee_keys.remote.master_key, &bytes[0..16]);
        assert_eq!(&callee_keys.local.master_salt, &bytes[46..60]);
        assert_eq!(&callee_keys.remote.master_salt, &bytes[32..46]);
    }

    /// Caller's outgoing keys must equal the callee's incoming keys,
    /// or media will not decrypt.
    #[test]
    #[allow(clippy::cast_possible_truncation)] // i ∈ 0..60 always fits u8
    fn caller_local_equals_callee_remote() {
        let mut bytes = [0u8; SRTP_MASTER_OKM_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let master = unsafe_construct_master(bytes);

        let alice = split_srtp_master(&master, Role::Caller);
        let bob = split_srtp_master(&master, Role::Callee);

        assert_eq!(alice.local.master_key, bob.remote.master_key);
        assert_eq!(alice.local.master_salt, bob.remote.master_salt);
        assert_eq!(alice.remote.master_key, bob.local.master_key);
        assert_eq!(alice.remote.master_salt, bob.local.master_salt);
    }

    /// Test-only helper: construct a `SrtpMasterKey` from a known
    /// 60-byte buffer, bypassing the HKDF derivation. Named "unsafe"
    /// because it produces a master that doesn't come from
    /// [`derive_srtp_master`] — wiring it into a real SRTP context
    /// would defeat the PQ fold.
    fn unsafe_construct_master(bytes: [u8; SRTP_MASTER_OKM_LEN]) -> SrtpMasterKey {
        SrtpMasterKey(bytes)
    }
}
