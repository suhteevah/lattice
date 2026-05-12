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

use bytes::Bytes;
use hkdf::Hkdf;
use sha2::Sha256;
use webrtc_srtp::context::Context as SrtpContext;
use webrtc_srtp::protection_profile::ProtectionProfile;
use zeroize::Zeroize;

use crate::call::{CallId, Role};
use crate::constants::{PQ_DTLS_SRTP_INFO_PREFIX, SRTP_MASTER_OKM_LEN};
use crate::error::MediaError;
use crate::handshake::PqSharedSecret;

/// SRTP protection profile pinned by [`crate::handshake::default_dtls_config`].
///
/// `AES-128-CM-HMAC-SHA1-80` is the only profile advertised in the DTLS
/// `use_srtp` extension, so this is the profile both endpoints must
/// install. Tracked as an M7 follow-up to add AES-GCM (which would
/// require a 56-byte rather than 60-byte SRTP master OKM).
pub const PQ_SRTP_PROFILE: ProtectionProfile = ProtectionProfile::Aes128CmHmacSha1_80;

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

/// One side of an SRTP session — owns a local-write `Context` for
/// encrypting outgoing RTP and a remote-write `Context` for decrypting
/// incoming RTP. Constructed from the [`SrtpSessionKeys`] that
/// [`split_srtp_master`] produces.
///
/// Pinned to [`PQ_SRTP_PROFILE`] (`AES-128-CM-HMAC-SHA1-80`). The two
/// `Context`s are intentionally separate per webrtc-srtp's documented
/// "one-way operations only" constraint — sharing one `Context` for
/// both directions would corrupt SSRC state.
///
/// Construction takes ownership of the [`SrtpSessionKeys`] so the
/// underlying key/salt bytes are zeroized when the endpoint drops.
pub struct PqSrtpEndpoint {
    local: SrtpContext,
    remote: SrtpContext,
}

impl PqSrtpEndpoint {
    /// Build a new endpoint from a pair of pre-derived session keys.
    ///
    /// `keys` typically comes from
    /// [`split_srtp_master`]`(master, role)` on the local participant's
    /// view of a freshly-derived [`SrtpMasterKey`].
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Srtp`] if `webrtc-srtp` rejects the key
    /// or salt material (e.g., wrong length for the pinned profile).
    /// With keys produced by [`split_srtp_master`] this is unreachable
    /// in practice; we still propagate the error rather than panic.
    pub fn from_session_keys(keys: SrtpSessionKeys) -> Result<Self, MediaError> {
        let local = SrtpContext::new(
            &keys.local.master_key,
            &keys.local.master_salt,
            PQ_SRTP_PROFILE,
            None,
            None,
        )
        .map_err(|e| MediaError::Srtp(format!("local context: {e}")))?;
        let remote = SrtpContext::new(
            &keys.remote.master_key,
            &keys.remote.master_salt,
            PQ_SRTP_PROFILE,
            None,
            None,
        )
        .map_err(|e| MediaError::Srtp(format!("remote context: {e}")))?;
        Ok(Self { local, remote })
    }

    /// Encrypt one outgoing RTP packet. `rtp_packet` must be the
    /// already-marshalled (header + payload) RTP packet bytes; the
    /// returned [`Bytes`] is the SRTP-protected form ready to put on
    /// the wire.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Srtp`] if the input isn't a valid RTP
    /// packet (header unmarshal fails) or the cipher errors. After
    /// 2^48 packets on the same SSRC the underlying counter overflows
    /// and webrtc-srtp returns `ErrExceededMaxPackets`; surface that
    /// as a re-key trigger in the orchestrator (M7 follow-up).
    pub fn protect_rtp(&mut self, rtp_packet: &[u8]) -> Result<Bytes, MediaError> {
        self.local
            .encrypt_rtp(rtp_packet)
            .map_err(|e| MediaError::Srtp(format!("encrypt_rtp: {e}")))
    }

    /// Decrypt one incoming SRTP packet. Returns the recovered RTP
    /// packet bytes (header + payload, marshalled). Replay protection
    /// is enabled by default on the remote context.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::Srtp`] on auth-tag failure, replay,
    /// malformed header, or SSRC-state mismatch.
    pub fn unprotect_rtp(&mut self, srtp_packet: &[u8]) -> Result<Bytes, MediaError> {
        self.remote
            .decrypt_rtp(srtp_packet)
            .map_err(|e| MediaError::Srtp(format!("decrypt_rtp: {e}")))
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

    /// Build a minimal RTP/2 packet by hand: 12-byte fixed header
    /// (V=2, no padding/extension/CSRC, PT=96 dynamic, marker clear)
    /// followed by the payload bytes. Self-contained so the test
    /// doesn't pull in the `rtp` crate as a dev-dep.
    fn build_rtp_packet(seq: u16, timestamp: u32, ssrc: u32, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(12 + payload.len());
        packet.push(0x80); // V=2, P=0, X=0, CC=0
        packet.push(96);   // M=0, PT=96
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&timestamp.to_be_bytes());
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    /// Build a Caller + Callee endpoint pair from a recognizable
    /// 60-byte master, so the in-process round-trip below uses keys
    /// laid out the same way `derive_srtp_master` would lay them.
    fn endpoint_pair() -> (PqSrtpEndpoint, PqSrtpEndpoint) {
        let mut bytes = [0u8; SRTP_MASTER_OKM_LEN];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(5);
        }
        let master = unsafe_construct_master(bytes);
        let caller_keys = split_srtp_master(&master, Role::Caller);
        let callee_keys = split_srtp_master(&master, Role::Callee);
        let caller = PqSrtpEndpoint::from_session_keys(caller_keys).expect("caller endpoint");
        let callee = PqSrtpEndpoint::from_session_keys(callee_keys).expect("callee endpoint");
        (caller, callee)
    }

    /// Real `webrtc-srtp::Context` round trip through the PQ-derived
    /// keys. Caller protects, callee unprotects — the recovered RTP
    /// packet must byte-equal the original. This is the smoke test
    /// the Phase F orchestrator relies on.
    #[test]
    fn pq_srtp_endpoint_round_trips_caller_to_callee() {
        let (mut caller, mut callee) = endpoint_pair();
        let payload = b"hello, lattice phase F";
        let rtp = build_rtp_packet(1234, 0x0001_0203, 0xabcd_ef01, payload);

        let protected = caller.protect_rtp(&rtp).expect("protect");
        // SRTP CM-80 appends a 10-byte HMAC tag — the protected blob
        // is strictly larger than the plain RTP packet.
        assert!(
            protected.len() > rtp.len(),
            "protected packet should be larger (auth tag); got {} vs {}",
            protected.len(),
            rtp.len()
        );

        let recovered = callee.unprotect_rtp(&protected).expect("unprotect");
        // decrypt_rtp returns just the RTP packet minus the auth tag,
        // i.e. the same bytes we passed to encrypt_rtp.
        assert_eq!(&recovered[..], &rtp[..]);
    }

    /// Symmetric round trip the other way — Callee → Caller. Different
    /// SSRCs / sequence numbers exercise the second direction's
    /// SSRC-state initialization.
    #[test]
    fn pq_srtp_endpoint_round_trips_callee_to_caller() {
        let (mut caller, mut callee) = endpoint_pair();
        let payload = b"reply, lattice phase F";
        let rtp = build_rtp_packet(7, 99, 0x1111_2222, payload);

        let protected = callee.protect_rtp(&rtp).expect("protect");
        let recovered = caller.unprotect_rtp(&protected).expect("unprotect");
        assert_eq!(&recovered[..], &rtp[..]);
    }

    /// Decrypt with the wrong endpoint must fail — proves the local
    /// vs remote context split is doing real work, not just labeling.
    #[test]
    fn pq_srtp_endpoint_rejects_wrong_direction() {
        let (mut caller, _callee) = endpoint_pair();
        let payload = b"wrong-direction probe";
        let rtp = build_rtp_packet(42, 100, 0x3333_4444, payload);
        let protected = caller.protect_rtp(&rtp).expect("protect");
        // Caller protected with its local (= client-write) key. The
        // caller's own remote context can't unprotect that — and neither
        // can the callee's local context, because callee.local is the
        // server-write key. Only callee.remote (= client-write) can.
        let result = caller.unprotect_rtp(&protected);
        assert!(result.is_err(), "caller decoded its own outbound packet");
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
