//! Domain-separation labels and HKDF salts used by the M7 voice/video
//! key derivation.
//!
//! Centralized here so that any drift between code paths and the
//! construction spec in `scratch/pq-dtls-srtp-construction.md` is
//! mechanical to detect. Pattern mirrors `lattice-crypto::constants`.

/// HKDF info-prefix for the PQ-hybrid SRTP master derivation. Pinned
/// by [`DECISIONS.md`] §D-18. The full HKDF input is
///
/// ```text
/// srtp_master = HKDF-SHA-256(
///     ikm  = dtls_exporter || ml_kem_shared_secret,
///     salt = empty,
///     info = PQ_DTLS_SRTP_INFO_PREFIX || call_id || epoch_id.to_be_bytes(),
///     length = SRTP_MASTER_OKM_LEN,
/// )
/// ```
///
/// 60 bytes is enough for one SRTP master key (16 B) plus its salt
/// (14 B) per direction; the standard webrtc-srtp `Context::new`
/// expects that exact layout. Length lives in [`SRTP_MASTER_OKM_LEN`].
///
/// The salt is left empty so that HKDF-Extract degenerates to
/// HMAC-SHA-256(0…0, ikm) per RFC 5869 §3.1 — fine here because all
/// the domain separation lives in `info` and `ikm` already contains
/// 60 B of high-entropy DTLS exporter output.
pub const PQ_DTLS_SRTP_INFO_PREFIX: &[u8] = b"lattice/dtls-srtp-pq/v1";

/// Output length, in bytes, of the SRTP master KDF.
pub const SRTP_MASTER_OKM_LEN: usize = 60;

/// HKDF salt for the optional cover-traffic dummy-frame keying.
///
/// Cover traffic uses an independent keystream so that an attacker
/// observing the wire cannot trivially XOR real and dummy frames.
pub const COVER_TRAFFIC_HKDF_SALT: &[u8] = b"lattice/cover-traffic/v1";

/// DTLS-SRTP exporter label (RFC 5764 §4.2). Standardized — pinned
/// here as the canonical Lattice spelling and to keep the
/// `extract_dtls_exporter` helper's call site self-documenting.
///
/// `webrtc-srtp` declares its own copy of this same constant as
/// `LABEL_EXTRACTOR_DTLS_SRTP` (`srtp/src/config.rs`); the strings
/// MUST agree or PQ keys won't decrypt media.
pub const DTLS_SRTP_EXPORTER_LABEL: &str = "EXTRACTOR-dtls_srtp";

/// Length, in bytes, of the DTLS exporter output we request.
///
/// Pinned to match `webrtc-srtp`'s
/// `(key_len * 2) + (salt_len * 2) = (16 * 2) + (14 * 2) = 60`
/// for the `AES_CM_128_HMAC_SHA1_80` and `AEAD_AES_128_GCM` SRTP
/// profiles (both lay their session keys out the same way at this
/// length).
pub const DTLS_EXPORTER_LEN: usize = 60;

/// Domain-separation prefix for the call-invite wire payload signed
/// transcript. The Ed25519 signature on a `CallInvite` covers
/// `CALL_INVITE_TRANSCRIPT_PREFIX || canonical_invite_bytes`.
pub const CALL_INVITE_TRANSCRIPT_PREFIX: &[u8] = b"lattice/call-invite/v1";
