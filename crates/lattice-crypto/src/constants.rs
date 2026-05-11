//! Locked HKDF info strings and other byte-string constants used across
//! the Lattice crypto subsystem.
//!
//! Every entry below is part of the wire contract. Changing any constant
//! requires bumping the wire protocol version in `lattice-protocol`. See
//! `docs/DECISIONS.md §D-02` for the lock and rationale.

/// HKDF info for the PQXDH-style initial session secret derivation.
///
/// Consumed by the initial 1:1 key exchange that seeds an MLS group's
/// `init_secret`. See `docs/ARCHITECTURE.md §"Crypto handshake spec"`.
pub const HKDF_INIT: &[u8] = b"lattice/init/v1";

/// Namespace prefix for the per-epoch external-PSK ID that folds the
/// ML-KEM-768 shared secret into the MLS key schedule.
///
/// The full `PreSharedKeyID::External` id used in MLS commits is this
/// prefix followed by the eight-byte little-endian epoch counter:
/// `HKDF_MLS_INIT || epoch.to_le_bytes()`. Both committer and joiner
/// derive the id identically given the epoch number, so PSK lookup is
/// deterministic per epoch.
///
/// Renamed in semantics by the 2026-05-10 re-open of D-04 — the byte
/// string is unchanged. See `docs/DECISIONS.md §D-04` for the PSK-injection
/// path that replaced the original "fold into `init_secret`" construction.
pub const HKDF_MLS_INIT: &[u8] = b"lattice/mls-init/v1";

/// HKDF info for sealed sender envelope key derivation.
///
/// Used by `crate::sealed_sender` to derive the per-epoch envelope key
/// from the MLS epoch secret. The Signal-style attribution cert (D-05)
/// authenticates the outer envelope; this key encrypts the inner payload.
pub const HKDF_SEALED_SENDER: &[u8] = b"lattice/sealed-sender/v1";

/// HKDF info for direction-specific AEAD nonce-prefix derivation.
///
/// Used by `crate::aead::derive_iv` so Alice→Bob and Bob→Alice streams
/// use different IVs even when sharing an AEAD key. The direction label
/// is appended after this prefix.
pub const HKDF_AEAD_NONCE_PREFIX: &[u8] = b"lattice/aead-nonce/v1";

/// HKDF info for identity-claim transcript binding hash.
///
/// The byte string that is signed by `crate::identity::sign` is
/// `HKDF(ikm = claim_bytes, info = HKDF_IDENTITY_CLAIM, salt = "", L = 32)`
/// — both ML-DSA-65 and Ed25519 sign the same 32-byte digest so transcript
/// equivalence is provable.
pub const HKDF_IDENTITY_CLAIM: &[u8] = b"lattice/identity-claim/v1";

/// HKDF info for `KeyPackage` signature transcript derivation.
pub const HKDF_KEY_PACKAGE_SIG: &[u8] = b"lattice/key-package-sig/v1";

/// HKDF info for federation server-to-server auth handshake.
pub const HKDF_FEDERATION_AUTH: &[u8] = b"lattice/federation-auth/v1";

/// HKDF info for the sealed sender outer-envelope MAC key (D-05).
pub const HKDF_SEALED_SENDER_MAC: &[u8] = b"lattice/sealed-sender-mac/v1";

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinning test — if these byte strings change, the wire version must
    /// bump (D-02). This test exists to fail loudly on accidental edits.
    #[test]
    fn info_strings_pinned() {
        assert_eq!(HKDF_INIT, b"lattice/init/v1");
        assert_eq!(HKDF_MLS_INIT, b"lattice/mls-init/v1");
        assert_eq!(HKDF_SEALED_SENDER, b"lattice/sealed-sender/v1");
        assert_eq!(HKDF_AEAD_NONCE_PREFIX, b"lattice/aead-nonce/v1");
        assert_eq!(HKDF_IDENTITY_CLAIM, b"lattice/identity-claim/v1");
        assert_eq!(HKDF_KEY_PACKAGE_SIG, b"lattice/key-package-sig/v1");
        assert_eq!(HKDF_FEDERATION_AUTH, b"lattice/federation-auth/v1");
        assert_eq!(HKDF_SEALED_SENDER_MAC, b"lattice/sealed-sender-mac/v1");
    }
}
