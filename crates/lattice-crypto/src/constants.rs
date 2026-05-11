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

/// HKDF info for folding the hybrid KEM secret into MLS `init_secret`.
///
/// Used by the custom `LATTICE_HYBRID_V1` ciphersuite (D-04) to extend
/// the standard MLS key schedule with the ML-KEM-768 layer.
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
