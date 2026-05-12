//! Hardware-backed key storage for the native shells (M7 Phase G).
//!
//! ## Posture
//!
//! Identity private keys — the ML-DSA-65 32-byte seed and the Ed25519
//! 32-byte signing key from
//! [`lattice_crypto::identity::IdentitySecretKey`] — live behind a
//! platform-specific seal. Callers hold an opaque [`KeyHandle`]; they
//! ask the keystore to sign on their behalf and never touch the secret
//! bytes themselves.
//!
//! G.1 ships the trait + a process-local [`memory::MemoryKeystore`] +
//! the Windows DPAPI-backed [`windows::WindowsKeystore`]. Linux Secret
//! Service and macOS Secure Enclave impls land in G.2; the Windows
//! TPM 2.0 / Windows Hello upgrade lands in G.3. See
//! [`scratch/m7-phase-g-plan.md`](../../../../../scratch/m7-phase-g-plan.md)
//! for the full sequencing and the DPAPI-vs-TPM rationale (DECISIONS
//! §D-26).
//!
//! ## RAM window
//!
//! The OS seal protects keys *at rest*. During [`Keystore::sign`] the
//! secret bytes are unsealed into a [`zeroize::Zeroizing`] buffer,
//! handed to [`lattice_crypto::identity::sign`] which itself uses
//! `Zeroize`-on-drop signing keys, and zeroized when the call returns.
//! True hardware signing — where the secret never leaves the secure
//! module — is not achievable on Windows for Ed25519 / ML-DSA-65
//! because NCrypt doesn't support those algorithms; the TPM 2.0 path
//! in G.3 stays a *wrapping* primitive for the same reason.

use std::fmt;
use std::time::SystemTime;

use lattice_crypto::identity::{HybridSignature, IdentityPublicKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod memory;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

/// Length of a stored [`IdentitySecretKey`] when serialized for OS
/// sealing: `ml_dsa_seed (32) || ed25519_sk (32)`.
///
/// Pinned here so the seal format stays stable across keystore impls.
/// Changing this is a breaking change for every persisted keystore
/// blob on disk; bump the on-disk version tag if it ever moves.
pub const SECRET_BLOB_LEN: usize = 64;

/// Stable identifier for a stored keypair. 16 random bytes generated
/// at [`Keystore::generate`] time.
///
/// Surfaced over IPC as hex; UI never sees raw bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct KeyHandle(pub [u8; 16]);

impl KeyHandle {
    /// Length of a [`KeyHandle`] in bytes (16).
    pub const LEN: usize = 16;

    /// Generate a fresh handle from [`OsRng`].
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; Self::LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Render this handle as 32 hex characters. Stable across runs.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Parse a 32-character hex string back into a handle.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::InvalidHandle`] if the hex is malformed
    /// or wrong length.
    pub fn from_hex(s: &str) -> Result<Self, KeystoreError> {
        let raw =
            hex::decode(s).map_err(|e| KeystoreError::InvalidHandle(format!("hex decode: {e}")))?;
        if raw.len() != Self::LEN {
            return Err(KeystoreError::InvalidHandle(format!(
                "wrong length: got {}, want {}",
                raw.len(),
                Self::LEN
            )));
        }
        let mut bytes = [0u8; Self::LEN];
        bytes.copy_from_slice(&raw);
        Ok(Self(bytes))
    }
}

impl fmt::Display for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", (*self).to_hex())
    }
}

/// What [`Keystore::list`] returns per stored key. Public-key bytes
/// only — secret bytes never leave the keystore.
#[derive(Clone, Debug)]
pub struct StoredKey {
    /// Handle assigned at generation time.
    pub handle: KeyHandle,
    /// Public-key bundle for this identity.
    pub public: IdentityPublicKey,
    /// When this key was generated. Surfaced in the UI key picker.
    pub created_at: SystemTime,
    /// User-supplied label, e.g. "kokonoe desktop". UI-only; not
    /// authenticated.
    pub label: String,
}

/// Errors a [`Keystore`] can raise.
///
/// Variants are sentence-case per the workspace style. `OS`-prefixed
/// variants point at the platform layer (DPAPI, Secret Service,
/// Secure Enclave, …) while the rest are keystore-layer failures.
#[derive(Debug, Error)]
pub enum KeystoreError {
    /// The handle isn't known to this keystore.
    #[error("keystore handle not found: {handle}")]
    NotFound {
        /// The handle that was looked up.
        handle: KeyHandle,
    },

    /// The OS-side seal primitive (`CryptProtectData` on Windows,
    /// Secret Service `CreateItem` on Linux, Keychain `add` on
    /// macOS) refused our request.
    #[error("OS seal failed: {message}")]
    Seal {
        /// Human-readable message from the platform error.
        message: String,
    },

    /// The OS-side unseal primitive failed. Common causes:
    /// blob corruption, wrong user account, TPM reset on Windows,
    /// keychain locked on macOS.
    #[error("OS unseal failed: {message}")]
    Unseal {
        /// Human-readable message from the platform error.
        message: String,
    },

    /// Reading or writing under the keystore directory failed.
    #[error("keystore IO failed: {0}")]
    Io(#[from] std::io::Error),

    /// `lattice-crypto` returned an error during key generation or
    /// signing (RNG failure, AEAD failure on the wrap path, …).
    #[error("lattice-crypto error: {0}")]
    Crypto(String),

    /// A persisted blob was the wrong length or otherwise malformed.
    /// Treat as cryptographic failure — do not retry.
    #[error("stored blob malformed: {0}")]
    MalformedBlob(String),

    /// A [`KeyHandle`] hex string couldn't be parsed.
    #[error("invalid key handle: {0}")]
    InvalidHandle(String),

    /// JSON serialization for the public-key sidecar failed.
    #[error("public-key sidecar encode/decode failed: {0}")]
    Sidecar(#[from] serde_json::Error),
}

/// Trait implemented by every keystore impl. Sync because all current
/// platform impls (DPAPI, Secret Service, Secure Enclave) expose sync
/// APIs and the signing op is CPU-bound. Tauri commands wrap calls
/// in `tokio::task::spawn_blocking` when needed; the in-process
/// `MemoryKeystore` is fast enough to invoke directly from an async
/// task.
pub trait Keystore: Send + Sync {
    /// Generate a fresh hybrid identity keypair, seal the secret
    /// bytes, and return the [`StoredKey`] view (public material
    /// + handle + label).
    fn generate(&self, label: &str) -> Result<StoredKey, KeystoreError>;

    /// Look up the public-key bundle for a handle without touching
    /// the seal — `list()` fast-path.
    fn pubkey(&self, handle: &KeyHandle) -> Result<IdentityPublicKey, KeystoreError>;

    /// Unseal, sign, zeroize, return.
    ///
    /// `message` is the raw bytes to sign. The keystore does **not**
    /// pre-hash; callers feed the full canonical bytes per Lattice's
    /// signature convention (Ed25519 + ML-DSA-65 both hash internally).
    fn sign(
        &self,
        handle: &KeyHandle,
        message: &[u8],
    ) -> Result<HybridSignature, KeystoreError>;

    /// Remove the key. Returns `true` if the handle was present.
    /// On Windows this unlinks the `.dpapi` + `.pub` sidecar files;
    /// on macOS / Linux it deletes the keychain item.
    fn delete(&self, handle: &KeyHandle) -> Result<bool, KeystoreError>;

    /// Enumerate all stored keys. Public-side only.
    fn list(&self) -> Result<Vec<StoredKey>, KeystoreError>;
}

/// JSON-friendly mirror of [`IdentityPublicKey`] for the `.pub`
/// sidecar file and for IPC. `IdentityPublicKey` itself doesn't
/// derive `Serialize` to keep the cryptographic types narrow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublicSidecar {
    pub(crate) version: u8,
    pub(crate) ml_dsa_pk_hex: String,
    pub(crate) ed25519_pk_hex: String,
    pub(crate) label: String,
    pub(crate) created_at_unix: u64,
}

impl PublicSidecar {
    pub(crate) const CURRENT_VERSION: u8 = 1;

    pub(crate) fn from_public(public: &IdentityPublicKey, label: &str, created_at: SystemTime) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            ml_dsa_pk_hex: hex::encode(&public.ml_dsa_pk),
            ed25519_pk_hex: hex::encode(public.ed25519_pk),
            label: label.to_string(),
            created_at_unix: created_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
        }
    }

    pub(crate) fn into_public(self) -> Result<(IdentityPublicKey, String, SystemTime), KeystoreError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(KeystoreError::MalformedBlob(format!(
                "sidecar version unsupported: got {}, want {}",
                self.version,
                Self::CURRENT_VERSION,
            )));
        }
        let ml_dsa_pk = hex::decode(&self.ml_dsa_pk_hex)
            .map_err(|e| KeystoreError::MalformedBlob(format!("ml_dsa_pk hex: {e}")))?;
        let ed_raw = hex::decode(&self.ed25519_pk_hex)
            .map_err(|e| KeystoreError::MalformedBlob(format!("ed25519_pk hex: {e}")))?;
        if ed_raw.len() != 32 {
            return Err(KeystoreError::MalformedBlob(format!(
                "ed25519_pk wrong length: got {}, want 32",
                ed_raw.len(),
            )));
        }
        let mut ed25519_pk = [0u8; 32];
        ed25519_pk.copy_from_slice(&ed_raw);
        let public = IdentityPublicKey {
            ml_dsa_pk,
            ed25519_pk,
        };
        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(self.created_at_unix);
        Ok((public, self.label, created_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_handle_round_trips_hex() {
        let handle = KeyHandle::random();
        let parsed = KeyHandle::from_hex(&handle.to_hex()).expect("parse");
        assert_eq!(handle, parsed);
    }

    #[test]
    fn key_handle_rejects_short_hex() {
        let err = KeyHandle::from_hex("aabb").expect_err("must reject");
        match err {
            KeystoreError::InvalidHandle(_) => {}
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn key_handle_rejects_non_hex() {
        let err = KeyHandle::from_hex("zz".repeat(16).as_str()).expect_err("must reject");
        match err {
            KeystoreError::InvalidHandle(_) => {}
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
