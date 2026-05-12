//! macOS [`Keystore`] backed by the login Keychain — M7 Phase G.2b.
//!
//! Identity secrets ride in the user's login Keychain as
//! generic-password items; public-key bundles live in a JSON
//! sidecar under `~/Library/Application Support/Lattice/keystore/
//! <handle>.pub`. The Keychain encrypts items at rest under the
//! user's login password (or, when a TouchID/Apple-Watch profile
//! is active, under a Secure-Enclave-bound wrap key).
//!
//! ## Secure-Enclave-bound wrap is Phase G.3+
//!
//! This impl ships **Keychain-stored secret bytes** — the same
//! shape as the Linux Secret Service path (`linux.rs`). Full
//! Secure-Enclave-bound ECDH wrapping (generate an SE-resident
//! P-256 key per identity, ECDH against an ephemeral userspace
//! key to derive a ChaCha20-Poly1305 wrap key, never let the
//! identity bytes touch unwrapped disk) is tracked as a Phase
//! G.3+ upgrade. The seam is internal to this module: the
//! [`Keystore`] trait surface doesn't change.
//!
//! ## API surface
//!
//! Uses `security_framework::passwords` for the generic-password
//! shape (`SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete`
//! under the hood). The high-level API doesn't expose
//! `kSecAttrAccessible`, so accessibility falls back to the
//! framework default (`AccessibleWhenUnlocked`). The G.3 upgrade
//! will switch to `SecAccessControl` with
//! `BiometryCurrentSet | PrivateKeyUsage` for SE-resident keys.

use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use lattice_crypto::identity::{HybridSignature, IdentityPublicKey, generate_identity, sign};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use tracing::{debug, instrument, warn};

use super::memory::{identity_secret_from_bytes, identity_secret_to_bytes};
use super::{KeyHandle, Keystore, KeystoreError, PublicSidecar, StoredKey};

const SIDECAR_SUFFIX: &str = "pub";

/// Keychain service identifier under which all Lattice identity
/// items are stored. The (service, account) pair is the primary
/// Keychain lookup key; the account is the per-identity hex
/// handle.
pub const KEYCHAIN_SERVICE: &str = "chat.lattice.identity.v1";

/// macOS Keychain-backed keystore.
#[derive(Debug)]
pub struct MacosKeystore {
    sidecar_dir: PathBuf,
}

impl MacosKeystore {
    /// Construct a keystore that holds sidecar files under
    /// `sidecar_dir`. Creates the directory if needed.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] if directory creation fails.
    pub fn new(sidecar_dir: impl Into<PathBuf>) -> Result<Self, KeystoreError> {
        let sidecar_dir = sidecar_dir.into();
        fs::create_dir_all(&sidecar_dir)?;
        debug!(?sidecar_dir, "MacosKeystore: ready");
        Ok(Self { sidecar_dir })
    }

    /// Convenience constructor pointing at `~/Library/Application
    /// Support/Lattice/keystore/`. Falls back to the current
    /// directory if `dirs::data_local_dir()` returns `None`.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] if directory creation fails.
    pub fn at_default_location() -> Result<Self, KeystoreError> {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        Self::new(base.join("Lattice").join("keystore"))
    }

    fn sidecar_path(&self, handle: &KeyHandle) -> PathBuf {
        self.sidecar_dir
            .join(format!("{}.{SIDECAR_SUFFIX}", handle.to_hex()))
    }

    fn read_sidecar(&self, handle: &KeyHandle) -> Result<StoredKey, KeystoreError> {
        let bytes = fs::read(self.sidecar_path(handle))?;
        let sidecar: PublicSidecar = serde_json::from_slice(&bytes)?;
        let (public, label, created_at) = sidecar.into_public()?;
        Ok(StoredKey {
            handle: *handle,
            public,
            label,
            created_at,
        })
    }
}

impl Keystore for MacosKeystore {
    #[instrument(level = "debug", skip(self), fields(label = %label))]
    fn generate(&self, label: &str) -> Result<StoredKey, KeystoreError> {
        let (public, secret) =
            generate_identity().map_err(|e| KeystoreError::Crypto(e.to_string()))?;
        let secret_bytes = identity_secret_to_bytes(&secret);
        let handle = KeyHandle::random();
        let created_at = SystemTime::now();

        set_generic_password(KEYCHAIN_SERVICE, &handle.to_hex(), &secret_bytes)
            .map_err(|e| KeystoreError::Seal {
                message: format!("set_generic_password: {e}"),
            })?;

        let sidecar = PublicSidecar::from_public(&public, label, created_at);
        let sidecar_json = serde_json::to_vec_pretty(&sidecar)?;
        fs::write(self.sidecar_path(&handle), sidecar_json)?;

        debug!(handle = %handle, "MacosKeystore: generated key");
        Ok(StoredKey {
            handle,
            public,
            created_at,
            label: label.to_string(),
        })
    }

    #[instrument(level = "debug", skip(self), fields(handle = %handle))]
    fn pubkey(&self, handle: &KeyHandle) -> Result<IdentityPublicKey, KeystoreError> {
        match self.read_sidecar(handle) {
            Ok(stored) => Ok(stored.public),
            Err(KeystoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(KeystoreError::NotFound { handle: *handle })
            }
            Err(other) => Err(other),
        }
    }

    #[instrument(level = "debug", skip(self, message), fields(handle = %handle, msg_len = message.len()))]
    fn sign(
        &self,
        handle: &KeyHandle,
        message: &[u8],
    ) -> Result<HybridSignature, KeystoreError> {
        let secret_bytes = match get_generic_password(KEYCHAIN_SERVICE, &handle.to_hex()) {
            Ok(bytes) => bytes,
            Err(e) => {
                // security-framework returns ErrorCode::ItemNotFound
                // (-25300) when the keychain entry is missing. Map
                // that explicitly; everything else is an Unseal
                // failure (locked keychain, ACL refusal, …).
                if e.code() == -25300 {
                    return Err(KeystoreError::NotFound { handle: *handle });
                }
                return Err(KeystoreError::Unseal {
                    message: format!("get_generic_password: {e}"),
                });
            }
        };
        let secret = identity_secret_from_bytes(&secret_bytes)?;
        sign(&secret, message).map_err(|e| KeystoreError::Crypto(e.to_string()))
    }

    #[instrument(level = "debug", skip(self), fields(handle = %handle))]
    fn delete(&self, handle: &KeyHandle) -> Result<bool, KeystoreError> {
        let kc_removed = match delete_generic_password(KEYCHAIN_SERVICE, &handle.to_hex()) {
            Ok(()) => true,
            Err(e) if e.code() == -25300 => false,
            Err(e) => {
                warn!(error = %e, "MacosKeystore: delete_generic_password failed");
                return Err(KeystoreError::Seal {
                    message: format!("delete_generic_password: {e}"),
                });
            }
        };
        let sidecar_removed = match fs::remove_file(self.sidecar_path(handle)) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(KeystoreError::Io(e)),
        };
        Ok(kc_removed || sidecar_removed)
    }

    #[instrument(level = "debug", skip(self))]
    fn list(&self) -> Result<Vec<StoredKey>, KeystoreError> {
        let mut entries: Vec<StoredKey> = Vec::new();
        for dirent in fs::read_dir(&self.sidecar_dir)? {
            let dirent = dirent?;
            let path = dirent.path();
            if path.extension().and_then(|e| e.to_str()) != Some(SIDECAR_SUFFIX) {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(handle) = KeyHandle::from_hex(stem) else {
                continue;
            };
            entries.push(self.read_sidecar(&handle)?);
        }
        entries.sort_by_key(|s| s.created_at);
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_keystore_constructs_without_panicking() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _ks = MacosKeystore::new(tmp.path()).expect("new");
    }

    // Functional tests against the real Keychain run only when
    // LATTICE_KC_TESTS=1 is set. CI / cross-platform builds skip.
    fn kc_tests_enabled() -> bool {
        std::env::var("LATTICE_KC_TESTS").is_ok()
    }

    #[test]
    fn macos_keystore_round_trip() {
        if !kc_tests_enabled() {
            eprintln!("skipping macos keystore round-trip (set LATTICE_KC_TESTS=1 to run)");
            return;
        }
        use lattice_crypto::identity::verify;
        let tmp = tempfile::tempdir().expect("tempdir");
        let ks = MacosKeystore::new(tmp.path()).expect("new");
        let stored = ks.generate("kc-round-trip").expect("generate");
        let msg = b"phase G.2b keychain round trip";
        let sig = ks.sign(&stored.handle, msg).expect("sign");
        verify(&stored.public, msg, &sig).expect("verify");
        assert!(ks.delete(&stored.handle).expect("delete"));
    }
}
