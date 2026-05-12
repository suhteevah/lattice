//! Linux [`Keystore`] backed by the FreeDesktop Secret Service
//! (KDE Wallet / GNOME Keyring) — M7 Phase G.2a.
//!
//! Identity secrets ride in the OS-keychain vault under
//! `org.freedesktop.secrets`; public-key bundles live in a JSON
//! sidecar under `$XDG_DATA_HOME/Lattice/keystore/<handle>.pub`
//! (typically `~/.local/share/Lattice/keystore/`). The sidecar is
//! readable without unlocking the keyring, so `list()` and
//! `pubkey()` don't trigger D-Bus calls.
//!
//! ## Why Secret Service and not direct TPM
//!
//! Not every Linux desktop has a TPM 2.0 chip wired into the kernel
//! (server distros, older laptops, virtualized environments). The
//! `secret-service` D-Bus API is the standardized cross-DE escape
//! hatch: GNOME Keyring and KWallet both implement it, and items
//! are wrapped under the user's session credentials (typically an
//! Argon2id-derived key from the login password, or the TPM if the
//! user has enrolled a hardware-backed login profile).
//!
//! A direct TPM 2.0 path via `tss-esapi` is tracked as Phase G.3+
//! for users who have a TPM available; the seam to attach it is
//! the same `Keystore` trait this impl satisfies.
//!
//! ## Async runtime
//!
//! `secret-service` v4 is async-first. We own a dedicated single-
//! threaded `tokio::runtime::Runtime` so the [`Keystore`] trait
//! stays sync. Construction creates the runtime once; each call
//! is `block_on`'d against it.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use lattice_crypto::identity::{HybridSignature, IdentityPublicKey, generate_identity, sign};
use secret_service::{EncryptionType, SecretService};
use tokio::runtime::Runtime;
use tracing::{debug, instrument, warn};

use super::memory::{identity_secret_from_bytes, identity_secret_to_bytes};
use super::{KeyHandle, Keystore, KeystoreError, PublicSidecar, StoredKey};

const SIDECAR_SUFFIX: &str = "pub";
const ATTR_HANDLE: &str = "lattice-handle";
const ATTR_VERSION: &str = "lattice-version";
const ATTR_APP: &str = "xdg:schema";
const ATTR_APP_VALUE: &str = "chat.lattice.identity.v1";
const ITEM_VERSION: &str = "1";
const CONTENT_TYPE: &str = "application/octet-stream";

/// Linux Secret-Service-backed keystore.
pub struct LinuxKeystore {
    sidecar_dir: PathBuf,
    // Held inside a Mutex so the trait stays `Sync`. The runtime
    // itself is `Send + Sync`, but we sometimes need exclusive
    // access (e.g. shutdown) and the Mutex makes that explicit.
    runtime: Mutex<Runtime>,
}

impl std::fmt::Debug for LinuxKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxKeystore")
            .field("sidecar_dir", &self.sidecar_dir)
            .finish_non_exhaustive()
    }
}

impl LinuxKeystore {
    /// Construct a keystore that holds sidecar files under `sidecar_dir`
    /// and stores secret material in the default Secret Service
    /// collection. Creates the sidecar directory if needed.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] if directory creation fails or
    /// the dedicated tokio runtime cannot be built.
    pub fn new(sidecar_dir: impl Into<PathBuf>) -> Result<Self, KeystoreError> {
        let sidecar_dir = sidecar_dir.into();
        fs::create_dir_all(&sidecar_dir)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(KeystoreError::Io)?;
        debug!(?sidecar_dir, "LinuxKeystore: ready");
        Ok(Self {
            sidecar_dir,
            runtime: Mutex::new(runtime),
        })
    }

    /// Convenience constructor pointing at `$XDG_DATA_HOME/Lattice/
    /// keystore/`. Falls back to the current working directory if
    /// `dirs::data_local_dir()` returns `None`.
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

    fn attributes_for(handle: &KeyHandle) -> HashMap<String, String> {
        HashMap::from([
            (ATTR_HANDLE.to_string(), handle.to_hex()),
            (ATTR_VERSION.to_string(), ITEM_VERSION.to_string()),
            (ATTR_APP.to_string(), ATTR_APP_VALUE.to_string()),
        ])
    }

    fn run<F, R>(&self, f: F) -> Result<R, KeystoreError>
    where
        F: std::future::Future<Output = Result<R, KeystoreError>>,
    {
        let guard = self
            .runtime
            .lock()
            .map_err(|_| KeystoreError::Seal {
                message: "tokio runtime mutex poisoned".to_string(),
            })?;
        guard.block_on(f)
    }
}

impl Keystore for LinuxKeystore {
    #[instrument(level = "debug", skip(self), fields(label = %label))]
    fn generate(&self, label: &str) -> Result<StoredKey, KeystoreError> {
        let (public, secret) =
            generate_identity().map_err(|e| KeystoreError::Crypto(e.to_string()))?;
        let secret_bytes = identity_secret_to_bytes(&secret);
        let handle = KeyHandle::random();
        let created_at = SystemTime::now();

        let item_label = format!("Lattice identity ({label})");
        let attributes = Self::attributes_for(&handle);
        let attr_refs: HashMap<&str, &str> =
            attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let secret_slice = secret_bytes.as_slice().to_vec();

        self.run(async {
            let ss = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(|e| KeystoreError::Seal {
                    message: format!("SecretService::connect: {e}"),
                })?;
            let collection =
                ss.get_default_collection()
                    .await
                    .map_err(|e| KeystoreError::Seal {
                        message: format!("get_default_collection: {e}"),
                    })?;
            // `replace = false` so a hash collision (extremely
            // unlikely with 16 random bytes) is surfaced as an
            // error rather than silently overwriting an existing
            // identity.
            collection
                .create_item(
                    &item_label,
                    attr_refs,
                    &secret_slice,
                    false,
                    CONTENT_TYPE,
                )
                .await
                .map_err(|e| KeystoreError::Seal {
                    message: format!("create_item: {e}"),
                })?;
            Ok(())
        })?;

        let sidecar = PublicSidecar::from_public(&public, label, created_at);
        let sidecar_json = serde_json::to_vec_pretty(&sidecar)?;
        fs::write(self.sidecar_path(&handle), sidecar_json)?;

        debug!(handle = %handle, "LinuxKeystore: generated key");
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
        let attributes = Self::attributes_for(handle);
        let attr_refs: HashMap<&str, &str> =
            attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let handle_copy = *handle;
        let secret_bytes = self.run(async {
            let ss = SecretService::connect(EncryptionType::Dh).await.map_err(|e| {
                KeystoreError::Unseal {
                    message: format!("SecretService::connect: {e}"),
                }
            })?;
            let items =
                ss.search_items(attr_refs)
                    .await
                    .map_err(|e| KeystoreError::Unseal {
                        message: format!("search_items: {e}"),
                    })?;
            let item = items
                .unlocked
                .first()
                .or_else(|| items.locked.first())
                .ok_or(KeystoreError::NotFound { handle: handle_copy })?;
            item.unlock().await.map_err(|e| KeystoreError::Unseal {
                message: format!("unlock: {e}"),
            })?;
            let bytes = item.get_secret().await.map_err(|e| KeystoreError::Unseal {
                message: format!("get_secret: {e}"),
            })?;
            Ok::<Vec<u8>, KeystoreError>(bytes)
        })?;
        let secret = identity_secret_from_bytes(&secret_bytes)?;
        sign(&secret, message).map_err(|e| KeystoreError::Crypto(e.to_string()))
    }

    #[instrument(level = "debug", skip(self), fields(handle = %handle))]
    fn delete(&self, handle: &KeyHandle) -> Result<bool, KeystoreError> {
        let attributes = Self::attributes_for(handle);
        let attr_refs: HashMap<&str, &str> =
            attributes.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let handle_copy = *handle;
        let ss_deleted = self.run(async {
            let ss = SecretService::connect(EncryptionType::Dh).await.map_err(|e| {
                KeystoreError::Seal {
                    message: format!("SecretService::connect: {e}"),
                }
            })?;
            let items =
                ss.search_items(attr_refs)
                    .await
                    .map_err(|e| KeystoreError::Seal {
                        message: format!("search_items: {e}"),
                    })?;
            let mut deleted = false;
            for item in items.unlocked.iter().chain(items.locked.iter()) {
                item.delete().await.map_err(|e| KeystoreError::Seal {
                    message: format!("delete: {e}"),
                })?;
                deleted = true;
            }
            let _ = handle_copy; // referenced for tracing context
            Ok::<bool, KeystoreError>(deleted)
        })?;
        let sidecar_removed = match fs::remove_file(self.sidecar_path(handle)) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                warn!(error = %e, "LinuxKeystore: sidecar remove failed (SS item already removed)");
                return Err(KeystoreError::Io(e));
            }
        };
        Ok(ss_deleted || sidecar_removed)
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
    fn linux_keystore_constructs_without_panicking() {
        // Pure construction test — no SS calls. Useful in CI on
        // hosts without a running keyring daemon.
        let tmp = tempfile::tempdir().expect("tempdir");
        let _ks = LinuxKeystore::new(tmp.path()).expect("new");
    }

    // Functional Secret Service tests run only when LATTICE_SS_TESTS=1
    // is set and a Secret Service daemon (GNOME Keyring, KWallet, or
    // a CI-provisioned gnome-keyring-daemon --unlock) is reachable on
    // the session bus. This matches the LATTICE_NET_TESTS pattern.
    fn ss_tests_enabled() -> bool {
        std::env::var("LATTICE_SS_TESTS").is_ok()
    }

    #[test]
    fn linux_keystore_round_trip() {
        if !ss_tests_enabled() {
            eprintln!("skipping linux keystore round-trip (set LATTICE_SS_TESTS=1 to run)");
            return;
        }
        use lattice_crypto::identity::verify;
        let tmp = tempfile::tempdir().expect("tempdir");
        let ks = LinuxKeystore::new(tmp.path()).expect("new");
        let stored = ks.generate("ss-round-trip").expect("generate");
        let msg = b"phase G.2a secret service round trip";
        let sig = ks.sign(&stored.handle, msg).expect("sign");
        verify(&stored.public, msg, &sig).expect("verify");
        assert!(ks.delete(&stored.handle).expect("delete"));
    }
}
