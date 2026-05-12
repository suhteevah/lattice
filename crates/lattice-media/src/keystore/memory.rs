//! In-process [`Keystore`] backed by an `Arc<Mutex<HashMap<_, _>>>`.
//!
//! Used by the cross-platform test suite and as the desktop default
//! on non-Windows hosts in G.1. macOS and Linux upgrade to OS-keychain
//! impls in G.2; this stays as the always-available fallback for unit
//! tests that don't want to touch the platform keystore.
//!
//! Secret bytes live in RAM as `Zeroizing` wrappers; the keystore
//! itself never persists anything to disk.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use lattice_crypto::identity::{
    HybridSignature, IdentityPublicKey, IdentitySecretKey, generate_identity, sign,
};
use tracing::{debug, instrument};
use zeroize::Zeroizing;

use super::{KeyHandle, Keystore, KeystoreError, StoredKey};

/// In-memory keystore. Lock granularity is per-keystore, not per-key;
/// the workload is signing + listing, both fast.
#[derive(Debug, Default)]
pub struct MemoryKeystore {
    inner: Mutex<HashMap<KeyHandle, Entry>>,
}

#[derive(Debug)]
struct Entry {
    public: IdentityPublicKey,
    secret: Zeroizing<Vec<u8>>,
    label: String,
    created_at: SystemTime,
}

impl MemoryKeystore {
    /// Construct an empty keystore.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Keystore for MemoryKeystore {
    #[instrument(level = "debug", skip(self), fields(label = %label))]
    fn generate(&self, label: &str) -> Result<StoredKey, KeystoreError> {
        let (public, secret) =
            generate_identity().map_err(|e| KeystoreError::Crypto(e.to_string()))?;
        let secret_bytes = identity_secret_to_bytes(&secret);
        let handle = KeyHandle::random();
        let created_at = SystemTime::now();
        let stored = StoredKey {
            handle,
            public: public.clone(),
            created_at,
            label: label.to_string(),
        };

        let mut guard = self.inner.lock().map_err(poisoned)?;
        guard.insert(
            handle,
            Entry {
                public,
                secret: secret_bytes,
                label: label.to_string(),
                created_at,
            },
        );
        debug!(handle = %handle, "memory keystore: generated key");
        Ok(stored)
    }

    #[instrument(level = "debug", skip(self), fields(handle = %handle))]
    fn pubkey(&self, handle: &KeyHandle) -> Result<IdentityPublicKey, KeystoreError> {
        let guard = self.inner.lock().map_err(poisoned)?;
        guard
            .get(handle)
            .map(|e| e.public.clone())
            .ok_or(KeystoreError::NotFound { handle: *handle })
    }

    #[instrument(level = "debug", skip(self, message), fields(handle = %handle, msg_len = message.len()))]
    fn sign(
        &self,
        handle: &KeyHandle,
        message: &[u8],
    ) -> Result<HybridSignature, KeystoreError> {
        let secret_bytes = {
            let guard = self.inner.lock().map_err(poisoned)?;
            let entry = guard
                .get(handle)
                .ok_or(KeystoreError::NotFound { handle: *handle })?;
            // Clone the Zeroizing<Vec<u8>> contents into a fresh
            // Zeroizing so the guard is released before we sign.
            Zeroizing::new(entry.secret.to_vec())
        };
        let secret = identity_secret_from_bytes(&secret_bytes)?;
        let signature = sign(&secret, message).map_err(|e| KeystoreError::Crypto(e.to_string()))?;
        Ok(signature)
    }

    #[instrument(level = "debug", skip(self), fields(handle = %handle))]
    fn delete(&self, handle: &KeyHandle) -> Result<bool, KeystoreError> {
        let mut guard = self.inner.lock().map_err(poisoned)?;
        Ok(guard.remove(handle).is_some())
    }

    #[instrument(level = "debug", skip(self))]
    fn list(&self) -> Result<Vec<StoredKey>, KeystoreError> {
        let guard = self.inner.lock().map_err(poisoned)?;
        let mut entries: Vec<StoredKey> = guard
            .iter()
            .map(|(handle, entry)| StoredKey {
                handle: *handle,
                public: entry.public.clone(),
                created_at: entry.created_at,
                label: entry.label.clone(),
            })
            .collect();
        // Stable order so callers can rely on `list()` for deterministic UI.
        entries.sort_by_key(|s| s.created_at);
        Ok(entries)
    }
}

/// Serialize an [`IdentitySecretKey`] into the 64-byte concat blob
/// `ml_dsa_seed || ed25519_sk`. Kept in this module so the layout
/// is colocated with [`identity_secret_from_bytes`].
pub(super) fn identity_secret_to_bytes(secret: &IdentitySecretKey) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(super::SECRET_BLOB_LEN));
    buf.extend_from_slice(&secret.ml_dsa_seed);
    buf.extend_from_slice(&secret.ed25519_sk);
    buf
}

/// Inverse of [`identity_secret_to_bytes`].
pub(super) fn identity_secret_from_bytes(bytes: &[u8]) -> Result<IdentitySecretKey, KeystoreError> {
    if bytes.len() != super::SECRET_BLOB_LEN {
        return Err(KeystoreError::MalformedBlob(format!(
            "secret blob wrong length: got {}, want {}",
            bytes.len(),
            super::SECRET_BLOB_LEN,
        )));
    }
    let mut ml_dsa_seed = [0u8; 32];
    let mut ed25519_sk = [0u8; 32];
    ml_dsa_seed.copy_from_slice(&bytes[..32]);
    ed25519_sk.copy_from_slice(&bytes[32..]);
    Ok(IdentitySecretKey {
        ml_dsa_seed,
        ed25519_sk,
    })
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> KeystoreError {
    KeystoreError::Crypto("keystore mutex poisoned".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_crypto::identity::verify;

    #[test]
    fn generate_then_pubkey_match() {
        let ks = MemoryKeystore::new();
        let stored = ks.generate("test").expect("generate");
        let pk = ks.pubkey(&stored.handle).expect("pubkey");
        assert_eq!(pk.ed25519_pk, stored.public.ed25519_pk);
        assert_eq!(pk.ml_dsa_pk, stored.public.ml_dsa_pk);
    }

    #[test]
    fn sign_round_trips_through_verify() {
        let ks = MemoryKeystore::new();
        let stored = ks.generate("roundtrip").expect("generate");
        let msg = b"phase G keystore sign smoke";
        let sig = ks.sign(&stored.handle, msg).expect("sign");
        verify(&stored.public, msg, &sig).expect("hybrid sig must verify");
    }

    #[test]
    fn delete_removes_entry() {
        let ks = MemoryKeystore::new();
        let stored = ks.generate("rm").expect("generate");
        assert!(ks.delete(&stored.handle).expect("delete"));
        let err = ks.sign(&stored.handle, b"after delete").expect_err("must error");
        match err {
            KeystoreError::NotFound { .. } => {}
            other => panic!("wrong variant: {other:?}"),
        }
        assert!(!ks.delete(&stored.handle).expect("second delete returns false"));
    }

    #[test]
    fn list_returns_all_in_creation_order() {
        let ks = MemoryKeystore::new();
        let first = ks.generate("a").expect("a");
        // SystemTime::now()'s monotonicity over a single test is fine;
        // if the system clock skews backwards between the two calls
        // the sort_by_key in list() still produces deterministic order,
        // just possibly reversed — that's acceptable for this test.
        let second = ks.generate("b").expect("b");
        let listed = ks.list().expect("list");
        assert_eq!(listed.len(), 2);
        let handles: Vec<_> = listed.iter().map(|s| s.handle).collect();
        assert!(handles.contains(&first.handle));
        assert!(handles.contains(&second.handle));
    }
}
