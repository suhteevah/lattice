//! # lattice-storage
//!
//! Encrypted local storage for Lattice clients.
//!
//! Exposes a [`Store`] trait with two implementations:
//!
//! - `WebStore` — IndexedDB-backed, used in the V1 browser client.
//! - `NativeStore` — SQLCipher-backed, used by V2 native shells.
//!
//! All values stored at rest are AEAD-encrypted under a key derived from
//! the user's passphrase via argon2id. The store API hides that detail and
//! presents a clean key/value interface to upper layers.
//!
//! ## Status
//!
//! Stub — see `docs/HANDOFF.md §6`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use tracing::instrument;

/// Storage backend trait. Implementations may live on different platforms.
#[allow(async_fn_in_trait)]
pub trait Store {
    /// Open or create a named bucket.
    async fn open(&mut self, bucket: &str) -> Result<(), Error>;

    /// Put a value at `key` in `bucket`. Overwrites silently.
    async fn put(&mut self, bucket: &str, key: &[u8], value: &[u8]) -> Result<(), Error>;

    /// Fetch a value. Returns `None` if absent.
    async fn get(&mut self, bucket: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// Delete a key. No-op if absent.
    async fn delete(&mut self, bucket: &str, key: &[u8]) -> Result<(), Error>;

    /// Wipe an entire bucket. Used during account-reset flows.
    async fn drop_bucket(&mut self, bucket: &str) -> Result<(), Error>;
}

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Backend-specific I/O failure.
    #[error("storage I/O: {0}")]
    Io(String),
    /// AEAD round-trip failed (corruption or wrong key).
    #[error("storage decrypt failure")]
    Decrypt,
    /// Operation propagated from `lattice-crypto`.
    #[error(transparent)]
    Crypto(#[from] lattice_crypto::Error),
}

/// Open a store appropriate for the current build target.
#[instrument(level = "info")]
pub async fn open_default() -> Result<impl Store, Error> {
    #[cfg(target_arch = "wasm32")]
    {
        tracing::info!("opening WebStore (IndexedDB)");
        unimplemented_store()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        tracing::info!("opening NativeStore (SQLCipher)");
        unimplemented_store()
    }
}

#[allow(dead_code)]
fn unimplemented_store() -> Result<UnimplementedStore, Error> {
    Ok(UnimplementedStore)
}

/// Placeholder until backends land. Returns `Io` for every call.
pub struct UnimplementedStore;

impl Store for UnimplementedStore {
    async fn open(&mut self, _bucket: &str) -> Result<(), Error> {
        Err(Error::Io("UnimplementedStore::open".into()))
    }
    async fn put(&mut self, _bucket: &str, _key: &[u8], _value: &[u8]) -> Result<(), Error> {
        Err(Error::Io("UnimplementedStore::put".into()))
    }
    async fn get(&mut self, _bucket: &str, _key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Err(Error::Io("UnimplementedStore::get".into()))
    }
    async fn delete(&mut self, _bucket: &str, _key: &[u8]) -> Result<(), Error> {
        Err(Error::Io("UnimplementedStore::delete".into()))
    }
    async fn drop_bucket(&mut self, _bucket: &str) -> Result<(), Error> {
        Err(Error::Io("UnimplementedStore::drop_bucket".into()))
    }
}
