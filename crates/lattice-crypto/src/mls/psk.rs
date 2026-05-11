//! Per-epoch external PSK derivation and storage for Lattice's hybrid
//! MLS construction.
//!
//! Per the D-04 2026-05-10 re-open, the ML-KEM-768 shared secret that
//! gives Lattice's MLS suite its PQ property is folded into the key
//! schedule via the standard MLS PreSharedKey mechanism rather than via
//! a private `init_secret` rewrite (mls-rs has no public hook for that).
//!
//! The committer encapsulates a fresh ML-KEM-768 secret per epoch and
//! stores it under a deterministic [`ExternalPskId`] computed from the
//! upcoming epoch number. Joiners and existing members decapsulate the
//! same secret (transmitted via a Welcome extension for joiners, derived
//! from the X25519 path for existing members) and write it to their own
//! local storage under the same id. mls-rs's commit path then injects
//! the secret into the key schedule via
//! `Extract(joiner_secret, psk_secret)` — exactly the hybrid binding
//! point described in D-04.
//!
//! ## ID format
//!
//! ```text
//! psk_id_for_epoch(epoch) = HKDF_MLS_INIT_PREFIX || epoch.to_le_bytes()
//!                        = b"lattice/mls-init/v1" || epoch.to_le_bytes()
//! ```
//!
//! Little-endian on the epoch is arbitrary but pinned — both sides must
//! derive identical bytes. Eight bytes is a `u64` epoch counter, which
//! matches mls-rs's `GroupContext::epoch` type.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use mls_rs_core::psk::{ExternalPskId, PreSharedKey, PreSharedKeyStorage};

use crate::constants::HKDF_MLS_INIT;

/// Compute the deterministic [`ExternalPskId`] for a given MLS epoch.
///
/// Both the committer and the joiner derive identical bytes from the
/// epoch number, so PSK lookup at `Group::process_incoming_message`
/// time succeeds deterministically given that both sides have stored
/// the secret under the same id.
#[must_use]
pub fn psk_id_for_epoch(epoch: u64) -> ExternalPskId {
    let mut id = Vec::with_capacity(HKDF_MLS_INIT.len() + 8);
    id.extend_from_slice(HKDF_MLS_INIT);
    id.extend_from_slice(&epoch.to_le_bytes());
    ExternalPskId::new(id)
}

/// In-memory [`PreSharedKeyStorage`] suitable for tests and short-lived
/// CLI processes.
///
/// Production use (server-side groups that persist across restarts) wants
/// a sqlx-backed impl; that lands in M3 alongside the rest of the
/// server-side storage providers. The trait is straightforward enough
/// that the in-memory impl is a 30-line reference implementation.
///
/// Internally a `HashMap<ExternalPskId, Zeroizing<Vec<u8>>>` behind an
/// `Arc<Mutex<_>>` so `Clone` shares state — matches the mls-rs
/// `InMemoryKeyPackageStorage` ergonomic.
#[derive(Clone, Debug, Default)]
pub struct LatticePskStorage {
    inner: Arc<Mutex<HashMap<ExternalPskId, PreSharedKey>>>,
}

impl LatticePskStorage {
    /// Construct an empty storage.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a PSK under the given id. Overwrites any existing entry
    /// silently — callers must avoid id collisions (the deterministic
    /// per-epoch derivation prevents this in normal use).
    ///
    /// # Errors
    ///
    /// Returns [`LatticePskStorageError::Poisoned`] if the internal mutex
    /// was poisoned by a panic in another thread.
    pub fn insert(
        &self,
        id: ExternalPskId,
        psk: PreSharedKey,
    ) -> Result<(), LatticePskStorageError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| LatticePskStorageError::Poisoned)?;
        guard.insert(id, psk);
        Ok(())
    }

    /// Remove a PSK if present (used by epoch-rotation cleanup).
    ///
    /// # Errors
    ///
    /// Returns [`LatticePskStorageError::Poisoned`] if the internal mutex
    /// was poisoned by a panic in another thread.
    pub fn remove(&self, id: &ExternalPskId) -> Result<(), LatticePskStorageError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| LatticePskStorageError::Poisoned)?;
        guard.remove(id);
        Ok(())
    }

    /// Return the number of stored entries.
    ///
    /// # Errors
    ///
    /// Returns [`LatticePskStorageError::Poisoned`] if the internal mutex
    /// was poisoned by a panic in another thread.
    pub fn len(&self) -> Result<usize, LatticePskStorageError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| LatticePskStorageError::Poisoned)?;
        Ok(guard.len())
    }
}

impl PreSharedKeyStorage for LatticePskStorage {
    type Error = LatticePskStorageError;

    fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| LatticePskStorageError::Poisoned)?;
        Ok(guard.get(id).cloned())
    }
}

/// Errors raised by [`LatticePskStorage`].
#[derive(Debug, thiserror::Error)]
pub enum LatticePskStorageError {
    /// Internal mutex poisoned by a panicking thread.
    #[error("PSK storage mutex was poisoned by a panicking thread")]
    Poisoned,
}

impl mls_rs_core::error::IntoAnyError for LatticePskStorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_id_format_is_deterministic() {
        let a = psk_id_for_epoch(42);
        let b = psk_id_for_epoch(42);
        assert_eq!(a, b);
    }

    #[test]
    fn psk_id_differs_per_epoch() {
        assert_ne!(psk_id_for_epoch(0), psk_id_for_epoch(1));
        assert_ne!(psk_id_for_epoch(1), psk_id_for_epoch(2));
    }

    #[test]
    fn psk_id_layout_matches_spec() {
        let id = psk_id_for_epoch(0x0102_0304_0506_0708);
        let bytes: &[u8] = id.as_ref();
        // Prefix + 8 bytes of little-endian epoch.
        assert_eq!(&bytes[..HKDF_MLS_INIT.len()], HKDF_MLS_INIT);
        assert_eq!(
            &bytes[HKDF_MLS_INIT.len()..],
            &0x0102_0304_0506_0708_u64.to_le_bytes(),
        );
    }

    #[test]
    fn psk_id_epoch_zero_terminates_in_zero_bytes() {
        // Sanity check: the epoch counter is suffixed verbatim and zero is
        // a valid epoch (the first group context epoch is 0).
        let id = psk_id_for_epoch(0);
        let bytes: &[u8] = id.as_ref();
        assert_eq!(&bytes[HKDF_MLS_INIT.len()..], &[0u8; 8]);
    }

    #[test]
    fn storage_round_trip() {
        let storage = LatticePskStorage::new();
        let id = psk_id_for_epoch(7);
        let psk = PreSharedKey::new(vec![0xAA; 32]);
        storage.insert(id.clone(), psk.clone()).expect("insert");

        let fetched = storage.get(&id).expect("get").expect("present");
        assert_eq!(fetched.raw_value(), psk.raw_value());
        assert_eq!(storage.len().expect("len"), 1);
    }

    #[test]
    fn storage_missing_id_returns_none() {
        let storage = LatticePskStorage::new();
        let missing = psk_id_for_epoch(99);
        assert!(storage.get(&missing).expect("get").is_none());
    }

    #[test]
    fn storage_remove_drops_entry() {
        let storage = LatticePskStorage::new();
        let id = psk_id_for_epoch(7);
        storage
            .insert(id.clone(), PreSharedKey::new(vec![0; 32]))
            .expect("insert");
        storage.remove(&id).expect("remove");
        assert!(storage.get(&id).expect("get").is_none());
        assert_eq!(storage.len().expect("len"), 0);
    }

    #[test]
    fn storage_clone_shares_state() {
        let a = LatticePskStorage::new();
        let b = a.clone();
        let id = psk_id_for_epoch(13);
        a.insert(id.clone(), PreSharedKey::new(vec![0xBB; 32]))
            .expect("insert");
        // The clone observes the same underlying map.
        assert!(b.get(&id).expect("get").is_some());
    }

    #[test]
    fn storage_overwrites_existing_id() {
        let storage = LatticePskStorage::new();
        let id = psk_id_for_epoch(7);
        storage
            .insert(id.clone(), PreSharedKey::new(vec![0xAA; 32]))
            .expect("first");
        storage
            .insert(id.clone(), PreSharedKey::new(vec![0xBB; 32]))
            .expect("overwrite");
        let fetched = storage.get(&id).expect("get").expect("present");
        assert_eq!(fetched.raw_value(), &[0xBB; 32][..]);
    }
}
