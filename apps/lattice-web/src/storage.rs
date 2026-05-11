//! localStorage-backed implementations of the mls-rs storage traits
//! (Phase δ.3).
//!
//! Together with the new generic parameter on
//! `lattice_crypto::mls::LatticeMlsConfig<G>`, this module lets the
//! browser client survive page reloads: MLS group state lands in
//! `localStorage` under a Lattice-namespaced key tree and reloads via
//! `mls_rs::Client::load_group(group_id)`.
//!
//! ## Storage key layout
//!
//! ```text
//! lattice/mls/group/{group_id_b64url}/state     → state.data (b64 std)
//! lattice/mls/group/{group_id_b64url}/epoch/{n} → epoch.data (b64 std)
//! lattice/mls/group/{group_id_b64url}/max_epoch → max epoch_id (u64 decimal)
//! lattice/mls/groups                            → JSON array of group ids
//! ```
//!
//! ## Send + Sync
//!
//! `web_sys::Storage` is not `Send + Sync`, but the storage providers
//! are required to be both. We sidestep that by making the structs
//! *empty markers* — every method re-fetches `window.localStorage`
//! locally rather than caching a handle. The structs hold nothing,
//! so they trivially satisfy `Send + Sync` (and `Clone` + `Default`,
//! which mls-rs's `Client::builder` needs).

use std::convert::Infallible;

use base64::Engine;
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use zeroize::Zeroizing;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Marker struct implementing
/// [`mls_rs_core::group::GroupStateStorage`] against
/// `window.localStorage`. See module docs for the key layout.
#[derive(Clone, Default, Debug)]
pub struct LocalStorageGroupStateStorage;

/// Failure surface for [`LocalStorageGroupStateStorage`]. mls-rs maps
/// this through `IntoAnyError` so the inner string text shows up in
/// `MlsError::GroupStorageError` messages.
#[derive(Debug, Clone)]
pub struct LocalStorageError(pub String);

impl core::fmt::Display for LocalStorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "localStorage error: {}", self.0)
    }
}

impl std::error::Error for LocalStorageError {}

impl IntoAnyError for LocalStorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl From<String> for LocalStorageError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<Infallible> for LocalStorageError {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl GroupStateStorage for LocalStorageGroupStateStorage {
    type Error = LocalStorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        match get_item(&state_key(group_id))? {
            None => Ok(None),
            Some(b64) => {
                let bytes = B64
                    .decode(&b64)
                    .map_err(|e| LocalStorageError(format!("state decode: {e}")))?;
                Ok(Some(Zeroizing::new(bytes)))
            }
        }
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        match get_item(&epoch_key(group_id, epoch_id))? {
            None => Ok(None),
            Some(b64) => {
                let bytes = B64
                    .decode(&b64)
                    .map_err(|e| LocalStorageError(format!("epoch decode: {e}")))?;
                Ok(Some(Zeroizing::new(bytes)))
            }
        }
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let storage = local_storage()?;

        // 1. Write the current state snapshot.
        let state_key = state_key(&state.id);
        storage
            .set_item(&state_key, &B64.encode(&state.data[..]))
            .map_err(|e| LocalStorageError(format!("set state: {e:?}")))?;

        // 2. Insert + update epoch records. Updates overwrite by id.
        let mut max_existing = read_max_epoch(&state.id)?;
        for ep in epoch_inserts.into_iter().chain(epoch_updates.into_iter()) {
            storage
                .set_item(&epoch_key(&state.id, ep.id), &B64.encode(&ep.data[..]))
                .map_err(|e| LocalStorageError(format!("set epoch {}: {e:?}", ep.id)))?;
            if max_existing.map_or(true, |m| ep.id > m) {
                max_existing = Some(ep.id);
            }
        }
        if let Some(m) = max_existing {
            storage
                .set_item(&max_epoch_key(&state.id), &m.to_string())
                .map_err(|e| LocalStorageError(format!("set max_epoch: {e:?}")))?;
        }

        // 3. Register the group_id in the group index so callers can
        //    enumerate without scanning every key.
        index_add_group(&state.id)?;
        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        read_max_epoch(group_id)
    }
}

impl LocalStorageGroupStateStorage {
    /// Drop every stored record for `group_id`. Useful when the UI
    /// clears identity / resets state.
    ///
    /// # Errors
    ///
    /// Bubbles up localStorage access failures.
    pub fn delete_group(&self, group_id: &[u8]) -> Result<(), LocalStorageError> {
        let storage = local_storage()?;
        let _ = storage.remove_item(&state_key(group_id));
        let _ = storage.remove_item(&max_epoch_key(group_id));
        // We don't know how many epochs were stored without scanning
        // — drop a wide range (max_epoch + 100) which covers any
        // plausible session.
        if let Some(max) = read_max_epoch(group_id)? {
            for id in 0..=max.saturating_add(100) {
                let _ = storage.remove_item(&epoch_key(group_id, id));
            }
        }
        index_remove_group(group_id)?;
        Ok(())
    }

    /// Enumerate every group id currently in the index. Useful for UI
    /// rosters / debugging.
    ///
    /// # Errors
    ///
    /// Bubbles up localStorage access failures.
    pub fn stored_groups(&self) -> Result<Vec<Vec<u8>>, LocalStorageError> {
        let raw = get_item(INDEX_KEY)?;
        let Some(json) = raw else {
            return Ok(Vec::new());
        };
        let entries: Vec<String> =
            serde_json::from_str(&json).map_err(|e| LocalStorageError(format!("index decode: {e}")))?;
        entries
            .into_iter()
            .map(|s| {
                B64URL
                    .decode(s.as_bytes())
                    .map_err(|e| LocalStorageError(format!("index entry decode: {e}")))
            })
            .collect()
    }
}

// === Internal helpers ===

const INDEX_KEY: &str = "lattice/mls/groups";

fn state_key(group_id: &[u8]) -> String {
    format!("lattice/mls/group/{}/state", B64URL.encode(group_id))
}

fn epoch_key(group_id: &[u8], epoch_id: u64) -> String {
    format!(
        "lattice/mls/group/{}/epoch/{epoch_id}",
        B64URL.encode(group_id)
    )
}

fn max_epoch_key(group_id: &[u8]) -> String {
    format!("lattice/mls/group/{}/max_epoch", B64URL.encode(group_id))
}

fn local_storage() -> Result<web_sys::Storage, LocalStorageError> {
    let window = web_sys::window().ok_or_else(|| LocalStorageError("no window".to_string()))?;
    window
        .local_storage()
        .map_err(|e| LocalStorageError(format!("window.localStorage: {e:?}")))?
        .ok_or_else(|| LocalStorageError("localStorage unavailable".to_string()))
}

fn get_item(key: &str) -> Result<Option<String>, LocalStorageError> {
    let storage = local_storage()?;
    storage
        .get_item(key)
        .map_err(|e| LocalStorageError(format!("get {key}: {e:?}")))
}

fn read_max_epoch(group_id: &[u8]) -> Result<Option<u64>, LocalStorageError> {
    match get_item(&max_epoch_key(group_id))? {
        None => Ok(None),
        Some(s) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|e| LocalStorageError(format!("parse max_epoch: {e}"))),
    }
}

fn index_add_group(group_id: &[u8]) -> Result<(), LocalStorageError> {
    let storage = local_storage()?;
    let existing: Vec<String> = match storage
        .get_item(INDEX_KEY)
        .map_err(|e| LocalStorageError(format!("read index: {e:?}")))?
    {
        Some(json) => {
            serde_json::from_str(&json).unwrap_or_default()
        }
        None => Vec::new(),
    };
    let id_b64 = B64URL.encode(group_id);
    if existing.iter().any(|s| s == &id_b64) {
        return Ok(());
    }
    let mut updated = existing;
    updated.push(id_b64);
    let json = serde_json::to_string(&updated)
        .map_err(|e| LocalStorageError(format!("encode index: {e}")))?;
    storage
        .set_item(INDEX_KEY, &json)
        .map_err(|e| LocalStorageError(format!("set index: {e:?}")))?;
    Ok(())
}

fn index_remove_group(group_id: &[u8]) -> Result<(), LocalStorageError> {
    let storage = local_storage()?;
    let Some(json) = storage
        .get_item(INDEX_KEY)
        .map_err(|e| LocalStorageError(format!("read index: {e:?}")))?
    else {
        return Ok(());
    };
    let mut existing: Vec<String> = serde_json::from_str(&json).unwrap_or_default();
    let id_b64 = B64URL.encode(group_id);
    existing.retain(|s| s != &id_b64);
    let json = serde_json::to_string(&existing)
        .map_err(|e| LocalStorageError(format!("encode index: {e}")))?;
    storage
        .set_item(INDEX_KEY, &json)
        .map_err(|e| LocalStorageError(format!("set index: {e:?}")))?;
    Ok(())
}
