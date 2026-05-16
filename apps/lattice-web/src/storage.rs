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
//! lattice/mls/kp/{kp_id_b64url}                 → MLS-codec KeyPackageData (b64 std)
//! lattice/mls/kp_ids                            → JSON array of KP ids
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

// ────────────────────────────────────────────────────────────────
// KeyPackage shadow-persistence
// ────────────────────────────────────────────────────────────────
//
// `lattice_crypto::mls::build_client` hardcodes `key_package_repo`
// to `InMemoryKeyPackageStorage` (the type lives on `LatticeIdentity`).
// Rather than refactor lattice-crypto to generalize that, we
// shadow-sync the in-memory storage to / from localStorage from
// the browser side:
//
// - After every `generate_key_package` call, `sync_kp_repo_to_storage`
//   enumerates the in-memory entries and writes any new ones.
// - On boot, `restore_kp_repo_from_storage` reads localStorage and
//   inserts each entry into a fresh in-memory storage so
//   `process_welcome` can find the matching private leaf init keys.
//
// Each `KeyPackageData` is serialized via mls-rs-codec, base64'd,
// and stored under `lattice/mls/kp/{kp_id_b64url}`. The list of
// known KP ids lives at `lattice/mls/kp_ids` so we can restore
// without scanning every localStorage key.

use mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::key_package::KeyPackageData;
use mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage;

const KP_INDEX_KEY: &str = "lattice/mls/kp_ids";

fn kp_key(id: &[u8]) -> String {
    format!("lattice/mls/kp/{}", B64URL.encode(id))
}

/// Write any in-memory KeyPackage entries that aren't yet persisted
/// to localStorage.
///
/// # Errors
///
/// Bubbles up localStorage write failures or MLS-codec encoding
/// errors.
pub fn sync_kp_repo_to_storage(
    repo: &InMemoryKeyPackageStorage,
) -> Result<(), LocalStorageError> {
    let storage = local_storage()?;
    let mut index: Vec<String> = match storage
        .get_item(KP_INDEX_KEY)
        .map_err(|e| LocalStorageError(format!("read kp_ids: {e:?}")))?
    {
        Some(json) => serde_json::from_str(&json).unwrap_or_default(),
        None => Vec::new(),
    };
    let known: std::collections::HashSet<String> = index.iter().cloned().collect();

    for (id, pkg) in repo.key_packages() {
        let id_b64url = B64URL.encode(&id);
        if known.contains(&id_b64url) {
            continue;
        }
        let encoded = pkg
            .mls_encode_to_vec()
            .map_err(|e| LocalStorageError(format!("encode KeyPackageData: {e}")))?;
        storage
            .set_item(&kp_key(&id), &B64.encode(&encoded))
            .map_err(|e| LocalStorageError(format!("set kp: {e:?}")))?;
        index.push(id_b64url);
    }
    let json = serde_json::to_string(&index)
        .map_err(|e| LocalStorageError(format!("encode kp_ids: {e}")))?;
    storage
        .set_item(KP_INDEX_KEY, &json)
        .map_err(|e| LocalStorageError(format!("set kp_ids: {e:?}")))?;
    Ok(())
}

/// Read all persisted KeyPackage entries from localStorage and
/// insert them into `repo`. Idempotent — entries already present
/// are silently overwritten with the persisted copy.
///
/// # Errors
///
/// Bubbles up localStorage read failures, base64 decode errors,
/// or MLS-codec decoding errors.
pub fn restore_kp_repo_from_storage(
    repo: &InMemoryKeyPackageStorage,
) -> Result<usize, LocalStorageError> {
    let Some(json) = get_item(KP_INDEX_KEY)? else {
        return Ok(0);
    };
    let entries: Vec<String> =
        serde_json::from_str(&json).map_err(|e| LocalStorageError(format!("kp_ids decode: {e}")))?;
    let mut restored = 0;
    for id_b64url in entries {
        let id = B64URL
            .decode(id_b64url.as_bytes())
            .map_err(|e| LocalStorageError(format!("kp id decode: {e}")))?;
        let Some(b64) = get_item(&kp_key(&id))? else {
            continue;
        };
        let bytes = B64
            .decode(b64.as_bytes())
            .map_err(|e| LocalStorageError(format!("kp data decode: {e}")))?;
        let data = KeyPackageData::mls_decode(&mut bytes.as_slice())
            .map_err(|e| LocalStorageError(format!("kp data MLS-decode: {e}")))?;
        repo.insert(id, data);
        restored += 1;
    }
    Ok(restored)
}

// ────────────────────────────────────────────────────────────────
// Invite-token persistence (Reg v2)
// ────────────────────────────────────────────────────────────────
//
// The user pastes a single-use invite token into the SettingsForm.
// The chat-shell bootstrap reads it on the next reload, attaches
// it to `POST /register` as `Authorization: Bearer <token>`, and
// clears the local copy on success so a stale token can't be
// replayed if the user reloads.

const INVITE_TOKEN_KEY: &str = "lattice/invite_token/v1";

/// Read the persisted invite token, if any. Returns `None` on empty
/// or read error.
#[must_use]
pub fn load_invite_token() -> Option<String> {
    let win = web_sys::window()?;
    let ls = win.local_storage().ok().flatten()?;
    let v = ls.get_item(INVITE_TOKEN_KEY).ok().flatten()?;
    let trimmed = v.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Persist a new invite token. An empty string clears the entry.
///
/// # Errors
///
/// Bubbles up localStorage write failures.
#[allow(clippy::needless_pass_by_value)]
pub fn save_invite_token(token: String) -> Result<(), String> {
    let trimmed = token.trim();
    let win = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let ls = win
        .local_storage()
        .map_err(|e| format!("local_storage: {e:?}"))?
        .ok_or_else(|| "no localStorage".to_string())?;
    if trimmed.is_empty() {
        ls.remove_item(INVITE_TOKEN_KEY)
            .map_err(|e| format!("remove: {e:?}"))?;
    } else {
        ls.set_item(INVITE_TOKEN_KEY, trimmed)
            .map_err(|e| format!("set: {e:?}"))?;
    }
    Ok(())
}

/// Clear the persisted token. Used after a successful register so
/// the consumed bytes don't linger.
///
/// # Errors
///
/// Bubbles up localStorage write failures.
pub fn clear_invite_token() -> Result<(), String> {
    save_invite_token(String::new())
}

/// Delete every persisted KeyPackage entry. Used on identity
/// reset / clear.
///
/// # Errors
///
/// Bubbles up localStorage write failures.
pub fn clear_kp_storage() -> Result<(), LocalStorageError> {
    let storage = local_storage()?;
    if let Some(json) = storage
        .get_item(KP_INDEX_KEY)
        .map_err(|e| LocalStorageError(format!("read kp_ids: {e:?}")))?
    {
        let entries: Vec<String> = serde_json::from_str(&json).unwrap_or_default();
        for id_b64url in entries {
            if let Ok(id) = B64URL.decode(id_b64url.as_bytes()) {
                let _ = storage.remove_item(&kp_key(&id));
            }
        }
    }
    let _ = storage.remove_item(KP_INDEX_KEY);
    Ok(())
}
