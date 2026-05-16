//! Chat-state plumbing for chunk C — real DM flow.
//!
//! Holds the mutable MLS state per active conversation and exposes
//! async methods for bootstrap / add-conversation / send / poll.
//! Lives outside Leptos's signal graph because `GroupHandle` isn't
//! `Clone`; the public conversation summary is exposed through
//! signal-tracked structures owned by `chat.rs`.
//!
//! ## Group ID derivation
//!
//! For 1:1 DMs we derive a deterministic group_id from the sorted
//! pair of user_ids: `blake3("lattice/dm/v1/" || min || max)[..16]`.
//! Both sides agree without coordination — whichever side issues
//! the "add conversation" first creates the group and sends the
//! Welcome; the other side discovers a Welcome already waiting
//! when they go to add the same conversation.
//!
//! ## Identity bootstrap
//!
//! On first run: generate fresh `LatticeIdentity`, register with
//! the home server, publish a KeyPackage, persist plaintext to
//! `localStorage["lattice/identity/v1"]`. On subsequent runs: load
//! plaintext blob via `persist::load(None)`.
//!
//! Encrypted (v2 / v3 PRF) blobs are unlocked through the existing
//! `app.rs` flow; this module assumes the identity is already
//! unlocked when its methods are called.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lattice_crypto::credential::{
    ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN, USER_ID_LEN,
};
use lattice_crypto::mls::cipher_suite::{LATTICE_HYBRID_V1, LatticeCryptoProvider};
use lattice_crypto::mls::leaf_node_kem::KemKeyPair;
use lattice_crypto::mls::psk::LatticePskStorage;
use lattice_crypto::mls::{
    GroupHandle, LatticeIdentity, add_member, add_members, apply_commit,
    create_group_with_storage, decrypt_with_sender, encrypt_application, generate_key_package,
    load_group_with_storage, process_welcome_with_storage,
};
use lattice_protocol::server_state::ServerStateOp;
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::api;
use crate::persist;
use crate::storage::{
    LocalStorageGroupStateStorage, restore_kp_repo_from_storage, sync_kp_repo_to_storage,
};

/// localStorage key for the user-configured home server URL.
/// Chunk E lets users point the chat at a non-default server.
const SERVER_URL_KEY: &str = "lattice/server_url/v1";

/// localStorage key for the contacts roster (chunk B).
const CONTACTS_KEY: &str = "lattice/contacts/v1";

/// One saved contact — a person you've messaged before.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    /// Hex of the 32-byte user_id.
    pub user_id_hex: String,
    /// User-supplied label (the same string typed into the
    /// add-conversation form).
    pub label: String,
    /// Unix seconds when first saved.
    pub added_at_unix: u64,
}

/// Read the saved contacts list, sorted by `added_at` desc.
pub fn load_contacts() -> Vec<Contact> {
    let storage = match web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let raw = storage.get_item(CONTACTS_KEY).ok().flatten();
    let Some(json) = raw else {
        return Vec::new();
    };
    let mut entries: Vec<Contact> = serde_json::from_str(&json).unwrap_or_default();
    entries.sort_by(|a, b| b.added_at_unix.cmp(&a.added_at_unix));
    entries
}

/// Persist (or update) a contact. Dedupes by `user_id_hex`.
pub fn save_contact(contact: Contact) -> Result<(), String> {
    let storage = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .ok_or_else(|| "localStorage unavailable".to_string())?;
    let raw = storage.get_item(CONTACTS_KEY).ok().flatten();
    let mut entries: Vec<Contact> = raw
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    if let Some(existing) = entries
        .iter_mut()
        .find(|c| c.user_id_hex == contact.user_id_hex)
    {
        // Keep the earliest added_at_unix, refresh label if
        // the caller passed something newer.
        existing.label = contact.label;
    } else {
        entries.push(contact);
    }
    let json =
        serde_json::to_string(&entries).map_err(|e| format!("encode contacts: {e}"))?;
    storage
        .set_item(CONTACTS_KEY, &json)
        .map_err(|e| format!("set contacts: {e:?}"))
}

/// Read the persisted home server URL, falling back to `default`
/// if none has been set yet.
pub fn load_server_url(default: &str) -> String {
    let storage = match web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        Some(s) => s,
        None => return default.to_string(),
    };
    storage
        .get_item(SERVER_URL_KEY)
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Persist the home server URL. Reloading the app picks it up.
///
/// # Errors
///
/// Returns a string if `localStorage` is unavailable.
pub fn save_server_url(url: &str) -> Result<(), String> {
    let storage = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .ok_or_else(|| "localStorage unavailable".to_string())?;
    storage
        .set_item(SERVER_URL_KEY, url.trim())
        .map_err(|e| format!("set server url: {e:?}"))
}

/// 16-byte deterministic group id derived from sorted user_ids.
pub type GroupId = [u8; 16];

/// What kind of conversation this is. Distinguishes between
/// plain 1:1 DMs, N-party groups, and Discord-style
/// server-membership groups for sidebar grouping + thread
/// filtering (ServerStateOps don't render in the thread).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConvoKind {
    /// 1:1 DM with deterministic-hash group_id (chunk C).
    OneOnOne,
    /// N-party group with random group_id (chunk 1).
    NamedGroup,
    /// Discord-style server-membership group (chunk 2).
    /// `server_name` + admin roster live here for authorization
    /// at classify time (only admins can issue AddChannel etc.).
    /// `channels` is the canonical view of which channels this
    /// server has — replayed from accepted ServerStateOps.
    ServerMembership {
        server_name: String,
        #[serde(default)]
        admins: Vec<String>,
        #[serde(default)]
        channels: Vec<PersistedChannelInfo>,
    },
    /// A channel inside a Discord-style server (chunk 2.5d).
    /// `server_id` links back to the server-membership group;
    /// the channel itself has its own MLS group identified by
    /// the convo's outer `group_id` key.
    ServerChannel {
        /// Hex of the parent server-membership group_id.
        server_id_hex: String,
        /// Channel name (e.g. "general", "design").
        channel_name: String,
    },
}

/// Channel entry persisted on a server-membership convo. Mirrors
/// `lattice_protocol::server_state::ChannelInfo` but lives here
/// to keep the serde-Deserialize path independent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedChannelInfo {
    /// Channel's MLS group_id, hex-encoded.
    pub channel_group_id_hex: String,
    /// Display name.
    pub name: String,
}

impl Default for ConvoKind {
    fn default() -> Self {
        Self::OneOnOne
    }
}

/// Per-conversation MLS state.
pub struct ConvoState {
    /// 32-byte peer user_id.
    pub peer_user_id: [u8; USER_ID_LEN],
    /// User-supplied label (e.g. "Bob (iMac)").
    pub label: String,
    /// Live MLS group state. Mutated on every encrypt/decrypt;
    /// persists through `LocalStorageGroupStateStorage` so page
    /// reloads can re-hydrate via [`load_group_with_storage`].
    pub group: GroupHandle<LocalStorageGroupStateStorage>,
    /// PSK storage shared with `group`; needed for sealed-sender +
    /// future commit-rotation paths.
    pub psk: LatticePskStorage,
    /// Highest server sequence number consumed by `poll_messages`.
    pub last_seq: u64,
    /// What this conversation is — 1:1 / N-party / server. Drives
    /// sidebar treatment + ServerStateOp filtering in the thread.
    pub kind: ConvoKind,
}

/// Persisted shape for the per-conversation chat metadata
/// (peer + label + last_seq). The MLS state itself lives in
/// `LocalStorageGroupStateStorage`; this index drives sidebar
/// restoration on reload.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ConvoRecord {
    /// 16-byte group_id, hex-encoded.
    group_id_hex: String,
    /// 32-byte peer user_id, hex-encoded.
    peer_user_id_hex: String,
    /// User-supplied label.
    label: String,
    /// Highest server sequence number consumed so far.
    last_seq: u64,
    /// Kind of conversation. Defaults to `OneOnOne` for blobs
    /// persisted before chunk 2 — they remain functional 1:1 DMs
    /// after the upgrade.
    #[serde(default)]
    kind: ConvoKind,
}

const CONVOS_KEY: &str = "lattice/conversations/v1";

/// Shared mutable chat state.
///
/// `Arc<Mutex<_>>` (not `Rc<RefCell<_>>`) because Leptos 0.8
/// component closures require `Send + Sync` even in CSR mode.
/// In single-threaded WASM the mutexes never contend; the
/// `Send + Sync` is purely a type-system gate.
#[derive(Clone)]
pub struct ChatState {
    /// Identity bundle — `None` until bootstrap completes.
    identity: Arc<Mutex<Option<LatticeIdentity>>>,
    /// Set `true` while bootstrap is in flight to debounce
    /// concurrent callers (Leptos can re-execute component bodies,
    /// firing multiple `bootstrap_identity` spawn_local tasks). The
    /// loser-of-the-race tasks poll `has_identity()` for completion
    /// instead of duplicating the register / publish_kp / persist
    /// roundtrips.
    bootstrap_in_flight: Arc<AtomicBool>,
    /// Active conversations keyed by group_id.
    active: Arc<Mutex<HashMap<GroupId, ConvoState>>>,
    /// Home server URL.
    server_url: String,
}

impl ChatState {
    /// Create an empty ChatState pointed at `server_url`.
    #[must_use]
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            identity: Arc::new(Mutex::new(None)),
            bootstrap_in_flight: Arc::new(AtomicBool::new(false)),
            active: Arc::new(Mutex::new(HashMap::new())),
            server_url: server_url.into(),
        }
    }

    /// `true` once the identity is loaded / generated.
    #[must_use]
    pub fn has_identity(&self) -> bool {
        self.identity
            .lock()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    /// Read-only access to the bootstrap user_id (for display).
    #[must_use]
    pub fn my_user_id(&self) -> Option<[u8; USER_ID_LEN]> {
        self.identity
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|i| i.credential.user_id))
    }

    /// Load existing plaintext identity, or generate + register +
    /// publish a fresh one. Stores it on `self.identity` for later
    /// methods.
    ///
    /// # Errors
    ///
    /// Returns any persist / server error stringified.
    pub async fn bootstrap_identity(
        &self,
        log: impl Fn(String) + Copy,
    ) -> Result<(), String> {
        if self.has_identity() {
            return Ok(());
        }
        // Race guard: if another caller is already bootstrapping,
        // wait for them to finish rather than duplicate the work.
        if self
            .bootstrap_in_flight
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            for _ in 0..60 {
                wait_ms(500).await;
                if self.has_identity() {
                    return Ok(());
                }
            }
            return Err("bootstrap: another in-flight call did not complete".to_string());
        }
        // We're the winner — make sure to clear the flag on every
        // exit path. A guard struct would be cleaner, but RAII
        // across async is awkward; flat early-returns + manual
        // clear is fine for this scope.
        let result = self.bootstrap_inner(log).await;
        self.bootstrap_in_flight.store(false, Ordering::SeqCst);
        result
    }

    async fn bootstrap_inner(
        &self,
        log: impl Fn(String) + Copy,
    ) -> Result<(), String> {
        // Only the plaintext path is handled here. Encrypted blobs
        // (v2 / v3) need an unlock UI; the existing app.rs already
        // surfaces that. Callers that have an encrypted blob can
        // call `set_identity` after unlocking.
        match persist::probe()? {
            persist::BlobShape::Plaintext => {
                if let Some(loaded) = persist::load(None)? {
                    log(format!(
                        "chat: loaded saved identity user_id={}",
                        hex::encode(&loaded.credential.user_id[..6]),
                    ));
                    // Restore the in-memory KeyPackage repo from
                    // localStorage so process_welcome can find the
                    // matching private leaf init keys for any
                    // conversation we're invited to (or already in).
                    let restored = restore_kp_repo_from_storage(&loaded.key_package_repo)
                        .map_err(|e| format!("restore_kp: {e}"))?;
                    log(format!("chat: restored {restored} key packages from localStorage"));
                    *self.identity.lock().map_err(poisoned)? = Some(loaded);
                    // Re-hydrate active conversations from the
                    // persisted index + the MLS group state in
                    // localStorage.
                    self.restore_conversations(log)?;
                    // Also discover any pending welcomes that
                    // arrived while we were offline (N-party
                    // group invites with random group_ids that
                    // we can't derive locally).
                    self.discover_pending_welcomes(log).await?;
                    return Ok(());
                }
            }
            persist::BlobShape::Encrypted | persist::BlobShape::PrfEncrypted => {
                return Err(
                    "encrypted identity present; unlock via the debug panel first"
                        .to_string(),
                );
            }
            persist::BlobShape::None => {}
        }

        // No saved identity → generate + register + publish.
        let identity = generate_random_identity()?;
        log(format!(
            "chat: generated fresh identity user_id={}",
            hex::encode(&identity.credential.user_id[..6]),
        ));
        let invite_token = crate::storage::load_invite_token();
        api::register(&self.server_url, &identity, invite_token.as_deref()).await?;
        // Successful register consumes the token server-side; drop
        // the local copy so a stale value can't be replayed on the
        // next reload.
        if invite_token.is_some() {
            if let Err(e) = crate::storage::clear_invite_token() {
                log(format!("chat: clear_invite_token: {e}"));
            }
        }
        let published_at =
            api::publish_key_package(&self.server_url, &identity, &LatticePskStorage::new())
                .await?;
        log(format!(
            "chat: registered + published KP (server ts={published_at})"
        ));
        // Shadow-persist the KPs that generate_random_identity +
        // publish_key_package generated. mls-rs stored their private
        // leaf init keys inside identity.key_package_repo; we mirror
        // those into localStorage so the next page load can resume
        // an invited conversation.
        sync_kp_repo_to_storage(&identity.key_package_repo)
            .map_err(|e| format!("sync_kp: {e}"))?;
        log("chat: synced KP repo to localStorage".to_string());
        persist::save(&identity, None)?;
        log("chat: persisted plaintext identity to localStorage".to_string());
        *self.identity.lock().map_err(poisoned)? = Some(identity);
        // Newly-bootstrapped identity has no saved groups, but we
        // still try to discover pending invites — useful when an
        // inviter created an N-party group with random group_id
        // while we were offline.
        self.discover_pending_welcomes(log).await?;
        Ok(())
    }

    /// Query the server for welcomes addressed to us across every
    /// group, process each one we don't already have an active
    /// conversation for, and persist + register the resulting
    /// ConvoState. Idempotent — re-processing a welcome whose KP
    /// has already been consumed fails cleanly inside mls-rs and
    /// is silently skipped.
    async fn discover_pending_welcomes(
        &self,
        log: impl Fn(String) + Copy,
    ) -> Result<(), String> {
        let my_user_id = match self.identity.lock().map_err(poisoned)?.as_ref() {
            Some(id) => id.credential.user_id,
            None => return Ok(()),
        };
        let pending = match api::fetch_pending_welcomes(&self.server_url, &my_user_id).await {
            Ok(v) => v,
            Err(e) => {
                log(format!("chat: fetch_pending_welcomes skipped ({e})"));
                return Ok(());
            }
        };
        if pending.is_empty() {
            return Ok(());
        }
        log(format!(
            "chat: discovered {} pending welcome(s) for us",
            pending.len()
        ));
        for entry in &pending {
            let (gid_raw, lattice_welcome) =
                match api::pending_welcome_into_lattice(entry) {
                    Ok(v) => v,
                    Err(e) => {
                        log(format!("chat: skipping malformed welcome: {e}"));
                        continue;
                    }
                };
            if gid_raw.len() != 16 {
                log(format!(
                    "chat: skipping welcome with wrong-length gid ({})",
                    gid_raw.len()
                ));
                continue;
            }
            let mut group_id = [0u8; 16];
            group_id.copy_from_slice(&gid_raw);
            if self
                .active
                .lock()
                .map_err(poisoned)?
                .contains_key(&group_id)
            {
                continue;
            }
            let psk = LatticePskStorage::new();
            let group = {
                let guard = self.identity.lock().map_err(poisoned)?;
                let identity = guard
                    .as_ref()
                    .ok_or_else(|| "identity not bootstrapped".to_string())?;
                match process_welcome_with_storage(
                    identity,
                    psk.clone(),
                    &lattice_welcome,
                    LocalStorageGroupStateStorage,
                ) {
                    Ok(g) => {
                        let _ = sync_kp_repo_to_storage(&identity.key_package_repo);
                        g
                    }
                    Err(e) => {
                        log(format!(
                            "chat: skip welcome for gid={} ({e})",
                            hex::encode(group_id)
                        ));
                        continue;
                    }
                }
            };
            // Without further metadata, we don't know who invited
            // us — record a placeholder peer + a "group …" label.
            // Chunk 2's server-membership-group message will carry
            // the inviter's user_id + a server name. For chunk 1,
            // the user can rename via a future settings flow.
            let label = format!("group {}", &hex::encode(group_id)[..8]);
            let peer_user_id = [0u8; USER_ID_LEN];
            self.active.lock().map_err(poisoned)?.insert(
                group_id,
                ConvoState {
                    peer_user_id,
                    label: label.clone(),
                    group,
                    psk,
                    last_seq: 0,
                    // We don't know yet whether this is an
                    // N-party group or a server-membership group;
                    // the first ServerStateOp::Init decrypt in
                    // poll_all will upgrade the kind to
                    // `ServerMembership` if applicable.
                    kind: ConvoKind::NamedGroup,
                },
            );
            persist_convo_record(&ConvoRecord {
                group_id_hex: hex::encode(group_id),
                peer_user_id_hex: hex::encode(peer_user_id),
                label,
                last_seq: 0,
                kind: ConvoKind::NamedGroup,
            })?;
            log(format!(
                "chat: auto-joined group {}",
                hex::encode(group_id)
            ));
        }
        Ok(())
    }

    /// Reload conversations from the localStorage index. Called once
    /// at the end of `bootstrap_inner` whenever a saved identity was
    /// found. Each entry's MLS state is re-hydrated via
    /// `load_group_with_storage`; entries whose MLS state failed to
    /// load are dropped from the index.
    fn restore_conversations(
        &self,
        log: impl Fn(String) + Copy,
    ) -> Result<(), String> {
        let records = load_convo_index()?;
        if records.is_empty() {
            return Ok(());
        }
        let identity_guard = self.identity.lock().map_err(poisoned)?;
        let identity = identity_guard
            .as_ref()
            .ok_or_else(|| "identity not set before restore".to_string())?;

        let mut surviving: Vec<ConvoRecord> = Vec::with_capacity(records.len());
        let mut active = self.active.lock().map_err(poisoned)?;
        for record in records {
            let group_id = match decode_gid_hex(&record.group_id_hex) {
                Ok(g) => g,
                Err(_) => continue,
            };
            let peer_user_id = match decode_user_id_hex(&record.peer_user_id_hex) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let psk = LatticePskStorage::new();
            match load_group_with_storage(
                identity,
                psk.clone(),
                &group_id,
                LocalStorageGroupStateStorage,
            ) {
                Ok(group) => {
                    let kind = record.kind.clone();
                    active.insert(
                        group_id,
                        ConvoState {
                            peer_user_id,
                            label: record.label.clone(),
                            group,
                            psk,
                            last_seq: record.last_seq,
                            kind,
                        },
                    );
                    surviving.push(record);
                }
                Err(e) => {
                    log(format!(
                        "chat: failed to restore group {}: {} (dropping from index)",
                        record.group_id_hex, e
                    ));
                }
            }
        }
        drop(active);
        drop(identity_guard);
        // Persist the pruned index so dead entries don't keep
        // erroring every reload.
        save_convo_index(&surviving)?;
        log(format!(
            "chat: restored {} active conversation(s) from localStorage",
            surviving.len()
        ));
        // Walk server-membership convos and reclassify any of
        // their channels that came back as NamedGroup (the
        // discover_pending_welcomes path can't tell a channel
        // welcome apart from a regular N-party welcome).
        self.reclassify_channels_after_restore()?;
        Ok(())
    }

    /// After `restore_conversations`, walk every ServerMembership
    /// convo and reclassify each channel in its `channels` list
    /// as `ServerChannel` if it currently stored as `NamedGroup`.
    /// Runs once per bootstrap.
    fn reclassify_channels_after_restore(&self) -> Result<(), String> {
        let promotions: Vec<(GroupId, String, String)> = {
            let active = self.active.lock().map_err(poisoned)?;
            let mut out: Vec<(GroupId, String, String)> = Vec::new();
            for (gid, convo) in active.iter() {
                if let ConvoKind::ServerMembership { channels, .. } = &convo.kind {
                    let server_id_hex = hex::encode(gid);
                    for ch in channels {
                        let Ok(cgid) = decode_gid_hex(&ch.channel_group_id_hex) else {
                            continue;
                        };
                        out.push((cgid, server_id_hex.clone(), ch.name.clone()));
                    }
                }
            }
            out
        };
        for (channel_gid, server_id_hex, channel_name) in promotions {
            let needs_persist = {
                let mut active = self.active.lock().map_err(poisoned)?;
                let Some(channel_convo) = active.get_mut(&channel_gid) else {
                    continue;
                };
                if matches!(&channel_convo.kind, ConvoKind::ServerChannel { .. }) {
                    false
                } else {
                    channel_convo.kind = ConvoKind::ServerChannel {
                        server_id_hex: server_id_hex.clone(),
                        channel_name: channel_name.clone(),
                    };
                    channel_convo.label = channel_name.clone();
                    true
                }
            };
            if needs_persist {
                let _ = update_convo_kind(
                    &channel_gid,
                    ConvoKind::ServerChannel {
                        server_id_hex,
                        channel_name: channel_name.clone(),
                    },
                    Some(channel_name),
                );
            }
        }
        Ok(())
    }

    /// Add a conversation with `peer_user_id`. If a Welcome is
    /// waiting for us under the derived group_id we accept it
    /// (we're joining a group the peer already invited us to);
    /// otherwise we create the group and send the Welcome to peer.
    ///
    /// Returns the resulting group_id so the caller can route to
    /// the new thread.
    ///
    /// # Errors
    ///
    /// Server / crypto errors stringified.
    pub async fn add_conversation(
        &self,
        peer_user_id: [u8; USER_ID_LEN],
        label: String,
        log: impl Fn(String) + Copy,
    ) -> Result<GroupId, String> {
        let my_user_id = self.require_my_user_id()?;
        if peer_user_id == my_user_id {
            return Err("can't start a conversation with yourself".to_string());
        }
        let group_id = derive_group_id(&my_user_id, &peer_user_id);
        if self
            .active
            .lock()
            .map_err(poisoned)?
            .contains_key(&group_id)
        {
            return Err(format!(
                "conversation already active for group {}",
                hex::encode(group_id),
            ));
        }
        log(format!(
            "chat: derived group_id={} for peer={}",
            hex::encode(group_id),
            hex::encode(&peer_user_id[..6]),
        ));

        // Try the "I'm joining" path first.
        match api::fetch_welcome(&self.server_url, &group_id, &my_user_id).await {
            Ok(welcome_bundle) => {
                log("chat: welcome found — joining peer's group".to_string());
                let psk = LatticePskStorage::new();
                let group = {
                    let guard = self.identity.lock().map_err(poisoned)?;
                    let identity = guard
                        .as_ref()
                        .ok_or_else(|| "identity not bootstrapped".to_string())?;
                    let g = process_welcome_with_storage(
                        identity,
                        psk.clone(),
                        &welcome_bundle,
                        LocalStorageGroupStateStorage,
                    )
                    .map_err(|e| format!("process_welcome: {e}"))?;
                    // After mls-rs consumes a leaf KP into a group,
                    // it removes it from the in-memory repo. Sync
                    // the deletion to localStorage too.
                    sync_kp_repo_to_storage(&identity.key_package_repo)
                        .map_err(|e| format!("sync_kp post-welcome: {e}"))?;
                    g
                };
                self.active.lock().map_err(poisoned)?.insert(
                    group_id,
                    ConvoState {
                        peer_user_id,
                        label: label.clone(),
                        group,
                        psk,
                        last_seq: 0,
                        kind: ConvoKind::OneOnOne,
                    },
                );
                persist_convo_record(&ConvoRecord {
                    group_id_hex: hex::encode(group_id),
                    peer_user_id_hex: hex::encode(peer_user_id),
                    label: label.clone(),
                    last_seq: 0,
                    kind: ConvoKind::OneOnOne,
                })?;
                return Ok(group_id);
            }
            Err(e) if e.contains("404") || e.contains("not found") => {
                // No welcome → fall through to invite path.
            }
            Err(e) => return Err(format!("fetch_welcome: {e}")),
        }

        // "I'm inviting" path.
        log("chat: no welcome found — inviting peer".to_string());
        let peer_kp = api::fetch_key_package(&self.server_url, &peer_user_id).await?;
        log(format!("chat: fetched peer KP ({} bytes)", peer_kp.len()));

        let psk = LatticePskStorage::new();
        // Build group + commit under an immutable borrow of identity,
        // then drop the borrow before the async submit_commit call.
        let (mut group, commit_bytes, welcome) = {
            let guard = self.identity.lock().map_err(poisoned)?;
            let identity = guard
                .as_ref()
                .ok_or_else(|| "identity not bootstrapped".to_string())?;
            let mut g = create_group_with_storage(
                identity,
                psk.clone(),
                &group_id,
                LocalStorageGroupStateStorage,
            )
            .map_err(|e| format!("create_group: {e}"))?;
            let commit_output =
                add_member(&mut g, &peer_kp).map_err(|e| format!("add_member: {e}"))?;
            let welcome = commit_output
                .welcomes
                .into_iter()
                .next()
                .ok_or_else(|| "add_member produced no welcome".to_string())?;
            (g, commit_output.commit, welcome)
        };
        let accepted = api::submit_commit(
            &self.server_url,
            &group_id,
            welcome.pq_payload.epoch,
            &commit_bytes,
            &welcome,
            &peer_user_id,
        )
        .await?;
        log(format!("chat: server accepted {accepted} welcome(s)"));
        apply_commit(&mut group).map_err(|e| format!("apply_commit: {e}"))?;

        self.active.lock().map_err(poisoned)?.insert(
            group_id,
            ConvoState {
                peer_user_id,
                label: label.clone(),
                group,
                psk,
                last_seq: 0,
                kind: ConvoKind::OneOnOne,
            },
        );
        persist_convo_record(&ConvoRecord {
            group_id_hex: hex::encode(group_id),
            peer_user_id_hex: hex::encode(peer_user_id),
            label: label.clone(),
            last_seq: 0,
            kind: ConvoKind::OneOnOne,
        })?;
        // Chunk B: auto-add to contacts so the user doesn't have
        // to re-paste the hex next time.
        let _ = save_contact(Contact {
            user_id_hex: hex::encode(peer_user_id),
            label,
            added_at_unix: js_sys::Date::now().div_euclid(1000.0) as u64,
        });
        Ok(group_id)
    }

    /// Create a new N-party group chat by inviting `peers`. The
    /// group_id is fresh random (NOT the 1:1 sorted-hash that
    /// [`derive_group_id`] produces) because N-party groups don't
    /// have a canonical sort key.
    ///
    /// `label` is the user-supplied display name (e.g. "design
    /// team"). `peers` is the full list of user_ids to invite —
    /// at least one peer is required.
    ///
    /// Returns the resulting `group_id` so the caller can route
    /// `current_view` to the new thread.
    ///
    /// # Errors
    ///
    /// Returns an error if `peers` is empty, any peer hex is
    /// invalid, any peer hasn't published a KeyPackage, or the
    /// server rejects the commit.
    pub async fn create_group_conversation(
        &self,
        label: String,
        peers: Vec<[u8; USER_ID_LEN]>,
        log: impl Fn(String) + Copy,
    ) -> Result<GroupId, String> {
        if peers.is_empty() {
            return Err("create_group_conversation: at least one peer required".to_string());
        }
        let my_user_id = self.require_my_user_id()?;
        for peer in &peers {
            if peer == &my_user_id {
                return Err("can't include yourself as a peer".to_string());
            }
        }
        // Deduplicate peer list — paste accidents shouldn't blow
        // up `add_members` with duplicate KPs.
        let mut deduped: Vec<[u8; USER_ID_LEN]> = Vec::with_capacity(peers.len());
        for p in &peers {
            if !deduped.contains(p) {
                deduped.push(*p);
            }
        }
        let peers = deduped;

        let mut group_id = [0u8; 16];
        OsRng.fill_bytes(&mut group_id);
        log(format!(
            "chat: create group label={label:?} peers={} group_id={}",
            peers.len(),
            hex::encode(group_id),
        ));

        // Fetch every peer's KeyPackage before touching the MLS
        // state so a single bad hex fails fast without leaving
        // a half-built group on the server.
        let mut peer_kp_bytes: Vec<Vec<u8>> = Vec::with_capacity(peers.len());
        for (idx, peer) in peers.iter().enumerate() {
            let kp = api::fetch_key_package(&self.server_url, peer)
                .await
                .map_err(|e| format!("fetch KP for peer #{idx} ({}): {e}", hex::encode(&peer[..6])))?;
            peer_kp_bytes.push(kp);
        }
        log(format!("chat: fetched {} peer KPs", peer_kp_bytes.len()));

        // Build group + commit under an immutable identity borrow;
        // drop before the async server submit.
        let (mut group, commit_bytes, welcomes) = {
            let guard = self.identity.lock().map_err(poisoned)?;
            let identity = guard
                .as_ref()
                .ok_or_else(|| "identity not bootstrapped".to_string())?;
            let psk = LatticePskStorage::new();
            let mut g = create_group_with_storage(
                identity,
                psk.clone(),
                &group_id,
                LocalStorageGroupStateStorage,
            )
            .map_err(|e| format!("create_group: {e}"))?;
            let kp_refs: Vec<&[u8]> = peer_kp_bytes.iter().map(Vec::as_slice).collect();
            let commit_output =
                add_members(&mut g, &kp_refs).map_err(|e| format!("add_members: {e}"))?;
            if commit_output.welcomes.len() != peers.len() {
                return Err(format!(
                    "add_members produced {} welcomes for {} peers",
                    commit_output.welcomes.len(),
                    peers.len(),
                ));
            }
            (g, commit_output.commit, commit_output.welcomes)
        };

        // Single POST with all per-joiner welcomes paired with
        // their user_ids in `add_members`-input order.
        let peer_refs: Vec<&[u8; USER_ID_LEN]> = peers.iter().collect();
        let zipped: Vec<(&lattice_crypto::mls::LatticeWelcome, &[u8; USER_ID_LEN])> = welcomes
            .iter()
            .zip(peer_refs.iter().copied())
            .collect();
        let epoch = welcomes[0].pq_payload.epoch;
        let accepted = api::submit_commit_multi(
            &self.server_url,
            &group_id,
            epoch,
            &commit_bytes,
            &zipped,
        )
        .await?;
        log(format!("chat: server accepted {accepted} welcome(s)"));
        apply_commit(&mut group).map_err(|e| format!("apply_commit: {e}"))?;

        // The PSK that add_members shares with all joiners is now
        // in the local group's psk store; we don't need a fresh
        // empty psk for ConvoState — but the per-conversation psk
        // field exists for forward compatibility, so keep it.
        let psk = LatticePskStorage::new();
        // For N-party groups, peer_user_id is the FIRST peer's id
        // (a placeholder — the real list lives in the group's
        // MLS roster, accessible via group.members()).
        let peer_user_id_for_record = peers[0];
        self.active.lock().map_err(poisoned)?.insert(
            group_id,
            ConvoState {
                peer_user_id: peer_user_id_for_record,
                label: label.clone(),
                group,
                psk,
                last_seq: 0,
                kind: ConvoKind::NamedGroup,
            },
        );
        persist_convo_record(&ConvoRecord {
            group_id_hex: hex::encode(group_id),
            peer_user_id_hex: hex::encode(peer_user_id_for_record),
            label,
            last_seq: 0,
            kind: ConvoKind::NamedGroup,
        })?;
        Ok(group_id)
    }

    /// Create a Discord-style server. Reuses the N-party group
    /// machinery underneath — a server-membership group is just
    /// an MLS group whose first application message is a
    /// `ServerStateOp::Init`. Subsequent app messages on this
    /// group are admin events (`AddChannel`, `RenameServer`, …)
    /// rather than chat plaintext; the UI hides them from the
    /// thread.
    ///
    /// For chunk 2 first cut the server-membership group also
    /// acts as the implicit "#general" channel — any non-Op
    /// plaintext sent here renders in the thread. Real
    /// channel-per-group separation lands in chunk 2.5.
    ///
    /// # Errors
    ///
    /// Same surface as `create_group_conversation` plus failures
    /// to encode / publish the `Init` op.
    pub async fn create_server(
        &self,
        server_name: String,
        peers: Vec<[u8; USER_ID_LEN]>,
        log: impl Fn(String) + Copy,
    ) -> Result<GroupId, String> {
        if peers.is_empty() {
            return Err("create_server: at least one peer required".to_string());
        }
        let my_user_id = self.require_my_user_id()?;
        for peer in &peers {
            if peer == &my_user_id {
                return Err("can't include yourself as a peer".to_string());
            }
        }
        let mut deduped: Vec<[u8; USER_ID_LEN]> = Vec::with_capacity(peers.len());
        for p in &peers {
            if !deduped.contains(p) {
                deduped.push(*p);
            }
        }
        let peers = deduped;

        let mut group_id = [0u8; 16];
        OsRng.fill_bytes(&mut group_id);
        log(format!(
            "chat: create server {server_name:?} peers={} sid={}",
            peers.len(),
            hex::encode(group_id),
        ));

        let mut peer_kp_bytes: Vec<Vec<u8>> = Vec::with_capacity(peers.len());
        for (idx, peer) in peers.iter().enumerate() {
            let kp = api::fetch_key_package(&self.server_url, peer)
                .await
                .map_err(|e| format!("fetch KP for peer #{idx}: {e}"))?;
            peer_kp_bytes.push(kp);
        }

        let (mut group, commit_bytes, welcomes) = {
            let guard = self.identity.lock().map_err(poisoned)?;
            let identity = guard
                .as_ref()
                .ok_or_else(|| "identity not bootstrapped".to_string())?;
            let psk = LatticePskStorage::new();
            let mut g = create_group_with_storage(
                identity,
                psk.clone(),
                &group_id,
                LocalStorageGroupStateStorage,
            )
            .map_err(|e| format!("create_group: {e}"))?;
            let kp_refs: Vec<&[u8]> = peer_kp_bytes.iter().map(Vec::as_slice).collect();
            let commit_output =
                add_members(&mut g, &kp_refs).map_err(|e| format!("add_members: {e}"))?;
            (g, commit_output.commit, commit_output.welcomes)
        };

        let peer_refs: Vec<&[u8; USER_ID_LEN]> = peers.iter().collect();
        let zipped: Vec<(&lattice_crypto::mls::LatticeWelcome, &[u8; USER_ID_LEN])> = welcomes
            .iter()
            .zip(peer_refs.iter().copied())
            .collect();
        let epoch = welcomes[0].pq_payload.epoch;
        let accepted = api::submit_commit_multi(
            &self.server_url,
            &group_id,
            epoch,
            &commit_bytes,
            &zipped,
        )
        .await?;
        log(format!("chat: server accepted {accepted} welcome(s) for server"));
        apply_commit(&mut group).map_err(|e| format!("apply_commit: {e}"))?;

        // Now publish the Init op as the first application message
        // in the server-membership group. mls-rs needs the group at
        // its post-commit epoch (which apply_commit just gave us).
        let init = ServerStateOp::Init {
            server_name: server_name.clone(),
            admins: vec![hex::encode(my_user_id)],
            channels: Vec::new(),
        };
        let init_bytes = init
            .encode()
            .map_err(|e| format!("encode Init op: {e}"))?;
        let init_ct = encrypt_application(&mut group, &init_bytes)
            .map_err(|e| format!("encrypt Init: {e}"))?;
        let init_seq = api::publish_message(&self.server_url, &group_id, &init_ct).await?;
        log(format!("chat: published Init op seq={init_seq}"));

        // Persist the convo with kind=ServerMembership. The
        // creator's own poll loop won't decrypt its outgoing
        // Init (MLS generation tracking), but we already know
        // the server_name locally.
        let psk = LatticePskStorage::new();
        let peer_user_id_for_record = peers[0];
        self.active.lock().map_err(poisoned)?.insert(
            group_id,
            ConvoState {
                peer_user_id: peer_user_id_for_record,
                label: server_name.clone(),
                group,
                psk,
                last_seq: 0,
                kind: ConvoKind::ServerMembership {
                    server_name: server_name.clone(),
                    admins: vec![hex::encode(my_user_id)],
                    channels: Vec::new(),
                },
            },
        );
        persist_convo_record(&ConvoRecord {
            group_id_hex: hex::encode(group_id),
            peer_user_id_hex: hex::encode(peer_user_id_for_record),
            label: server_name.clone(),
            last_seq: 0,
            kind: ConvoKind::ServerMembership {
                server_name,
                admins: vec![hex::encode(my_user_id)],
                channels: Vec::new(),
            },
        })?;
        Ok(group_id)
    }

    /// Add a new channel to an existing server. Creates a fresh
    /// MLS group with all current server members as joiners,
    /// posts the `AddChannel` op on the server-membership group,
    /// and seeds a `ConvoKind::ServerChannel` entry locally.
    ///
    /// **Authorization (chunk 2.5b):** the caller must be in the
    /// server's admin roster. The classifier on every recipient
    /// also rejects non-admin `AddChannel` ops, but enforcing it
    /// here too gives the caller a fast local error.
    ///
    /// # Errors
    ///
    /// - `not an admin` if the caller isn't in `admins`.
    /// - `server not found` if `server_id` doesn't resolve.
    /// - Same server / crypto errors as
    ///   [`create_group_conversation`].
    pub async fn add_channel_to_server(
        &self,
        server_id: GroupId,
        channel_name: String,
        log: impl Fn(String) + Copy,
    ) -> Result<GroupId, String> {
        let my_user_id = self.require_my_user_id()?;
        let my_uid_hex = hex::encode(my_user_id);

        // Snapshot: server admins, current members, and verify
        // the kind under a brief lock.
        let (member_user_ids, server_name) = {
            let active = self.active.lock().map_err(poisoned)?;
            let convo = active
                .get(&server_id)
                .ok_or_else(|| "server not found".to_string())?;
            let (admins, server_name) = match &convo.kind {
                ConvoKind::ServerMembership {
                    admins,
                    server_name,
                    ..
                } => (admins.clone(), server_name.clone()),
                _ => return Err("target is not a server-membership group".to_string()),
            };
            if !admins.contains(&my_uid_hex) {
                return Err("not an admin of this server".to_string());
            }
            // Read the server's MLS roster — these are the
            // peers we need to invite to the new channel.
            let roster = convo
                .group
                .members()
                .map_err(|e| format!("read server roster: {e}"))?;
            let members: Vec<[u8; USER_ID_LEN]> = roster
                .into_iter()
                .map(|(_idx, uid)| uid)
                .filter(|uid| *uid != my_user_id)
                .collect();
            (members, server_name)
        };
        log(format!(
            "chat: add_channel '{channel_name}' to server '{server_name}' with {} peer(s)",
            member_user_ids.len()
        ));

        let mut channel_gid = [0u8; 16];
        OsRng.fill_bytes(&mut channel_gid);

        // Empty channel = no peers (just the creator). MLS allows
        // a one-member group; the user can invite peers later
        // (chunk 2.6+ — invite-existing-member-to-channel flow).
        if member_user_ids.is_empty() {
            let group = {
                let guard = self.identity.lock().map_err(poisoned)?;
                let identity = guard
                    .as_ref()
                    .ok_or_else(|| "identity not bootstrapped".to_string())?;
                create_group_with_storage(
                    identity,
                    LatticePskStorage::new(),
                    &channel_gid,
                    LocalStorageGroupStateStorage,
                )
                .map_err(|e| format!("create_group: {e}"))?
            };
            self.register_channel(server_id, channel_gid, channel_name.clone(), group)
                .await?;
            self.announce_channel(server_id, channel_gid, channel_name)
                .await?;
            return Ok(channel_gid);
        }

        // Fetch each peer's KP up-front.
        let mut peer_kp_bytes: Vec<Vec<u8>> = Vec::with_capacity(member_user_ids.len());
        for uid in &member_user_ids {
            let kp = api::fetch_key_package(&self.server_url, uid)
                .await
                .map_err(|e| {
                    format!("fetch KP for {}: {e}", hex::encode(&uid[..6]))
                })?;
            peer_kp_bytes.push(kp);
        }

        let (mut group, commit_bytes, welcomes) = {
            let guard = self.identity.lock().map_err(poisoned)?;
            let identity = guard
                .as_ref()
                .ok_or_else(|| "identity not bootstrapped".to_string())?;
            let psk = LatticePskStorage::new();
            let mut g = create_group_with_storage(
                identity,
                psk.clone(),
                &channel_gid,
                LocalStorageGroupStateStorage,
            )
            .map_err(|e| format!("create_group: {e}"))?;
            let kp_refs: Vec<&[u8]> = peer_kp_bytes.iter().map(Vec::as_slice).collect();
            let commit_output =
                add_members(&mut g, &kp_refs).map_err(|e| format!("add_members: {e}"))?;
            (g, commit_output.commit, commit_output.welcomes)
        };

        let peer_refs: Vec<&[u8; USER_ID_LEN]> = member_user_ids.iter().collect();
        let zipped: Vec<(&lattice_crypto::mls::LatticeWelcome, &[u8; USER_ID_LEN])> =
            welcomes.iter().zip(peer_refs.iter().copied()).collect();
        let epoch = welcomes[0].pq_payload.epoch;
        let _accepted = api::submit_commit_multi(
            &self.server_url,
            &channel_gid,
            epoch,
            &commit_bytes,
            &zipped,
        )
        .await?;
        apply_commit(&mut group).map_err(|e| format!("apply_commit: {e}"))?;

        self.register_channel(server_id, channel_gid, channel_name.clone(), group)
            .await?;
        self.announce_channel(server_id, channel_gid, channel_name)
            .await?;
        Ok(channel_gid)
    }

    /// Insert a fresh-built channel group into `active` + persist
    /// the convo record. Shared by `add_channel_to_server`'s two
    /// branches (empty channel vs invited channel).
    async fn register_channel(
        &self,
        server_id: GroupId,
        channel_gid: GroupId,
        channel_name: String,
        group: GroupHandle<LocalStorageGroupStateStorage>,
    ) -> Result<(), String> {
        // Sidebar already prepends "# " based on
        // ConvoKind::ServerChannel; store just the bare name in
        // the label to avoid "# # general" double-prefix.
        let label = channel_name.clone();
        let server_id_hex = hex::encode(server_id);
        let psk = LatticePskStorage::new();
        self.active.lock().map_err(poisoned)?.insert(
            channel_gid,
            ConvoState {
                peer_user_id: [0u8; USER_ID_LEN],
                label: label.clone(),
                group,
                psk,
                last_seq: 0,
                kind: ConvoKind::ServerChannel {
                    server_id_hex: server_id_hex.clone(),
                    channel_name: channel_name.clone(),
                },
            },
        );
        persist_convo_record(&ConvoRecord {
            group_id_hex: hex::encode(channel_gid),
            peer_user_id_hex: hex::encode([0u8; USER_ID_LEN]),
            label,
            last_seq: 0,
            kind: ConvoKind::ServerChannel {
                server_id_hex,
                channel_name,
            },
        })?;
        Ok(())
    }

    /// Send the `AddChannel` op on the server-membership group so
    /// every other server member learns about the new channel +
    /// processes their pending welcome for it.
    async fn announce_channel(
        &self,
        server_id: GroupId,
        channel_gid: GroupId,
        channel_name: String,
    ) -> Result<(), String> {
        let op = ServerStateOp::AddChannel {
            channel_group_id: hex::encode(channel_gid),
            name: channel_name.clone(),
        };
        let op_bytes = op
            .encode()
            .map_err(|e| format!("encode AddChannel op: {e}"))?;
        let ct = {
            let mut active = self.active.lock().map_err(poisoned)?;
            let convo = active
                .get_mut(&server_id)
                .ok_or_else(|| "server vanished mid-add".to_string())?;
            encrypt_application(&mut convo.group, &op_bytes)
                .map_err(|e| format!("encrypt AddChannel: {e}"))?
        };
        let _seq = api::publish_message(&self.server_url, &server_id, &ct).await?;
        // Update creator's own server-membership convo state to
        // include the new channel (other clients learn via the
        // poll classifier).
        if let Some(server) = self.active.lock().map_err(poisoned)?.get_mut(&server_id) {
            if let ConvoKind::ServerMembership { channels, .. } = &mut server.kind {
                if !channels
                    .iter()
                    .any(|c| c.channel_group_id_hex == hex::encode(channel_gid))
                {
                    channels.push(PersistedChannelInfo {
                        channel_group_id_hex: hex::encode(channel_gid),
                        name: channel_name,
                    });
                }
            }
            let _ = update_convo_kind(&server_id, server.kind.clone(), None);
        }
        Ok(())
    }

    /// Encrypt + send a chat message on `group_id`. Returns the
    /// server-assigned sequence number.
    ///
    /// # Errors
    ///
    /// Returns an error if the group isn't active, encryption
    /// fails, or the POST fails.
    pub async fn send_message(
        &self,
        group_id: GroupId,
        body: String,
    ) -> Result<u64, String> {
        let ct = {
            let mut active = self.active.lock().map_err(poisoned)?;
            let convo = active
                .get_mut(&group_id)
                .ok_or_else(|| "no active conversation".to_string())?;
            encrypt_application(&mut convo.group, body.as_bytes())
                .map_err(|e| format!("encrypt_application: {e}"))?
        };
        let seq = api::publish_message(&self.server_url, &group_id, &ct).await?;
        Ok(seq)
    }

    /// Poll every active conversation for new messages since the
    /// last seen seq. Returns one `(group_id, sender_label, plaintext)`
    /// tuple per decrypted message. Caller routes them into the
    /// thread signals.
    ///
    /// # Errors
    ///
    /// First server / crypto error halts the poll for that
    /// conversation but lets the rest continue.
    pub async fn poll_all(&self) -> Result<Vec<PolledMessage>, String> {
        // Snapshot conversation ids + last_seq so we don't hold
        // the lock across awaits.
        let snapshot: Vec<(GroupId, u64, String)> = {
            let active = self.active.lock().map_err(poisoned)?;
            active
                .iter()
                .map(|(gid, c)| (*gid, c.last_seq, c.label.clone()))
                .collect()
        };
        let mut out = Vec::new();
        for (gid, since, label) in snapshot {
            let (latest_seq, envelopes) =
                match api::fetch_messages(&self.server_url, &gid, since).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
            if envelopes.is_empty() {
                continue;
            }
            // Tracks whether classification or admin-roster ops
            // mutated the convo's persisted state during this
            // batch — drives the post-loop persist call.
            let mut kind_or_roster_changed = false;
            let plaintexts: Vec<(u64, Vec<u8>, Option<[u8; USER_ID_LEN]>)> = {
                let mut active = self.active.lock().map_err(poisoned)?;
                let Some(convo) = active.get_mut(&gid) else {
                    continue;
                };
                let mut pts = Vec::with_capacity(envelopes.len());
                for env in envelopes {
                    match decrypt_with_sender(&mut convo.group, &env.envelope) {
                        Ok((pt, sender_uid)) => {
                            // Try ServerStateOp first. If it
                            // parses, it's an admin event — never
                            // render as chat plaintext.
                            if let Some(op) = ServerStateOp::try_decode(&pt) {
                                if process_server_state_op(convo, &op, sender_uid.as_ref()) {
                                    kind_or_roster_changed = true;
                                }
                                continue;
                            }
                            pts.push((env.seq, pt, sender_uid));
                        }
                        Err(e) => {
                            web_sys::console::warn_1(
                                &format!(
                                    "chat: skipped seq={} group={} ({} bytes): {}",
                                    env.seq,
                                    hex::encode(gid),
                                    env.envelope.len(),
                                    e,
                                )
                                .into(),
                            );
                            continue;
                        }
                    }
                }
                convo.last_seq = latest_seq;
                pts
            };
            let _ = update_convo_last_seq(&gid, latest_seq);
            // Persist the upgraded kind / admin roster / channel
            // list so the sidebar reflects classifications across
            // reloads.
            if kind_or_roster_changed {
                // Snapshot the server's channel list so we can
                // promote any sibling channel convos that were
                // auto-joined as NamedGroup placeholders.
                let channels_to_promote: Vec<(GroupId, String, String)> = {
                    let active = self.active.lock().map_err(poisoned)?;
                    match active.get(&gid) {
                        Some(convo) => {
                            let _ = update_convo_kind(
                                &gid,
                                convo.kind.clone(),
                                Some(convo.label.clone()),
                            );
                            if let ConvoKind::ServerMembership { channels, .. } = &convo.kind {
                                let server_id_hex = hex::encode(gid);
                                channels
                                    .iter()
                                    .filter_map(|c| {
                                        let cgid = decode_gid_hex(&c.channel_group_id_hex).ok()?;
                                        Some((cgid, server_id_hex.clone(), c.name.clone()))
                                    })
                                    .collect()
                            } else {
                                Vec::new()
                            }
                        }
                        None => Vec::new(),
                    }
                };
                for (channel_gid, server_id_hex, channel_name) in channels_to_promote {
                    let needs_persist = {
                        let mut active = self.active.lock().map_err(poisoned)?;
                        if let Some(channel_convo) = active.get_mut(&channel_gid) {
                            let already = matches!(
                                &channel_convo.kind,
                                ConvoKind::ServerChannel { .. },
                            );
                            if already {
                                false
                            } else {
                                channel_convo.kind = ConvoKind::ServerChannel {
                                    server_id_hex: server_id_hex.clone(),
                                    channel_name: channel_name.clone(),
                                };
                                channel_convo.label = channel_name.clone();
                                true
                            }
                        } else {
                            false
                        }
                    };
                    if needs_persist {
                        let _ = update_convo_kind(
                            &channel_gid,
                            ConvoKind::ServerChannel {
                                server_id_hex,
                                channel_name: channel_name.clone(),
                            },
                            Some(channel_name),
                        );
                    }
                }
            }
            for (seq, pt, sender) in plaintexts {
                // Real sender attribution (chunk 2.5a): use the
                // user_id's first 6 hex chars when we know it, so
                // the thread shows "from b3a1f0…" instead of
                // "from $conversation_label". The convo label is
                // the fallback when mls-rs couldn't resolve the
                // leaf (handshake messages, etc.).
                let display = sender
                    .map(|uid| format!("{}…", &hex::encode(uid)[..6]))
                    .unwrap_or_else(|| label.clone());
                out.push(PolledMessage {
                    group_id: gid,
                    seq,
                    sender_label: display,
                    body: String::from_utf8_lossy(&pt).into_owned(),
                });
            }
        }
        Ok(out)
    }

    /// Group ids of every currently active conversation (chunk D —
    /// the WS push subscriber iterates this list at bootstrap).
    #[must_use]
    pub fn active_group_ids(&self) -> Vec<GroupId> {
        self.active
            .lock()
            .map(|active| active.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Home server URL (chunk D — the WS subscriber needs it to
    /// translate http→ws and reach `/group/:gid/messages/ws`).
    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Snapshot of active conversations for the sidebar.
    #[must_use]
    pub fn conversation_summaries(&self) -> Vec<ConversationSummary> {
        self.active
            .lock()
            .map(|active| {
                active
                    .iter()
                    .map(|(gid, c)| ConversationSummary {
                        group_id: *gid,
                        peer_user_id: c.peer_user_id,
                        label: c.label.clone(),
                        kind: c.kind.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn require_my_user_id(&self) -> Result<[u8; USER_ID_LEN], String> {
        self.identity
            .lock()
            .map_err(poisoned)?
            .as_ref()
            .map(|i| i.credential.user_id)
            .ok_or_else(|| "identity not bootstrapped".to_string())
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> String {
    "chat-state mutex poisoned".to_string()
}

/// Apply one decoded `ServerStateOp` to a convo's local state.
/// Returns `true` if the convo's persisted view (kind, label,
/// admin roster, channel list) changed and the caller should
/// re-persist via `update_convo_kind`.
///
/// **Authorization (chunk 2.5b).** Every non-Init op is rejected
/// unless `sender_uid` is in the current admin roster. Init has
/// no prior admin set; the creator's claim is trusted as the
/// initial admin. Non-admin ops are silently dropped (logged
/// via `console::warn` for visibility).
fn process_server_state_op(
    convo: &mut ConvoState,
    op: &ServerStateOp,
    sender_uid: Option<&[u8; USER_ID_LEN]>,
) -> bool {
    match op {
        ServerStateOp::Init {
            server_name,
            admins,
            channels,
        } => {
            // Init carries the creator's full initial state.
            // Trust this verbatim — the chunk-2-first-cut classifier
            // had nothing else to go on, and the sender is necessarily
            // the creator (only they had the group at epoch 0).
            convo.kind = ConvoKind::ServerMembership {
                server_name: server_name.clone(),
                admins: admins.clone(),
                channels: channels
                    .iter()
                    .map(|c| PersistedChannelInfo {
                        channel_group_id_hex: c.channel_group_id.clone(),
                        name: c.name.clone(),
                    })
                    .collect(),
            };
            convo.label = server_name.clone();
            true
        }
        ServerStateOp::AddChannel {
            channel_group_id,
            name,
        } => {
            if !is_sender_admin(convo, sender_uid) {
                drop_unauthorized_op("AddChannel", sender_uid);
                return false;
            }
            if let ConvoKind::ServerMembership { channels, .. } = &mut convo.kind {
                if channels
                    .iter()
                    .any(|c| c.channel_group_id_hex == *channel_group_id)
                {
                    return false;
                }
                channels.push(PersistedChannelInfo {
                    channel_group_id_hex: channel_group_id.clone(),
                    name: name.clone(),
                });
                return true;
            }
            false
        }
        ServerStateOp::RemoveChannel { channel_group_id } => {
            if !is_sender_admin(convo, sender_uid) {
                drop_unauthorized_op("RemoveChannel", sender_uid);
                return false;
            }
            if let ConvoKind::ServerMembership { channels, .. } = &mut convo.kind {
                let before = channels.len();
                channels.retain(|c| c.channel_group_id_hex != *channel_group_id);
                return channels.len() != before;
            }
            false
        }
        ServerStateOp::RenameServer { name } => {
            if !is_sender_admin(convo, sender_uid) {
                drop_unauthorized_op("RenameServer", sender_uid);
                return false;
            }
            if let ConvoKind::ServerMembership { server_name, .. } = &mut convo.kind {
                if *server_name == *name {
                    return false;
                }
                *server_name = name.clone();
                convo.label = name.clone();
                return true;
            }
            false
        }
        ServerStateOp::PromoteAdmin { user_id } => {
            if !is_sender_admin(convo, sender_uid) {
                drop_unauthorized_op("PromoteAdmin", sender_uid);
                return false;
            }
            if let ConvoKind::ServerMembership { admins, .. } = &mut convo.kind {
                if admins.contains(user_id) {
                    return false;
                }
                admins.push(user_id.clone());
                return true;
            }
            false
        }
        ServerStateOp::DemoteAdmin { user_id } => {
            if !is_sender_admin(convo, sender_uid) {
                drop_unauthorized_op("DemoteAdmin", sender_uid);
                return false;
            }
            if let ConvoKind::ServerMembership { admins, .. } = &mut convo.kind {
                let before = admins.len();
                admins.retain(|a| a != user_id);
                return admins.len() != before;
            }
            false
        }
    }
}

fn is_sender_admin(convo: &ConvoState, sender_uid: Option<&[u8; USER_ID_LEN]>) -> bool {
    let Some(uid) = sender_uid else {
        return false;
    };
    let uid_hex = hex::encode(uid);
    matches!(
        &convo.kind,
        ConvoKind::ServerMembership { admins, .. } if admins.contains(&uid_hex)
    )
}

fn drop_unauthorized_op(op_name: &str, sender_uid: Option<&[u8; USER_ID_LEN]>) {
    let sender_label = sender_uid
        .map(|uid| hex::encode(&uid[..6]))
        .unwrap_or_else(|| "<unknown>".to_string());
    web_sys::console::warn_1(
        &format!(
            "chat: dropping unauthorized {op_name} from non-admin {sender_label}"
        )
        .into(),
    );
}

fn decode_gid_hex(hex_str: &str) -> Result<GroupId, String> {
    let raw = hex::decode(hex_str).map_err(|e| format!("group_id hex decode: {e}"))?;
    if raw.len() != 16 {
        return Err(format!(
            "group_id wrong length: got {}, want 16",
            raw.len()
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn decode_user_id_hex(hex_str: &str) -> Result<[u8; USER_ID_LEN], String> {
    let raw = hex::decode(hex_str).map_err(|e| format!("user_id hex decode: {e}"))?;
    if raw.len() != USER_ID_LEN {
        return Err(format!(
            "user_id wrong length: got {}, want {}",
            raw.len(),
            USER_ID_LEN
        ));
    }
    let mut out = [0u8; USER_ID_LEN];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn local_storage() -> Result<web_sys::Storage, String> {
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    window
        .local_storage()
        .map_err(|e| format!("window.localStorage: {e:?}"))?
        .ok_or_else(|| "localStorage unavailable".to_string())
}

fn load_convo_index() -> Result<Vec<ConvoRecord>, String> {
    let storage = local_storage()?;
    let Some(json) = storage
        .get_item(CONVOS_KEY)
        .map_err(|e| format!("read convos: {e:?}"))?
    else {
        return Ok(Vec::new());
    };
    serde_json::from_str(&json).map_err(|e| format!("decode convos: {e}"))
}

fn save_convo_index(records: &[ConvoRecord]) -> Result<(), String> {
    let storage = local_storage()?;
    let json = serde_json::to_string(records).map_err(|e| format!("encode convos: {e}"))?;
    storage
        .set_item(CONVOS_KEY, &json)
        .map_err(|e| format!("set convos: {e:?}"))
}

fn persist_convo_record(record: &ConvoRecord) -> Result<(), String> {
    let mut records = load_convo_index().unwrap_or_default();
    // Replace any existing entry for this group_id (e.g. user
    // re-adds a previously dropped conversation).
    records.retain(|r| r.group_id_hex != record.group_id_hex);
    records.push(record.clone());
    save_convo_index(&records)
}

fn update_convo_last_seq(gid: &GroupId, last_seq: u64) -> Result<(), String> {
    let target = hex::encode(gid);
    let mut records = load_convo_index().unwrap_or_default();
    let mut changed = false;
    for r in &mut records {
        if r.group_id_hex == target && r.last_seq != last_seq {
            r.last_seq = last_seq;
            changed = true;
        }
    }
    if changed {
        save_convo_index(&records)?;
    }
    Ok(())
}

/// Bump a persisted convo record's `kind` (and optionally its
/// `label`). Called when classify-on-decrypt upgrades a freshly-
/// joined group from `NamedGroup` to `ServerMembership`.
fn update_convo_kind(
    gid: &GroupId,
    kind: ConvoKind,
    new_label: Option<String>,
) -> Result<(), String> {
    let target = hex::encode(gid);
    let mut records = load_convo_index().unwrap_or_default();
    let mut changed = false;
    for r in &mut records {
        if r.group_id_hex == target {
            if r.kind != kind {
                r.kind = kind.clone();
                changed = true;
            }
            if let Some(label) = &new_label {
                if &r.label != label {
                    r.label = label.clone();
                    changed = true;
                }
            }
        }
    }
    if changed {
        save_convo_index(&records)?;
    }
    Ok(())
}

async fn wait_ms(ms: u32) {
    // setTimeout-backed sleep for the in-flight bootstrap poller.
    // Same shape as `chat::sleep`; duplicated here to avoid a
    // public re-export across modules.
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen_futures::JsFuture;
    let _ = JsFuture::from(js_sys::Promise::new(&mut |resolve, _reject| {
        let cb = Closure::once_into_js(move || {
            let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
        });
        if let Some(w) = web_sys::window() {
            #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.unchecked_ref(),
                ms as i32,
            );
        }
    }))
    .await;
}

// Silence unused-import warning when std::time::Duration isn't
// directly referenced after the refactor.
#[allow(dead_code)]
fn _force_duration(_: Duration) {}

/// Decoded incoming message handed back from `poll_all`.
#[derive(Clone, Debug)]
pub struct PolledMessage {
    /// Conversation this message belongs to.
    pub group_id: GroupId,
    /// Server sequence number.
    pub seq: u64,
    /// Human label of the sender (peer's label, since the only
    /// non-me sender in a 1:1 is the peer).
    pub sender_label: String,
    /// UTF-8 plaintext.
    pub body: String,
}

/// Public summary of one conversation — what the sidebar shows.
#[derive(Clone, Debug)]
pub struct ConversationSummary {
    /// Group id.
    pub group_id: GroupId,
    /// Peer's user_id (for display + lookup).
    pub peer_user_id: [u8; USER_ID_LEN],
    /// User-supplied label (or server name for server-membership
    /// kind).
    pub label: String,
    /// Kind of conversation — drives sidebar treatment (server
    /// entries render with a ★ prefix).
    pub kind: ConvoKind,
}

/// Derive the canonical 1:1 group_id from sorted user_ids.
#[must_use]
pub fn derive_group_id(a: &[u8; USER_ID_LEN], b: &[u8; USER_ID_LEN]) -> GroupId {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = blake3::Hasher::new();
    h.update(b"lattice/dm/v1/");
    h.update(lo);
    h.update(hi);
    let mut out = [0u8; 16];
    h.finalize_xof().fill(&mut out);
    out
}

/// Generate a fresh hybrid identity with a random user_id. Same
/// shape as `app.rs::make_identity` but with `OsRng`-filled
/// `user_id` instead of a constant byte.
fn generate_random_identity() -> Result<LatticeIdentity, String> {
    let provider = LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .ok_or_else(|| "ciphersuite missing".to_string())?;
    let (sk, pk) = suite
        .signature_key_generate()
        .map_err(|e| format!("sig keygen: {e:?}"))?;
    let pk_bytes = pk.as_bytes();
    if pk_bytes.len() != ED25519_PK_LEN + ML_DSA_65_PK_LEN {
        return Err(format!(
            "unexpected hybrid pubkey length: {}",
            pk_bytes.len()
        ));
    }
    let mut ed25519_pub = [0u8; ED25519_PK_LEN];
    ed25519_pub.copy_from_slice(&pk_bytes[..ED25519_PK_LEN]);
    let ml_dsa_pub = pk_bytes[ED25519_PK_LEN..].to_vec();

    let mut user_id = [0u8; USER_ID_LEN];
    OsRng.fill_bytes(&mut user_id);

    let credential = LatticeCredential {
        user_id,
        ed25519_pub,
        ml_dsa_pub,
    };
    let kem_keypair = KemKeyPair::generate();

    let identity = LatticeIdentity {
        credential,
        signature_secret: sk,
        kem_keypair,
        key_package_repo: mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage::default(),
    };

    // Generate at least one KeyPackage so the user can be invited
    // by peers. Storage holds the private leaf key for later
    // process_welcome.
    let _kp = generate_key_package(&identity, LatticePskStorage::new())
        .map_err(|e| format!("generate_key_package: {e}"))?;

    Ok(identity)
}
