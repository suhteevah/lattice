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
    create_group_with_storage, decrypt, encrypt_application, generate_key_package,
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
    /// Discord-style server-membership group (chunk 2 first cut).
    /// `server_name` lives here so the sidebar can render
    /// "★ server_name" without re-decrypting Init.
    ServerMembership { server_name: String },
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
        api::register(&self.server_url, &identity).await?;
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
                },
            },
        );
        persist_convo_record(&ConvoRecord {
            group_id_hex: hex::encode(group_id),
            peer_user_id_hex: hex::encode(peer_user_id_for_record),
            label: server_name.clone(),
            last_seq: 0,
            kind: ConvoKind::ServerMembership { server_name },
        })?;
        Ok(group_id)
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
            // Per-conversation classification flag — set to true
            // when at least one decrypted message in this batch
            // was a `ServerStateOp::Init`, so we know to upgrade
            // the convo's kind to `ServerMembership`.
            let mut detected_server_kind: Option<ConvoKind> = None;
            let plaintexts: Vec<(u64, Vec<u8>)> = {
                let mut active = self.active.lock().map_err(poisoned)?;
                let Some(convo) = active.get_mut(&gid) else {
                    continue;
                };
                let mut pts = Vec::with_capacity(envelopes.len());
                for env in envelopes {
                    match decrypt(&mut convo.group, &env.envelope) {
                        Ok(pt) => {
                            // Try ServerStateOp first. If it
                            // parses, it's an admin event — never
                            // render as chat plaintext.
                            if let Some(op) = ServerStateOp::try_decode(&pt) {
                                if let ServerStateOp::Init { server_name, .. } = &op {
                                    detected_server_kind = Some(ConvoKind::ServerMembership {
                                        server_name: server_name.clone(),
                                    });
                                    convo.kind = ConvoKind::ServerMembership {
                                        server_name: server_name.clone(),
                                    };
                                    convo.label = server_name.clone();
                                }
                                // TODO chunk 2.5: process
                                // AddChannel / RemoveChannel /
                                // PromoteAdmin / etc. ops here.
                                continue;
                            }
                            pts.push((env.seq, pt));
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
            // If we classified the convo as a server during this
            // batch, persist the upgraded kind + new label so the
            // sidebar renders correctly after reload.
            if let Some(kind) = detected_server_kind {
                if let ConvoKind::ServerMembership { server_name } = &kind {
                    let _ = update_convo_kind(&gid, kind.clone(), Some(server_name.clone()));
                }
            }
            for (seq, pt) in plaintexts {
                out.push(PolledMessage {
                    group_id: gid,
                    seq,
                    sender_label: label.clone(),
                    body: String::from_utf8_lossy(&pt).into_owned(),
                });
            }
        }
        Ok(out)
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
