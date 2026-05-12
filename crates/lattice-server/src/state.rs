//! In-memory server state for M3.
//!
//! This is the home-server's view of identities, key-package inboxes,
//! group state, and peer-server registry. All stores are
//! `Arc<RwLock<HashMap<_>>>` — cheap to clone for axum's per-request
//! state and the federation client.
//!
//! The sqlx-backed equivalents land later in M3 alongside the
//! Postgres migration; until then we keep the data model identical
//! so the swap-over is a refactor of the storage trait rather than
//! a redesign.

#![allow(
    clippy::module_name_repetitions,
    // *_b64 field-name suffix is intentional — it tells JSON consumers
    // the value is base64-encoded.
    clippy::struct_field_names,
    // `load_snapshot` and `save_snapshot` linearly walk every store
    // inline so the wire layout is obvious. Refactoring into helpers
    // hurts locality.
    clippy::too_many_lines,
)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic,))]

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand_core::RngCore;
use tokio::sync::{RwLock, broadcast};

use serde::{Deserialize, Serialize};

use lattice_protocol::wire::{IdentityClaim, SealedEnvelope};

/// Server-side identity registration entry. Persistence is in-memory
/// for M3; sqlx-backed later in the milestone.
#[derive(Clone, Debug)]
pub struct RegisteredUser {
    /// 32-byte BLAKE3 user_id (matches the credential field).
    pub user_id: [u8; 32],
    /// The user's hybrid identity claim, as published.
    pub claim: IdentityClaim,
    /// Unix-epoch seconds when the claim was accepted.
    pub registered_at: i64,
}

/// A published KeyPackage waiting to be consumed by a future inviter.
#[derive(Clone, Debug)]
pub struct PublishedKeyPackage {
    /// The owning user's user_id.
    pub user_id: [u8; 32],
    /// `mls_rs::MlsMessage::mls_encode_to_vec()` bytes for the
    /// KeyPackage. Server is opaque to the contents.
    pub key_package: Vec<u8>,
    /// Unix-epoch seconds when the KP was published. Used for
    /// last-resort lifetime tracking once we add KP rotation.
    pub published_at: i64,
}

/// One entry in a group's commit log. Servers replay commits to
/// late-joiners so they can rebuild state without re-soliciting.
#[derive(Clone, Debug)]
pub struct GroupCommitEntry {
    /// MLS epoch this commit advances to (i.e. the *post*-commit epoch).
    pub epoch: u64,
    /// Serialized MLS commit message (`MlsMessage` bytes).
    pub commit: Vec<u8>,
    /// One Welcome per joiner added by this commit. Each entry pairs
    /// the joiner's `user_id` with the bundled MLS-Welcome bytes +
    /// the PQ Welcome payload bytes.
    pub welcomes: Vec<WelcomeForJoiner>,
}

/// Server-side projection of a [`lattice_crypto::mls::LatticeWelcome`]
/// addressed to a single joiner.
#[derive(Clone, Debug)]
pub struct WelcomeForJoiner {
    /// Recipient's user_id (the inviter tells us; we use it for
    /// federation routing).
    pub joiner_user_id: [u8; 32],
    /// Serialized `MlsMessage::Welcome` bytes.
    pub mls_welcome: Vec<u8>,
    /// Serialized `PqWelcomePayload` bytes (`MlsEncode`).
    pub pq_payload: Vec<u8>,
}

/// One application message awaiting fetch by a recipient. Stored
/// opaquely — server doesn't decrypt.
#[derive(Clone, Debug)]
pub struct StoredAppMessage {
    /// Sender's `LeafNodeIndex` is hidden — only the group_id and the
    /// envelope are visible. For sealed envelopes the routing server
    /// has already run `verify_at_router`; for plain group sends the
    /// server takes the bytes opaquely.
    pub group_id: [u8; 16],
    /// Sealed envelope OR raw MLS application-message bytes.
    pub envelope: Vec<u8>,
    /// Monotonic sequence number so clients can fetch with a
    /// `since` filter.
    pub seq: u64,
}

/// Federation peer descriptor. Each known peer server's federation
/// pubkey (D-06) is cached after first contact; trust-on-first-use
/// pinning per §M3 plan.
#[derive(Clone, Debug)]
pub struct FederationPeer {
    /// Lowercased host (e.g. `pixie.lattice.chat`).
    pub host: String,
    /// Base URL with scheme and optional port (e.g.
    /// `https://pixie.lattice.chat:4443`).
    pub base_url: String,
    /// Peer's federation Ed25519 pubkey (32 bytes).
    pub federation_pubkey: [u8; 32],
}

/// The single server state object passed as axum's `State<ServerState>`.
#[derive(Clone)]
pub struct ServerState {
    /// This server's own federation signing key (Ed25519). Used to
    /// sign `MembershipCert` issuance + `.well-known` server descriptors.
    pub federation_sk: Arc<SigningKey>,
    /// This server's federation pubkey, hex-encoded for log lines and
    /// `.well-known` JSON.
    pub federation_pubkey_b64: String,
    /// Registered users keyed by `user_id`.
    pub users: Arc<RwLock<HashMap<[u8; 32], RegisteredUser>>>,
    /// Published KeyPackages keyed by `user_id`. Last-write-wins: the
    /// server keeps only the most recent KP per user for M3. KP
    /// rotation policy is a follow-up.
    pub key_packages: Arc<RwLock<HashMap<[u8; 32], PublishedKeyPackage>>>,
    /// Commit log keyed by group_id.
    pub groups: Arc<RwLock<HashMap<[u8; 16], Vec<GroupCommitEntry>>>>,
    /// Message inboxes keyed by group_id. Each new send appends with
    /// a monotonically-increasing `seq`.
    pub messages: Arc<RwLock<HashMap<[u8; 16], Vec<StoredAppMessage>>>>,
    /// Federation peer registry. Key = host string.
    pub peers: Arc<RwLock<HashMap<String, FederationPeer>>>,
    /// Monotonic seq counter shared across all groups.
    pub next_seq: Arc<RwLock<u64>>,
    /// `reqwest` client for outbound federation pushes. One per
    /// process; reused.
    pub federation_http: reqwest::Client,
    /// Live-subscription broadcast channels keyed by group_id. Each
    /// successful `append_message` fires `(seq, envelope_bytes)` to
    /// every subscriber attached to that group. WebSocket clients
    /// (D-11 fallback tier of γ.4) subscribe via
    /// `GET /group/:gid/messages/ws`.
    ///
    /// Capacity 64 is a soft buffer per group — if a subscriber
    /// can't keep up, `broadcast::Receiver` returns `Lagged(_)` and
    /// the WS handler closes the stream so the client knows to
    /// re-poll from the HTTP path.
    pub subscribers: Arc<RwLock<HashMap<[u8; 16], broadcast::Sender<(u64, Vec<u8>)>>>>,
}

impl ServerState {
    /// Construct a fresh server state. The federation signing key is
    /// generated with `OsRng` — the persistence story (load from
    /// `LATTICE_FEDERATION_KEY_PATH` if present) lives one layer up
    /// in `main.rs`.
    #[must_use]
    pub fn new_with_federation_key(federation_sk: SigningKey) -> Self {
        let pk = federation_sk.verifying_key().to_bytes();
        let federation_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(pk);
        let http = reqwest::Client::builder()
            .user_agent("lattice-server/0.1")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            federation_sk: Arc::new(federation_sk),
            federation_pubkey_b64,
            users: Arc::default(),
            key_packages: Arc::default(),
            groups: Arc::default(),
            messages: Arc::default(),
            peers: Arc::default(),
            next_seq: Arc::new(RwLock::new(0)),
            federation_http: http,
            subscribers: Arc::default(),
        }
    }

    /// Get-or-create the broadcast `Sender` for `group_id` so a fresh
    /// subscriber can attach. Returns a new `Receiver` each call —
    /// the caller is the WebSocket task.
    pub async fn subscribe(&self, group_id: [u8; 16]) -> broadcast::Receiver<(u64, Vec<u8>)> {
        let mut subs = self.subscribers.write().await;
        let sender = subs
            .entry(group_id)
            .or_insert_with(|| broadcast::channel(64).0);
        sender.subscribe()
    }

    /// Build a fresh state with a freshly-generated federation key.
    /// Convenience wrapper for tests and the dev path.
    #[must_use]
    pub fn new_test() -> Self {
        let mut seed = [0u8; 32];
        // `OsRng` does not fail in normal operation; if it does we're
        // in catastrophic OS state and aborting is the right move.
        if let Err(e) = OsRng.try_fill_bytes(&mut seed) {
            tracing::error!(error = %e, "OsRng failed in new_test; aborting");
            std::process::abort();
        }
        Self::new_with_federation_key(SigningKey::from_bytes(&seed))
    }
}

/// Append-only push of a single application message into a group's
/// inbox. Returns the assigned monotonic `seq`.
pub async fn append_message(state: &ServerState, group_id: [u8; 16], envelope: Vec<u8>) -> u64 {
    let mut seq_guard = state.next_seq.write().await;
    *seq_guard += 1;
    let seq = *seq_guard;
    drop(seq_guard);

    let mut messages = state.messages.write().await;
    let inbox = messages.entry(group_id).or_default();
    inbox.push(StoredAppMessage {
        group_id,
        envelope: envelope.clone(),
        seq,
    });
    drop(messages);

    // Push to any live WebSocket subscribers. Failed sends are
    // silently dropped — the subscriber will catch up via the
    // HTTP /messages?since=N path. `try_send` would actively close
    // a saturated channel; we let `send` block-or-drop instead.
    let subs = state.subscribers.read().await;
    if let Some(sender) = subs.get(&group_id) {
        // `broadcast::Sender::send` returns Err only when there are
        // zero active receivers — that's just "no subscribers", not
        // a failure worth surfacing.
        let _ = sender.send((seq, envelope));
    }
    seq
}

/// Fetch all messages with `seq > since_seq`, ordered by `seq`.
pub async fn fetch_messages(
    state: &ServerState,
    group_id: [u8; 16],
    since_seq: u64,
) -> Vec<StoredAppMessage> {
    let messages = state.messages.read().await;
    messages
        .get(&group_id)
        .map(|inbox| {
            inbox
                .iter()
                .filter(|m| m.seq > since_seq)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Look up a user's most recently-published KeyPackage. Returns
/// `None` if the user has never published.
pub async fn fetch_key_package(
    state: &ServerState,
    user_id: [u8; 32],
) -> Option<PublishedKeyPackage> {
    state.key_packages.read().await.get(&user_id).cloned()
}

/// Store / overwrite the most recent KeyPackage for a user.
pub async fn put_key_package(state: &ServerState, kp: PublishedKeyPackage) {
    state.key_packages.write().await.insert(kp.user_id, kp);
}

/// Register a new user (or update an existing claim). Returns true if
/// this was a new registration.
pub async fn register_user(state: &ServerState, user: RegisteredUser) -> bool {
    state
        .users
        .write()
        .await
        .insert(user.user_id, user)
        .is_none()
}

/// Look up a federation peer by host.
pub async fn peer_by_host(state: &ServerState, host: &str) -> Option<FederationPeer> {
    state.peers.read().await.get(host).cloned()
}

/// Insert or replace a federation peer (trust-on-first-use cache).
pub async fn upsert_peer(state: &ServerState, peer: FederationPeer) {
    state.peers.write().await.insert(peer.host.clone(), peer);
}

/// Append a commit entry to a group's log.
pub async fn append_commit(state: &ServerState, group_id: [u8; 16], entry: GroupCommitEntry) {
    let mut groups = state.groups.write().await;
    groups.entry(group_id).or_default().push(entry);
}

/// Walk a group's commit log. Returns owned copies for the caller to
/// serialize.
pub async fn commit_log(state: &ServerState, group_id: [u8; 16]) -> Vec<GroupCommitEntry> {
    state
        .groups
        .read()
        .await
        .get(&group_id)
        .cloned()
        .unwrap_or_default()
}

/// Suppress the unused import warning when only some helpers are used.
const _: fn(&SealedEnvelope) = |_| {};

// ============================================================================
// Snapshot — graceful-shutdown JSON dump + startup restore.
//
// On clean shutdown the server writes its full in-memory state to a JSON
// file at `LATTICE__SNAPSHOT_PATH`. On startup, if that file exists, the
// state is restored before the HTTP listener binds. Hard crashes (SIGKILL,
// OOM, power loss) still lose any state since the last snapshot — sqlite
// integration in the next M3 polish commit closes that gap.
// ============================================================================

#[derive(Serialize, Deserialize)]
struct UserSnap {
    user_id_b64: String,
    /// Prost-encoded `IdentityClaim`, base64.
    claim_b64: String,
    registered_at: i64,
}

#[derive(Serialize, Deserialize)]
struct KpSnap {
    user_id_b64: String,
    key_package_b64: String,
    published_at: i64,
}

#[derive(Serialize, Deserialize)]
struct CommitSnap {
    group_id_b64: String,
    epoch: u64,
    commit_b64: String,
    welcomes: Vec<WelcomeSnap>,
}

#[derive(Serialize, Deserialize)]
struct WelcomeSnap {
    joiner_user_id_b64: String,
    mls_welcome_b64: String,
    pq_payload_b64: String,
}

#[derive(Serialize, Deserialize)]
struct MessageSnap {
    group_id_b64: String,
    envelope_b64: String,
    seq: u64,
}

#[derive(Serialize, Deserialize)]
struct PeerSnap {
    host: String,
    base_url: String,
    federation_pubkey_b64: String,
}

#[derive(Serialize, Deserialize)]
struct StateSnapshot {
    /// Snapshot wire version. Bump on any breaking field rename.
    snapshot_version: u32,
    users: Vec<UserSnap>,
    key_packages: Vec<KpSnap>,
    commits: Vec<CommitSnap>,
    messages: Vec<MessageSnap>,
    peers: Vec<PeerSnap>,
    next_seq: u64,
}

impl ServerState {
    /// Serialize the entire in-memory state to JSON at `path`.
    ///
    /// Acquires read locks on all stores; safe to call concurrently
    /// with reads, blocked by in-flight writes briefly.
    ///
    /// # Errors
    ///
    /// I/O failure (`SnapshotError::Io`) or serialization failure
    /// (`SnapshotError::Codec`).
    pub async fn save_snapshot(&self, path: &std::path::Path) -> Result<(), SnapshotError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let snap = StateSnapshot {
            snapshot_version: 1,
            users: self
                .users
                .read()
                .await
                .values()
                .map(|u| UserSnap {
                    user_id_b64: b64.encode(u.user_id),
                    claim_b64: b64.encode(lattice_protocol::wire::encode(&u.claim)),
                    registered_at: u.registered_at,
                })
                .collect(),
            key_packages: self
                .key_packages
                .read()
                .await
                .values()
                .map(|kp| KpSnap {
                    user_id_b64: b64.encode(kp.user_id),
                    key_package_b64: b64.encode(&kp.key_package),
                    published_at: kp.published_at,
                })
                .collect(),
            commits: {
                let mut acc = Vec::new();
                for (gid, log) in self.groups.read().await.iter() {
                    for entry in log {
                        acc.push(CommitSnap {
                            group_id_b64: b64.encode(gid),
                            epoch: entry.epoch,
                            commit_b64: b64.encode(&entry.commit),
                            welcomes: entry
                                .welcomes
                                .iter()
                                .map(|w| WelcomeSnap {
                                    joiner_user_id_b64: b64.encode(w.joiner_user_id),
                                    mls_welcome_b64: b64.encode(&w.mls_welcome),
                                    pq_payload_b64: b64.encode(&w.pq_payload),
                                })
                                .collect(),
                        });
                    }
                }
                acc
            },
            messages: {
                let mut acc = Vec::new();
                for inbox in self.messages.read().await.values() {
                    for m in inbox {
                        acc.push(MessageSnap {
                            group_id_b64: b64.encode(m.group_id),
                            envelope_b64: b64.encode(&m.envelope),
                            seq: m.seq,
                        });
                    }
                }
                acc
            },
            peers: self
                .peers
                .read()
                .await
                .values()
                .map(|p| PeerSnap {
                    host: p.host.clone(),
                    base_url: p.base_url.clone(),
                    federation_pubkey_b64: b64.encode(p.federation_pubkey),
                })
                .collect(),
            next_seq: *self.next_seq.read().await,
        };
        let bytes = serde_json::to_vec_pretty(&snap).map_err(SnapshotError::codec)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(SnapshotError::Io)?;
        }
        std::fs::write(path, bytes).map_err(SnapshotError::Io)?;
        tracing::info!(
            path = %path.display(),
            users = snap.users.len(),
            key_packages = snap.key_packages.len(),
            commits = snap.commits.len(),
            messages = snap.messages.len(),
            peers = snap.peers.len(),
            "snapshot written"
        );
        Ok(())
    }

    /// Load a snapshot from `path` and populate the in-memory state.
    /// Overwrites any current state (call before serving requests).
    ///
    /// # Errors
    ///
    /// `SnapshotError::Io` if the file can't be read,
    /// `SnapshotError::Codec` on malformed JSON or field-length
    /// mismatches.
    pub async fn load_snapshot(&self, path: &std::path::Path) -> Result<(), SnapshotError> {
        let bytes = std::fs::read(path).map_err(SnapshotError::Io)?;
        let snap: StateSnapshot = serde_json::from_slice(&bytes).map_err(SnapshotError::codec)?;
        if snap.snapshot_version != 1 {
            return Err(SnapshotError::Codec(format!(
                "unsupported snapshot version {}",
                snap.snapshot_version
            )));
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let decode_32 = |s: &str| -> Result<[u8; 32], SnapshotError> {
            let v = b64.decode(s).map_err(SnapshotError::codec)?;
            v.as_slice()
                .try_into()
                .map_err(|_| SnapshotError::Codec(format!("expected 32 bytes, got {}", v.len())))
        };
        let decode_16 = |s: &str| -> Result<[u8; 16], SnapshotError> {
            let v = b64.decode(s).map_err(SnapshotError::codec)?;
            v.as_slice()
                .try_into()
                .map_err(|_| SnapshotError::Codec(format!("expected 16 bytes, got {}", v.len())))
        };

        {
            let mut users = self.users.write().await;
            users.clear();
            for u in &snap.users {
                let user_id = decode_32(&u.user_id_b64)?;
                let claim_bytes = b64.decode(&u.claim_b64).map_err(SnapshotError::codec)?;
                let claim = lattice_protocol::wire::decode::<IdentityClaim>(
                    claim_bytes.as_slice(),
                )
                .map_err(SnapshotError::codec)?;
                users.insert(
                    user_id,
                    RegisteredUser {
                        user_id,
                        claim,
                        registered_at: u.registered_at,
                    },
                );
            }
        }
        {
            let mut kps = self.key_packages.write().await;
            kps.clear();
            for kp in &snap.key_packages {
                let user_id = decode_32(&kp.user_id_b64)?;
                let key_package =
                    b64.decode(&kp.key_package_b64).map_err(SnapshotError::codec)?;
                kps.insert(
                    user_id,
                    PublishedKeyPackage {
                        user_id,
                        key_package,
                        published_at: kp.published_at,
                    },
                );
            }
        }
        {
            let mut groups = self.groups.write().await;
            groups.clear();
            for c in &snap.commits {
                let gid = decode_16(&c.group_id_b64)?;
                let mut welcomes = Vec::with_capacity(c.welcomes.len());
                for w in &c.welcomes {
                    welcomes.push(WelcomeForJoiner {
                        joiner_user_id: decode_32(&w.joiner_user_id_b64)?,
                        mls_welcome: b64
                            .decode(&w.mls_welcome_b64)
                            .map_err(SnapshotError::codec)?,
                        pq_payload: b64
                            .decode(&w.pq_payload_b64)
                            .map_err(SnapshotError::codec)?,
                    });
                }
                groups.entry(gid).or_default().push(GroupCommitEntry {
                    epoch: c.epoch,
                    commit: b64.decode(&c.commit_b64).map_err(SnapshotError::codec)?,
                    welcomes,
                });
            }
        }
        {
            let mut msgs = self.messages.write().await;
            msgs.clear();
            for m in &snap.messages {
                let gid = decode_16(&m.group_id_b64)?;
                let envelope =
                    b64.decode(&m.envelope_b64).map_err(SnapshotError::codec)?;
                msgs.entry(gid).or_default().push(StoredAppMessage {
                    group_id: gid,
                    envelope,
                    seq: m.seq,
                });
            }
        }
        {
            let mut peers = self.peers.write().await;
            peers.clear();
            for p in &snap.peers {
                let pk_v = b64
                    .decode(&p.federation_pubkey_b64)
                    .map_err(SnapshotError::codec)?;
                let pk: [u8; 32] = pk_v.as_slice().try_into().map_err(|_| {
                    SnapshotError::Codec(format!(
                        "peer pubkey length {} (expected 32)",
                        pk_v.len()
                    ))
                })?;
                peers.insert(
                    p.host.clone(),
                    FederationPeer {
                        host: p.host.clone(),
                        base_url: p.base_url.clone(),
                        federation_pubkey: pk,
                    },
                );
            }
        }
        *self.next_seq.write().await = snap.next_seq;
        tracing::info!(
            path = %path.display(),
            users = snap.users.len(),
            key_packages = snap.key_packages.len(),
            commits = snap.commits.len(),
            messages = snap.messages.len(),
            peers = snap.peers.len(),
            next_seq = snap.next_seq,
            "snapshot restored"
        );
        Ok(())
    }
}

/// Errors raised by snapshot save / load.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// File-system failure.
    #[error("snapshot IO: {0}")]
    Io(#[from] std::io::Error),
    /// Codec failure (JSON / Prost / length mismatch).
    #[error("snapshot codec: {0}")]
    Codec(String),
}

impl SnapshotError {
    fn codec<E: std::fmt::Display>(e: E) -> Self {
        Self::Codec(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn message_inbox_seq_is_monotonic() {
        let state = ServerState::new_test();
        let gid = [0xAA; 16];
        let a = append_message(&state, gid, b"a".to_vec()).await;
        let b = append_message(&state, gid, b"b".to_vec()).await;
        let c = append_message(&state, gid, b"c".to_vec()).await;
        assert!(a < b && b < c);

        let after_a = fetch_messages(&state, gid, a).await;
        assert_eq!(after_a.len(), 2);
        assert_eq!(after_a[0].seq, b);
        assert_eq!(after_a[1].seq, c);
    }

    #[tokio::test]
    async fn fetch_returns_empty_for_unknown_group() {
        let state = ServerState::new_test();
        let unknown = [0xFF; 16];
        let msgs = fetch_messages(&state, unknown, 0).await;
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn key_package_last_write_wins() {
        let state = ServerState::new_test();
        let uid = [0xBB; 32];
        put_key_package(
            &state,
            PublishedKeyPackage {
                user_id: uid,
                key_package: b"first".to_vec(),
                published_at: 1,
            },
        )
        .await;
        put_key_package(
            &state,
            PublishedKeyPackage {
                user_id: uid,
                key_package: b"second".to_vec(),
                published_at: 2,
            },
        )
        .await;
        let fetched = fetch_key_package(&state, uid).await.expect("present");
        assert_eq!(fetched.key_package, b"second");
        assert_eq!(fetched.published_at, 2);
    }

    #[tokio::test]
    async fn register_user_returns_true_on_first_insert() {
        let state = ServerState::new_test();
        let user = RegisteredUser {
            user_id: [0xCC; 32],
            claim: IdentityClaim::default(),
            registered_at: 1,
        };
        assert!(register_user(&state, user.clone()).await);
        assert!(!register_user(&state, user).await);
    }

    #[tokio::test]
    async fn peer_upsert_round_trip() {
        let state = ServerState::new_test();
        let peer = FederationPeer {
            host: "home.example.com".into(),
            base_url: "https://home.example.com:4443".into(),
            federation_pubkey: [0x11; 32],
        };
        upsert_peer(&state, peer.clone()).await;
        let found = peer_by_host(&state, "home.example.com")
            .await
            .expect("present");
        assert_eq!(found.federation_pubkey, [0x11; 32]);
    }

    #[tokio::test]
    async fn snapshot_round_trip_preserves_state() {
        let src = ServerState::new_test();
        // Populate every store with at least one entry.
        let uid = [0x42u8; 32];
        register_user(
            &src,
            RegisteredUser {
                user_id: uid,
                claim: IdentityClaim::default(),
                registered_at: 1700,
            },
        )
        .await;
        put_key_package(
            &src,
            PublishedKeyPackage {
                user_id: uid,
                key_package: vec![1, 2, 3, 4],
                published_at: 1701,
            },
        )
        .await;
        let gid = [0x11u8; 16];
        append_commit(
            &src,
            gid,
            GroupCommitEntry {
                epoch: 7,
                commit: vec![0xAA, 0xBB],
                welcomes: vec![WelcomeForJoiner {
                    joiner_user_id: uid,
                    mls_welcome: vec![0xCC; 8],
                    pq_payload: vec![0xDD; 4],
                }],
            },
        )
        .await;
        append_message(&src, gid, vec![0xEE; 16]).await;
        upsert_peer(
            &src,
            FederationPeer {
                host: "peer.example".into(),
                base_url: "https://peer.example:4443".into(),
                federation_pubkey: [0x99; 32],
            },
        )
        .await;

        // Snapshot to a temp file.
        let tmp = std::env::temp_dir().join(format!(
            "lattice-snap-test-{}.json",
            std::process::id()
        ));
        src.save_snapshot(&tmp).await.expect("save");

        // Restore into a fresh state and compare.
        let dst = ServerState::new_test();
        dst.load_snapshot(&tmp).await.expect("load");

        assert!(dst.users.read().await.contains_key(&uid));
        assert_eq!(
            dst.key_packages.read().await.get(&uid).unwrap().key_package,
            vec![1, 2, 3, 4]
        );
        let groups = dst.groups.read().await;
        let log = groups.get(&gid).expect("group log");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].epoch, 7);
        assert_eq!(log[0].welcomes[0].joiner_user_id, uid);
        drop(groups);
        let messages = dst.messages.read().await;
        assert_eq!(messages.get(&gid).unwrap().len(), 1);
        drop(messages);
        let peers = dst.peers.read().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers.get("peer.example").unwrap().federation_pubkey,
            [0x99; 32]
        );

        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn commit_log_appends_in_order() {
        let state = ServerState::new_test();
        let gid = [0xDD; 16];
        for epoch in 1..=3 {
            append_commit(
                &state,
                gid,
                GroupCommitEntry {
                    epoch,
                    commit: vec![u8::try_from(epoch & 0xFF).unwrap_or(0)],
                    welcomes: vec![],
                },
            )
            .await;
        }
        let log = commit_log(&state, gid).await;
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].epoch, 1);
        assert_eq!(log[2].epoch, 3);
    }
}
