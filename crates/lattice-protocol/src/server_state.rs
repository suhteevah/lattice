//! Discord-style server-membership-group state ops.
//!
//! A "server" in Lattice is an emergent UX concept on top of MLS
//! groups: it's an MLS group whose application messages carry
//! [`ServerStateOp`] payloads instead of (or alongside) regular
//! chat plaintexts. The first message in a server-membership
//! group is always a [`ServerStateOp::Init`] sent by the creator;
//! clients use that as the type marker to distinguish a server
//! from an N-party chat group at classification time.
//!
//! Subsequent ops mutate the server's logical state — adding /
//! removing channels, renaming the server, promoting / demoting
//! admins. Each op is signed by its sender's MLS leaf (mls-rs
//! already does this for any application message); the
//! authorization layer (rejecting non-admin AddChannel etc.) is
//! enforced client-side from each peer's local view of the
//! admin roster.
//!
//! ## Wire encoding
//!
//! JSON via `serde_json`. The body of an MLS application message
//! is `Vec<u8>`; we put the JSON-encoded `ServerStateOp` bytes
//! there directly. A regular chat message is just UTF-8 plaintext
//! that fails JSON-decode as a `ServerStateOp` — the receiver
//! falls through to plaintext rendering when classification
//! returns `None`.
//!
//! ## Why JSON, not Prost / Cap'n Proto
//!
//! ServerStateOps are infrequent (server lifecycle events, not
//! per-message). JSON keeps the encoding human-debuggable in
//! transit and avoids growing the capnp schema for a short-lived
//! first-cut design. Future hardening can swap to capnp once the
//! op set stabilizes.

use serde::{Deserialize, Serialize};

/// 32-byte user_id, same shape as `lattice_crypto::credential::USER_ID_LEN`.
/// Kept hex-encoded in transit so the JSON envelope is text-only.
pub type UserIdHex = String;

/// 16-byte group_id, hex-encoded.
pub type GroupIdHex = String;

/// State-machine event for a server-membership group.
///
/// The first message in a server-membership group is always
/// `Init`. Subsequent messages mutate state. Clients replay all
/// ops in receive order to reconstruct the server's view; merge
/// conflicts on out-of-order delivery are resolved last-write-
/// wins at the MLS-application-message-seq layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
pub enum ServerStateOp {
    /// First-ever message in a server-membership group. Carries
    /// the server's human-readable name and the initial admin
    /// roster (the creator).
    Init {
        /// User-supplied server name (e.g. "Friends", "Work").
        server_name: String,
        /// Initial admin roster. The creator is always present.
        admins: Vec<UserIdHex>,
        /// Optional initial channel list. Empty for chunk-2
        /// first-cut where the server-membership group IS the
        /// implicit #general channel.
        #[serde(default)]
        channels: Vec<ChannelInfo>,
    },
    /// Announce a new channel. The channel's MLS group is created
    /// in a separate flow; this op only records its existence so
    /// clients can show it in the channel list.
    AddChannel {
        /// MLS group_id of the channel's own MLS group.
        channel_group_id: GroupIdHex,
        /// Channel name, e.g. "general", "design".
        name: String,
    },
    /// Mark a channel as removed. Clients hide it; the underlying
    /// MLS group is not destroyed (clients can't reach consensus
    /// on deletion without a separate sweep).
    RemoveChannel {
        /// MLS group_id of the channel.
        channel_group_id: GroupIdHex,
    },
    /// Rename the server.
    RenameServer {
        /// New name.
        name: String,
    },
    /// Promote a user to admin. The admin roster is the
    /// union-of-promotes minus the set-of-demotes for that user
    /// over the lifetime of the server.
    PromoteAdmin {
        /// Newly-promoted user.
        user_id: UserIdHex,
    },
    /// Revoke admin status.
    DemoteAdmin {
        /// Demoted user.
        user_id: UserIdHex,
    },
}

impl ServerStateOp {
    /// JSON-encode the op. Used as the body of the carrying MLS
    /// application message.
    ///
    /// # Errors
    ///
    /// `serde_json::to_vec` failure (effectively impossible for
    /// the variants defined here).
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Try to decode an op from MLS application-message bytes.
    /// Returns `None` if the bytes aren't valid JSON or don't
    /// match this enum's shape — used by classification to fall
    /// through to "regular chat message."
    #[must_use]
    pub fn try_decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// One channel inside a server. Stored inside `Init.channels`
/// (initial roster) and `AddChannel` (incremental adds).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// MLS group_id of the channel's own MLS group (hex-encoded).
    pub channel_group_id: GroupIdHex,
    /// Channel name.
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_round_trip() {
        let op = ServerStateOp::Init {
            server_name: "Friends".to_string(),
            admins: vec!["aa".repeat(32)],
            channels: vec![ChannelInfo {
                channel_group_id: "bb".repeat(16),
                name: "general".to_string(),
            }],
        };
        let bytes = op.encode().expect("encode");
        let decoded = ServerStateOp::try_decode(&bytes).expect("decode");
        match decoded {
            ServerStateOp::Init {
                server_name,
                admins,
                channels,
            } => {
                assert_eq!(server_name, "Friends");
                assert_eq!(admins.len(), 1);
                assert_eq!(channels.len(), 1);
                assert_eq!(channels[0].name, "general");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn add_channel_round_trip() {
        let op = ServerStateOp::AddChannel {
            channel_group_id: "cc".repeat(16),
            name: "design".to_string(),
        };
        let bytes = op.encode().expect("encode");
        let decoded = ServerStateOp::try_decode(&bytes).expect("decode");
        match decoded {
            ServerStateOp::AddChannel {
                channel_group_id,
                name,
            } => {
                assert_eq!(name, "design");
                assert_eq!(channel_group_id.len(), 32);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn random_bytes_do_not_decode_as_op() {
        // Used by the classification path — a regular UTF-8 chat
        // message must NOT accidentally parse as a ServerStateOp.
        assert!(ServerStateOp::try_decode(b"hello").is_none());
        assert!(ServerStateOp::try_decode(b"").is_none());
        // Even structured-looking JSON without the "op" field
        // shouldn't match.
        assert!(ServerStateOp::try_decode(b"{\"foo\":1}").is_none());
    }

    #[test]
    fn admin_ops_round_trip() {
        for op in [
            ServerStateOp::PromoteAdmin {
                user_id: "11".repeat(32),
            },
            ServerStateOp::DemoteAdmin {
                user_id: "22".repeat(32),
            },
            ServerStateOp::RenameServer {
                name: "renamed".to_string(),
            },
            ServerStateOp::RemoveChannel {
                channel_group_id: "33".repeat(16),
            },
        ] {
            let bytes = op.encode().expect("encode");
            let decoded = ServerStateOp::try_decode(&bytes).expect("decode");
            // Just verify it round-trips without panicking.
            let _ = decoded;
        }
    }
}
