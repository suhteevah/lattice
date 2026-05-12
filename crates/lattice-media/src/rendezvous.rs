//! Self-hosted STUN / TURN client configuration (D-19).
//!
//! Each home server publishes its STUN/TURN endpoint in
//! `.well-known/lattice/server`. Clients picking a rendezvous for a
//! given call prefer their own home server, fall back to the remote
//! party's home server, and rotate per-call so traffic analysis at
//! any single STUN operator only sees a fraction of the user's
//! activity.
//!
//! No global STUN providers (Google, Cloudflare) — D-19 explicitly
//! rejects relay federation in V2 because it'd give an external party
//! the ability to enumerate Lattice call partners.
//!
//! Phase B scope: config struct + selection helper signatures. The
//! actual STUN/TURN protocol work lands in Phase C.

use serde::{Deserialize, Serialize};

/// One rendezvous endpoint as advertised by a home server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousEndpoint {
    /// Hostname (or IP literal) of the STUN/TURN server.
    pub host: String,
    /// UDP port. Standard 3478 unless the server admin overrode it.
    pub port: u16,
    /// Whether the server also speaks TURN (relay) or just STUN
    /// (reflexive only).
    pub supports_turn: bool,
    /// TURN credential lifetime, in seconds, for short-lived per-call
    /// credentials issued by the home server. Ignored if
    /// [`Self::supports_turn`] is false.
    pub turn_credential_ttl_secs: u32,
}

/// Per-call rendezvous selection. Phase C will hydrate this from the
/// caller's + callee's `.well-known/lattice/server` documents.
#[derive(Clone, Debug, Default)]
pub struct RendezvousConfig {
    /// Endpoints in preference order. Empty = local-only host
    /// candidates only (works on the same LAN, fails otherwise).
    pub endpoints: Vec<RendezvousEndpoint>,
}

impl RendezvousConfig {
    /// Construct an empty config. Used by tests that only need host
    /// candidates and by the Phase B sanity test.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            endpoints: Vec::new(),
        }
    }
}
