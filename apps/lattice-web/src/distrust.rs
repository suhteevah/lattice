//! Local-only federation distrust scoring (D-13 / M5).
//!
//! Per ROADMAP §M5 / DECISIONS.md §D-13, distrust scoring in V1/V1.5
//! is **local-only — no gossip**. Each browser instance maintains its
//! own opinion of every peer server based on observable behavior:
//!
//! * **Trust-positive events** — successful TLS, valid federation
//!   pubkey signature on a `.well-known/lattice/server` descriptor,
//!   on-time message delivery.
//! * **Trust-negative events** — TLS failure, mismatched federation
//!   pubkey (TOFU pin violation), timeouts, malformed protocol
//!   frames.
//!
//! The score is a simple integer in `[-100, +100]` with linear
//! adjustment per event. The UI shows a badge (green / yellow / red)
//! based on bucketed thresholds. Scores persist in localStorage so
//! they survive page reloads.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const STORAGE_KEY: &str = "lattice/distrust/v1";

/// Threshold above which a peer is "trusted" for UI badge purposes.
pub const TRUST_THRESHOLD: i32 = 20;
/// Threshold below which a peer is "distrusted" / sketchy.
pub const DISTRUST_THRESHOLD: i32 = -20;
/// Hard clamp on both ends so a single run of events can't lock out a
/// peer forever.
pub const SCORE_MIN: i32 = -100;
/// Hard clamp on the positive side — even a long-trusted peer can be
/// re-scored down quickly if it starts misbehaving.
pub const SCORE_MAX: i32 = 100;

/// Observable events that move the distrust score. `Warning` and
/// `NetworkFailure` are public API for callers wiring real
/// federation transport but aren't fired by the current demo — they
/// land once the WebTransport path (γ.4) and structured timeout
/// telemetry exist.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum DistrustEvent {
    /// Federation key validated against the TOFU pin or first-seen.
    PinnedKeyMatch,
    /// Successful HTTP exchange with the peer.
    Ok,
    /// Generic warning — late response, suspicious framing, etc.
    Warning,
    /// Federation pubkey did not match the locally-stored pin.
    PinViolation,
    /// Connection-level failure (TLS, refused, timeout).
    NetworkFailure,
}

impl DistrustEvent {
    /// Score delta applied to the peer when this event fires.
    #[must_use]
    pub fn delta(self) -> i32 {
        match self {
            Self::PinnedKeyMatch => 5,
            Self::Ok => 1,
            Self::Warning => -3,
            Self::PinViolation => -50,
            Self::NetworkFailure => -10,
        }
    }
}

/// Bucketed trust verdict for UI rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Score ≥ [`TRUST_THRESHOLD`]. Green badge.
    Trusted,
    /// Between thresholds — yellow badge.
    Neutral,
    /// Score ≤ [`DISTRUST_THRESHOLD`]. Red badge.
    Distrusted,
}

impl Verdict {
    /// Bucket a raw score.
    #[must_use]
    pub const fn from_score(score: i32) -> Self {
        if score >= TRUST_THRESHOLD {
            Self::Trusted
        } else if score <= DISTRUST_THRESHOLD {
            Self::Distrusted
        } else {
            Self::Neutral
        }
    }
}

/// One entry in the distrust ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    /// Server base URL (the key in the ledger).
    pub server_url: String,
    /// Current cumulative score, clamped to `[SCORE_MIN, SCORE_MAX]`.
    pub score: i32,
    /// Federation pubkey we've TOFU-pinned for this server, if any.
    pub pinned_pubkey_b64: Option<String>,
    /// Last update time as Unix seconds (best-effort browser clock).
    pub last_updated: i64,
}

/// The full distrust ledger — a map of server base URLs to
/// `PeerScore`. The whole map round-trips through localStorage as
/// JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DistrustLedger {
    /// One entry per known peer.
    pub peers: HashMap<String, PeerScore>,
}

impl DistrustLedger {
    /// Load the ledger from localStorage, or return an empty ledger
    /// on first run. Malformed blobs reset to empty.
    #[must_use]
    pub fn load() -> Self {
        let Some(window) = web_sys::window() else {
            return Self::default();
        };
        let Ok(Some(storage)) = window.local_storage() else {
            return Self::default();
        };
        match storage.get_item(STORAGE_KEY) {
            Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
            _ => Self::default(),
        }
    }

    /// Persist the ledger back to localStorage. Best-effort —
    /// failures (quota, no storage) are silent because the ledger is
    /// non-critical state.
    pub fn save(&self) {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Ok(Some(storage)) = window.local_storage() else {
            return;
        };
        if let Ok(json) = serde_json::to_string(self) {
            let _ = storage.set_item(STORAGE_KEY, &json);
        }
    }

    /// Apply `event` to `server_url`'s score. Creates the entry if
    /// missing. Returns the new score after the update.
    pub fn record(&mut self, server_url: &str, event: DistrustEvent, now_unix: i64) -> i32 {
        let entry = self
            .peers
            .entry(server_url.to_string())
            .or_insert_with(|| PeerScore {
                server_url: server_url.to_string(),
                score: 0,
                pinned_pubkey_b64: None,
                last_updated: now_unix,
            });
        entry.score = (entry.score + event.delta()).clamp(SCORE_MIN, SCORE_MAX);
        entry.last_updated = now_unix;
        entry.score
    }

    /// TOFU-pin a federation pubkey. The first call wins; subsequent
    /// calls only succeed if `pubkey_b64` matches the existing pin —
    /// otherwise we record a `PinViolation` event and return `Err`.
    ///
    /// # Errors
    ///
    /// Returns the existing pinned pubkey if it differs from the
    /// provided one.
    pub fn pin_pubkey(
        &mut self,
        server_url: &str,
        pubkey_b64: &str,
        now_unix: i64,
    ) -> Result<i32, String> {
        let entry = self
            .peers
            .entry(server_url.to_string())
            .or_insert_with(|| PeerScore {
                server_url: server_url.to_string(),
                score: 0,
                pinned_pubkey_b64: None,
                last_updated: now_unix,
            });
        match &entry.pinned_pubkey_b64 {
            None => {
                entry.pinned_pubkey_b64 = Some(pubkey_b64.to_string());
                entry.score = (entry.score + DistrustEvent::PinnedKeyMatch.delta())
                    .clamp(SCORE_MIN, SCORE_MAX);
                entry.last_updated = now_unix;
                Ok(entry.score)
            }
            Some(existing) if existing == pubkey_b64 => {
                entry.score = (entry.score + DistrustEvent::PinnedKeyMatch.delta())
                    .clamp(SCORE_MIN, SCORE_MAX);
                entry.last_updated = now_unix;
                Ok(entry.score)
            }
            Some(existing) => {
                entry.score = (entry.score + DistrustEvent::PinViolation.delta())
                    .clamp(SCORE_MIN, SCORE_MAX);
                entry.last_updated = now_unix;
                Err(format!(
                    "TOFU pin violation: server {server_url} previously pinned to {} \
                     ({}), now claims {pubkey_b64}",
                    short(existing),
                    short(&B64.encode(blake3::hash(existing.as_bytes()).as_bytes())),
                ))
            }
        }
    }
}

/// Truncate a string to 12 chars + "…" for log messages.
fn short(s: &str) -> String {
    if s.len() <= 12 {
        s.to_string()
    } else {
        format!("{}…", &s[..12])
    }
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
