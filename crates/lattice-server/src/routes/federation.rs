//! Server-to-server federation inbox: `POST /federation/inbox`.
//!
//! Peer servers push commits + welcomes here when one of their users
//! is invited into a group whose owning server is us. The full flow
//! and trust model are in `docs/DECISIONS.md` §D-06 / §D-07.
//!
//! This is intentionally simple in M3: a peer-signed envelope wraps
//! a commit and per-joiner welcomes, we verify the peer's signature
//! using the cached federation_pubkey (or TOFU-cache on first
//! contact via `.well-known/lattice/server`), and append into our
//! local commit log so the joiner can fetch it.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::post,
};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::routes::groups::CommitWelcome;
use crate::state::{
    FederationPeer, GroupCommitEntry, ServerState, WelcomeForJoiner, append_commit, peer_by_host,
    upsert_peer,
};

/// `POST /federation/inbox` body. A peer server is forwarding a commit
/// that mentions a user we host.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FederationInboxRequest {
    /// Origin host (the sending peer server's hostname).
    pub origin_host: String,
    /// Origin host's base URL, used for trust-on-first-use peer lookup.
    pub origin_base_url: String,
    /// Origin host's federation pubkey, base64 32-byte. For TOFU we
    /// compare against the cached value (if any) and reject on
    /// mismatch.
    pub origin_pubkey_b64: String,
    /// Base64 16-byte group_id.
    pub group_id_b64: String,
    /// MLS epoch this push corresponds to.
    pub epoch: u64,
    /// Base64 MLS commit message bytes.
    pub commit_b64: String,
    /// Per-joiner welcomes addressed to users we host.
    #[serde(default)]
    pub welcomes: Vec<CommitWelcome>,
    /// Base64 Ed25519 signature by `origin_pubkey` over the
    /// canonical request body (everything above this field, in field
    /// order, mls-codec-encoded — see `canonical_inbox_bytes`).
    pub signature_b64: String,
}

#[derive(Debug, Serialize)]
pub struct FederationInboxResponse {
    /// True if the push was accepted into our local log.
    pub accepted: bool,
}

/// Build the canonical to-be-signed byte string for a federation push.
/// Deterministic ordering so the sender + receiver agree.
fn canonical_inbox_bytes(req: &FederationInboxRequest) -> Vec<u8> {
    use prost::Message;
    #[derive(Message)]
    struct Tbs {
        #[prost(string, tag = "1")]
        origin_host: String,
        #[prost(string, tag = "2")]
        origin_base_url: String,
        #[prost(bytes = "vec", tag = "3")]
        group_id: Vec<u8>,
        #[prost(uint64, tag = "4")]
        epoch: u64,
        #[prost(bytes = "vec", tag = "5")]
        commit: Vec<u8>,
        #[prost(bytes = "vec", tag = "6")]
        welcomes_concat: Vec<u8>,
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let group_id = b64.decode(&req.group_id_b64).unwrap_or_default();
    let commit = b64.decode(&req.commit_b64).unwrap_or_default();
    // For welcomes, concatenate their base64 strings deterministically.
    let mut welcomes_concat = String::new();
    for w in &req.welcomes {
        welcomes_concat.push_str(&w.joiner_user_id_b64);
        welcomes_concat.push('|');
        welcomes_concat.push_str(&w.mls_welcome_b64);
        welcomes_concat.push('|');
        welcomes_concat.push_str(&w.pq_payload_b64);
        welcomes_concat.push('\n');
    }
    let tbs = Tbs {
        origin_host: req.origin_host.clone(),
        origin_base_url: req.origin_base_url.clone(),
        group_id,
        epoch: req.epoch,
        commit,
        welcomes_concat: welcomes_concat.into_bytes(),
    };
    tbs.encode_to_vec()
}

async fn inbox_handler(
    State(state): State<ServerState>,
    Json(body): Json<FederationInboxRequest>,
) -> Result<Json<FederationInboxResponse>, (StatusCode, String)> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // Decode the origin pubkey + signature.
    let pk_bytes_vec = b64
        .decode(&body.origin_pubkey_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("origin_pubkey_b64: {e}")))?;
    let pk_bytes: [u8; 32] = pk_bytes_vec.as_slice().try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("origin_pubkey length {} (expected 32)", pk_bytes_vec.len()),
        )
    })?;
    let pubkey = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("origin_pubkey not a valid Ed25519 key: {e}"),
        )
    })?;
    let sig_bytes_vec = b64
        .decode(&body.signature_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("signature_b64: {e}")))?;
    let sig_bytes: [u8; 64] = sig_bytes_vec.as_slice().try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("signature length {} (expected 64)", sig_bytes_vec.len()),
        )
    })?;
    let sig = Signature::from_bytes(&sig_bytes);

    // TOFU: cache the peer's pubkey under its host on first contact. If
    // we've seen this host before with a *different* pubkey, refuse —
    // the operator must clear the cache manually (admin op for M3+).
    let tbs = canonical_inbox_bytes(&body);
    pubkey.verify(&tbs, &sig).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "federation push signature did not verify".into(),
        )
    })?;

    if let Some(cached) = peer_by_host(&state, &body.origin_host).await {
        if cached.federation_pubkey != pk_bytes {
            tracing::warn!(
                host = %body.origin_host,
                "federation peer pubkey changed — refusing push (TOFU pinning)"
            );
            return Err((
                StatusCode::FORBIDDEN,
                "peer pubkey mismatch vs TOFU cache".into(),
            ));
        }
    } else {
        upsert_peer(
            &state,
            FederationPeer {
                host: body.origin_host.clone(),
                base_url: body.origin_base_url.clone(),
                federation_pubkey: pk_bytes,
            },
        )
        .await;
    }

    // Decode + store the commit entry locally so our hosted users can
    // fetch it.
    let group_id: [u8; 16] = b64
        .decode(&body.group_id_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("group_id_b64: {e}")))?
        .as_slice()
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "group_id length (expected 16)".into(),
            )
        })?;
    let commit = b64.decode(&body.commit_b64).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("commit_b64: {e}"),
        )
    })?;

    let mut welcomes = Vec::with_capacity(body.welcomes.len());
    for w in &body.welcomes {
        let joiner_user_id: [u8; 32] = b64
            .decode(&w.joiner_user_id_b64)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("joiner_user_id_b64: {e}")))?
            .as_slice()
            .try_into()
            .map_err(|_| (StatusCode::BAD_REQUEST, "joiner_user_id length".into()))?;
        let mls_welcome = b64
            .decode(&w.mls_welcome_b64)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("mls_welcome_b64: {e}")))?;
        let pq_payload = b64
            .decode(&w.pq_payload_b64)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("pq_payload_b64: {e}")))?;
        welcomes.push(WelcomeForJoiner {
            joiner_user_id,
            mls_welcome,
            pq_payload,
        });
    }

    append_commit(
        &state,
        group_id,
        GroupCommitEntry {
            epoch: body.epoch,
            commit,
            welcomes,
        },
    )
    .await;
    tracing::info!(
        origin = %body.origin_host,
        epoch = body.epoch,
        "federation push accepted"
    );

    Ok(Json(FederationInboxResponse { accepted: true }))
}

pub fn router() -> Router<ServerState> {
    Router::new().route("/federation/inbox", post(inbox_handler))
}

/// Exposed for tests that want to compute the same canonical bytes the
/// inbox uses.
#[must_use]
pub fn canonical_inbox_bytes_for_test(req: &FederationInboxRequest) -> Vec<u8> {
    canonical_inbox_bytes(req)
}

/// Outbound federation push. Called from the `commit` handler when the
/// commit body lists `remote_routing` entries.
///
/// For each routing hint, builds + signs a `FederationInboxRequest`,
/// POSTs it to the peer's `/federation/inbox`. Logs (does not error)
/// on peer failures — federation push is best-effort in M3; missed
/// peers can pull-replicate later. Network errors are logged so an
/// operator can see them in real time.
pub async fn push_to_peers(
    state: &ServerState,
    gid: [u8; 16],
    epoch: u64,
    commit: &[u8],
    welcomes: &[crate::state::WelcomeForJoiner],
    routing: &[crate::routes::groups::RemoteRoutingHint],
    origin_host: &str,
    origin_base_url: &str,
) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut req = FederationInboxRequest {
        origin_host: origin_host.to_string(),
        origin_base_url: origin_base_url.to_string(),
        origin_pubkey_b64: state.federation_pubkey_b64.clone(),
        group_id_b64: b64.encode(gid),
        epoch,
        commit_b64: b64.encode(commit),
        welcomes: welcomes
            .iter()
            .map(|w| crate::routes::groups::CommitWelcome {
                joiner_user_id_b64: b64.encode(w.joiner_user_id),
                mls_welcome_b64: b64.encode(&w.mls_welcome),
                pq_payload_b64: b64.encode(&w.pq_payload),
            })
            .collect(),
        signature_b64: String::new(),
    };
    let tbs = canonical_inbox_bytes(&req);
    use ed25519_dalek::Signer;
    let sig = state.federation_sk.sign(&tbs);
    req.signature_b64 = b64.encode(sig.to_bytes());

    for hint in routing {
        let url = format!(
            "{}/federation/inbox",
            hint.home_server_base_url.trim_end_matches('/')
        );
        let client = state.federation_http.clone();
        let body = req.clone();
        let target = hint.home_server_base_url.clone();
        // Fire-and-forget per peer; M3 doesn't queue retries. M5
        // adds durable retry on top.
        tokio::spawn(async move {
            match client.post(&url).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(target = %target, "federation push delivered");
                }
                Ok(resp) => {
                    tracing::warn!(
                        target = %target,
                        status = resp.status().as_u16(),
                        "federation push rejected"
                    );
                }
                Err(e) => {
                    tracing::warn!(target = %target, error = %e, "federation push failed");
                }
            }
        });
    }
}
