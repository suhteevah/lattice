//! Group-layer routes: commit submission, welcome claim, application
//! message inbox, server-issued attribution certs.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::state::{
    GroupCommitEntry, ServerState, StoredAppMessage, WelcomeForJoiner, append_commit,
    append_message, commit_log, fetch_messages,
};
use lattice_protocol::sealed_sender::{ED25519_PUB_LEN, issue_cert};
use lattice_protocol::wire::MembershipCert;
use prost::Message;

fn decode_b64<const N: usize>(s: &str) -> Result<[u8; N], (StatusCode, String)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let bytes = b64
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("b64 decode: {e}")))?;
    bytes.as_slice().try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("length {} (expected {N})", bytes.len()),
        )
    })
}

fn decode_b64_vec(s: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    b64.decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("b64 decode: {e}")))
}

/// Per-joiner welcome bundle inside a `POST /commit` body.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CommitWelcome {
    /// Base64 32-byte recipient user_id.
    pub joiner_user_id_b64: String,
    /// Base64 MLS Welcome message bytes.
    pub mls_welcome_b64: String,
    /// Base64 `PqWelcomePayload` MLS-codec bytes.
    pub pq_payload_b64: String,
}

/// `POST /group/:gid/commit` body.
#[derive(Debug, Deserialize)]
pub struct CommitRequest {
    /// MLS epoch this commit advances to (i.e. epoch *after* the commit).
    pub epoch: u64,
    /// Base64 MLS commit message bytes.
    pub commit_b64: String,
    /// Per-joiner welcomes. Empty for self-commits / updates.
    #[serde(default)]
    pub welcomes: Vec<CommitWelcome>,
}

/// `POST /group/:gid/commit` response.
#[derive(Debug, Serialize)]
pub struct CommitResponse {
    /// Echoed epoch.
    pub epoch: u64,
    /// Number of welcomes the server accepted for fan-out.
    pub welcomes_accepted: usize,
}

async fn commit_handler(
    State(state): State<ServerState>,
    Path(gid_b64): Path<String>,
    Json(body): Json<CommitRequest>,
) -> Result<Json<CommitResponse>, (StatusCode, String)> {
    let gid: [u8; 16] = decode_b64(&gid_b64)?;
    let commit = decode_b64_vec(&body.commit_b64)?;

    let mut welcomes = Vec::with_capacity(body.welcomes.len());
    for w in &body.welcomes {
        let joiner_user_id: [u8; 32] = decode_b64(&w.joiner_user_id_b64)?;
        let mls_welcome = decode_b64_vec(&w.mls_welcome_b64)?;
        let pq_payload = decode_b64_vec(&w.pq_payload_b64)?;
        welcomes.push(WelcomeForJoiner {
            joiner_user_id,
            mls_welcome,
            pq_payload,
        });
    }

    let entry = GroupCommitEntry {
        epoch: body.epoch,
        commit,
        welcomes: welcomes.clone(),
    };
    append_commit(&state, gid, entry).await;
    let welcomes_accepted = welcomes.len();

    tracing::info!(
        group_prefix = ?&gid[..4],
        epoch = body.epoch,
        welcomes_accepted,
        "commit accepted"
    );
    Ok(Json(CommitResponse {
        epoch: body.epoch,
        welcomes_accepted,
    }))
}

/// `GET /group/:gid/welcome/:user_id` response. Returns the most-
/// recently appended welcome addressed to `user_id` in this group.
///
/// 404 if there is no pending welcome.
#[derive(Debug, Serialize)]
pub struct WelcomeResponse {
    /// Commit epoch this welcome corresponds to.
    pub epoch: u64,
    /// Base64 MLS Welcome bytes.
    pub mls_welcome_b64: String,
    /// Base64 PqWelcomePayload bytes.
    pub pq_payload_b64: String,
}

async fn welcome_handler(
    State(state): State<ServerState>,
    Path((gid_b64, user_id_b64)): Path<(String, String)>,
) -> Result<Json<WelcomeResponse>, (StatusCode, String)> {
    let gid: [u8; 16] = decode_b64(&gid_b64)?;
    let user_id: [u8; 32] = decode_b64(&user_id_b64)?;

    let log = commit_log(&state, gid).await;
    // Find the latest commit entry that contains a welcome for this user.
    let found = log
        .iter()
        .rev()
        .find_map(|entry| {
            entry
                .welcomes
                .iter()
                .find(|w| w.joiner_user_id == user_id)
                .map(|w| (entry.epoch, w.clone()))
        });
    let (epoch, w) = found.ok_or((
        StatusCode::NOT_FOUND,
        "no pending welcome for that user in this group".into(),
    ))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Json(WelcomeResponse {
        epoch,
        mls_welcome_b64: b64.encode(&w.mls_welcome),
        pq_payload_b64: b64.encode(&w.pq_payload),
    }))
}

/// `POST /group/:gid/messages` body.
#[derive(Debug, Deserialize)]
pub struct PublishMessageRequest {
    /// Base64 sealed envelope or raw MLS application message bytes.
    pub envelope_b64: String,
}

/// `POST /group/:gid/messages` response.
#[derive(Debug, Serialize)]
pub struct PublishMessageResponse {
    /// Monotonic sequence number assigned to this message.
    pub seq: u64,
}

async fn publish_message_handler(
    State(state): State<ServerState>,
    Path(gid_b64): Path<String>,
    Json(body): Json<PublishMessageRequest>,
) -> Result<Json<PublishMessageResponse>, (StatusCode, String)> {
    let gid: [u8; 16] = decode_b64(&gid_b64)?;
    let envelope = decode_b64_vec(&body.envelope_b64)?;
    let seq = append_message(&state, gid, envelope).await;
    Ok(Json(PublishMessageResponse { seq }))
}

#[derive(Debug, Deserialize)]
pub struct FetchMessagesQuery {
    /// Return only messages with `seq > since`. Defaults to 0 (start).
    #[serde(default)]
    pub since: u64,
}

#[derive(Debug, Serialize)]
pub struct FetchMessagesResponse {
    /// Most recent `seq` returned, for the caller's next polling cursor.
    pub latest_seq: u64,
    /// Messages in `seq`-ascending order.
    pub messages: Vec<MessageEntry>,
}

#[derive(Debug, Serialize)]
pub struct MessageEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Base64 envelope bytes.
    pub envelope_b64: String,
}

async fn fetch_messages_handler(
    State(state): State<ServerState>,
    Path(gid_b64): Path<String>,
    Query(q): Query<FetchMessagesQuery>,
) -> Result<Json<FetchMessagesResponse>, (StatusCode, String)> {
    let gid: [u8; 16] = decode_b64(&gid_b64)?;
    let msgs: Vec<StoredAppMessage> = fetch_messages(&state, gid, q.since).await;
    let b64 = base64::engine::general_purpose::STANDARD;
    let latest_seq = msgs.last().map(|m| m.seq).unwrap_or(q.since);
    let messages = msgs
        .into_iter()
        .map(|m| MessageEntry {
            seq: m.seq,
            envelope_b64: b64.encode(&m.envelope),
        })
        .collect();
    Ok(Json(FetchMessagesResponse {
        latest_seq,
        messages,
    }))
}

/// `POST /group/:gid/issue_cert` body.
#[derive(Debug, Deserialize)]
pub struct IssueCertRequest {
    /// MLS epoch the cert should be valid for.
    pub epoch: u64,
    /// Base64 32-byte Ed25519 ephemeral pubkey the requesting client
    /// will use to sign sealed envelopes during this epoch.
    pub ephemeral_pubkey_b64: String,
    /// Cert validity window — Unix-epoch seconds. Recommended ≤ 1 hour.
    pub valid_until: i64,
}

/// `POST /group/:gid/issue_cert` response: the signed cert.
#[derive(Debug, Serialize)]
pub struct IssueCertResponse {
    /// Base64 Prost-encoded `MembershipCert`.
    pub cert_b64: String,
}

async fn issue_cert_handler(
    State(state): State<ServerState>,
    Path(gid_b64): Path<String>,
    Json(body): Json<IssueCertRequest>,
) -> Result<Json<IssueCertResponse>, (StatusCode, String)> {
    let gid: [u8; 16] = decode_b64(&gid_b64)?;
    let ephemeral_pk: [u8; ED25519_PUB_LEN] = decode_b64(&body.ephemeral_pubkey_b64)?;
    let cert: MembershipCert = issue_cert(
        &state.federation_sk,
        gid.to_vec(),
        body.epoch,
        ephemeral_pk.to_vec(),
        body.valid_until,
    );
    let mut bytes = Vec::new();
    cert.encode(&mut bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("encode cert: {e}")))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Json(IssueCertResponse {
        cert_b64: b64.encode(&bytes),
    }))
}

/// Build the group router fragment.
pub fn router() -> Router<ServerState> {
    Router::new()
        .route("/group/{gid_b64}/commit", post(commit_handler))
        .route(
            "/group/{gid_b64}/welcome/{user_id_b64}",
            get(welcome_handler),
        )
        .route(
            "/group/{gid_b64}/messages",
            post(publish_message_handler).get(fetch_messages_handler),
        )
        .route("/group/{gid_b64}/issue_cert", post(issue_cert_handler))
}
