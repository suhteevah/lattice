//! Group-layer routes: commit submission, welcome claim, application
//! message inbox, server-issued attribution certs.

use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::IntoResponse,
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
    /// Origin host that the SUBMITTING client wants the server to
    /// claim when forwarding this commit to remote peers. Used in
    /// the federation push's signed `origin_host` field. Defaults to
    /// the local server's own host if absent.
    #[serde(default)]
    pub origin_host: Option<String>,
    /// Origin base URL (likewise for federation push). Defaults to a
    /// blank string if absent.
    #[serde(default)]
    pub origin_base_url: Option<String>,
    /// Routing hints: per-joiner home-server base URLs for joiners
    /// hosted on other servers. The home server will federate-push
    /// the commit + welcomes to each listed URL's /federation/inbox.
    /// Local joiners (hosted by us) are inferred from `welcomes` and
    /// not duplicated here.
    #[serde(default)]
    pub remote_routing: Vec<RemoteRoutingHint>,
}

/// One entry in [`CommitRequest::remote_routing`].
#[derive(Debug, Deserialize, Clone)]
pub struct RemoteRoutingHint {
    /// Base64 32-byte user_id of the joiner who lives on a remote
    /// server.
    pub joiner_user_id_b64: String,
    /// Base URL of that joiner's home server, including scheme +
    /// optional port (e.g. `http://localhost:4444`).
    pub home_server_base_url: String,
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
        commit: commit.clone(),
        welcomes: welcomes.clone(),
    };
    append_commit(&state, gid, entry).await;
    let welcomes_accepted = welcomes.len();

    tracing::info!(
        group_prefix = ?&gid[..4],
        epoch = body.epoch,
        welcomes_accepted,
        remote_routes = body.remote_routing.len(),
        "commit accepted"
    );

    // Federation push: forward commit + the welcomes addressed to each
    // remote joiner to that joiner's home server. We push the FULL
    // welcome list per recipient (not just their slice) so peers see
    // the same commit log we do — they filter locally on read.
    if !body.remote_routing.is_empty() {
        let origin_host = body.origin_host.clone().unwrap_or_default();
        let origin_base_url = body.origin_base_url.clone().unwrap_or_default();
        crate::routes::federation::push_to_peers(
            &state,
            gid,
            body.epoch,
            &commit,
            &welcomes,
            &body.remote_routing,
            &origin_host,
            &origin_base_url,
        )
        .await;
    }

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
    let found = log.iter().rev().find_map(|entry| {
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
    /// Federation routing: each entry is the base URL of a peer
    /// server hosting one of this group's members. The server will
    /// federate-push the message to each peer's
    /// `/federation/message_inbox` so recipients can fetch from
    /// their own home server.
    #[serde(default)]
    pub remote_routing: Vec<String>,
    /// Submitter's claimed origin host (signed into the federation
    /// push). Defaults to empty.
    #[serde(default)]
    pub origin_host: Option<String>,
    /// Submitter's claimed origin base URL.
    #[serde(default)]
    pub origin_base_url: Option<String>,
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
    let seq = append_message(&state, gid, envelope.clone()).await;

    // Fan out to peers. The request body's `remote_routing` wins if
    // present (lets a client override topology per-send); otherwise
    // fall back to the per-group `group_replication` list stored
    // via PUT /group/:gid/replication_peers (M6 store-and-forward).
    let effective_peers: Vec<String> = if body.remote_routing.is_empty() {
        state
            .group_replication
            .read()
            .await
            .get(&gid)
            .cloned()
            .unwrap_or_default()
    } else {
        body.remote_routing.clone()
    };
    if !effective_peers.is_empty() {
        let origin_host = body.origin_host.clone().unwrap_or_default();
        let origin_base_url = body.origin_base_url.clone().unwrap_or_default();
        crate::routes::federation::push_message_to_peers(
            &state,
            gid,
            &envelope,
            &effective_peers,
            &origin_host,
            &origin_base_url,
        )
        .await;
    }
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
    let bytes = lattice_protocol::wire::encode(&cert);
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
        .route("/group/{gid_b64}/messages/ws", get(messages_ws_handler))
        .route("/group/{gid_b64}/issue_cert", post(issue_cert_handler))
        .route(
            "/group/{gid_b64}/replication_peers",
            post(set_replication_peers_handler).get(get_replication_peers_handler),
        )
}

/// `PUT/POST /group/:gid/replication_peers` body — list of peer
/// base URLs that should mirror this group's traffic.
#[derive(Debug, Deserialize)]
pub struct SetReplicationPeersRequest {
    /// Peer base URLs (e.g. `["http://cnc:4443", "http://pixie:4444"]`).
    pub peers: Vec<String>,
}

/// `GET /group/:gid/replication_peers` response.
#[derive(Debug, Serialize)]
pub struct GetReplicationPeersResponse {
    /// Currently-configured peer list. Empty if none.
    pub peers: Vec<String>,
}

async fn set_replication_peers_handler(
    State(state): State<ServerState>,
    Path(gid_b64): Path<String>,
    Json(body): Json<SetReplicationPeersRequest>,
) -> Result<Json<GetReplicationPeersResponse>, (StatusCode, String)> {
    let gid: [u8; 16] = decode_b64(&gid_b64)?;
    let mut map = state.group_replication.write().await;
    map.insert(gid, body.peers.clone());
    Ok(Json(GetReplicationPeersResponse { peers: body.peers }))
}

async fn get_replication_peers_handler(
    State(state): State<ServerState>,
    Path(gid_b64): Path<String>,
) -> Result<Json<GetReplicationPeersResponse>, (StatusCode, String)> {
    let gid: [u8; 16] = decode_b64(&gid_b64)?;
    let map = state.group_replication.read().await;
    let peers = map.get(&gid).cloned().unwrap_or_default();
    Ok(Json(GetReplicationPeersResponse { peers }))
}

/// `GET /group/:gid/messages/ws` — WebSocket upgrade. Each
/// `(seq, envelope_bytes)` posted to the group via
/// `POST /group/:gid/messages` after the connection is established
/// is pushed to the client as a JSON text frame
/// `{ "seq": …, "envelope_b64": "…" }`.
///
/// Catch-up before subscribe: clients should query
/// `GET /group/:gid/messages?since=N` once on connect; the WS stream
/// covers only messages received AFTER the broadcast subscription
/// attached.
///
/// γ.4 D-11 fallback tier — WebTransport gets a similar handler
/// once the server-side QUIC stack lands.
async fn messages_ws_handler(
    State(state): State<ServerState>,
    Path(gid_b64): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let gid: [u8; 16] = decode_b64(&gid_b64)?;
    Ok(ws.on_upgrade(move |socket| handle_messages_ws(state, gid, socket)))
}

async fn handle_messages_ws(
    state: ServerState,
    gid: [u8; 16],
    mut socket: WebSocket,
) {
    let mut rx = state.subscribe(gid).await;
    let b64 = base64::engine::general_purpose::STANDARD;
    tracing::info!(gid_prefix = ?&gid[..4], "ws subscriber attached");
    loop {
        tokio::select! {
            push = rx.recv() => match push {
                Ok((seq, envelope)) => {
                    let frame = serde_json::json!({
                        "seq": seq,
                        "envelope_b64": b64.encode(&envelope),
                    });
                    if let Err(e) = socket
                        .send(WsMessage::Text(frame.to_string().into()))
                        .await
                    {
                        tracing::debug!(error = %e, "ws send failed; closing");
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    tracing::debug!("ws broadcast closed");
                    return;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(missed = n, "ws subscriber lagged; reconnect");
                    return;
                }
            },
            // Drain any pings / disconnects from the client so the
            // socket health check works.
            inbound = socket.recv() => match inbound {
                Some(Ok(WsMessage::Close(_))) | None => return,
                Some(Err(e)) => {
                    tracing::debug!(error = %e, "ws recv error");
                    return;
                }
                _ => {}
            },
        }
    }
}
