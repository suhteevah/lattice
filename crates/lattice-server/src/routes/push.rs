//! Push-notification subscription routes (M6 / D-17).
//!
//! Implements two endpoints:
//!
//! * `POST /push/subscribe` — a client registers a Web Push API
//!   subscription `(endpoint, keys.p256dh, keys.auth, distributor)`
//!   under their user_id. Replaces any prior subscription with the
//!   same endpoint for that user. One user may register multiple
//!   subscriptions (multiple devices, primary UnifiedPush + FCM
//!   fallback, etc.).
//! * `GET /push/subscriptions/:user_id_b64` — read the user's
//!   active subscriptions. Used by other services that emit
//!   push payloads server-side; clients normally don't query this.
//!
//! Encryption / payload emission against the endpoints is a
//! separate path that consumes the registry on outgoing message
//! events. D-17 names the `web-push` crate as the per-payload
//! encryption shim; that integration lands alongside the actual
//! push-emit hook on `append_message`.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::state::{PushSubscription, ServerState};

/// `POST /push/subscribe` body.
#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    /// Owner user_id, base64.
    pub user_id_b64: String,
    /// Push provider endpoint URL.
    pub endpoint: String,
    /// Recipient public key (P-256), base64.
    pub p256dh_b64: String,
    /// Authentication secret (16 bytes), base64.
    pub auth_b64: String,
    /// Distributor label — informational only (see
    /// [`PushSubscription::distributor`]).
    #[serde(default)]
    pub distributor: Option<String>,
}

/// `POST /push/subscribe` response.
#[derive(Debug, Serialize)]
pub struct SubscribeResponse {
    /// True if this is a fresh subscription for `(user_id, endpoint)`;
    /// false if the endpoint already existed and was updated in
    /// place.
    pub new_subscription: bool,
    /// Count of distinct subscriptions on file for this user after
    /// the update.
    pub total_subscriptions: usize,
}

async fn subscribe_handler(
    State(state): State<ServerState>,
    Json(body): Json<SubscribeRequest>,
) -> Result<Json<SubscribeResponse>, (StatusCode, String)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let user_id_bytes = b64
        .decode(&body.user_id_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("user_id_b64 decode: {e}")))?;
    let user_id: [u8; 32] = user_id_bytes.as_slice().try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("user_id length {} (expected 32)", user_id_bytes.len()),
        )
    })?;

    let now = chrono::Utc::now().timestamp();
    let sub = PushSubscription {
        endpoint: body.endpoint.clone(),
        p256dh_b64: body.p256dh_b64,
        auth_b64: body.auth_b64,
        created_at: now,
        distributor: body
            .distributor
            .unwrap_or_else(|| "web-push".to_string()),
    };

    let mut subs = state.push_subscriptions.write().await;
    let entry = subs.entry(user_id).or_default();
    let existing = entry.iter_mut().find(|s| s.endpoint == sub.endpoint);
    let new_subscription;
    match existing {
        Some(s) => {
            *s = sub;
            new_subscription = false;
        }
        None => {
            entry.push(sub);
            new_subscription = true;
        }
    }
    let total = entry.len();
    Ok(Json(SubscribeResponse {
        new_subscription,
        total_subscriptions: total,
    }))
}

/// `GET /push/subscriptions/:user_id_b64` response.
#[derive(Debug, Serialize)]
pub struct ListResponse {
    /// Active subscriptions for this user. Empty if none registered.
    pub subscriptions: Vec<PushSubscription>,
}

async fn list_handler(
    State(state): State<ServerState>,
    Path(user_id_b64): Path<String>,
) -> Result<Json<ListResponse>, (StatusCode, String)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let user_id_bytes = b64
        .decode(&user_id_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&user_id_b64))
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("user_id_b64 decode: {e}")))?;
    let user_id: [u8; 32] = user_id_bytes.as_slice().try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("user_id length {} (expected 32)", user_id_bytes.len()),
        )
    })?;
    let subs = state.push_subscriptions.read().await;
    let subscriptions = subs.get(&user_id).cloned().unwrap_or_default();
    Ok(Json(ListResponse { subscriptions }))
}

/// Build the push-routes fragment.
pub fn router() -> Router<ServerState> {
    Router::new()
        .route("/push/subscribe", post(subscribe_handler))
        .route("/push/subscriptions/{user_id_b64}", get(list_handler))
}
