//! `/admin/*` routes — invite-token CRUD gated by X-Lattice-Admin-Key.
//!
//! The single-lookup `GET /admin/tokens/:token` route is deliberately
//! unauthenticated so the public `/invite/<t>` landing page can verify
//! an invite's state. The `InviteView` DTO returned omits the raw
//! `consumed_by` user_id; only a 4-byte hex prefix is exposed.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::HeaderName},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::state::{InviteToken, ServerState};

const ADMIN_KEY_HEADER: HeaderName = HeaderName::from_static("x-lattice-admin-key");

/// Verify the X-Lattice-Admin-Key header against state.admin_api_key.
/// Returns `Ok(())` on match. Returns 503 if admin is disabled, 401
/// if missing or wrong.
fn check_admin_key(state: &ServerState, headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let expected = match state.admin_api_key.as_deref() {
        Some(k) => k,
        None => return Err((StatusCode::SERVICE_UNAVAILABLE, "admin disabled on this server")),
    };
    let supplied = headers
        .get(&ADMIN_KEY_HEADER)
        .and_then(|h| h.to_str().ok());
    let ok = supplied
        .map(|s| s.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1)
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "admin authentication required"))
    }
}

#[derive(Debug, Deserialize)]
pub struct MintRequest {
    pub label: Option<String>,
    pub ttl_secs: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct InviteView {
    pub token: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub label: Option<String>,
    pub consumed_at: Option<i64>,
    pub consumed_by_prefix: Option<String>,
}

impl From<&InviteToken> for InviteView {
    fn from(i: &InviteToken) -> Self {
        Self {
            token: i.token.clone(),
            created_at: i.created_at,
            expires_at: i.expires_at,
            label: i.label.clone(),
            consumed_at: i.consumed_at,
            consumed_by_prefix: i
                .consumed_by
                .as_ref()
                .map(|u| hex::encode(&u[..4])),
        }
    }
}

async fn mint_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(body): Json<MintRequest>,
) -> Result<Json<InviteView>, (StatusCode, String)> {
    check_admin_key(&state, &headers).map_err(|(s, m)| (s, m.into()))?;
    let issued = state.mint_invite_token(body.label, body.ttl_secs).await;
    tracing::info!(
        token_prefix = &issued.token[..8],
        expires_at = issued.expires_at,
        label = ?issued.label,
        "invite minted"
    );
    Ok(Json((&issued).into()))
}

async fn list_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InviteView>>, (StatusCode, String)> {
    check_admin_key(&state, &headers).map_err(|(s, m)| (s, m.into()))?;
    let invites = state.list_invite_tokens().await;
    Ok(Json(invites.iter().map(InviteView::from).collect()))
}

async fn single_handler(
    State(state): State<ServerState>,
    Path(token): Path<String>,
) -> Result<Json<InviteView>, (StatusCode, String)> {
    // Deliberately UNAUTHENTICATED — see module-level doc comment.
    match state.invite_tokens.read().await.get(&token) {
        Some(t) => Ok(Json(t.into())),
        None => Err((StatusCode::NOT_FOUND, "unknown token".into())),
    }
}

async fn revoke_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    check_admin_key(&state, &headers).map_err(|(s, m)| (s, m.into()))?;
    if state.revoke_invite_token(&token).await {
        tracing::info!(token_prefix = &token[..8.min(token.len())], "invite revoked");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "unknown token".into()))
    }
}

pub fn router() -> Router<ServerState> {
    Router::new()
        .route("/admin/tokens", post(mint_handler).get(list_handler))
        .route(
            "/admin/tokens/{token}",
            get(single_handler).delete(revoke_handler),
        )
}
