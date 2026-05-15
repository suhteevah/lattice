//! Identity-layer routes: `/register`, `/key_packages`.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::state::{
    PublishedKeyPackage, RegisteredUser, ServerState, fetch_key_package, put_key_package,
    register_user,
};
use lattice_protocol::wire::IdentityClaim;

/// Wire shape for `POST /register`.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Base64 of the 32-byte user_id.
    pub user_id_b64: String,
    /// Base64 of the Prost-encoded `IdentityClaim`.
    pub claim_b64: String,
}

/// Wire shape for `POST /register` response.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    /// True if this was a fresh registration; false if the user_id was
    /// already known (claim was updated in place).
    pub new_registration: bool,
}

/// `POST /register` handler. Accepts a base64 user_id + base64
/// `IdentityClaim`, stores in the in-memory registry.
///
/// If `state.registration_token` is set, the request must carry
/// `Authorization: Bearer <token>` with constant-time-equal bytes,
/// otherwise it is rejected with 401. Other endpoints stay open —
/// federation peers must continue to be able to fetch KPs for
/// arbitrary user_ids, and the federation push surface authenticates
/// via its own Ed25519 signed-TBS pattern.
async fn register_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    if let Some(expected) = state.registration_token.as_deref() {
        let supplied = headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let ok = supplied
            .map(|s| s.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1)
            .unwrap_or(false);
        if !ok {
            tracing::warn!(
                supplied_token_present = supplied.is_some(),
                "register rejected: bad or missing token"
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                "registration token required".into(),
            ));
        }
    }

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
    let claim_bytes = b64
        .decode(&body.claim_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("claim_b64 decode: {e}")))?;
    let claim = lattice_protocol::wire::decode::<IdentityClaim>(claim_bytes.as_slice())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("claim decode: {e}")))?;

    let now = chrono::Utc::now().timestamp();
    let new_registration = register_user(
        &state,
        RegisteredUser {
            user_id,
            claim,
            registered_at: now,
        },
    )
    .await;
    tracing::info!(
        new_registration,
        user_id_prefix = ?&user_id[..4],
        "user registered"
    );
    Ok(Json(RegisterResponse { new_registration }))
}

/// Wire shape for `POST /key_packages`.
#[derive(Debug, Deserialize)]
pub struct PublishKeyPackageRequest {
    /// Base64 of the 32-byte user_id.
    pub user_id_b64: String,
    /// Base64 of the `MlsMessage::mls_encode_to_vec()` KeyPackage bytes.
    pub key_package_b64: String,
}

/// Wire shape for `POST /key_packages` response.
#[derive(Debug, Serialize)]
pub struct PublishKeyPackageResponse {
    /// Echo back of the published_at timestamp.
    pub published_at: i64,
}

/// `POST /key_packages` handler.
async fn publish_kp_handler(
    State(state): State<ServerState>,
    Json(body): Json<PublishKeyPackageRequest>,
) -> Result<Json<PublishKeyPackageResponse>, (StatusCode, String)> {
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
    let key_package = b64.decode(&body.key_package_b64).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("key_package_b64 decode: {e}"),
        )
    })?;

    // Validate the user is registered before accepting a KP.
    if state.users.read().await.get(&user_id).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "user_id not registered — call /register first".into(),
        ));
    }
    let now = chrono::Utc::now().timestamp();
    put_key_package(
        &state,
        PublishedKeyPackage {
            user_id,
            key_package,
            published_at: now,
        },
    )
    .await;
    tracing::info!(
        user_id_prefix = ?&user_id[..4],
        kp_bytes = body.key_package_b64.len(),
        "key package published"
    );
    Ok(Json(PublishKeyPackageResponse { published_at: now }))
}

/// Wire shape for `GET /key_packages/:user_id_b64` response.
#[derive(Debug, Serialize)]
pub struct FetchKeyPackageResponse {
    /// Base64 of the KeyPackage bytes.
    pub key_package_b64: String,
    /// Unix-epoch seconds when the KP was published.
    pub published_at: i64,
}

/// `GET /key_packages/:user_id_b64` handler.
async fn fetch_kp_handler(
    State(state): State<ServerState>,
    Path(user_id_b64): Path<String>,
) -> Result<Json<FetchKeyPackageResponse>, (StatusCode, String)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    // Path segments use URL-safe alphabet by convention but we still try
    // standard first to keep clients simple.
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

    let kp = fetch_key_package(&state, user_id).await.ok_or((
        StatusCode::NOT_FOUND,
        "no published KeyPackage for that user".into(),
    ))?;
    Ok(Json(FetchKeyPackageResponse {
        key_package_b64: b64.encode(&kp.key_package),
        published_at: kp.published_at,
    }))
}

/// Build the identity router fragment.
pub fn router() -> Router<ServerState> {
    Router::new()
        .route("/register", post(register_handler))
        .route("/key_packages", post(publish_kp_handler))
        .route("/key_packages/{user_id_b64}", get(fetch_kp_handler))
}

// `IntoResponse` for our error type lets `?` work inside handlers.
const _: fn(StatusCode) -> StatusCode = std::convert::identity;
fn _ensure_intoresponse_compat() -> impl IntoResponse {
    StatusCode::OK
}
