//! Thin HTTP client for the M3 `lattice-server` REST surface.
//!
//! Mirrors the per-flow shape used by `crates/lattice-cli/src/main.rs`
//! (`register`, `publish_kp`, `fetch_kp`, …) but uses `gloo-net` so the
//! same logic runs in the browser. Server-side CORS is wired in
//! `lattice_server::app()` — see the workspace handoff.
//!
//! The API surface is deliberately tiny right now (just `register`); the
//! rest of the per-action methods land in later M4 γ sub-phases as the
//! browser UI gains more buttons.

use base64::Engine;
use gloo_net::http::Request;
use lattice_crypto::mls::LatticeIdentity;
use lattice_crypto::mls::psk::LatticePskStorage;
use lattice_protocol::wire::{IdentityClaim, encode};
use serde::Deserialize;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Mirror of `lattice_server::routes::identity::RegisterResponse`.
///
/// The server returns `{ "new_registration": bool }` and nothing else;
/// we only decode the bool flag.
#[derive(Debug, Deserialize)]
struct RegisterResponse {
    new_registration: bool,
}

/// `POST /register` against a `lattice-server` URL.
///
/// Encodes a (currently empty) `IdentityClaim` placeholder per
/// `lattice_cli::register_raw` — the server today accepts any
/// well-formed Prost claim and does not yet verify the hybrid signature
/// against the credential. Returns the server's `new_registration` flag
/// (`true` on first registration, `false` if the user_id was already
/// known and the claim was overwritten in place).
///
/// # Errors
///
/// Returns a `String` describing where the call failed — network
/// reachability, non-2xx status, or JSON decode mismatch. Errors are
/// surfaced to the UI as-is.
pub async fn register(server: &str, identity: &LatticeIdentity) -> Result<bool, String> {
    let claim_bytes = encode(&IdentityClaim::default());
    let body = serde_json::json!({
        "user_id_b64": B64.encode(identity.credential.user_id),
        "claim_b64": B64.encode(&claim_bytes),
    });

    let request = Request::post(&format!("{server}/register"))
        .json(&body)
        .map_err(|e| format!("build register request: {e}"))?;

    let response = request
        .send()
        .await
        .map_err(|e| format!("send register: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "register HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }

    let parsed: RegisterResponse = response
        .json()
        .await
        .map_err(|e| format!("decode register response: {e}"))?;
    Ok(parsed.new_registration)
}

/// Mirror of `lattice_server::routes::identity::PublishKeyPackageResponse`.
#[derive(Debug, Deserialize)]
struct PublishKpResponse {
    published_at: i64,
}

/// Mirror of `lattice_server::routes::identity::FetchKeyPackageResponse`.
#[derive(Debug, Deserialize)]
struct FetchKpResponse {
    key_package_b64: String,
    #[allow(dead_code)] // surfaced through publish flow; fetch returns it too
    published_at: i64,
}

/// `POST /key_packages` — generate a KeyPackage for `identity` and
/// publish it to the server.
///
/// Returns the server-reported `published_at` timestamp on success.
/// Generates the KeyPackage in-WASM via
/// `lattice_crypto::mls::generate_key_package`, using the caller's
/// `LatticePskStorage` so the eventual `process_welcome` step can
/// recover the PQ secret.
///
/// # Errors
///
/// Surfaces failure points individually — KP generation, request
/// build, send, non-2xx, JSON decode.
pub async fn publish_key_package(
    server: &str,
    identity: &LatticeIdentity,
    psk_store: &LatticePskStorage,
) -> Result<i64, String> {
    let kp_bytes = lattice_crypto::mls::generate_key_package(identity, psk_store.clone())
        .map_err(|e| format!("generate_key_package: {e}"))?;
    let body = serde_json::json!({
        "user_id_b64": B64.encode(identity.credential.user_id),
        "key_package_b64": B64.encode(&kp_bytes),
    });

    let response = Request::post(&format!("{server}/key_packages"))
        .json(&body)
        .map_err(|e| format!("build publish_kp request: {e}"))?
        .send()
        .await
        .map_err(|e| format!("send publish_kp: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "publish_kp HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }

    let parsed: PublishKpResponse = response
        .json()
        .await
        .map_err(|e| format!("decode publish_kp response: {e}"))?;
    Ok(parsed.published_at)
}

/// `GET /key_packages/:user_id_b64url` — fetch the latest published
/// KeyPackage for a user, returning the raw bytes ready to feed back
/// into `lattice_crypto::mls::add_member`.
///
/// We pass the user_id in URL-safe base64 (no padding) to keep clean
/// path segments. The server tries both encodings on its end.
///
/// # Errors
///
/// 404 when no KP has been published for that user — surfaced as a
/// clear string so the UI can distinguish missing-state from network.
pub async fn fetch_key_package(
    server: &str,
    user_id: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let user_id_b64url = B64URL.encode(user_id);
    let response = Request::get(&format!("{server}/key_packages/{user_id_b64url}"))
        .send()
        .await
        .map_err(|e| format!("send fetch_kp: {e}"))?;

    if !response.ok() {
        return Err(format!(
            "fetch_kp HTTP {} ({})",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string())
        ));
    }

    let parsed: FetchKpResponse = response
        .json()
        .await
        .map_err(|e| format!("decode fetch_kp response: {e}"))?;
    B64.decode(&parsed.key_package_b64)
        .map_err(|e| format!("decode key_package_b64: {e}"))
}
