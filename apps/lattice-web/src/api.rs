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
use lattice_protocol::wire::{IdentityClaim, encode};
use serde::Deserialize;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

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
