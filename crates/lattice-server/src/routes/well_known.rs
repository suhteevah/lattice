//! `.well-known/lattice/server` descriptor endpoint per D-06.
//!
//! Returns the server's federation pubkey and basic metadata. The full
//! signed-descriptor flow (with canonical-CBOR signed_at + signature)
//! is a follow-up; M3 ships the minimal JSON that lets peers TOFU-pin
//! the pubkey.

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;

use crate::state::ServerState;

#[derive(Debug, Serialize)]
pub struct ServerDescriptor {
    /// Wire protocol version supported (currently 1).
    pub wire_version: u32,
    /// Server's federation Ed25519 pubkey, base64-encoded.
    pub federation_pubkey_b64: String,
    /// Server software version string.
    pub server_version: String,
}

async fn descriptor_handler(State(state): State<ServerState>) -> Json<ServerDescriptor> {
    Json(ServerDescriptor {
        wire_version: lattice_protocol::WIRE_VERSION,
        federation_pubkey_b64: state.federation_pubkey_b64.clone(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

pub fn router() -> Router<ServerState> {
    Router::new().route("/.well-known/lattice/server", get(descriptor_handler))
}
