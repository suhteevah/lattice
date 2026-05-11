//! `/health` endpoint. Returns service liveness and component checks.

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};

/// Build the health router fragment.
#[must_use]
pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

#[tracing::instrument(level = "debug")]
async fn health() -> Json<Value> {
    tracing::debug!("health check");
    Json(json!({
        "status": "ok",
        "service": "lattice-server",
        "version": env!("CARGO_PKG_VERSION"),
        "wire_version": lattice_protocol::WIRE_VERSION,
    }))
}
