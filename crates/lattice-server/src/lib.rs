//! # lattice-server (library surface)
//!
//! Re-exports the public module set so integration tests in `tests/` can
//! import them. Binary is at `src/main.rs`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod observability;
pub mod routes;

/// Build the full Axum router with all middleware applied.
///
/// Exposed so integration tests can spin up the app in-process via
/// `axum::serve` against a randomly-bound port.
pub fn app() -> axum::Router {
    use tower_http::trace::TraceLayer;

    axum::Router::new().merge(routes::health::router()).layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &axum::http::Request<_>| {
                let request_id = uuid::Uuid::new_v4();
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    uri = %request.uri(),
                    request_id = %request_id,
                )
            })
            .on_response(
                |response: &axum::http::Response<_>,
                 latency: std::time::Duration,
                 _span: &tracing::Span| {
                    tracing::info!(
                        status = response.status().as_u16(),
                        latency_ms = latency.as_millis(),
                        "Response sent",
                    );
                },
            )
            .on_failure(
                |error: tower_http::classify::ServerErrorsFailureClass,
                 latency: std::time::Duration,
                 _span: &tracing::Span| {
                    tracing::error!(?error, latency_ms = latency.as_millis(), "Request failed");
                },
            ),
    )
}
