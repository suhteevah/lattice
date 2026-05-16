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
pub mod state;

/// Build the full Axum router with all middleware applied.
///
/// Exposed so integration tests can spin up the app in-process via
/// `axum::serve` against a randomly-bound port.
pub fn app(state: state::ServerState) -> axum::Router {
    use tower_http::cors::{Any, CorsLayer};
    use tower_http::trace::TraceLayer;

    // CORS for the browser client. We accept any origin in dev because
    // Trunk serves the SPA on a different port than this server; in
    // production the home server fronts both and same-origin makes this
    // unnecessary. Wildcard origin with no credentials is the safe
    // combination per the Fetch spec — we never set cookies, so there's
    // no `Access-Control-Allow-Credentials` to leak.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    axum::Router::new()
        .merge(routes::health::router())
        .merge(routes::well_known::router().with_state(state.clone()))
        .merge(routes::identity::router().with_state(state.clone()))
        .merge(routes::admin::router().with_state(state.clone()))
        .merge(routes::groups::router().with_state(state.clone()))
        .merge(routes::push::router().with_state(state.clone()))
        .merge(routes::federation::router().with_state(state))
        .layer(cors)
        .layer(
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
