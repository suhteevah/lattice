//! Integration tests for the v2 invite-token registration path.
//!
//! Covers the full mint → register → list cycle plus single-spend
//! enforcement under concurrency.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
)]

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use rand::rngs::OsRng;
use rand_core::RngCore;
use serde_json::json;
use tokio::net::TcpListener;

use lattice_server::state::ServerState;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Bind an in-process axum server on an OS-assigned port, return base URL.
async fn spawn_server(state: ServerState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let app = lattice_server::app(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{addr}")
}

/// Build a valid `/register` JSON body for a freshly-generated random identity.
///
/// Uses `IdentityClaim::default()` (the same approach as the CLI's
/// `register_raw`) encoded via `lattice_protocol::wire::encode`, paired with
/// a 32-byte random `user_id`. Each call produces a distinct identity so
/// concurrent race-test calls won't collide on `user_id`.
fn fake_register_body() -> serde_json::Value {
    let mut user_id = [0u8; 32];
    OsRng.try_fill_bytes(&mut user_id).expect("OsRng");

    let claim = lattice_protocol::wire::IdentityClaim::default();
    let claim_bytes = lattice_protocol::wire::encode(&claim);

    json!({
        "user_id_b64": B64.encode(user_id),
        "claim_b64": B64.encode(&claim_bytes),
    })
}

// ============================================================================
// Task 11: full mint → register → list flow
// ============================================================================

/// Happy path: mint a token, register with it, verify token shows consumed.
#[tokio::test]
async fn register_consumes_a_minted_invite() {
    let state = ServerState::new_test().with_admin_api_key("admin-secret");
    let url = spawn_server(state).await;
    let client = reqwest::Client::new();

    // Mint a token via the admin endpoint.
    let mint_resp: serde_json::Value = client
        .post(format!("{url}/admin/tokens"))
        .header("X-Lattice-Admin-Key", "admin-secret")
        .json(&json!({ "label": "test-invite", "ttl_secs": 3600 }))
        .send()
        .await
        .expect("mint POST")
        .json()
        .await
        .expect("mint JSON");

    let token = mint_resp["token"].as_str().expect("token field").to_string();
    assert!(mint_resp["consumed_at"].is_null(), "freshly minted token must not be consumed");

    // Register with the minted token.
    let reg_resp = client
        .post(format!("{url}/register"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&fake_register_body())
        .send()
        .await
        .expect("register POST");
    assert_eq!(reg_resp.status().as_u16(), 200, "first register must succeed");
    let body: serde_json::Value = reg_resp.json().await.expect("register JSON");
    assert_eq!(body["new_registration"], true);

    // List tokens and verify the token is now marked consumed.
    let list: Vec<serde_json::Value> = client
        .get(format!("{url}/admin/tokens"))
        .header("X-Lattice-Admin-Key", "admin-secret")
        .send()
        .await
        .expect("list GET")
        .json()
        .await
        .expect("list JSON");

    let entry = list.iter().find(|t| t["token"] == token).expect("token in list");
    assert!(
        !entry["consumed_at"].is_null(),
        "token must be marked consumed after register"
    );
}

/// Supplying an unknown (not minted) token must yield 401.
#[tokio::test]
async fn register_rejects_unknown_token() {
    let state = ServerState::new_test().with_admin_api_key("admin-secret");
    let url = spawn_server(state.clone()).await;
    let client = reqwest::Client::new();

    // Mint one token so the registry is non-empty (triggers token gating).
    client
        .post(format!("{url}/admin/tokens"))
        .header("X-Lattice-Admin-Key", "admin-secret")
        .json(&json!({ "label": "real-invite" }))
        .send()
        .await
        .expect("mint POST");

    // Register with a completely different bearer value.
    let status = client
        .post(format!("{url}/register"))
        .header("Authorization", "Bearer this-token-was-never-minted")
        .json(&fake_register_body())
        .send()
        .await
        .expect("register POST")
        .status()
        .as_u16();

    assert_eq!(status, 401, "unknown token must be rejected with 401");
}

/// Using the same token twice must yield 200 then 401.
#[tokio::test]
async fn register_rejects_consumed_token() {
    let state = ServerState::new_test().with_admin_api_key("admin-secret");
    let url = spawn_server(state).await;
    let client = reqwest::Client::new();

    // Mint one invite.
    let mint_resp: serde_json::Value = client
        .post(format!("{url}/admin/tokens"))
        .header("X-Lattice-Admin-Key", "admin-secret")
        .json(&json!({}))
        .send()
        .await
        .expect("mint POST")
        .json()
        .await
        .expect("mint JSON");
    let token = mint_resp["token"].as_str().expect("token").to_string();

    // First register: must succeed.
    let first = client
        .post(format!("{url}/register"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&fake_register_body())
        .send()
        .await
        .expect("first register POST")
        .status()
        .as_u16();
    assert_eq!(first, 200, "first register with fresh token must succeed");

    // Second register with the same token: must fail.
    let second = client
        .post(format!("{url}/register"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&fake_register_body())
        .send()
        .await
        .expect("second register POST")
        .status()
        .as_u16();
    assert_eq!(second, 401, "second register with consumed token must fail with 401");
}

// ============================================================================
// Task 12: race test — exactly one winner under 200 concurrent POSTs
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_token_one_winner_under_concurrency() {
    let state = ServerState::new_test().with_admin_api_key("k");
    let issued = state.mint_invite_token(None, None).await;
    let url = spawn_server(state).await;
    let client = Arc::new(reqwest::Client::new());

    let mut handles = Vec::new();
    for _ in 0..200 {
        let c = client.clone();
        let u = url.clone();
        let t = issued.token.clone();
        handles.push(tokio::spawn(async move {
            c.post(format!("{u}/register"))
                .header("Authorization", format!("Bearer {t}"))
                .json(&fake_register_body())
                .send()
                .await
                .expect("send")
                .status()
                .as_u16()
        }));
    }

    let mut wins = 0u32;
    let mut losses = 0u32;
    for h in handles {
        match h.await.expect("join") {
            200 => wins += 1,
            401 => losses += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(wins, 1, "exactly one register should win the race");
    assert_eq!(losses, 199, "the other 199 should all 401");
}
