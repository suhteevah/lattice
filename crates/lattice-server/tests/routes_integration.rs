//! In-process integration test for the M3 single-server route surface.
//!
//! Spawns the server on a randomly-bound localhost port, exercises
//! register / publish-KP / fetch-KP / commit / welcome / messages /
//! issue_cert end-to-end. The MLS state is fabricated against the
//! real `lattice-crypto::mls::*` helpers so we know the wire shapes
//! match what the CLI will produce.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::redundant_clone,
    clippy::too_many_lines,
    clippy::items_after_statements
)]

use base64::Engine;
use ed25519_dalek::SigningKey;
use lattice_crypto::credential::{ED25519_PK_LEN, LatticeCredential, USER_ID_LEN};
use lattice_crypto::mls::{
    LatticeIdentity, add_member, apply_commit, cipher_suite::LATTICE_HYBRID_V1, create_group,
    encrypt_application, generate_key_package, leaf_node_kem::KemKeyPair, psk::LatticePskStorage,
};
use lattice_server::state::ServerState;
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use rand::rngs::OsRng;
use rand_core::RngCore;
use tokio::net::TcpListener;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn make_identity(user_id_byte: u8) -> LatticeIdentity {
    let provider = lattice_crypto::mls::cipher_suite::LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .expect("suite");
    let (sk, pk) = suite.signature_key_generate().expect("keygen");
    let pk_bytes = pk.as_bytes();
    let mut ed25519_pub = [0u8; ED25519_PK_LEN];
    ed25519_pub.copy_from_slice(&pk_bytes[..ED25519_PK_LEN]);
    let ml_dsa_pub = pk_bytes[ED25519_PK_LEN..].to_vec();
    LatticeIdentity {
        credential: LatticeCredential {
            user_id: [user_id_byte; USER_ID_LEN],
            ed25519_pub,
            ml_dsa_pub,
        },
        signature_secret: sk,
        kem_keypair: KemKeyPair::generate(),
        key_package_repo: mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage::default(),
    }
}

async fn spawn_server() -> (String, ServerState) {
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).unwrap();
    let federation_sk = SigningKey::from_bytes(&seed);
    let state = ServerState::new_with_federation_key(federation_sk);
    let app = lattice_server::app(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

#[tokio::test]
async fn well_known_returns_federation_pubkey() {
    let (base, state) = spawn_server().await;
    let client = reqwest::Client::new();
    let r: serde_json::Value = client
        .get(format!("{base}/.well-known/lattice/server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["wire_version"], 3);
    assert_eq!(r["federation_pubkey_b64"], state.federation_pubkey_b64);
}

#[tokio::test]
async fn register_then_publish_then_fetch_key_package() {
    let (base, _) = spawn_server().await;
    let alice = make_identity(0xAA);
    let mut alice_psk = LatticePskStorage::new();
    let _ = &mut alice_psk;

    let client = reqwest::Client::new();

    // Register.
    let claim = lattice_protocol::wire::IdentityClaim::default();
    let claim_bytes = lattice_protocol::wire::encode(&claim);
    let r: serde_json::Value = client
        .post(format!("{base}/register"))
        .json(&serde_json::json!({
            "user_id_b64": B64.encode(alice.credential.user_id),
            "claim_b64": B64.encode(&claim_bytes),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["new_registration"], true);

    // Publish a KeyPackage produced by the real crypto layer.
    let kp_bytes = generate_key_package(&alice, LatticePskStorage::new()).unwrap();
    let r: serde_json::Value = client
        .post(format!("{base}/key_packages"))
        .json(&serde_json::json!({
            "user_id_b64": B64.encode(alice.credential.user_id),
            "key_package_b64": B64.encode(&kp_bytes),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(r["published_at"].as_i64().unwrap() > 0);

    // Fetch it back.
    let user_id_b64 = B64.encode(alice.credential.user_id);
    let fetched: serde_json::Value = client
        .get(format!("{base}/key_packages/{user_id_b64}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched["key_package_b64"], B64.encode(&kp_bytes));
}

#[tokio::test]
async fn publishing_kp_without_register_fails() {
    let (base, _) = spawn_server().await;
    let alice = make_identity(0xBB);
    let kp_bytes = generate_key_package(&alice, LatticePskStorage::new()).unwrap();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/key_packages"))
        .json(&serde_json::json!({
            "user_id_b64": B64.encode(alice.credential.user_id),
            "key_package_b64": B64.encode(&kp_bytes),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn commit_welcome_message_round_trip_single_server() {
    // Alice creates a group, invites Bob via the server, sends a
    // message; Bob fetches the welcome, joins, fetches the message,
    // decrypts.
    let (base, _) = spawn_server().await;
    let alice = make_identity(0xAA);
    let bob = make_identity(0xBB);
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();
    let client = reqwest::Client::new();

    // Register both users (claim payload is a default-encoded
    // IdentityClaim — empty bytes aren't a valid Cap'n Proto frame
    // since v3).
    let empty_claim = lattice_protocol::wire::encode(
        &lattice_protocol::wire::IdentityClaim::default(),
    );
    for user_id in [alice.credential.user_id, bob.credential.user_id] {
        let r: serde_json::Value = client
            .post(format!("{base}/register"))
            .json(&serde_json::json!({
                "user_id_b64": B64.encode(user_id),
                "claim_b64": B64.encode(&empty_claim),
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(r["new_registration"], true);
    }

    // Bob publishes his KeyPackage so Alice can fetch it.
    let bob_kp = generate_key_package(&bob, bob_psk.clone()).unwrap();
    client
        .post(format!("{base}/key_packages"))
        .json(&serde_json::json!({
            "user_id_b64": B64.encode(bob.credential.user_id),
            "key_package_b64": B64.encode(&bob_kp),
        }))
        .send()
        .await
        .unwrap();

    // Alice fetches Bob's KP and creates a group.
    let bob_user_b64 = B64.encode(bob.credential.user_id);
    let fetched: serde_json::Value = client
        .get(format!("{base}/key_packages/{bob_user_b64}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bob_kp_bytes = B64
        .decode(fetched["key_package_b64"].as_str().unwrap())
        .unwrap();

    let group_id = *b"int-test-1234567";
    let mut alice_group = create_group(&alice, alice_psk.clone(), &group_id).unwrap();
    let commit_output = add_member(&mut alice_group, &bob_kp_bytes).unwrap();
    apply_commit(&mut alice_group).unwrap();

    // Alice POSTs the commit + welcome to the server.
    let welcome = commit_output.welcomes.into_iter().next().unwrap();
    let pq_payload_bytes = {
        use mls_rs::mls_rs_codec::MlsEncode;
        welcome.pq_payload.mls_encode_to_vec().unwrap()
    };
    let gid_b64 = B64.encode(group_id);
    let r: serde_json::Value = client
        .post(format!("{base}/group/{gid_b64}/commit"))
        .json(&serde_json::json!({
            "epoch": 1,
            "commit_b64": B64.encode(&commit_output.commit),
            "welcomes": [{
                "joiner_user_id_b64": B64.encode(bob.credential.user_id),
                "mls_welcome_b64": B64.encode(&welcome.mls_welcome),
                "pq_payload_b64": B64.encode(&pq_payload_bytes),
            }],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["welcomes_accepted"], 1);

    // Bob fetches his welcome.
    let bob_b64 = B64.encode(bob.credential.user_id);
    let w: serde_json::Value = client
        .get(format!("{base}/group/{gid_b64}/welcome/{bob_b64}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mls_welcome = B64.decode(w["mls_welcome_b64"].as_str().unwrap()).unwrap();
    let pq_payload_bytes_back = B64.decode(w["pq_payload_b64"].as_str().unwrap()).unwrap();

    // Bob reconstructs the LatticeWelcome and joins.
    use mls_rs::mls_rs_codec::MlsDecode;
    let pq_payload =
        lattice_crypto::mls::welcome_pq::PqWelcomePayload::mls_decode(&mut &*pq_payload_bytes_back)
            .unwrap();
    let lattice_welcome = lattice_crypto::mls::LatticeWelcome {
        mls_welcome,
        pq_payload,
    };
    let mut bob_group =
        lattice_crypto::mls::process_welcome(&bob, bob_psk.clone(), &lattice_welcome).unwrap();

    // Alice sends a message via the server.
    let ct = encrypt_application(&mut alice_group, b"hello over the wire").unwrap();
    let r: serde_json::Value = client
        .post(format!("{base}/group/{gid_b64}/messages"))
        .json(&serde_json::json!({
            "envelope_b64": B64.encode(&ct),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let seq = r["seq"].as_u64().unwrap();
    assert!(seq > 0);

    // Bob fetches and decrypts.
    let resp: serde_json::Value = client
        .get(format!("{base}/group/{gid_b64}/messages?since=0"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let messages = resp["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    let envelope = B64
        .decode(messages[0]["envelope_b64"].as_str().unwrap())
        .unwrap();
    let plaintext = lattice_crypto::mls::decrypt(&mut bob_group, &envelope).unwrap();
    assert_eq!(plaintext, b"hello over the wire");
}

#[tokio::test]
async fn issue_cert_returns_valid_membership_cert() {
    let (base, state) = spawn_server().await;
    let client = reqwest::Client::new();

    // Generate an ephemeral Ed25519 keypair (the client's cert pair).
    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).unwrap();
    let eph_sk = SigningKey::from_bytes(&seed);
    let eph_pk = eph_sk.verifying_key();

    let group_id = [0x77u8; 16];
    let gid_b64 = B64.encode(group_id);
    let valid_until = chrono::Utc::now().timestamp() + 3600;

    let r: serde_json::Value = client
        .post(format!("{base}/group/{gid_b64}/issue_cert"))
        .json(&serde_json::json!({
            "epoch": 1,
            "ephemeral_pubkey_b64": B64.encode(eph_pk.to_bytes()),
            "valid_until": valid_until,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cert_bytes = B64.decode(r["cert_b64"].as_str().unwrap()).unwrap();
    let cert = lattice_protocol::wire::decode::<lattice_protocol::wire::MembershipCert>(
        cert_bytes.as_slice(),
    )
    .unwrap();

    // The cert should round-trip a sealed-sender envelope verify.
    let env = lattice_protocol::sealed_sender::seal(cert, &eph_sk, b"some inner".to_vec()).unwrap();
    lattice_protocol::sealed_sender::verify_at_router(
        &state.federation_sk.verifying_key(),
        &env,
        valid_until - 60,
    )
    .unwrap();
}

#[tokio::test]
async fn replication_peers_round_trip() {
    // M6 / ROADMAP §M6 acceptance: per-group replication list
    // (store-and-forward topology) can be set + read back. The
    // actual cross-server delivery is exercised in the existing
    // cross-host federation tests; this verifies the per-group list
    // round-trips through the new endpoint pair.
    let (base, _state) = spawn_server().await;
    let client = reqwest::Client::new();
    let gid: [u8; 16] = *b"replication-rt!!";
    let gid_b64 = B64.encode(gid);

    // Initially empty.
    let r: serde_json::Value = client
        .get(format!("{base}/group/{gid_b64}/replication_peers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["peers"].as_array().unwrap().len(), 0);

    // Set a list.
    let peers = vec![
        "http://cnc.lattice.local:4443".to_string(),
        "http://pixie.lattice.local:4443".to_string(),
    ];
    let r: serde_json::Value = client
        .post(format!("{base}/group/{gid_b64}/replication_peers"))
        .json(&serde_json::json!({ "peers": peers }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let got_peers: Vec<String> = r["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(got_peers, peers);

    // Read back.
    let r: serde_json::Value = client
        .get(format!("{base}/group/{gid_b64}/replication_peers"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let got_peers: Vec<String> = r["peers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(got_peers, peers);
}

#[tokio::test]
async fn push_subscription_round_trip() {
    // M6 / D-17: a client registers a Web Push API subscription
    // and reads it back. Multiple endpoints per user (UnifiedPush
    // primary + FCM/APNS fallback) coexist.
    let (base, _state) = spawn_server().await;
    let client = reqwest::Client::new();
    let alice = make_identity(0xCD);
    let user_id_b64 = B64.encode(alice.credential.user_id);

    // Initially empty.
    let r: serde_json::Value = client
        .get(format!("{base}/push/subscriptions/{user_id_b64}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["subscriptions"].as_array().unwrap().len(), 0);

    // Register a UnifiedPush subscription.
    let r: serde_json::Value = client
        .post(format!("{base}/push/subscribe"))
        .json(&serde_json::json!({
            "user_id_b64": user_id_b64,
            "endpoint": "https://up.example.org/push/abc123",
            "p256dh_b64": B64.encode([1u8; 65]),
            "auth_b64": B64.encode([2u8; 16]),
            "distributor": "unifiedpush",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["new_subscription"], true);
    assert_eq!(r["total_subscriptions"], 1);

    // Add an FCM fallback subscription for the same user.
    let r: serde_json::Value = client
        .post(format!("{base}/push/subscribe"))
        .json(&serde_json::json!({
            "user_id_b64": user_id_b64,
            "endpoint": "https://fcm.googleapis.com/fcm/send/xyz",
            "p256dh_b64": B64.encode([3u8; 65]),
            "auth_b64": B64.encode([4u8; 16]),
            "distributor": "fcm",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["new_subscription"], true);
    assert_eq!(r["total_subscriptions"], 2);

    // Re-register the FCM endpoint with new keys (rotation case).
    let r: serde_json::Value = client
        .post(format!("{base}/push/subscribe"))
        .json(&serde_json::json!({
            "user_id_b64": user_id_b64,
            "endpoint": "https://fcm.googleapis.com/fcm/send/xyz",
            "p256dh_b64": B64.encode([5u8; 65]),
            "auth_b64": B64.encode([6u8; 16]),
            "distributor": "fcm",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["new_subscription"], false);
    assert_eq!(r["total_subscriptions"], 2);

    // List and verify both endpoints + distributors are present.
    let r: serde_json::Value = client
        .get(format!("{base}/push/subscriptions/{user_id_b64}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let subs = r["subscriptions"].as_array().unwrap();
    assert_eq!(subs.len(), 2);
    let distributors: Vec<&str> = subs
        .iter()
        .map(|s| s["distributor"].as_str().unwrap())
        .collect();
    assert!(distributors.contains(&"unifiedpush"));
    assert!(distributors.contains(&"fcm"));
}
