//! `lattice` — admin and developer CLI.
//!
//! The headline subcommand for M3 is `demo`, which orchestrates the
//! whole "Alice on server A invites Bob on server B and they exchange
//! a message" flow inside a single process. It proves the federation
//! bridge works end-to-end against two real `lattice-server`
//! instances. The per-action subcommands (`register`, `invite`, etc.)
//! still require file-backed per-invocation state, which is a
//! follow-up — for the M3 acceptance gate `demo` is sufficient.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines, clippy::large_futures)]

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use clap::{Parser, Subcommand};
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use tracing_subscriber::{EnvFilter, prelude::*};

use lattice_crypto::credential::{
    ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN, USER_ID_LEN,
};
use lattice_crypto::mls::cipher_suite::{LATTICE_HYBRID_V1, LatticeCryptoProvider};
use lattice_crypto::mls::leaf_node_kem::KemKeyPair;
use lattice_crypto::mls::psk::LatticePskStorage;
use lattice_crypto::mls::{
    LatticeIdentity, LatticeWelcome, add_member, apply_commit, create_group, decrypt,
    encrypt_application, generate_key_package, process_welcome,
};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, Parser)]
#[command(name = "lattice", version, about = "Lattice CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the M3 vertical-slice demo: Alice (on `--server-a`)
    /// invites Bob (on `--server-b`) into a group, sends `--message`,
    /// Bob receives + decrypts. Exits 0 on success and prints the
    /// recovered plaintext to stdout.
    Demo {
        /// Alice's home server base URL (e.g. `http://localhost:4443`).
        #[arg(long)]
        server_a: String,
        /// Bob's home server base URL (e.g. `http://localhost:4444`).
        #[arg(long)]
        server_b: String,
        /// Message Alice sends to Bob.
        #[arg(long, default_value = "hello, lattice")]
        message: String,
        /// Group ID (16 ASCII bytes). Defaults to a fixed test value.
        #[arg(long, default_value = "lattice-demo-001")]
        group_id: String,
    },
}

fn make_identity(user_id_byte: u8) -> Result<LatticeIdentity> {
    let provider = LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .ok_or_else(|| anyhow!("LATTICE_HYBRID_V1 cipher suite missing"))?;
    let (sk, pk) = suite
        .signature_key_generate()
        .map_err(|e| anyhow!("sig keygen: {e}"))?;
    let pk_bytes = pk.as_bytes();
    if pk_bytes.len() != ED25519_PK_LEN + ML_DSA_65_PK_LEN {
        return Err(anyhow!(
            "unexpected hybrid pk length {} (expected {})",
            pk_bytes.len(),
            ED25519_PK_LEN + ML_DSA_65_PK_LEN
        ));
    }
    let mut ed25519_pub = [0u8; ED25519_PK_LEN];
    ed25519_pub.copy_from_slice(&pk_bytes[..ED25519_PK_LEN]);
    let ml_dsa_pub = pk_bytes[ED25519_PK_LEN..].to_vec();
    Ok(LatticeIdentity {
        credential: LatticeCredential {
            user_id: [user_id_byte; USER_ID_LEN],
            ed25519_pub,
            ml_dsa_pub,
        },
        signature_secret: sk,
        kem_keypair: KemKeyPair::generate(),
        key_package_repo: mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage::default(),
    })
}

async fn register(client: &reqwest::Client, server: &str, identity: &LatticeIdentity) -> Result<()> {
    let claim = lattice_protocol::wire::IdentityClaim::default();
    let mut claim_bytes = Vec::new();
    prost::Message::encode(&claim, &mut claim_bytes)?;
    let resp: serde_json::Value = client
        .post(format!("{server}/register"))
        .json(&serde_json::json!({
            "user_id_b64": B64.encode(identity.credential.user_id),
            "claim_b64": B64.encode(&claim_bytes),
        }))
        .send()
        .await
        .context("register POST")?
        .json()
        .await
        .context("register response decode")?;
    tracing::info!(server, registered = ?resp["new_registration"], "register OK");
    Ok(())
}

async fn publish_kp(
    client: &reqwest::Client,
    server: &str,
    identity: &LatticeIdentity,
    psk_store: &LatticePskStorage,
) -> Result<()> {
    let kp_bytes = generate_key_package(identity, psk_store.clone())
        .map_err(|e| anyhow!("generate_key_package: {e}"))?;
    let resp: serde_json::Value = client
        .post(format!("{server}/key_packages"))
        .json(&serde_json::json!({
            "user_id_b64": B64.encode(identity.credential.user_id),
            "key_package_b64": B64.encode(&kp_bytes),
        }))
        .send()
        .await
        .context("publish_kp POST")?
        .json()
        .await
        .context("publish_kp response decode")?;
    tracing::info!(
        server,
        published_at = ?resp["published_at"],
        kp_bytes = kp_bytes.len(),
        "key package published"
    );
    Ok(())
}

async fn fetch_kp(client: &reqwest::Client, server: &str, user_id: [u8; 32]) -> Result<Vec<u8>> {
    let user_b64 = B64.encode(user_id);
    let resp: serde_json::Value = client
        .get(format!("{server}/key_packages/{user_b64}"))
        .send()
        .await
        .context("fetch_kp GET")?
        .json()
        .await
        .context("fetch_kp response decode")?;
    let kp_b64 = resp["key_package_b64"]
        .as_str()
        .ok_or_else(|| anyhow!("fetch_kp: missing key_package_b64 in response"))?;
    let bytes = B64
        .decode(kp_b64)
        .context("fetch_kp: key_package_b64 decode")?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
async fn run_demo(
    server_a: String,
    server_b: String,
    message: String,
    group_id_str: String,
) -> Result<()> {
    if group_id_str.len() != 16 {
        return Err(anyhow!(
            "group_id must be exactly 16 bytes (got {})",
            group_id_str.len()
        ));
    }
    let mut gid_bytes = [0u8; 16];
    gid_bytes.copy_from_slice(group_id_str.as_bytes());

    let client = reqwest::Client::builder()
        .user_agent("lattice-cli-demo/0.1")
        .build()?;

    // === Identities ===
    let alice = make_identity(0xAA)?;
    let bob = make_identity(0xBB)?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();
    tracing::info!(
        alice_user = %hex::encode(&alice.credential.user_id[..4]),
        bob_user = %hex::encode(&bob.credential.user_id[..4]),
        "identities generated"
    );

    // === Register both on their home servers ===
    register(&client, &server_a, &alice).await?;
    register(&client, &server_b, &bob).await?;

    // === Bob publishes his KP on server B ===
    publish_kp(&client, &server_b, &bob, &bob_psk).await?;

    // === Alice fetches Bob's KP directly from server B (cross-server) ===
    let bob_kp_bytes = fetch_kp(&client, &server_b, bob.credential.user_id).await?;
    tracing::info!(
        bob_kp_bytes = bob_kp_bytes.len(),
        "Alice fetched Bob's KP from server B"
    );

    // === Alice creates a group locally and invites Bob ===
    let mut alice_group =
        create_group(&alice, alice_psk.clone(), &gid_bytes).map_err(|e| anyhow!("{e}"))?;
    let commit_output =
        add_member(&mut alice_group, &bob_kp_bytes).map_err(|e| anyhow!("{e}"))?;
    apply_commit(&mut alice_group).map_err(|e| anyhow!("{e}"))?;
    let welcome = commit_output
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("expected one welcome from add_member"))?;
    let pq_payload_bytes = welcome
        .pq_payload
        .mls_encode_to_vec()
        .map_err(|e| anyhow!("encode PqWelcomePayload: {e}"))?;
    let gid_b64 = B64.encode(gid_bytes);

    // === Alice POSTs commit to server A with remote routing to server B ===
    let resp: serde_json::Value = client
        .post(format!("{server_a}/group/{gid_b64}/commit"))
        .json(&serde_json::json!({
            "epoch": 1,
            "commit_b64": B64.encode(&commit_output.commit),
            "welcomes": [{
                "joiner_user_id_b64": B64.encode(bob.credential.user_id),
                "mls_welcome_b64": B64.encode(&welcome.mls_welcome),
                "pq_payload_b64": B64.encode(&pq_payload_bytes),
            }],
            "origin_host": "alice.local",
            "origin_base_url": server_a,
            "remote_routing": [{
                "joiner_user_id_b64": B64.encode(bob.credential.user_id),
                "home_server_base_url": server_b,
            }],
        }))
        .send()
        .await
        .context("commit POST")?
        .json()
        .await
        .context("commit response decode")?;
    tracing::info!(
        welcomes_accepted = ?resp["welcomes_accepted"],
        "Alice posted commit; A federation-pushed to B"
    );

    // Give the spawn-pushed federation request a moment to land at B.
    // M3 ships best-effort fire-and-forget pushes; M5 adds retry/queue.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // === Bob fetches his welcome from server B ===
    let bob_b64 = B64.encode(bob.credential.user_id);
    let resp: serde_json::Value = client
        .get(format!("{server_b}/group/{gid_b64}/welcome/{bob_b64}"))
        .send()
        .await
        .context("welcome GET from server B")?
        .json()
        .await
        .context("welcome response decode")?;
    let mls_welcome = B64.decode(
        resp["mls_welcome_b64"]
            .as_str()
            .ok_or_else(|| anyhow!("missing mls_welcome_b64"))?,
    )?;
    let pq_payload_back = B64.decode(
        resp["pq_payload_b64"]
            .as_str()
            .ok_or_else(|| anyhow!("missing pq_payload_b64"))?,
    )?;
    use mls_rs::mls_rs_codec::MlsDecode;
    let pq_payload =
        lattice_crypto::mls::welcome_pq::PqWelcomePayload::mls_decode(&mut &*pq_payload_back)
            .map_err(|e| anyhow!("decode PqWelcomePayload: {e}"))?;
    let lw = LatticeWelcome {
        mls_welcome,
        pq_payload,
    };
    let mut bob_group =
        process_welcome(&bob, bob_psk.clone(), &lw).map_err(|e| anyhow!("{e}"))?;
    tracing::info!("Bob joined the group via federated Welcome");

    // === Alice encrypts and sends ===
    let ct = encrypt_application(&mut alice_group, message.as_bytes())
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    let _: serde_json::Value = client
        .post(format!("{server_a}/group/{gid_b64}/messages"))
        .json(&serde_json::json!({ "envelope_b64": B64.encode(&ct) }))
        .send()
        .await
        .context("send POST to server A")?
        .json()
        .await
        .context("send response decode")?;
    tracing::info!(bytes = ct.len(), "Alice sent encrypted message via server A");

    // For M3 simplicity: Bob fetches messages from server A directly
    // (the group's owning server). Cross-server message federation
    // is wired in `groups.rs` for welcomes; the message-inbox path
    // is a follow-up. For the demo, Bob pulls from A.
    let resp: serde_json::Value = client
        .get(format!("{server_a}/group/{gid_b64}/messages?since=0"))
        .send()
        .await
        .context("recv GET from server A")?
        .json()
        .await
        .context("recv response decode")?;
    let messages = resp["messages"]
        .as_array()
        .ok_or_else(|| anyhow!("missing messages array"))?;
    if messages.is_empty() {
        return Err(anyhow!("no messages on server A — federation flow stalled"));
    }
    let envelope = B64.decode(
        messages[0]["envelope_b64"]
            .as_str()
            .ok_or_else(|| anyhow!("missing envelope_b64"))?,
    )?;
    let plaintext = decrypt(&mut bob_group, &envelope).map_err(|e| anyhow!("decrypt: {e}"))?;
    let recovered = String::from_utf8(plaintext.clone())
        .unwrap_or_else(|_| format!("<binary {} bytes>", plaintext.len()));
    tracing::info!(
        recovered = %recovered,
        "Bob decrypted the message"
    );
    println!("{recovered}");
    if recovered != message {
        return Err(anyhow!(
            "round-trip mismatch: sent {message:?}, recovered {recovered:?}"
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("lattice=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().compact())
        .try_init()
        .ok();

    let cli = Cli::parse();
    lattice_core::init().map_err(|e| anyhow!("core init: {e}"))?;

    match cli.cmd {
        Cmd::Demo {
            server_a,
            server_b,
            message,
            group_id,
        } => {
            run_demo(server_a, server_b, message, group_id).await?;
            tracing::info!("demo completed successfully");
        }
    }

    Ok(())
}
