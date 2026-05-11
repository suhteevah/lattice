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

mod client;
mod identity_file;
mod store;

use std::path::PathBuf;

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
    /// recovered plaintext to stdout. Single-process; no persistence.
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

    /// Initialize a new identity, register on a server, publish a KP.
    /// Saves identity + storage to `<home>` (default `~/.lattice`).
    /// Subsequent commands load the same state from disk.
    Init {
        /// Home server base URL.
        #[arg(long)]
        server: String,
        /// Display name (defaults to the user_id hex prefix).
        #[arg(long)]
        name: Option<String>,
        /// Override the default `<home>` directory.
        #[arg(long, env = "LATTICE_HOME_DIR")]
        home: Option<PathBuf>,
    },

    /// Print our own `user_id` hex (read from the local identity).
    Whoami {
        /// Override the default `<home>` directory.
        #[arg(long, env = "LATTICE_HOME_DIR")]
        home: Option<PathBuf>,
    },

    /// Create a group locally and invite a peer in one shot.
    CreateAndInvite {
        /// Our own home server URL.
        #[arg(long)]
        server: String,
        /// Group ID (16 ASCII bytes).
        #[arg(long)]
        group_id: String,
        /// Invitee's home server URL (may differ from ours).
        #[arg(long)]
        invitee_server: String,
        /// Invitee's user_id, base64-encoded.
        #[arg(long)]
        invitee_user_b64: String,
        /// Override the default `<home>` directory.
        #[arg(long, env = "LATTICE_HOME_DIR")]
        home: Option<PathBuf>,
    },

    /// Accept the pending welcome from our server for a given group.
    Accept {
        /// Our own home server URL.
        #[arg(long)]
        server: String,
        /// Group ID (16 ASCII bytes).
        #[arg(long)]
        group_id: String,
        /// Override the default `<home>` directory.
        #[arg(long, env = "LATTICE_HOME_DIR")]
        home: Option<PathBuf>,
    },

    /// Encrypt + post a message to a group via our home server.
    Send {
        /// Our own home server URL.
        #[arg(long)]
        server: String,
        /// Group ID (16 ASCII bytes).
        #[arg(long)]
        group_id: String,
        /// Plaintext message.
        #[arg(long)]
        message: String,
        /// Peer home server URLs to federation-push the message to,
        /// one per remote member. The server will sign the push and
        /// POST it to each URL's `/federation/message_inbox`. Empty
        /// means no federation (local-only groups).
        #[arg(long = "peer-server")]
        peer_servers: Vec<String>,
        /// Override the default `<home>` directory.
        #[arg(long, env = "LATTICE_HOME_DIR")]
        home: Option<PathBuf>,
    },

    /// Poll a group's message inbox until at least one new message
    /// arrives, decrypt it, print to stdout. Times out after
    /// `--timeout` seconds.
    Recv {
        /// Source server URL (this is the group's *owning* server in
        /// M3; future versions fetch from our home server).
        #[arg(long)]
        server: String,
        /// Group ID (16 ASCII bytes).
        #[arg(long)]
        group_id: String,
        /// Polling timeout in seconds.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        /// `since` cursor (the seq to fetch *after*).
        #[arg(long, default_value_t = 0)]
        since: u64,
        /// Override the default `<home>` directory.
        #[arg(long, env = "LATTICE_HOME_DIR")]
        home: Option<PathBuf>,
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
    register_raw(client, server, identity.credential.user_id).await
}

async fn register_raw(
    client: &reqwest::Client,
    server: &str,
    user_id: [u8; 32],
) -> Result<()> {
    let claim = lattice_protocol::wire::IdentityClaim::default();
    let mut claim_bytes = Vec::new();
    prost::Message::encode(&claim, &mut claim_bytes)?;
    let resp: serde_json::Value = client
        .post(format!("{server}/register"))
        .json(&serde_json::json!({
            "user_id_b64": B64.encode(user_id),
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
        Cmd::Init { server, name, home } => cli_init(server, name, home).await?,
        Cmd::Whoami { home } => cli_whoami(home)?,
        Cmd::CreateAndInvite {
            server,
            group_id,
            invitee_server,
            invitee_user_b64,
            home,
        } => cli_create_and_invite(server, group_id, invitee_server, invitee_user_b64, home).await?,
        Cmd::Accept {
            server,
            group_id,
            home,
        } => cli_accept(server, group_id, home).await?,
        Cmd::Send {
            server,
            group_id,
            message,
            peer_servers,
            home,
        } => cli_send(server, group_id, message, peer_servers, home).await?,
        Cmd::Recv {
            server,
            group_id,
            timeout,
            since,
            home,
        } => cli_recv(server, group_id, timeout, since, home).await?,
    }

    Ok(())
}

fn resolve_home(arg: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = arg {
        std::fs::create_dir_all(&p)?;
        return Ok(p);
    }
    Ok(store::resolve_home()?)
}

fn parse_group_id(s: &str) -> Result<[u8; 16]> {
    if s.len() != 16 {
        return Err(anyhow!("group_id must be exactly 16 bytes (got {})", s.len()));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(s.as_bytes());
    Ok(out)
}

async fn cli_init(server: String, name: Option<String>, home: Option<PathBuf>) -> Result<()> {
    let home = resolve_home(home)?;
    let provider = lattice_crypto::mls::cipher_suite::LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(lattice_crypto::mls::cipher_suite::LATTICE_HYBRID_V1)
        .ok_or_else(|| anyhow!("missing LATTICE_HYBRID_V1 suite"))?;
    let (sk, pk) = suite
        .signature_key_generate()
        .map_err(|e| anyhow!("sig keygen: {e}"))?;
    let pk_bytes = pk.as_bytes();
    let mut ed25519_pub = [0u8; lattice_crypto::credential::ED25519_PK_LEN];
    ed25519_pub.copy_from_slice(&pk_bytes[..lattice_crypto::credential::ED25519_PK_LEN]);
    let ml_dsa_pub = pk_bytes[lattice_crypto::credential::ED25519_PK_LEN..].to_vec();

    // Derive a user_id deterministically from the ed25519_pub via BLAKE3
    // — gives each device a stable identity even without a server-side
    // handle namespace.
    let user_id = *blake3::hash(&ed25519_pub).as_bytes();

    let credential = lattice_crypto::credential::LatticeCredential {
        user_id,
        ed25519_pub,
        ml_dsa_pub,
    };
    let kem_keypair = lattice_crypto::mls::leaf_node_kem::KemKeyPair::generate();
    let identity = identity_file::CliIdentity {
        credential,
        signature_secret: sk,
        kem_keypair,
        display_name: name.unwrap_or_else(|| {
            format!("user-{}", identity_file::hex_prefix(&user_id))
        }),
    };
    identity.save(&home)?;
    tracing::info!(
        home = %home.display(),
        user_id_b64 = %B64.encode(user_id),
        "identity created"
    );

    let stores = client::CliStores::open(&home)?;
    let mls_client = client::build_client(&identity, &stores)?;

    let http = reqwest::Client::builder().user_agent("lattice-cli/0.1").build()?;
    register_raw(&http, &server, identity.credential.user_id).await?;
    let kp_bytes = client::cli_generate_key_package(&mls_client, &identity)?;
    let resp: serde_json::Value = http
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
        "init complete; identity registered, KP published"
    );
    println!("{}", B64.encode(identity.credential.user_id));
    Ok(())
}

fn cli_whoami(home: Option<PathBuf>) -> Result<()> {
    let home = resolve_home(home)?;
    let identity = identity_file::CliIdentity::load(&home)?;
    println!("{}", B64.encode(identity.credential.user_id));
    eprintln!("display_name: {}", identity.display_name);
    Ok(())
}

async fn cli_create_and_invite(
    server: String,
    group_id: String,
    invitee_server: String,
    invitee_user_b64: String,
    home: Option<PathBuf>,
) -> Result<()> {
    let home = resolve_home(home)?;
    let identity = identity_file::CliIdentity::load(&home)?;
    let stores = client::CliStores::open(&home)?;
    let mls_client = client::build_client(&identity, &stores)?;
    let gid = parse_group_id(&group_id)?;

    let http = reqwest::Client::builder().user_agent("lattice-cli/0.1").build()?;

    // Fetch invitee's KP from their home server.
    let resp: serde_json::Value = http
        .get(format!(
            "{}/key_packages/{}",
            invitee_server.trim_end_matches('/'),
            invitee_user_b64
        ))
        .send()
        .await
        .context("fetch invitee KP")?
        .json()
        .await
        .context("fetch invitee KP response decode")?;
    let invitee_kp = B64.decode(
        resp["key_package_b64"]
            .as_str()
            .ok_or_else(|| anyhow!("missing key_package_b64"))?,
    )?;

    // Create the group locally (idempotent on retry — load_group returns
    // an error if it already exists, but we tolerate that for retry).
    if client::cli_create_group(&mls_client, &identity, &gid).is_err() {
        tracing::info!("group already exists locally, continuing");
    }

    let commit = client::cli_add_member(&mls_client, &stores, &gid, &invitee_kp)?;
    let welcome = commit
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no welcome produced by add_member"))?;

    let gid_b64 = B64.encode(gid);
    let resp: serde_json::Value = http
        .post(format!("{server}/group/{gid_b64}/commit"))
        .json(&serde_json::json!({
            "epoch": 1,
            "commit_b64": B64.encode(&commit.commit),
            "welcomes": [{
                "joiner_user_id_b64": B64.encode(welcome.joiner_user_id),
                "mls_welcome_b64": B64.encode(&welcome.mls_welcome),
                "pq_payload_b64": B64.encode(&welcome.pq_payload),
            }],
            "origin_host": "cli.local",
            "origin_base_url": server,
            "remote_routing": [{
                "joiner_user_id_b64": B64.encode(welcome.joiner_user_id),
                "home_server_base_url": invitee_server,
            }],
        }))
        .send()
        .await
        .context("commit POST")?
        .json()
        .await
        .context("commit response decode")?;
    tracing::info!(welcomes_accepted = ?resp["welcomes_accepted"], "commit posted");
    client::cli_apply_pending(&mls_client, &gid)?;
    tracing::info!("local pending commit applied");
    Ok(())
}

async fn cli_accept(server: String, group_id: String, home: Option<PathBuf>) -> Result<()> {
    let home = resolve_home(home)?;
    let identity = identity_file::CliIdentity::load(&home)?;
    let stores = client::CliStores::open(&home)?;
    let mls_client = client::build_client(&identity, &stores)?;
    let gid = parse_group_id(&group_id)?;

    let http = reqwest::Client::builder().user_agent("lattice-cli/0.1").build()?;
    let gid_b64 = B64.encode(gid);
    let user_b64 = B64.encode(identity.credential.user_id);

    let resp: serde_json::Value = http
        .get(format!("{server}/group/{gid_b64}/welcome/{user_b64}"))
        .send()
        .await
        .context("welcome GET")?
        .json()
        .await
        .context("welcome decode")?;
    let mls_welcome = B64.decode(
        resp["mls_welcome_b64"]
            .as_str()
            .ok_or_else(|| anyhow!("missing mls_welcome_b64"))?,
    )?;
    let pq_payload = B64.decode(
        resp["pq_payload_b64"]
            .as_str()
            .ok_or_else(|| anyhow!("missing pq_payload_b64"))?,
    )?;
    let joined_gid =
        client::cli_process_welcome(&mls_client, &identity, &stores, &mls_welcome, &pq_payload)?;
    tracing::info!(group_b64 = %B64.encode(&joined_gid), "joined group");
    Ok(())
}

async fn cli_send(
    server: String,
    group_id: String,
    message: String,
    peer_servers: Vec<String>,
    home: Option<PathBuf>,
) -> Result<()> {
    let home = resolve_home(home)?;
    let identity = identity_file::CliIdentity::load(&home)?;
    let stores = client::CliStores::open(&home)?;
    let mls_client = client::build_client(&identity, &stores)?;
    let gid = parse_group_id(&group_id)?;

    let ct = client::cli_encrypt(&mls_client, &gid, message.as_bytes())?;
    let http = reqwest::Client::builder().user_agent("lattice-cli/0.1").build()?;
    let gid_b64 = B64.encode(gid);
    let mut body = serde_json::json!({
        "envelope_b64": B64.encode(&ct),
        "origin_host": "cli.local",
        "origin_base_url": server,
    });
    if !peer_servers.is_empty() {
        body["remote_routing"] = serde_json::Value::Array(
            peer_servers
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );
    }
    let resp: serde_json::Value = http
        .post(format!("{server}/group/{gid_b64}/messages"))
        .json(&body)
        .send()
        .await
        .context("send POST")?
        .json()
        .await
        .context("send decode")?;
    tracing::info!(seq = ?resp["seq"], bytes = ct.len(), "message sent");
    Ok(())
}

async fn cli_recv(
    server: String,
    group_id: String,
    timeout_s: u64,
    since: u64,
    home: Option<PathBuf>,
) -> Result<()> {
    let home = resolve_home(home)?;
    let identity = identity_file::CliIdentity::load(&home)?;
    let stores = client::CliStores::open(&home)?;
    let mls_client = client::build_client(&identity, &stores)?;
    let gid = parse_group_id(&group_id)?;

    let http = reqwest::Client::builder().user_agent("lattice-cli/0.1").build()?;
    let gid_b64 = B64.encode(gid);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);
    loop {
        let resp: serde_json::Value = http
            .get(format!(
                "{server}/group/{gid_b64}/messages?since={since}"
            ))
            .send()
            .await
            .context("recv GET")?
            .json()
            .await
            .context("recv decode")?;
        if let Some(arr) = resp["messages"].as_array() {
            if !arr.is_empty() {
                let envelope = B64.decode(
                    arr[0]["envelope_b64"]
                        .as_str()
                        .ok_or_else(|| anyhow!("missing envelope_b64"))?,
                )?;
                let pt = client::cli_decrypt(&mls_client, &gid, &envelope)?;
                let s = String::from_utf8(pt.clone())
                    .unwrap_or_else(|_| format!("<binary {} bytes>", pt.len()));
                println!("{s}");
                return Ok(());
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!("recv timed out after {timeout_s}s"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}
