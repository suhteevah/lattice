//! Top-level Leptos component for the M4 in-browser preview.
//!
//! Phase α exercises `lattice-crypto`'s hybrid signature + hybrid KEM in
//! the browser. Phase β runs the full Alice ⇌ Bob MLS round-trip from
//! `lattice-crypto::mls` — group create, KeyPackage publish, add-member
//! commit + Welcome, process_welcome on the joiner, then bidirectional
//! `encrypt_application` / `decrypt`. Same code paths the CLI demo and
//! the M2 integration test exercise; here they run entirely in WASM.

use base64::Engine;
use leptos::prelude::*;
use leptos::task::spawn_local;

use lattice_crypto::credential::{
    ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN, USER_ID_LEN,
};
use lattice_crypto::hybrid_kex;
use lattice_crypto::mls::cipher_suite::{LATTICE_HYBRID_V1, LatticeCryptoProvider};
use lattice_crypto::mls::leaf_node_kem::KemKeyPair;
use lattice_crypto::mls::psk::LatticePskStorage;
use lattice_crypto::mls::{
    LatticeIdentity, add_member, apply_commit, create_group, decrypt, encrypt_application,
    generate_key_package, process_welcome,
};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};

use crate::api;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Default `lattice-server` endpoint for browser-side calls. Matches the
/// `LATTICE_BIND_ADDR` Matt uses for local dev. Override at compile time
/// later if we need to point at pixie / cnc.
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";

#[component]
pub fn App() -> impl IntoView {
    let (status, set_status) =
        signal::<String>(format!("lattice-core v{} ready", lattice_core::VERSION));
    let (log_lines, set_log_lines) = signal::<Vec<String>>(Vec::new());

    let append = move |line: String| {
        set_log_lines.update(|lines| lines.push(line));
    };

    let run_primitives = move |_| {
        set_log_lines.set(Vec::new());
        match try_run_primitives(append) {
            Ok(()) => set_status.set("primitives OK".to_string()),
            Err(e) => set_status.set(format!("primitives error: {e}")),
        }
    };

    let run_mls = move |_| {
        set_log_lines.set(Vec::new());
        match try_run_mls_round_trip(append) {
            Ok(()) => set_status.set("MLS round-trip OK".to_string()),
            Err(e) => set_status.set(format!("MLS error: {e}")),
        }
    };

    let register_server = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("registering…".to_string());
        let log = append;
        spawn_local(async move {
            match try_register_with_server(DEFAULT_SERVER_URL, log).await {
                Ok(new) => set_status.set(format!("register OK (new_registration={new})")),
                Err(e) => set_status.set(format!("register error: {e}")),
            }
        });
    };

    let key_package_round_trip = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("publishing key package…".to_string());
        let log = append;
        spawn_local(async move {
            match try_kp_round_trip(DEFAULT_SERVER_URL, log).await {
                Ok(len) => set_status.set(format!("KP round-trip OK ({len} bytes)")),
                Err(e) => set_status.set(format!("KP round-trip error: {e}")),
            }
        });
    };

    let server_backed_demo = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("running server-backed demo…".to_string());
        let log = append;
        spawn_local(async move {
            match try_server_backed_demo(DEFAULT_SERVER_URL, log).await {
                Ok(()) => set_status.set("server-backed demo OK".to_string()),
                Err(e) => set_status.set(format!("server-backed demo error: {e}")),
            }
        });
    };

    view! {
        <div class="page">
            <div class="card">
                <h1>"Lattice"</h1>
                <p class="tagline">"Post-quantum encrypted messaging. M4 in-browser preview."</p>
                <div class="status">{move || status.get()}</div>
                <div class="button-row">
                    <button class="button" on:click=run_primitives>"Run primitives demo"</button>
                    <button class="button" on:click=run_mls>"Run MLS round-trip"</button>
                    <button class="button" on:click=register_server>"Register with server"</button>
                    <button class="button" on:click=key_package_round_trip>"KP publish + fetch"</button>
                    <button class="button" on:click=server_backed_demo>"Server-backed demo"</button>
                </div>
                <Show
                    when=move || !log_lines.get().is_empty()
                    fallback=|| view! {}
                >
                    <pre class="log">
                        {move || log_lines.get().join("\n")}
                    </pre>
                </Show>
                <div class="footer">
                    <span class="dot-sage"></span>
                    <span class="muted">"End-to-end encrypted • PQ-hybrid"</span>
                </div>
            </div>
        </div>
    }
}

/// Exercise the hybrid signature and hybrid KEM primitives directly,
/// without going through MLS. Useful for sanity-checking the wasm32
/// build of `lattice-crypto` independently of `mls-rs`.
fn try_run_primitives(log: impl Fn(String) + Copy) -> Result<(), String> {
    log("== hybrid signature ==".to_string());
    let provider = LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .ok_or_else(|| "ciphersuite missing".to_string())?;
    let (sk, pk) = suite
        .signature_key_generate()
        .map_err(|e| format!("sig keygen: {e:?}"))?;
    let pk_bytes = pk.as_bytes();
    let user_id = blake3::hash(&pk_bytes[..32]);
    log(format!(
        "user_id: {}…",
        &B64.encode(user_id.as_bytes())[..20]
    ));
    log(format!(
        "sig pk: {} bytes ({} ed25519 + {} ml-dsa)",
        pk_bytes.len(),
        ED25519_PK_LEN,
        pk_bytes.len() - ED25519_PK_LEN,
    ));
    let msg = b"hello, lattice browser";
    let sig = suite.sign(&sk, msg).map_err(|e| format!("sign: {e:?}"))?;
    log(format!("sig: {} bytes", sig.len()));
    suite
        .verify(&pk, &sig, msg)
        .map_err(|e| format!("verify failed: {e:?}"))?;
    log("verify: OK".to_string());

    log("== hybrid kem (X25519 + ML-KEM-768) ==".to_string());
    let (peer_pk, peer_sk) =
        hybrid_kex::generate_keypair().map_err(|e| format!("kem keygen: {e}"))?;
    log(format!(
        "kem pk: {} bytes ({} x25519 + {} ml-kem)",
        32 + peer_pk.ml_kem.len(),
        32,
        peer_pk.ml_kem.len(),
    ));
    let info = b"lattice/browser-demo/v1";
    let (ct, shared) =
        hybrid_kex::encapsulate(&peer_pk, info).map_err(|e| format!("encap: {e}"))?;
    log(format!(
        "ct: {} bytes ({} x25519 eph + {} ml-kem ct)",
        32 + ct.ml_kem_ct.len(),
        32,
        ct.ml_kem_ct.len(),
    ));
    log(format!(
        "session: {}…",
        &B64.encode(shared.session_key)[..12]
    ));
    let shared2 =
        hybrid_kex::decapsulate(&peer_sk, &ct, info).map_err(|e| format!("decap: {e}"))?;
    if shared.session_key != shared2.session_key {
        return Err("session keys did not agree after encap/decap".into());
    }
    log("secrets agree: true".to_string());
    log("== primitives complete ==".to_string());
    Ok(())
}

/// Mirror of `lattice-crypto::tests::mls_integration::alice_invites_bob_…`
/// running in the browser. Walks Alice + Bob through the full MLS join
/// + ratchet round-trip using the same APIs the CLI demo calls. No
/// network, no server — all state lives in this tab.
fn try_run_mls_round_trip(log: impl Fn(String) + Copy) -> Result<(), String> {
    log("== build identities ==".to_string());
    let alice = make_identity(0xAA).map_err(|e| format!("alice identity: {e}"))?;
    let bob = make_identity(0xBB).map_err(|e| format!("bob identity: {e}"))?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();
    log(format!(
        "alice user_id: {}… / bob user_id: {}…",
        &B64.encode(alice.credential.user_id)[..16],
        &B64.encode(bob.credential.user_id)[..16],
    ));

    log("== alice creates group ==".to_string());
    let group_id: [u8; 16] = *b"lattice-browser1";
    let mut alice_group = create_group(&alice, alice_psk.clone(), &group_id)
        .map_err(|e| format!("create_group: {e}"))?;
    log("group created".to_string());

    log("== bob publishes a KeyPackage ==".to_string());
    let bob_kp = generate_key_package(&bob, bob_psk.clone())
        .map_err(|e| format!("generate_key_package: {e}"))?;
    log(format!("bob kp: {} bytes", bob_kp.len()));

    log("== alice adds bob ==".to_string());
    let commit_output =
        add_member(&mut alice_group, &bob_kp).map_err(|e| format!("add_member: {e}"))?;
    if commit_output.welcomes.len() != 1 {
        return Err(format!(
            "expected 1 welcome, got {}",
            commit_output.welcomes.len()
        ));
    }
    let welcome = commit_output
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| "welcome vanished".to_string())?;
    log(format!(
        "commit: {} bytes, welcome (mls): {} bytes, pq ct: {} bytes (epoch {})",
        commit_output.commit.len(),
        welcome.mls_welcome.len(),
        welcome.pq_payload.ml_kem_ct.len(),
        welcome.pq_payload.epoch,
    ));
    let alice_psk_count = alice_psk
        .len()
        .map_err(|e| format!("alice psk len: {e}"))?;
    log(format!(
        "alice PSK store size after seal: {}",
        alice_psk_count
    ));

    log("== alice applies commit ==".to_string());
    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit: {e}"))?;

    log("== bob processes welcome ==".to_string());
    let mut bob_group = process_welcome(&bob, bob_psk.clone(), &welcome)
        .map_err(|e| format!("process_welcome: {e}"))?;
    let bob_psk_count = bob_psk.len().map_err(|e| format!("bob psk len: {e}"))?;
    log(format!("bob PSK store size after open: {}", bob_psk_count));

    log("== alice → bob ==".to_string());
    let ct_a = encrypt_application(&mut alice_group, b"hello, lattice")
        .map_err(|e| format!("alice encrypt: {e}"))?;
    log(format!("ciphertext: {} bytes", ct_a.len()));
    let pt_at_bob =
        decrypt(&mut bob_group, &ct_a).map_err(|e| format!("bob decrypt: {e}"))?;
    if pt_at_bob != b"hello, lattice" {
        return Err(format!(
            "bob recovered {:?}, expected 'hello, lattice'",
            String::from_utf8_lossy(&pt_at_bob),
        ));
    }
    log(format!(
        "bob recovered: {:?}",
        String::from_utf8_lossy(&pt_at_bob)
    ));

    log("== bob → alice ==".to_string());
    let ct_b = encrypt_application(&mut bob_group, b"hello, alice")
        .map_err(|e| format!("bob encrypt: {e}"))?;
    log(format!("ciphertext: {} bytes", ct_b.len()));
    let pt_at_alice =
        decrypt(&mut alice_group, &ct_b).map_err(|e| format!("alice decrypt: {e}"))?;
    if pt_at_alice != b"hello, alice" {
        return Err(format!(
            "alice recovered {:?}, expected 'hello, alice'",
            String::from_utf8_lossy(&pt_at_alice),
        ));
    }
    log(format!(
        "alice recovered: {:?}",
        String::from_utf8_lossy(&pt_at_alice)
    ));

    log("== M4 phase β complete ==".to_string());
    Ok(())
}

/// Build a fresh Alice identity in-browser, then call the lattice-server
/// `/register` route and report success.
///
/// This is the M4 Phase γ minimum proof-of-life: that the browser can
/// hit a live `lattice-server` over `gloo-net::http::Request` with CORS
/// permitted, and that an identity built entirely in-WASM round-trips
/// through the wire encoding.
async fn try_register_with_server(
    server: &str,
    log: impl Fn(String) + Copy,
) -> Result<bool, String> {
    log(format!("== register against {server} =="));
    let alice = make_identity(0xAA)?;
    log(format!(
        "user_id: {}",
        B64.encode(alice.credential.user_id)
    ));
    log("POST /register …".to_string());
    let new_registration = api::register(server, &alice).await?;
    log(format!(
        "server response: new_registration={new_registration}"
    ));
    log("== M4 phase γ.1 complete ==".to_string());
    Ok(new_registration)
}

/// Phase γ.2: register Bob, then `POST /key_packages` with a
/// freshly-generated `LatticeIdentity` KeyPackage, then
/// `GET /key_packages/:user_id_b64url` to fetch the same bytes back.
/// Proves the publish/fetch path round-trips intact.
///
/// We use a Bob identity (`0xBB`) to keep the user_ids in the server
/// state distinct from the γ.1 Alice flow.
async fn try_kp_round_trip(
    server: &str,
    log: impl Fn(String) + Copy,
) -> Result<usize, String> {
    log(format!("== KP round-trip against {server} =="));
    let bob = make_identity(0xBB)?;
    let psk_store = LatticePskStorage::new();
    log(format!(
        "user_id: {}",
        B64.encode(bob.credential.user_id)
    ));

    log("POST /register …".to_string());
    let new_registration = api::register(server, &bob).await?;
    log(format!(
        "registered (new_registration={new_registration})"
    ));

    log("POST /key_packages …".to_string());
    let published_at = api::publish_key_package(server, &bob, &psk_store).await?;
    log(format!("published_at: {published_at}"));

    log(format!(
        "GET /key_packages/{}…",
        B64.encode(bob.credential.user_id)
    ));
    let kp_bytes = api::fetch_key_package(server, &bob.credential.user_id).await?;
    log(format!("fetched {} bytes", kp_bytes.len()));

    log("== M4 phase γ.2 complete ==".to_string());
    Ok(kp_bytes.len())
}

/// Phase γ.3: full Alice ⇌ Bob round-trip backed by a live
/// `lattice-server`. Mirrors the M3 e2e flow `lattice-cli demo`
/// drives, but from inside the browser tab. Same MLS state machine
/// the in-tab Phase β demo runs — only the message bytes go over
/// HTTP instead of staying in-process.
async fn try_server_backed_demo(
    server: &str,
    log: impl Fn(String) + Copy,
) -> Result<(), String> {
    log(format!("== server-backed demo against {server} =="));
    let alice = make_identity(0xAC)?;
    let bob = make_identity(0xBD)?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();
    log(format!(
        "alice user_id: {} / bob user_id: {}",
        &B64.encode(alice.credential.user_id)[..12],
        &B64.encode(bob.credential.user_id)[..12],
    ));

    log("== register both ==".to_string());
    api::register(server, &alice).await?;
    api::register(server, &bob).await?;

    log("== bob publishes KP ==".to_string());
    let _ = api::publish_key_package(server, &bob, &bob_psk).await?;

    log("== alice fetches bob's KP ==".to_string());
    let bob_kp_bytes = api::fetch_key_package(server, &bob.credential.user_id).await?;
    log(format!("bob kp: {} bytes", bob_kp_bytes.len()));

    log("== alice creates group ==".to_string());
    let group_id: [u8; 16] = *b"lattice-browser2";
    let mut alice_group = create_group(&alice, alice_psk.clone(), &group_id)
        .map_err(|e| format!("create_group: {e}"))?;

    log("== alice adds bob (locally) ==".to_string());
    let commit_output =
        add_member(&mut alice_group, &bob_kp_bytes).map_err(|e| format!("add_member: {e}"))?;
    let welcome = commit_output
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| "no welcome".to_string())?;
    log(format!(
        "commit: {} bytes, mls welcome: {} bytes, pq ct: {} bytes (epoch {})",
        commit_output.commit.len(),
        welcome.mls_welcome.len(),
        welcome.pq_payload.ml_kem_ct.len(),
        welcome.pq_payload.epoch,
    ));

    log("== alice POSTs /group/:gid/commit ==".to_string());
    let accepted = api::submit_commit(
        server,
        &group_id,
        welcome.pq_payload.epoch,
        &commit_output.commit,
        &welcome,
        &bob.credential.user_id,
    )
    .await?;
    log(format!("server accepted {accepted} welcome(s) for fan-out"));
    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit: {e}"))?;

    log("== bob GETs /group/:gid/welcome/:user_id ==".to_string());
    let welcome_for_bob = api::fetch_welcome(server, &group_id, &bob.credential.user_id).await?;
    log(format!(
        "fetched welcome (mls: {} bytes, pq epoch: {})",
        welcome_for_bob.mls_welcome.len(),
        welcome_for_bob.pq_payload.epoch,
    ));

    log("== bob process_welcome ==".to_string());
    let mut bob_group = process_welcome(&bob, bob_psk.clone(), &welcome_for_bob)
        .map_err(|e| format!("process_welcome: {e}"))?;

    log("== alice encrypts + POSTs /group/:gid/messages ==".to_string());
    let ct = encrypt_application(&mut alice_group, b"hello via server")
        .map_err(|e| format!("alice encrypt: {e}"))?;
    let seq = api::publish_message(server, &group_id, &ct).await?;
    log(format!("published seq={seq} ({} bytes)", ct.len()));

    log("== bob GETs /group/:gid/messages?since=0 ==".to_string());
    let (latest, messages) = api::fetch_messages(server, &group_id, 0).await?;
    log(format!("latest_seq={latest}, count={}", messages.len()));
    let first = messages
        .first()
        .ok_or_else(|| "no messages returned".to_string())?;
    let plaintext = decrypt(&mut bob_group, &first.envelope)
        .map_err(|e| format!("bob decrypt: {e}"))?;
    if plaintext != b"hello via server" {
        return Err(format!(
            "bob recovered {:?}, expected 'hello via server'",
            String::from_utf8_lossy(&plaintext),
        ));
    }
    log(format!(
        "bob recovered: {:?}",
        String::from_utf8_lossy(&plaintext)
    ));

    log("== M4 phase γ.3 complete ==".to_string());
    Ok(())
}

/// Build a fresh `LatticeIdentity` from scratch — signature keypair via
/// the hybrid suite, ML-KEM-768 keypair from `KemKeyPair::generate`,
/// `LatticeCredential` filled with a deterministic test `user_id` byte
/// pattern. The flow mirrors `tests/mls_integration::make_identity` but
/// surfaces errors as `String`s so the closure-based UI logger can
/// report them.
fn make_identity(user_id_byte: u8) -> Result<LatticeIdentity, String> {
    let provider = LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .ok_or_else(|| "ciphersuite missing".to_string())?;
    let (sk, pk) = suite
        .signature_key_generate()
        .map_err(|e| format!("sig keygen: {e:?}"))?;
    let pk_bytes = pk.as_bytes();
    if pk_bytes.len() != ED25519_PK_LEN + ML_DSA_65_PK_LEN {
        return Err(format!(
            "unexpected hybrid pubkey length: {} (expected {})",
            pk_bytes.len(),
            ED25519_PK_LEN + ML_DSA_65_PK_LEN
        ));
    }
    let mut ed25519_pub = [0u8; ED25519_PK_LEN];
    ed25519_pub.copy_from_slice(&pk_bytes[..ED25519_PK_LEN]);
    let ml_dsa_pub = pk_bytes[ED25519_PK_LEN..].to_vec();

    let credential = LatticeCredential {
        user_id: [user_id_byte; USER_ID_LEN],
        ed25519_pub,
        ml_dsa_pub,
    };
    let kem_keypair = KemKeyPair::generate();

    Ok(LatticeIdentity {
        credential,
        signature_secret: sk,
        kem_keypair,
        key_package_repo: mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage::default(),
    })
}
