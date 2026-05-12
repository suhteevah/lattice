//! Top-level Leptos component for the M4 in-browser preview.
//!
//! Phase α exercises `lattice-crypto`'s hybrid signature + hybrid KEM in
//! the browser. Phase β runs the full Alice ⇌ Bob MLS round-trip from
//! `lattice-crypto::mls` — group create, KeyPackage publish, add-member
//! commit + Welcome, process_welcome on the joiner, then bidirectional
//! `encrypt_application` / `decrypt`. Same code paths the CLI demo and
//! the M2 integration test exercise; here they run entirely in WASM.

use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use leptos::prelude::*;
use leptos::task::spawn_local;
use rand::rngs::OsRng;

use lattice_crypto::credential::{
    ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN, USER_ID_LEN,
};
use lattice_crypto::aead::{AeadKey, AeadNonce, decrypt as aead_decrypt, encrypt as aead_encrypt};
use lattice_crypto::fingerprint;
use lattice_crypto::hybrid_kex;
use lattice_crypto::padding;
use rand::RngCore;
use lattice_crypto::mls::cipher_suite::{LATTICE_HYBRID_V1, LatticeCryptoProvider};
use lattice_crypto::mls::leaf_node_kem::KemKeyPair;
use lattice_crypto::mls::psk::LatticePskStorage;
use lattice_crypto::mls::{
    LatticeIdentity, add_member, add_members, apply_commit, commit, create_group,
    create_group_with_storage, decrypt, encrypt_application, generate_key_package,
    process_welcome, process_welcome_with_storage, remove_member,
};
use lattice_protocol::sealed_sender::{open_at_recipient, seal};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};

use crate::api;
use crate::capabilities::Capabilities;
use crate::distrust::{DistrustEvent, DistrustLedger, Verdict};
use crate::passkey;
use crate::persist;
use crate::storage::LocalStorageGroupStateStorage;

const PASSKEY_CREDENTIAL_LS_KEY: &str = "lattice/passkey/credential_id_b64url";

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Default `lattice-server` endpoint for browser-side calls. Matches the
/// `LATTICE_BIND_ADDR` Matt uses for local dev. Override at compile time
/// later if we need to point at pixie / cnc.
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";

#[component]
pub fn App() -> impl IntoView {
    let boot_status = match persist::probe() {
        Ok(persist::BlobShape::None) => format!(
            "lattice-core v{} ready · no saved identity",
            lattice_core::VERSION
        ),
        Ok(persist::BlobShape::Plaintext) => match persist::load(None) {
            Ok(Some(identity)) => format!(
                "lattice-core v{} ready · restored identity {}…",
                lattice_core::VERSION,
                &B64.encode(identity.credential.user_id)[..12]
            ),
            Ok(None) => format!("lattice-core v{} ready", lattice_core::VERSION),
            Err(e) => format!(
                "lattice-core v{} ready · load error: {e}",
                lattice_core::VERSION
            ),
        },
        Ok(persist::BlobShape::Encrypted) => format!(
            "lattice-core v{} ready · encrypted identity present (click \
             \"Load encrypted\" to unlock)",
            lattice_core::VERSION
        ),
        Ok(persist::BlobShape::PrfEncrypted) => {
            let prefix = persist::v3_credential_id()
                .ok()
                .flatten()
                .map(|id| id.chars().take(12).collect::<String>())
                .unwrap_or_else(|| "?".to_string());
            format!(
                "lattice-core v{} ready · passkey-encrypted identity for credential {}… \
                 (click \"Load PRF-encrypted\")",
                lattice_core::VERSION,
                prefix,
            )
        }
        Err(e) => format!(
            "lattice-core v{} ready · probe error: {e}",
            lattice_core::VERSION
        ),
    };
    let (status, set_status) = signal::<String>(boot_status);
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

    let safety_number_demo = move |_| {
        set_log_lines.set(Vec::new());
        match try_safety_number_demo(append) {
            Ok(()) => set_status.set("safety numbers OK".to_string()),
            Err(e) => set_status.set(format!("safety numbers error: {e}")),
        }
    };

    let live_ws_demo = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("opening WS subscription…".to_string());
        let log = append;
        spawn_local(async move {
            match try_live_ws_demo(DEFAULT_SERVER_URL, log).await {
                Ok(count) => {
                    set_status.set(format!("WS push OK ({count} message(s) received)"))
                }
                Err(e) => set_status.set(format!("WS error: {e}")),
            }
        });
    };

    let multi_member_demo = move |_| {
        set_log_lines.set(Vec::new());
        match try_multi_member_demo(append) {
            Ok(()) => set_status.set("multi-member demo OK".to_string()),
            Err(e) => set_status.set(format!("multi-member error: {e}")),
        }
    };

    let persistent_group_demo = move |_| {
        set_log_lines.set(Vec::new());
        match try_persistent_group_demo(append) {
            Ok(()) => set_status.set("persistent group demo OK".to_string()),
            Err(e) => set_status.set(format!("persistent group error: {e}")),
        }
    };

    let distrust_demo = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("running distrust demo…".to_string());
        let log = append;
        spawn_local(async move {
            match try_distrust_demo(DEFAULT_SERVER_URL, log).await {
                Ok(verdict) => {
                    set_status.set(format!("distrust demo OK ({verdict:?})"))
                }
                Err(e) => set_status.set(format!("distrust error: {e}")),
            }
        });
    };

    let revocation_demo = move |_| {
        set_log_lines.set(Vec::new());
        match try_revocation_demo(append) {
            Ok(()) => set_status.set("revocation demo OK".to_string()),
            Err(e) => set_status.set(format!("revocation error: {e}")),
        }
    };

    let attachment_demo = move |_| {
        set_log_lines.set(Vec::new());
        match try_attachment_demo(append) {
            Ok(()) => set_status.set("attachment demo OK".to_string()),
            Err(e) => set_status.set(format!("attachment error: {e}")),
        }
    };

    let cadence_demo = move |_| {
        set_log_lines.set(Vec::new());
        match try_cadence_demo(append) {
            Ok(()) => set_status.set("cadence demo OK".to_string()),
            Err(e) => set_status.set(format!("cadence error: {e}")),
        }
    };

    let sealed_sender_demo = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("running sealed-sender demo…".to_string());
        let log = append;
        spawn_local(async move {
            match try_sealed_sender_demo(DEFAULT_SERVER_URL, log).await {
                Ok(()) => set_status.set("sealed-sender OK".to_string()),
                Err(e) => set_status.set(format!("sealed-sender error: {e}")),
            }
        });
    };

    let save_identity = move |_| {
        set_log_lines.set(Vec::new());
        let log = append;
        match try_save_identity(log, None) {
            Ok(user_id_prefix) => {
                set_status.set(format!("saved identity {user_id_prefix}…"));
            }
            Err(e) => set_status.set(format!("save error: {e}")),
        }
    };

    let save_encrypted = move |_| {
        set_log_lines.set(Vec::new());
        let log = append;
        match prompt_passphrase("Set passphrase to encrypt the identity at rest") {
            Ok(Some(pw)) => match try_save_identity(log, Some(&pw)) {
                Ok(user_id_prefix) => {
                    set_status.set(format!("saved encrypted identity {user_id_prefix}…"));
                }
                Err(e) => set_status.set(format!("save error: {e}")),
            },
            Ok(None) => set_status.set("save cancelled".to_string()),
            Err(e) => set_status.set(format!("prompt error: {e}")),
        }
    };

    let load_encrypted = move |_| {
        set_log_lines.set(Vec::new());
        let log = append;
        match prompt_passphrase("Enter passphrase to decrypt the saved identity") {
            Ok(Some(pw)) => match persist::load(Some(&pw)) {
                Ok(Some(identity)) => {
                    log("== loaded encrypted identity ==".to_string());
                    log(format!(
                        "user_id: {}",
                        B64.encode(identity.credential.user_id)
                    ));
                    set_status.set(format!(
                        "loaded identity {}…",
                        &B64.encode(identity.credential.user_id)[..12]
                    ));
                }
                Ok(None) => set_status.set("no saved identity".to_string()),
                Err(e) => set_status.set(format!("load error: {e}")),
            },
            Ok(None) => set_status.set("load cancelled".to_string()),
            Err(e) => set_status.set(format!("prompt error: {e}")),
        }
    };

    let save_prf_encrypted = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("save passkey-encrypted identity…".to_string());
        let log = append;
        spawn_local(async move {
            match try_save_prf_encrypted(log).await {
                Ok(user_id_prefix) => set_status.set(format!(
                    "saved passkey-encrypted identity {user_id_prefix}…"
                )),
                Err(e) => set_status.set(format!("save PRF error: {e}")),
            }
        });
    };

    let load_prf_encrypted = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("loading passkey-encrypted identity…".to_string());
        let log = append;
        spawn_local(async move {
            match try_load_prf_encrypted(log).await {
                Ok(user_id_prefix) => {
                    set_status.set(format!("loaded passkey-encrypted identity {user_id_prefix}…"));
                }
                Err(e) => set_status.set(format!("load PRF error: {e}")),
            }
        });
    };

    let create_passkey = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("creating passkey…".to_string());
        let log = append;
        spawn_local(async move {
            match try_create_passkey(log).await {
                Ok(id_prefix) => set_status.set(format!(
                    "passkey created (credential_id {id_prefix}…)"
                )),
                Err(e) => set_status.set(format!("passkey create error: {e}")),
            }
        });
    };

    let derive_passkey_kek = move |_| {
        set_log_lines.set(Vec::new());
        set_status.set("deriving PRF KEK…".to_string());
        let log = append;
        spawn_local(async move {
            match try_derive_passkey_kek(log).await {
                Ok(kek_prefix) => {
                    set_status.set(format!("PRF KEK derived ({kek_prefix}…)"));
                }
                Err(e) => set_status.set(format!("passkey PRF error: {e}")),
            }
        });
    };

    let clear_identity = move |_| {
        set_log_lines.set(Vec::new());
        match persist::clear() {
            Ok(true) => set_status.set("cleared saved identity".to_string()),
            Ok(false) => set_status.set("no saved identity to clear".to_string()),
            Err(e) => set_status.set(format!("clear error: {e}")),
        }
    };

    let tauri_host = crate::tauri::is_tauri();

    let desktop_handshake = move |_| {
        set_log_lines.set(Vec::new());
        if !tauri_host {
            set_status.set(
                "desktop info: not running inside the Lattice desktop shell".to_string(),
            );
            return;
        }
        set_status.set("desktop info: querying shell…".to_string());
        let log = append;
        spawn_local(async move {
            match crate::tauri::desktop_info().await {
                Ok(Some(info)) => {
                    log(format!("greeting: {}", info.greeting));
                    log(format!("core_version: {}", info.core_version));
                    log(format!("media_version: {}", info.media_version));
                    set_status.set("desktop info OK".to_string());
                }
                Ok(None) => set_status.set("desktop info: probe returned None".to_string()),
                Err(e) => set_status.set(format!("desktop info error: {e}")),
            }
        });
    };

    let phase_f_call_demo = move |_| {
        set_log_lines.set(Vec::new());
        if !tauri_host {
            set_status.set(
                "Phase F call demo runs inside the Lattice desktop shell — \
                 build with `cargo tauri dev` from apps/lattice-desktop/src-tauri/"
                    .to_string(),
            );
            return;
        }
        set_status.set("Phase F call: running PQ-DTLS-SRTP loopback in the shell…".to_string());
        let log = append;
        spawn_local(async move {
            let request = crate::tauri::StartCallRequest::default();
            match crate::tauri::start_call(&request).await {
                Ok(report) => {
                    log("== Phase F call demo (lattice-media loopback) ==".to_string());
                    log(format!("call_id: {}", report.call_id_hex));
                    log(format!(
                        "ice candidates seen: caller={}, callee={}",
                        report.caller_candidates_seen, report.callee_candidates_seen
                    ));
                    log(format!("srtp master prefix: {}", report.srtp_master_prefix));
                    log(format!(
                        "rtp: plain={} B → protected={} B → recovered={} B",
                        report.plain_rtp_len, report.protected_rtp_len, report.recovered_rtp_len
                    ));
                    set_status.set(format!(
                        "Phase F call OK (call_id {})",
                        &report.call_id_hex[..16.min(report.call_id_hex.len())]
                    ));
                    // Best-effort teardown so the shell registry doesn't grow.
                    if let Err(e) = crate::tauri::end_call(&report.call_id_hex).await {
                        log(format!("end_call cleanup error: {e}"));
                    }
                }
                Err(e) => set_status.set(format!("Phase F call error: {e}")),
            }
        });
    };

    // Chunk A — chat shell signals. Seeded with one mock conversation
    // so the panes feel populated; chunk C wires this to real MLS
    // state and removes the seed. Display name defaults to a short
    // user_id prefix once we restore an identity; falls back to "me".
    let (chat_convos_seed, chat_messages_seed) = crate::chat::mock_seed();
    let chat_convos = RwSignal::new(chat_convos_seed);
    let chat_messages = RwSignal::new(chat_messages_seed);
    let chat_view = RwSignal::new(crate::chat::ChatView::Empty);
    let chat_display_name = Signal::derive(move || {
        match persist::probe() {
            Ok(persist::BlobShape::Plaintext) => persist::load(None)
                .ok()
                .flatten()
                .map(|id| {
                    let prefix = &B64.encode(id.credential.user_id)[..6];
                    format!("me ({prefix})")
                })
                .unwrap_or_else(|| "me".to_string()),
            _ => "me".to_string(),
        }
    });

    // Toggle the legacy debug grid open/closed. Default closed so the
    // chat shell is the visible default; one click opens debug.
    let (debug_open, set_debug_open) = signal(false);

    view! {
        <main class="page">
            <section class="card" aria-labelledby="lattice-heading">
                <h1 id="lattice-heading">"Lattice"</h1>
                <p class="tagline">"Post-quantum encrypted messaging."</p>
                <div class="status" role="status" aria-live="polite">
                    {move || status.get()}
                </div>
                <crate::chat::ChatShell
                    conversations=chat_convos
                    messages=chat_messages
                    current_view=chat_view
                    display_name=chat_display_name
                />
                <details class="debug-details" open=move || debug_open.get()>
                    <summary
                        class="debug-summary"
                        on:click=move |_| set_debug_open.update(|b| *b = !*b)
                    >
                        "Debug tools (legacy demo grid)"
                    </summary>
                <CapabilitiesPanel/>
                <div class="button-row" role="group" aria-label="demo actions">
                    <button class="button" on:click=run_primitives>"Run primitives demo"</button>
                    <button class="button" on:click=run_mls>"Run MLS round-trip"</button>
                    <button class="button" on:click=register_server>"Register with server"</button>
                    <button class="button" on:click=key_package_round_trip>"KP publish + fetch"</button>
                    <button class="button" on:click=server_backed_demo>"Server-backed demo"</button>
                    <button class="button" on:click=sealed_sender_demo>"Sealed-sender demo"</button>
                    <button class="button" on:click=cadence_demo>"Commit cadence demo"</button>
                    <button class="button" on:click=attachment_demo>"Attachment demo"</button>
                    <button class="button" on:click=revocation_demo>"Device revocation demo"</button>
                    <button class="button" on:click=distrust_demo>"Federation distrust demo"</button>
                    <button class="button" on:click=persistent_group_demo>"Persistent group demo (δ.3)"</button>
                    <button class="button" on:click=multi_member_demo>"Multi-member group (3-party)"</button>
                    <button class="button" on:click=live_ws_demo>"Live WS push (γ.4 fallback)"</button>
                    <button class="button" on:click=safety_number_demo>"Safety number (M6)"</button>
                    <button class="button" on:click=save_identity>"Save identity"</button>
                    <button class="button" on:click=save_encrypted>"Save encrypted"</button>
                    <button class="button" on:click=load_encrypted>"Load encrypted"</button>
                    <button class="button" on:click=create_passkey>"Create passkey"</button>
                    <button class="button" on:click=derive_passkey_kek>"Derive PRF KEK"</button>
                    <button class="button" on:click=save_prf_encrypted>"Save PRF-encrypted"</button>
                    <button class="button" on:click=load_prf_encrypted>"Load PRF-encrypted"</button>
                    <button class="button" on:click=clear_identity>"Clear saved identity"</button>
                    <button class="button" on:click=desktop_handshake>
                        {if tauri_host { "Desktop info (Phase F)" } else { "Desktop info (desktop only)" }}
                    </button>
                    <button class="button" on:click=phase_f_call_demo>
                        {if tauri_host { "Phase F: PQ call demo" } else { "Phase F: PQ call demo (desktop only)" }}
                    </button>
                </div>
                <div class="muted" aria-label="host environment">
                    {if tauri_host {
                        "Host: Lattice desktop shell — native voice/video available."
                    } else {
                        "Host: browser tab — voice/video runs only in the desktop shell."
                    }}
                </div>
                <Show
                    when=move || !log_lines.get().is_empty()
                    fallback=|| view! {}
                >
                    <pre class="log" role="log" aria-live="polite" aria-label="demo output">
                        {move || log_lines.get().join("\n")}
                    </pre>
                </Show>
                </details>
                <footer class="footer">
                    <span class="dot-sage" aria-hidden="true"></span>
                    <span class="muted">"End-to-end encrypted • PQ-hybrid"</span>
                </footer>
            </section>
        </main>
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

/// M6 safety numbers (ROADMAP §M6). Computes the pairwise
/// fingerprint for Alice + Bob's hybrid identity pubkeys and shows
/// the rendered 60-decimal-digit comparison string. Two parties
/// reading the same string out loud over a side channel (phone
/// call, in-person) detect a MITM that swapped one user's key
/// bundle before they ever met on-band.
///
/// The render is order-independent — Alice and Bob compute the
/// same digits regardless of who lists themselves first.
fn try_safety_number_demo(log: impl Fn(String) + Copy) -> Result<(), String> {
    log("== safety number demo ==".to_string());
    let alice = make_identity(0xF1)?;
    let bob = make_identity(0xF2)?;

    // The "identity pubkey" in fingerprint terms is the packed
    // ed25519 || ml-dsa pubkey that lives in the credential. Same
    // bytes mls-rs sees as the leaf signing key.
    let mut alice_pk = Vec::with_capacity(
        alice.credential.ed25519_pub.len() + alice.credential.ml_dsa_pub.len(),
    );
    alice_pk.extend_from_slice(&alice.credential.ed25519_pub);
    alice_pk.extend_from_slice(&alice.credential.ml_dsa_pub);
    let mut bob_pk = Vec::with_capacity(
        bob.credential.ed25519_pub.len() + bob.credential.ml_dsa_pub.len(),
    );
    bob_pk.extend_from_slice(&bob.credential.ed25519_pub);
    bob_pk.extend_from_slice(&bob.credential.ml_dsa_pub);

    let num_ab = fingerprint::safety_number(&alice_pk, &bob_pk);
    let num_ba = fingerprint::safety_number(&bob_pk, &alice_pk);
    if num_ab != num_ba {
        return Err("safety number is not order-independent".into());
    }
    log(format!("alice pubkey: {} bytes", alice_pk.len()));
    log(format!("bob pubkey:   {} bytes", bob_pk.len()));
    log(format!("safety number: {num_ab}"));
    log("order-independent: yes (A↔B == B↔A)".to_string());

    // Sanity: a third party with different keys produces a different
    // number — confirms the function is sensitive to its inputs.
    let carol = make_identity(0xF3)?;
    let mut carol_pk = Vec::with_capacity(
        carol.credential.ed25519_pub.len() + carol.credential.ml_dsa_pub.len(),
    );
    carol_pk.extend_from_slice(&carol.credential.ed25519_pub);
    carol_pk.extend_from_slice(&carol.credential.ml_dsa_pub);
    let num_ac = fingerprint::safety_number(&alice_pk, &carol_pk);
    log(format!("alice↔carol:   {num_ac}"));
    if num_ab == num_ac {
        return Err("different peers must produce different safety numbers".into());
    }
    log("different peer → different number: yes".to_string());

    log("== M6 safety numbers complete ==".to_string());
    Ok(())
}

/// M4 γ.4 fallback: WebSocket message push. D-11 names WebTransport
/// as the preferred transport and WebSocket as the fallback when
/// WT isn't available. Full WT server-side ships in a focused
/// session (sized at ~1500 LOC in HANDOFF §M4 status); this is the
/// fallback path running today.
///
/// Flow:
/// 1. Register + publish KP for a fresh user.
/// 2. Create a 1:1 group (group_id stable so multiple tabs can join
///    the same conversation).
/// 3. Open `/group/:gid/messages/ws`.
/// 4. Publish a message via the HTTP POST path.
/// 5. Verify it arrives on the WS subscription.
///
/// Returns the number of WS pushes observed. Production callers
/// would keep the socket live for the duration of the session, not
/// close it after one message.
async fn try_live_ws_demo(
    server: &str,
    log: impl Fn(String) + Copy + 'static,
) -> Result<u32, String> {
    use std::cell::RefCell;
    use std::rc::Rc;
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;

    log(format!("== live WS push demo against {server} =="));
    let alice = make_identity(0xD0)?;
    let bob = make_identity(0xD1)?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();
    api::register(server, &alice).await?;
    api::register(server, &bob).await?;
    let _ = api::publish_key_package(server, &bob, &bob_psk).await?;
    let bob_kp_bytes = api::fetch_key_package(server, &bob.credential.user_id).await?;

    let group_id: [u8; 16] = *b"lattice-ws-live!";
    let mut alice_group = create_group(&alice, alice_psk.clone(), &group_id)
        .map_err(|e| format!("create_group: {e}"))?;
    let commit_output =
        add_member(&mut alice_group, &bob_kp_bytes).map_err(|e| format!("add_member: {e}"))?;
    let welcome = commit_output
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| "no welcome".to_string())?;
    let _ = api::submit_commit(
        server,
        &group_id,
        welcome.pq_payload.epoch,
        &commit_output.commit,
        &welcome,
        &bob.credential.user_id,
    )
    .await?;
    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit: {e}"))?;
    let mut bob_group = process_welcome(&bob, bob_psk.clone(), &welcome)
        .map_err(|e| format!("process_welcome: {e}"))?;
    log("group ready; opening WS subscription…".to_string());

    let ws = api::open_messages_ws(server, &group_id)?;
    let received: Rc<RefCell<Vec<api::WsPush>>> = Rc::new(RefCell::new(Vec::new()));

    let received_for_open = received.clone();
    let on_open = Closure::wrap(Box::new(move |_evt: web_sys::Event| {
        log("WS open".to_string());
        // touch received so the closure captures it (otherwise the
        // borrow checker drops it before on_message runs).
        let _ = received_for_open.clone();
    }) as Box<dyn FnMut(web_sys::Event)>);
    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    on_open.forget();

    let received_for_msg = received.clone();
    let on_message = Closure::wrap(Box::new(move |evt: web_sys::MessageEvent| {
        if let Some(s) = evt.data().as_string() {
            match api::parse_ws_push(&s) {
                Ok(push) => {
                    log(format!(
                        "WS push: seq={}, envelope {} bytes",
                        push.seq,
                        push.envelope.len()
                    ));
                    received_for_msg.borrow_mut().push(push);
                }
                Err(e) => log(format!("WS parse error: {e}")),
            }
        }
    }) as Box<dyn FnMut(web_sys::MessageEvent)>);
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();

    // Wait a beat for the WS to attach before we publish — the
    // server-side broadcast::Sender is created lazily by
    // `subscribe()`, so the publisher firing before subscription is
    // attached would deliver to nobody.
    sleep_ms(200).await;

    log("publishing 2 messages via HTTP POST…".to_string());
    let ct1 = encrypt_application(&mut alice_group, b"ws push #1")
        .map_err(|e| format!("encrypt #1: {e}"))?;
    let _ = api::publish_message(server, &group_id, &ct1).await?;
    let ct2 = encrypt_application(&mut alice_group, b"ws push #2")
        .map_err(|e| format!("encrypt #2: {e}"))?;
    let _ = api::publish_message(server, &group_id, &ct2).await?;

    // Wait for the pushes to land on the WS.
    for _ in 0..40 {
        if received.borrow().len() >= 2 {
            break;
        }
        sleep_ms(50).await;
    }

    let pushes = received.borrow();
    let count = u32::try_from(pushes.len()).unwrap_or(u32::MAX);
    if pushes.len() < 2 {
        return Err(format!(
            "expected ≥ 2 WS pushes, got {count} (server saw broadcast subscriber late?)"
        ));
    }

    // Verify Bob can decrypt the pushed envelopes off the WS stream
    // (rather than via the HTTP fetch path).
    let pt1 = decrypt(&mut bob_group, &pushes[0].envelope)
        .map_err(|e| format!("bob decrypt #1: {e}"))?;
    let pt2 = decrypt(&mut bob_group, &pushes[1].envelope)
        .map_err(|e| format!("bob decrypt #2: {e}"))?;
    log(format!(
        "bob decrypted from WS: {:?}, {:?}",
        std::str::from_utf8(&pt1).unwrap_or("?"),
        std::str::from_utf8(&pt2).unwrap_or("?"),
    ));

    let _ = ws.close();
    log("== M4 γ.4 fallback (WS) complete ==".to_string());
    Ok(count)
}

/// Tiny sleep helper backed by `setTimeout`. Used to give the
/// browser event loop a chance to run async network callbacks
/// before the demo flow continues.
async fn sleep_ms(ms: i32) {
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen_futures::JsFuture;
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        if let Some(window) = web_sys::window() {
            let cb = Closure::once_into_js(move || {
                let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
            });
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                ms,
            );
        }
    });
    let _ = JsFuture::from(promise).await;
}

/// M5: multi-member MLS group with shared PSK injection. Three
/// parties (Alice + Bob + Carol) join the same group in **one
/// commit** thanks to the wire-v2 `PqWelcomePayload` carrying an
/// HKDF-wrap of a single shared 32-byte secret `W`. Both joiners
/// recover the same `W` from their own ML-KEM ciphertext + wrap_ct,
/// register it under the same PSK id, and `Client::join_group`
/// succeeds for both.
///
/// After the commit applies the group is at epoch 1 with three
/// members. Alice broadcasts a message; both Bob and Carol decrypt
/// it.
fn try_multi_member_demo(log: impl Fn(String) + Copy) -> Result<(), String> {
    log("== multi-member group demo ==".to_string());
    let alice = make_identity(0xA1)?;
    let bob = make_identity(0xA2)?;
    let carol = make_identity(0xA3)?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();
    let carol_psk = LatticePskStorage::new();
    log(format!(
        "alice/bob/carol user_ids: {}/{}/{}",
        &B64.encode(alice.credential.user_id)[..8],
        &B64.encode(bob.credential.user_id)[..8],
        &B64.encode(carol.credential.user_id)[..8],
    ));

    let group_id: [u8; 16] = *b"lattice-3-party!";
    let mut alice_group = create_group(&alice, alice_psk.clone(), &group_id)
        .map_err(|e| format!("create_group: {e}"))?;
    log(format!(
        "alice created group (epoch {})",
        alice_group.current_epoch()
    ));

    let bob_kp =
        generate_key_package(&bob, bob_psk.clone()).map_err(|e| format!("bob kp: {e}"))?;
    let carol_kp =
        generate_key_package(&carol, carol_psk.clone()).map_err(|e| format!("carol kp: {e}"))?;
    log(format!(
        "bob kp: {} bytes, carol kp: {} bytes",
        bob_kp.len(),
        carol_kp.len()
    ));

    log("== alice adds {bob, carol} in one commit ==".to_string());
    let commit_output = add_members(&mut alice_group, &[&bob_kp, &carol_kp])
        .map_err(|e| format!("add_members: {e}"))?;
    if commit_output.welcomes.len() != 2 {
        return Err(format!(
            "expected 2 welcomes, got {}",
            commit_output.welcomes.len()
        ));
    }
    log(format!(
        "commit: {} bytes, welcomes: 2 (idx 0 pq epoch {}, idx 1 pq epoch {})",
        commit_output.commit.len(),
        commit_output.welcomes[0].pq_payload.epoch,
        commit_output.welcomes[1].pq_payload.epoch,
    ));
    log(format!(
        "joiner_idx: w0={}, w1={}",
        commit_output.welcomes[0].pq_payload.joiner_idx,
        commit_output.welcomes[1].pq_payload.joiner_idx,
    ));

    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit: {e}"))?;

    // Each joiner gets the welcome at their position in the add list.
    let bob_welcome = &commit_output.welcomes[0];
    let carol_welcome = &commit_output.welcomes[1];
    let mut bob_group = process_welcome(&bob, bob_psk.clone(), bob_welcome)
        .map_err(|e| format!("bob process_welcome: {e}"))?;
    let mut carol_group = process_welcome(&carol, carol_psk.clone(), carol_welcome)
        .map_err(|e| format!("carol process_welcome: {e}"))?;
    log(format!(
        "epochs after join — alice={}, bob={}, carol={}",
        alice_group.current_epoch(),
        bob_group.current_epoch(),
        carol_group.current_epoch()
    ));

    // PSK stores all hold the same W under epoch 1.
    let alice_psk_count = alice_psk
        .len()
        .map_err(|e| format!("alice psk len: {e}"))?;
    let bob_psk_count = bob_psk.len().map_err(|e| format!("bob psk len: {e}"))?;
    let carol_psk_count = carol_psk.len().map_err(|e| format!("carol psk len: {e}"))?;
    log(format!(
        "PSK stores: alice={alice_psk_count}, bob={bob_psk_count}, carol={carol_psk_count}"
    ));

    // Alice broadcasts to both joiners.
    let ct = encrypt_application(&mut alice_group, b"hello, 3-party group!")
        .map_err(|e| format!("alice encrypt: {e}"))?;
    log(format!("alice ciphertext: {} bytes", ct.len()));

    let bob_pt = decrypt(&mut bob_group, &ct).map_err(|e| format!("bob decrypt: {e}"))?;
    if bob_pt != b"hello, 3-party group!" {
        return Err("bob plaintext mismatch".into());
    }
    let carol_pt = decrypt(&mut carol_group, &ct).map_err(|e| format!("carol decrypt: {e}"))?;
    if carol_pt != b"hello, 3-party group!" {
        return Err("carol plaintext mismatch".into());
    }
    log("bob & carol both recovered: \"hello, 3-party group!\"".to_string());
    log("== M5 multi-member (3-party) complete ==".to_string());
    Ok(())
}

/// M4 Phase δ.3: MLS group state persisted to localStorage via
/// `LocalStorageGroupStateStorage`. The demo creates a fresh 1:1
/// group with Alice and Bob, sends an application message, then
/// reads `LocalStorageGroupStateStorage::stored_groups()` to prove
/// the group state is on disk. Reload-survival is the deferred
/// follow-up (needs a load_group entrypoint wired into the demo
/// flow).
fn try_persistent_group_demo(log: impl Fn(String) + Copy) -> Result<(), String> {
    log("== persistent group demo ==".to_string());
    let alice = make_identity(0xE1)?;
    let bob = make_identity(0xE2)?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();
    let storage = LocalStorageGroupStateStorage;

    // Clean any leftover state from a previous run so the test is
    // reproducible across clicks.
    let group_id: [u8; 16] = *b"lattice-persist1";
    let _ = storage.delete_group(&group_id);

    let mut alice_group =
        create_group_with_storage(&alice, alice_psk.clone(), &group_id, storage.clone())
            .map_err(|e| format!("create_group: {e}"))?;
    let bob_kp = generate_key_package(&bob, bob_psk.clone())
        .map_err(|e| format!("generate_key_package: {e}"))?;
    let commit_output =
        add_member(&mut alice_group, &bob_kp).map_err(|e| format!("add_member: {e}"))?;
    let welcome = commit_output
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| "no welcome".to_string())?;
    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit: {e}"))?;
    let mut bob_group =
        process_welcome_with_storage(&bob, bob_psk.clone(), &welcome, storage.clone())
            .map_err(|e| format!("process_welcome: {e}"))?;
    log(format!(
        "group created & joined — epoch {}",
        alice_group.current_epoch()
    ));

    let ct = encrypt_application(&mut alice_group, b"persisted hello")
        .map_err(|e| format!("alice encrypt: {e}"))?;
    let pt = decrypt(&mut bob_group, &ct)
        .map_err(|e| format!("bob decrypt: {e}"))?;
    if pt.as_slice() != b"persisted hello" {
        return Err("plaintext mismatch".into());
    }
    log(format!(
        "encrypt/decrypt OK ({} bytes ciphertext)",
        ct.len()
    ));

    let stored = storage
        .stored_groups()
        .map_err(|e| format!("stored_groups: {e}"))?;
    log(format!(
        "stored_groups index: {} entry/ies",
        stored.len()
    ));
    let found = stored.iter().any(|gid| gid == &group_id);
    if !found {
        return Err("group_id missing from stored_groups index".into());
    }
    log("group_id found in localStorage index".to_string());

    // Read back the raw state bytes so we can show their size.
    use mls_rs_core::group::GroupStateStorage as _;
    let raw = storage
        .state(&group_id)
        .map_err(|e| format!("storage.state: {e}"))?
        .ok_or_else(|| "state missing".to_string())?;
    log(format!(
        "alice state snapshot in localStorage: {} bytes",
        raw.len()
    ));
    if let Some(max_epoch) = storage
        .max_epoch_id(&group_id)
        .map_err(|e| format!("max_epoch_id: {e}"))?
    {
        log(format!("max persisted epoch_id: {max_epoch}"));
    }

    log("== M4 phase δ.3 (group state persistence) complete ==".to_string());
    Ok(())
}

/// M5: local-only federation distrust scoring (D-13). Exercises
/// the in-tab `DistrustLedger`:
///
/// 1. Load the ledger from localStorage.
/// 2. Fetch the dev server's `/.well-known/lattice/server`
///    descriptor, TOFU-pin its federation pubkey, record a
///    `PinnedKeyMatch` event.
/// 3. Try pinning a fake-but-different pubkey to the same URL —
///    `pin_pubkey` returns `Err` and records a `PinViolation`,
///    which knocks the score down hard.
/// 4. Apply a few `Ok` events to show the score recovering.
/// 5. Save the ledger back to localStorage.
async fn try_distrust_demo(
    server: &str,
    log: impl Fn(String) + Copy,
) -> Result<Verdict, String> {
    log("== distrust demo ==".to_string());
    let mut ledger = DistrustLedger::load();
    let pre_count = ledger.peers.len();
    log(format!("ledger loaded ({pre_count} peer(s) before)"));

    let descriptor = api::fetch_descriptor(server).await?;
    log(format!(
        "fetched descriptor: federation_pubkey={}…",
        &descriptor.federation_pubkey_b64[..16]
    ));

    let now = chrono_now_unix();
    let pin1 = ledger.pin_pubkey(server, &descriptor.federation_pubkey_b64, now)?;
    log(format!("after PinnedKeyMatch: score = {pin1}"));

    let pin2 = ledger.pin_pubkey(server, "AAAA-fake-key-that-does-not-match-AAAA=", now);
    match pin2 {
        Err(e) => log(format!("violation caught (expected): {e}")),
        Ok(s) => return Err(format!("violation NOT caught: score={s}")),
    }
    let after_violation = ledger
        .peers
        .get(server)
        .map(|p| p.score)
        .unwrap_or_default();
    log(format!("after PinViolation: score = {after_violation}"));

    for _ in 0..5 {
        let _ = ledger.record(server, DistrustEvent::Ok, now);
    }
    let after_recovery = ledger
        .peers
        .get(server)
        .map(|p| p.score)
        .unwrap_or_default();
    log(format!("after 5×Ok events: score = {after_recovery}"));

    ledger.save();
    let post_count = ledger.peers.len();
    log(format!("ledger saved ({post_count} peer(s) now)"));

    let verdict = Verdict::from_score(after_recovery);
    log(format!("verdict: {verdict:?}"));
    log("== M5 distrust scoring complete ==".to_string());
    Ok(verdict)
}

/// M5: device revocation via MLS Remove proposal. ROADMAP §M5
/// names "device revocation via MLS Remove proposal; UI to list and
/// revoke devices" as a deliverable. Here we ship the protocol
/// half — the UI list is a chip later.
///
/// 1:1 demo: Alice creates a 2-member group with Bob, exchanges a
/// "before revocation" message, then issues a `remove_member`
/// commit pointed at Bob's leaf. Alice's epoch advances; Bob
/// processes the commit and his subsequent decrypt attempts must
/// fail (he's no longer in the group). We assert both halves: pre-
/// revocation success + post-revocation failure.
fn try_revocation_demo(log: impl Fn(String) + Copy) -> Result<(), String> {
    log("== device revocation demo ==".to_string());
    let alice = make_identity(0xD1)?;
    let bob = make_identity(0xD2)?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();

    let group_id: [u8; 16] = *b"lattice-revoke!!";
    let mut alice_group = create_group(&alice, alice_psk.clone(), &group_id)
        .map_err(|e| format!("create_group: {e}"))?;
    let bob_kp = generate_key_package(&bob, bob_psk.clone())
        .map_err(|e| format!("generate_key_package: {e}"))?;
    let commit_output =
        add_member(&mut alice_group, &bob_kp).map_err(|e| format!("add_member: {e}"))?;
    let welcome = commit_output
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| "no welcome".to_string())?;
    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit (add): {e}"))?;
    let mut bob_group = process_welcome(&bob, bob_psk.clone(), &welcome)
        .map_err(|e| format!("process_welcome: {e}"))?;

    let members = alice_group
        .members()
        .map_err(|e| format!("members: {e}"))?;
    log(format!(
        "roster: {}",
        members
            .iter()
            .map(|(idx, uid)| format!("leaf={idx} uid={}", &B64.encode(uid)[..12]))
            .collect::<Vec<_>>()
            .join(", "),
    ));

    // Pre-revocation: round-trip a message to prove the group is live.
    let pre_ct = encrypt_application(&mut alice_group, b"pre-revoke ping")
        .map_err(|e| format!("alice encrypt (pre): {e}"))?;
    let pre_pt =
        decrypt(&mut bob_group, &pre_ct).map_err(|e| format!("bob decrypt (pre): {e}"))?;
    if pre_pt.as_slice() != b"pre-revoke ping" {
        return Err("pre-revocation plaintext mismatch".into());
    }
    log("pre-revocation: bob received \"pre-revoke ping\"".to_string());

    // Find Bob's leaf via user_id.
    let bob_user_id = bob.credential.user_id;
    let bob_leaf = members
        .iter()
        .find_map(|(idx, uid)| (*uid == bob_user_id).then_some(*idx))
        .ok_or_else(|| "bob not in roster".to_string())?;
    log(format!(
        "issuing Remove proposal for bob @ leaf {bob_leaf}"
    ));
    let remove_output =
        remove_member(&mut alice_group, bob_leaf).map_err(|e| format!("remove_member: {e}"))?;
    log(format!(
        "remove-commit: {} bytes (welcomes: {})",
        remove_output.commit.len(),
        remove_output.welcomes.len(),
    ));
    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit (remove): {e}"))?;

    // Bob processes the commit. mls-rs's process_incoming_message
    // accepts the commit even though the receiver is being removed —
    // it advances his state, then subsequent encrypt/decrypt fails
    // because his leaf is gone.
    let _ = decrypt(&mut bob_group, &remove_output.commit)
        .map_err(|e| format!("bob process remove-commit: {e}"))?;
    log(format!(
        "post-revocation epochs — alice={}, bob={}",
        alice_group.current_epoch(),
        bob_group.current_epoch()
    ));

    // Post-revocation: Bob should no longer be able to decrypt
    // application messages from Alice. (Alice can't trivially encrypt
    // either — a 1-member group has no peers in mls-rs's
    // application-message path.)
    let post_attempt = encrypt_application(&mut alice_group, b"post-revoke ping");
    match post_attempt {
        Err(e) => log(format!(
            "alice encrypt post-revoke: rejected (expected — solo group): {e}"
        )),
        Ok(ct) => match decrypt(&mut bob_group, &ct) {
            Err(e) => log(format!(
                "bob decrypt post-revoke: rejected (expected): {e}"
            )),
            Ok(_) => return Err("bob should not have been able to decrypt after revocation".into()),
        },
    }

    log("== M5 revocation flow complete ==".to_string());
    Ok(())
}

/// M5: encrypted, padded attachment round-trip. ROADMAP §M5 names
/// "File + image attachments: encrypted, padded to upload buckets,
/// ciphertext stored on home server" as a deliverable. This shows the
/// crypto half end-to-end in WASM: random plaintext of varying sizes
/// gets bucketed via `lattice_crypto::padding`, then sealed with
/// ChaCha20-Poly1305. The server-storage half (upload + retention)
/// hooks onto this same byte stream and lands as a separate phase.
fn try_attachment_demo(log: impl Fn(String) + Copy) -> Result<(), String> {
    log("== attachment demo ==".to_string());
    log(format!(
        "padding buckets: {:?}",
        padding::BUCKETS
    ));

    // Probe a few size points to show bucket selection.
    let probes: &[usize] = &[200, 1_000, 10_000, 60_000];
    for &size in probes {
        let mut payload = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut payload);

        let padded = padding::pad(&payload)
            .map_err(|e| format!("pad {size}: {e}"))?;
        log(format!(
            "payload {size}B → padded {} B (bucket selected)",
            padded.len()
        ));

        // Fresh ChaCha20-Poly1305 key + nonce per attachment. In M5
        // proper, the key is HKDF'd from the group's MLS exporter
        // secret + attachment id, but the encrypt/decrypt path is the
        // same.
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = AeadKey::from_bytes(key_bytes);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = AeadNonce(nonce_bytes);

        let aad = b"lattice/attachment/v1";
        let ciphertext = aead_encrypt(&key, nonce, aad, &padded)
            .map_err(|e| format!("encrypt {size}: {e}"))?;
        log(format!(
            "  ciphertext: {} bytes (+16 Poly1305 tag over padded)",
            ciphertext.len()
        ));

        let recovered_padded = aead_decrypt(&key, nonce, aad, &ciphertext)
            .map_err(|e| format!("decrypt {size}: {e}"))?;
        let recovered = padding::unpad(&recovered_padded)
            .map_err(|e| format!("unpad {size}: {e}"))?;
        if recovered != payload {
            return Err(format!("attachment size {size} did not round-trip"));
        }
        log(format!("  round-trip: OK ({} bytes recovered)", recovered.len()));
    }

    log("== M5 attachment crypto path complete ==".to_string());
    Ok(())
}

/// M5: commit cadence scheduler. ROADMAP §M5 calls for "aggressive
/// commit cadence: every 50 messages OR every 5 minutes" — the M5
/// goal is post-compromise secrecy via key rotation. Here we
/// demonstrate the rotation primitive for 1:1 groups: between every
/// application message we issue a self-commit (Update path) that
/// rotates the ratchet without changing membership.
///
/// Single-tab demo: Alice + Bob in a 1:1 group, 4 messages, with a
/// self-commit between each so Alice's epoch advances 0 → 1 → 2 →
/// 3 → 4 → 5. Each step verifies Bob can still decrypt despite the
/// ratchet rotation. Server-backed multi-member cadence with PSK
/// rotation is the M5 follow-up.
fn try_cadence_demo(log: impl Fn(String) + Copy) -> Result<(), String> {
    log("== commit cadence demo ==".to_string());
    let alice = make_identity(0xC1)?;
    let bob = make_identity(0xC2)?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();

    let group_id: [u8; 16] = *b"lattice-cadence!";
    let mut alice_group = create_group(&alice, alice_psk.clone(), &group_id)
        .map_err(|e| format!("create_group: {e}"))?;
    let bob_kp = generate_key_package(&bob, bob_psk.clone())
        .map_err(|e| format!("generate_key_package: {e}"))?;
    let commit_output =
        add_member(&mut alice_group, &bob_kp).map_err(|e| format!("add_member: {e}"))?;
    let welcome = commit_output
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| "no welcome".to_string())?;
    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit (add): {e}"))?;
    let mut bob_group = process_welcome(&bob, bob_psk.clone(), &welcome)
        .map_err(|e| format!("process_welcome: {e}"))?;
    log(format!(
        "initial epoch — alice={}, bob={}",
        alice_group.current_epoch(),
        bob_group.current_epoch()
    ));

    let messages = [
        b"cadence msg 1".as_slice(),
        b"cadence msg 2",
        b"cadence msg 3",
        b"cadence msg 4",
    ];

    for (i, payload) in messages.iter().enumerate() {
        let ct = encrypt_application(&mut alice_group, payload)
            .map_err(|e| format!("alice encrypt round {}: {e}", i + 1))?;
        let pt = decrypt(&mut bob_group, &ct)
            .map_err(|e| format!("bob decrypt round {}: {e}", i + 1))?;
        if pt.as_slice() != *payload {
            return Err(format!("round {} plaintext mismatch", i + 1));
        }
        log(format!(
            "round {} — alice→bob {:?} recovered ({} bytes ct, epoch {})",
            i + 1,
            std::str::from_utf8(payload).unwrap_or("?"),
            ct.len(),
            alice_group.current_epoch(),
        ));

        // Self-commit (Update path) rotates the ratchet.
        let upd = commit(&mut alice_group).map_err(|e| format!("commit round {}: {e}", i + 1))?;
        apply_commit(&mut alice_group)
            .map_err(|e| format!("apply_commit round {}: {e}", i + 1))?;
        // Bob processes the commit so his epoch advances too. decrypt
        // returns Vec::new() for non-application messages.
        let _ = decrypt(&mut bob_group, &upd.commit)
            .map_err(|e| format!("bob process commit round {}: {e}", i + 1))?;
        log(format!(
            "       self-commit — alice={}, bob={}",
            alice_group.current_epoch(),
            bob_group.current_epoch()
        ));
    }

    if alice_group.current_epoch() != bob_group.current_epoch() {
        return Err(format!(
            "epoch drift: alice={} bob={}",
            alice_group.current_epoch(),
            bob_group.current_epoch()
        ));
    }
    log(format!(
        "== M5 cadence (1:1) complete — {} rotations, final epoch {} ==",
        messages.len(),
        alice_group.current_epoch()
    ));
    Ok(())
}

/// Phase γ-polish: full Alice⇌Bob round-trip with D-05 sealed-sender
/// envelopes. Alice asks the server for a membership cert binding her
/// ephemeral Ed25519 pubkey to the group's current epoch, then wraps
/// the MLS ciphertext in a `SealedEnvelope` whose envelope signature
/// is checkable by the server (router can't ID the sender) and whose
/// inner ciphertext is decryptable only by group members.
async fn try_sealed_sender_demo(
    server: &str,
    log: impl Fn(String) + Copy,
) -> Result<(), String> {
    log(format!("== sealed-sender demo against {server} =="));
    let alice = make_identity(0xCE)?;
    let bob = make_identity(0xCF)?;
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();
    log(format!(
        "alice user_id: {} / bob user_id: {}",
        &B64.encode(alice.credential.user_id)[..12],
        &B64.encode(bob.credential.user_id)[..12],
    ));

    log("== fetch server descriptor (server pubkey) ==".to_string());
    let descriptor = api::fetch_descriptor(server).await?;
    log(format!(
        "server v{} wire v{}",
        descriptor.server_version, descriptor.wire_version,
    ));
    let server_pk_bytes = B64
        .decode(&descriptor.federation_pubkey_b64)
        .map_err(|e| format!("decode federation_pubkey: {e}"))?;
    let server_pk_array: [u8; 32] = server_pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("server pubkey length {}", server_pk_bytes.len()))?;
    let server_verifying_key = VerifyingKey::from_bytes(&server_pk_array)
        .map_err(|e| format!("parse server pubkey: {e}"))?;

    log("== register both + bob publishes KP ==".to_string());
    api::register(server, &alice).await?;
    api::register(server, &bob).await?;
    let _ = api::publish_key_package(server, &bob, &bob_psk).await?;

    log("== alice creates group, adds bob, commits ==".to_string());
    let bob_kp_bytes = api::fetch_key_package(server, &bob.credential.user_id).await?;
    let group_id: [u8; 16] = *b"lattice-sealed-1";
    let mut alice_group = create_group(&alice, alice_psk.clone(), &group_id)
        .map_err(|e| format!("create_group: {e}"))?;
    let commit_output =
        add_member(&mut alice_group, &bob_kp_bytes).map_err(|e| format!("add_member: {e}"))?;
    let welcome = commit_output
        .welcomes
        .into_iter()
        .next()
        .ok_or_else(|| "no welcome".to_string())?;
    let _ = api::submit_commit(
        server,
        &group_id,
        welcome.pq_payload.epoch,
        &commit_output.commit,
        &welcome,
        &bob.credential.user_id,
    )
    .await?;
    apply_commit(&mut alice_group).map_err(|e| format!("apply_commit: {e}"))?;
    let epoch = alice_group.current_epoch();
    log(format!("alice epoch after commit: {epoch}"));

    log("== alice generates ephemeral Ed25519 keypair ==".to_string());
    let ephemeral_sk = SigningKey::generate(&mut OsRng);
    let ephemeral_pk: [u8; 32] = ephemeral_sk.verifying_key().to_bytes();
    log(format!("ephemeral pk: {}", &B64.encode(ephemeral_pk)[..12]));

    log("== alice POSTs /group/:gid/issue_cert ==".to_string());
    let valid_until = chrono_now_unix() + 3600;
    let cert = api::issue_cert(server, &group_id, epoch, &ephemeral_pk, valid_until).await?;
    log(format!(
        "cert: epoch={}, valid_until={}, sig len={}",
        cert.epoch,
        cert.valid_until,
        cert.server_sig.len(),
    ));

    log("== bob fetches welcome + joins ==".to_string());
    let welcome_for_bob = api::fetch_welcome(server, &group_id, &bob.credential.user_id).await?;
    let mut bob_group = process_welcome(&bob, bob_psk.clone(), &welcome_for_bob)
        .map_err(|e| format!("process_welcome: {e}"))?;

    log("== alice encrypts MLS msg + seals envelope ==".to_string());
    let inner_ct = encrypt_application(&mut alice_group, b"hello, sealed sender")
        .map_err(|e| format!("alice encrypt: {e}"))?;
    log(format!("inner_ct: {} bytes", inner_ct.len()));
    let envelope = seal(cert, &ephemeral_sk, inner_ct.clone())
        .map_err(|e| format!("seal: {e:?}"))?;
    let envelope_bytes = api::encode_sealed(&envelope);
    log(format!("sealed envelope: {} bytes", envelope_bytes.len()));

    log("== alice POSTs sealed envelope ==".to_string());
    let _seq = api::publish_message(server, &group_id, &envelope_bytes).await?;

    log("== bob fetches + opens at recipient ==".to_string());
    let (_, messages) = api::fetch_messages(server, &group_id, 0).await?;
    let first = messages
        .first()
        .ok_or_else(|| "no messages returned".to_string())?;
    let recovered_envelope = api::decode_sealed(&first.envelope)?;
    let inner_recovered =
        open_at_recipient(&server_verifying_key, &recovered_envelope, chrono_now_unix())
            .map_err(|e| format!("open_at_recipient: {e:?}"))?;
    if inner_recovered != inner_ct.as_slice() {
        return Err("inner_ciphertext mismatch after open_at_recipient".into());
    }
    log("inner ct round-trips intact".to_string());

    log("== bob MLS-decrypts inner ==".to_string());
    let plaintext = decrypt(&mut bob_group, inner_recovered)
        .map_err(|e| format!("bob decrypt: {e}"))?;
    if plaintext != b"hello, sealed sender" {
        return Err(format!(
            "bob recovered {:?}",
            String::from_utf8_lossy(&plaintext)
        ));
    }
    log(format!(
        "bob recovered: {:?}",
        String::from_utf8_lossy(&plaintext)
    ));
    log("== M4 phase γ-polish complete ==".to_string());
    Ok(())
}

/// Best-effort current-time accessor for the browser. `chrono` doesn't
/// compile cleanly to wasm32 without `js-sys` feature flags we
/// haven't enabled, so we go through `js_sys::Date::now()` directly.
/// Returns Unix seconds; sufficient resolution for sealed-sender cert
/// expiry checks (D-05 recommends ≤ 1 hour windows anyway).
fn chrono_now_unix() -> i64 {
    let ms = js_sys::Date::now();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let secs = (ms / 1000.0) as i64;
    secs
}

/// Phase δ.1 / δ.2: persist a freshly-built Alice identity in
/// `window.localStorage` under `lattice/identity/v1`. With
/// `passphrase = None` writes the v1 plaintext blob; with `Some(pw)`
/// writes the v2 Argon2id-keyed ChaCha20-Poly1305 envelope around the
/// secret fields.
///
/// Returns the user_id prefix the UI status surfaces.
fn try_save_identity(
    log: impl Fn(String) + Copy,
    passphrase: Option<&str>,
) -> Result<String, String> {
    let header = if passphrase.is_some() {
        "save encrypted identity"
    } else {
        "save identity"
    };
    log(format!("== {header} =="));
    let alice = make_identity(0xAA)?;
    let user_id_b64 = B64.encode(alice.credential.user_id);
    log(format!("user_id: {user_id_b64}"));
    let bytes_written = persist::save(&alice, passphrase)?;
    let kind = if passphrase.is_some() { "v2" } else { "v1" };
    log(format!(
        "wrote {bytes_written} bytes ({kind}) to localStorage[\"lattice/identity/v1\"]"
    ));
    log("reload the page to verify restore".to_string());
    if passphrase.is_some() {
        log("== M4 phase δ.2 complete ==".to_string());
    } else {
        log("== M4 phase δ.1 complete ==".to_string());
    }
    Ok(user_id_b64.chars().take(12).collect::<String>())
}

/// Phase ε.2 save path. Reads the credential_id saved by
/// `try_create_passkey`, drives `evaluate_prf` to recover the 32-byte
/// KEK, then `persist::save_prf` writes a v3 blob with the secret
/// material sealed under that KEK.
async fn try_save_prf_encrypted(log: impl Fn(String) + Copy) -> Result<String, String> {
    log("== save PRF-encrypted identity ==".to_string());
    let credential_id = read_saved_credential_id()?;
    log(format!(
        "credential_id (b64url): {credential_id}",
    ));
    log("evaluating PRF (will prompt for the passkey)…".to_string());
    let kek = passkey::evaluate_prf(&credential_id).await?;
    log(format!("KEK (32 bytes, prefix): {}…", &B64.encode(kek)[..12]));

    let alice = make_identity(0xAA)?;
    let user_id_b64 = B64.encode(alice.credential.user_id);
    log(format!("user_id: {user_id_b64}"));
    let bytes_written = persist::save_prf(&alice, &credential_id, &kek)?;
    log(format!(
        "wrote {bytes_written} bytes (v3) to localStorage[\"lattice/identity/v1\"]"
    ));
    log("reload the page to verify restore".to_string());
    log("== M4 phase ε.2 (save) complete ==".to_string());
    Ok(user_id_b64.chars().take(12).collect::<String>())
}

/// Phase ε.2 load path. Looks at the persisted v3 blob's recorded
/// credential_id, re-runs `evaluate_prf` against that credential, then
/// `persist::load_prf` unwraps the v3 envelope with the recovered
/// KEK.
async fn try_load_prf_encrypted(log: impl Fn(String) + Copy) -> Result<String, String> {
    log("== load PRF-encrypted identity ==".to_string());
    let credential_id = persist::v3_credential_id()?
        .ok_or_else(|| "no v3 blob in localStorage".to_string())?;
    log(format!("credential_id (b64url): {credential_id}"));
    log("evaluating PRF (will prompt for the passkey)…".to_string());
    let kek = passkey::evaluate_prf(&credential_id).await?;
    log(format!("KEK (32 bytes, prefix): {}…", &B64.encode(kek)[..12]));
    let identity = persist::load_prf(&kek)?
        .ok_or_else(|| "load_prf returned None".to_string())?;
    let user_id_b64 = B64.encode(identity.credential.user_id);
    log(format!("recovered user_id: {user_id_b64}"));
    log("== M4 phase ε.2 (load) complete ==".to_string());
    Ok(user_id_b64.chars().take(12).collect::<String>())
}

/// Helper: pull `credential_id_b64url` previously written by
/// `try_create_passkey`. Errors clearly if the user hasn't created a
/// passkey yet (which would make every PRF flow undefined).
fn read_saved_credential_id() -> Result<String, String> {
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let storage = window
        .local_storage()
        .map_err(|e| format!("localStorage: {e:?}"))?
        .ok_or_else(|| "localStorage unavailable".to_string())?;
    storage
        .get_item(PASSKEY_CREDENTIAL_LS_KEY)
        .map_err(|e| format!("read credential_id: {e:?}"))?
        .ok_or_else(|| "no saved credential_id — create a passkey first".to_string())
}

/// Phase ε: register a passkey for the dev RP `localhost`, request
/// the PRF extension, and stash the credential_id_b64url in
/// localStorage for [`try_derive_passkey_kek`] to use later.
///
/// Returns the credential_id prefix the UI status surfaces.
async fn try_create_passkey(log: impl Fn(String) + Copy) -> Result<String, String> {
    log("== create passkey ==".to_string());
    log("calling navigator.credentials.create with PRF extension".to_string());
    let created = passkey::create_passkey("lattice-dev").await?;
    log(format!(
        "credential_id (b64url): {}",
        created.credential_id_b64url
    ));
    log(format!("PRF extension supported: {}", created.prf_supported));
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let storage = window
        .local_storage()
        .map_err(|e| format!("localStorage: {e:?}"))?
        .ok_or_else(|| "localStorage unavailable".to_string())?;
    storage
        .set_item(PASSKEY_CREDENTIAL_LS_KEY, &created.credential_id_b64url)
        .map_err(|e| format!("save credential_id: {e:?}"))?;
    log(format!(
        "credential_id saved to localStorage[\"{PASSKEY_CREDENTIAL_LS_KEY}\"]"
    ));
    log("== M4 phase ε.1 complete ==".to_string());
    Ok(created
        .credential_id_b64url
        .chars()
        .take(12)
        .collect::<String>())
}

/// Phase ε.2: run navigator.credentials.get to extract the PRF output
/// for the saved credential. The 32-byte result is suitable as a KEK
/// for an at-rest envelope (replaces the Argon2id-derived KEK from
/// Phase δ.2 in the future v3 blob format).
async fn try_derive_passkey_kek(log: impl Fn(String) + Copy) -> Result<String, String> {
    log("== derive PRF KEK ==".to_string());
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let storage = window
        .local_storage()
        .map_err(|e| format!("localStorage: {e:?}"))?
        .ok_or_else(|| "localStorage unavailable".to_string())?;
    let credential_id_b64url = storage
        .get_item(PASSKEY_CREDENTIAL_LS_KEY)
        .map_err(|e| format!("read credential_id: {e:?}"))?
        .ok_or_else(|| "no saved credential_id — create a passkey first".to_string())?;
    log(format!("credential_id loaded: {credential_id_b64url}"));
    let kek = passkey::evaluate_prf(&credential_id_b64url).await?;
    let kek_b64 = B64.encode(kek);
    log(format!("KEK (32 bytes): {kek_b64}"));
    log("==> would now use this as ChaCha20-Poly1305 key for v3 persist blob".to_string());
    log("== M4 phase ε.2 complete ==".to_string());
    Ok(kek_b64.chars().take(12).collect::<String>())
}

/// Capability summary chip row. Shows green/grey indicators for
/// WebAuthn passkey support (Phase ε prerequisite) and WebTransport
/// availability (Phase γ.4 prerequisite). Probed once at component
/// render — capabilities don't change without a page reload.
#[component]
fn CapabilitiesPanel() -> impl IntoView {
    let caps = Capabilities::probe();
    let row = |label: &'static str, enabled: bool| {
        let badge_class = if enabled { "cap-on" } else { "cap-off" };
        let badge_text = if enabled { "ready" } else { "n/a" };
        view! {
            <span class="cap-chip">
                <span class={badge_class} aria-hidden="true"></span>
                <span class="cap-label">{label}</span>
                <span class="cap-badge">{badge_text}</span>
            </span>
        }
    };
    view! {
        <div class="cap-row" aria-label="browser capabilities">
            {row("WebAuthn passkeys", caps.webauthn && caps.credentials_container)}
            {row("WebTransport", caps.webtransport)}
        </div>
    }
}

/// Pop a `window.prompt` to collect a passphrase. Returns `Ok(None)`
/// if the user dismissed the dialog; `Ok(Some(text))` otherwise.
/// Browser support is universal but it's a blocking modal — fine for
/// dev, not production UX.
fn prompt_passphrase(message: &str) -> Result<Option<String>, String> {
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    match window.prompt_with_message(message) {
        Ok(Some(s)) => Ok(Some(s)),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("prompt: {e:?}")),
    }
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
