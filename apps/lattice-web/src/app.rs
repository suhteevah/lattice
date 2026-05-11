//! Top-level Leptos component for the M4 in-browser preview.
//!
//! Exercises `lattice-crypto`'s hybrid signature + hybrid KEM in the
//! browser to verify the PQ primitives run cleanly under WASM. Real
//! group / DM UI lands in the next M4 phases.

use base64::Engine;
use leptos::prelude::*;

use lattice_crypto::hybrid_kex::{self, HybridPublicKey, HybridSecretKey};
use lattice_crypto::mls::cipher_suite::{LatticeCryptoProvider, LATTICE_HYBRID_V1};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[component]
pub fn App() -> impl IntoView {
    let (status, set_status) =
        signal::<String>(format!("lattice-core v{} ready", lattice_core::VERSION));
    let (log_lines, set_log_lines) = signal::<Vec<String>>(Vec::new());

    let append = move |line: String| {
        set_log_lines.update(|lines| lines.push(line));
    };
    // Clone `append` so each closure gets its own copy.
    let append_for_run = append;

    let run_demo = move |_| {
        set_log_lines.set(Vec::new());
        let log = append_for_run;
        match try_run_demo(log) {
            Ok(()) => set_status.set("demo OK".to_string()),
            Err(e) => set_status.set(format!("demo error: {e}")),
        }
    };

    view! {
        <div class="page">
            <div class="card">
                <h1>"Lattice"</h1>
                <p class="tagline">"Post-quantum encrypted messaging. M4 in-browser preview."</p>
                <div class="status">{move || status.get()}</div>
                <button class="button" on:click=run_demo>"Run crypto demo"</button>
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

/// Wrap the demo body in a single `?`-friendly function. Each step
/// appends a line via the closure passed in.
fn try_run_demo(log: impl Fn(String) + Copy) -> Result<(), String> {
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
        32,
        pk_bytes.len() - 32,
    ));
    let msg = b"hello, lattice browser";
    let sig = suite
        .sign(&sk, msg)
        .map_err(|e| format!("sign: {e:?}"))?;
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
    let (ct, shared) = hybrid_kex::encapsulate(&peer_pk, info)
        .map_err(|e| format!("encap: {e}"))?;
    log(format!(
        "ct: {} bytes ({} x25519 eph + {} ml-kem ct)",
        32 + ct.ml_kem_ct.len(),
        32,
        ct.ml_kem_ct.len(),
    ));
    let session_b64 = B64.encode(shared.session_key);
    log(format!("session: {}…", &session_b64[..12]));
    let shared2 = hybrid_kex::decapsulate(&peer_sk, &ct, info)
        .map_err(|e| format!("decap: {e}"))?;
    let agree = shared.session_key == shared2.session_key;
    log(format!("secrets agree: {agree}"));
    if !agree {
        return Err("session keys did not agree after encap/decap".into());
    }
    // Silence the `Send`-unused-import-style warnings on these.
    let _ = (HybridPublicKey { x25519: [0; 32], ml_kem: vec![] },
             HybridSecretKey { x25519: [0; 32], ml_kem: vec![] });

    log("== M4 phase α complete ==".to_string());
    Ok(())
}
