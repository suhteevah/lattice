//! `wasm-bindgen` FFI surface for the browser client.
//!
//! Only compiled on `wasm32`. Exposes a hand-curated set of
//! `lattice-crypto` primitives so the Solid UI can drive identity +
//! sign/verify + hybrid KEM operations without re-implementing them
//! in JavaScript. MLS group operations (create / invite / join / send)
//! land in a follow-up — they need an opaque-handle pattern around
//! `mls_rs::Group` which is more involved than the primitives below.
//!
//! ## Wire conventions
//!
//! All `*_b64` strings use **standard** base64 (`+/=`). The CLI uses
//! URL-safe base64 only in URL path segments; here we always pass via
//! JS function args, so standard is fine.
//!
//! ## Error handling
//!
//! Each exported function returns `Result<JsValue, JsError>` where
//! `JsError` carries the underlying Rust error message. JS callers
//! receive an `Error` object they can `try { ... } catch (e) { ... }`.

#![allow(clippy::module_name_repetitions)]

use base64::Engine;
use lattice_crypto::hybrid_kex::{self, HybridPublicKey, HybridSecretKey};
use lattice_crypto::mls::cipher_suite::{LatticeCryptoProvider, LATTICE_HYBRID_V1};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider, SignaturePublicKey, SignatureSecretKey};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Initialize the WASM module: install a panic hook that forwards to
/// `console.error`, initialize crypto, log to the JS console.
///
/// Idempotent — safe to call multiple times.
#[wasm_bindgen(js_name = init)]
pub fn init_wasm() -> Result<(), JsError> {
    // Use the same panic hook as lib.rs::init().
    std::panic::set_hook(Box::new(|info| {
        web_sys::console::error_1(&format!("[lattice-core panic] {info}").into());
    }));
    lattice_crypto::init().map_err(|e| JsError::new(&format!("crypto init: {e}")))?;
    web_sys::console::log_1(&format!("lattice-core initialized v{}", crate::VERSION).into());
    Ok(())
}

/// Result of [`generate_signing_keypair`] — the packed
/// `LatticeHybridCipherSuite` keypair plus a stable `user_id` derived
/// as BLAKE3 of the Ed25519 pubkey.
#[derive(Serialize, Deserialize)]
pub struct WasmSigningKeypair {
    /// 32-byte user_id, base64-encoded. Stable across registrations
    /// for the same Ed25519 pubkey.
    pub user_id_b64: String,
    /// Packed signature pubkey: `ed25519_pub(32) || ml_dsa_pub(1952)`,
    /// base64-encoded.
    pub sig_pk_b64: String,
    /// Packed signature secret: `ed25519_sk(32) || ml_dsa_seed(32)`,
    /// base64-encoded.
    pub sig_sk_b64: String,
}

/// Generate a fresh hybrid signing keypair (Ed25519 + ML-DSA-65).
/// Uses the browser's `crypto.getRandomValues` via `getrandom`'s JS
/// backend.
#[wasm_bindgen(js_name = generateSigningKeypair)]
pub fn generate_signing_keypair() -> Result<JsValue, JsError> {
    let provider = LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .ok_or_else(|| JsError::new("ciphersuite missing"))?;
    let (sk, pk) = suite
        .signature_key_generate()
        .map_err(|e| JsError::new(&format!("keygen: {e:?}")))?;
    let pk_bytes = pk.as_bytes();
    let sk_bytes = sk.as_bytes();
    let user_id = blake3::hash(&pk_bytes[..32]);
    let out = WasmSigningKeypair {
        user_id_b64: B64.encode(user_id.as_bytes()),
        sig_pk_b64: B64.encode(pk_bytes),
        sig_sk_b64: B64.encode(sk_bytes),
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Produce a hybrid signature over `message_b64` with the packed
/// `sig_sk_b64`. Both halves (Ed25519 + ML-DSA-65) must succeed.
#[wasm_bindgen(js_name = sign)]
pub fn sign_message(sig_sk_b64: &str, message_b64: &str) -> Result<String, JsError> {
    let sk_bytes = B64
        .decode(sig_sk_b64)
        .map_err(|e| JsError::new(&format!("sig_sk decode: {e}")))?;
    let msg = B64
        .decode(message_b64)
        .map_err(|e| JsError::new(&format!("message decode: {e}")))?;
    let provider = LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .ok_or_else(|| JsError::new("ciphersuite missing"))?;
    let sk = SignatureSecretKey::from(sk_bytes);
    let sig = suite
        .sign(&sk, &msg)
        .map_err(|e| JsError::new(&format!("sign: {e:?}")))?;
    Ok(B64.encode(&sig))
}

/// Verify a hybrid signature. Both halves must validate.
#[wasm_bindgen(js_name = verify)]
pub fn verify_message(
    sig_pk_b64: &str,
    sig_b64: &str,
    message_b64: &str,
) -> Result<bool, JsError> {
    let pk_bytes = B64
        .decode(sig_pk_b64)
        .map_err(|e| JsError::new(&format!("sig_pk decode: {e}")))?;
    let sig = B64
        .decode(sig_b64)
        .map_err(|e| JsError::new(&format!("sig decode: {e}")))?;
    let msg = B64
        .decode(message_b64)
        .map_err(|e| JsError::new(&format!("message decode: {e}")))?;
    let provider = LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .ok_or_else(|| JsError::new("ciphersuite missing"))?;
    let pk = SignaturePublicKey::from(pk_bytes);
    Ok(suite.verify(&pk, &sig, &msg).is_ok())
}

/// Output of [`hybrid_kem_generate`]: X25519 + ML-KEM-768 keypair.
#[derive(Serialize, Deserialize)]
pub struct WasmKemKeypair {
    /// Hybrid public key bytes: `x25519_pub(32) || ml_kem_ek(1184)`,
    /// base64-encoded.
    pub pk_b64: String,
    /// Hybrid secret key bytes: `x25519_sk(32) || ml_kem_dk(2400)`,
    /// base64-encoded.
    pub sk_b64: String,
}

/// Generate a hybrid X25519 + ML-KEM-768 keypair for the PQXDH-style
/// initial KEX (also used as a sanity check that ML-KEM-768 runs in
/// the browser).
#[wasm_bindgen(js_name = generateKemKeypair)]
pub fn generate_kem_keypair() -> Result<JsValue, JsError> {
    let (pk, sk) =
        hybrid_kex::generate_keypair().map_err(|e| JsError::new(&format!("kem keygen: {e}")))?;
    let mut pk_bytes = Vec::with_capacity(32 + pk.ml_kem.len());
    pk_bytes.extend_from_slice(&pk.x25519);
    pk_bytes.extend_from_slice(&pk.ml_kem);
    let mut sk_bytes = Vec::with_capacity(32 + sk.ml_kem.len());
    sk_bytes.extend_from_slice(&sk.x25519);
    sk_bytes.extend_from_slice(&sk.ml_kem);
    let out = WasmKemKeypair {
        pk_b64: B64.encode(&pk_bytes),
        sk_b64: B64.encode(&sk_bytes),
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Output of [`hybrid_kem_encap`]: the wire ciphertext + 64-byte
/// shared secret (32-byte session key + 32-byte confirmation tag,
/// per [`hybrid_kex::HybridSharedSecret`]).
#[derive(Serialize, Deserialize)]
pub struct WasmKemEncap {
    /// Wire ciphertext: `x25519_eph_pk(32) || ml_kem_ct(1088)`,
    /// base64-encoded.
    pub ciphertext_b64: String,
    /// 32-byte session key, base64-encoded.
    pub session_key_b64: String,
    /// 32-byte confirmation tag, base64-encoded.
    pub confirmation_b64: String,
}

/// Encapsulate to a peer's hybrid public key. The 64-byte shared
/// secret is split into a session key (first 32 bytes) and a
/// confirmation tag (last 32 bytes) so callers can plug into AEAD +
/// transcript binding separately.
#[wasm_bindgen(js_name = hybridKemEncap)]
pub fn hybrid_kem_encap(peer_pk_b64: &str, info_b64: &str) -> Result<JsValue, JsError> {
    let pk_bytes = B64
        .decode(peer_pk_b64)
        .map_err(|e| JsError::new(&format!("peer_pk decode: {e}")))?;
    let info = B64
        .decode(info_b64)
        .map_err(|e| JsError::new(&format!("info decode: {e}")))?;
    if pk_bytes.len() != 32 + 1184 {
        return Err(JsError::new(&format!(
            "peer_pk length {} (expected {})",
            pk_bytes.len(),
            32 + 1184
        )));
    }
    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&pk_bytes[..32]);
    let pk = HybridPublicKey {
        x25519,
        ml_kem: pk_bytes[32..].to_vec(),
    };
    let (ct, shared) = hybrid_kex::encapsulate(&pk, &info)
        .map_err(|e| JsError::new(&format!("encap: {e}")))?;
    let mut ct_bytes = Vec::with_capacity(32 + ct.ml_kem_ct.len());
    ct_bytes.extend_from_slice(&ct.x25519_eph_pk);
    ct_bytes.extend_from_slice(&ct.ml_kem_ct);
    let out = WasmKemEncap {
        ciphertext_b64: B64.encode(&ct_bytes),
        session_key_b64: B64.encode(shared.session_key),
        confirmation_b64: B64.encode(shared.confirmation),
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Output of [`hybrid_kem_decap`]: the recovered 64-byte secret split
/// into session key + confirmation tag.
#[derive(Serialize, Deserialize)]
pub struct WasmKemShared {
    /// 32-byte session key, base64-encoded.
    pub session_key_b64: String,
    /// 32-byte confirmation tag, base64-encoded.
    pub confirmation_b64: String,
}

/// Decapsulate a peer's ciphertext using our hybrid secret key.
#[wasm_bindgen(js_name = hybridKemDecap)]
pub fn hybrid_kem_decap(
    sk_b64: &str,
    ciphertext_b64: &str,
    info_b64: &str,
) -> Result<JsValue, JsError> {
    let sk_bytes = B64
        .decode(sk_b64)
        .map_err(|e| JsError::new(&format!("sk decode: {e}")))?;
    let ct_bytes = B64
        .decode(ciphertext_b64)
        .map_err(|e| JsError::new(&format!("ct decode: {e}")))?;
    let info = B64
        .decode(info_b64)
        .map_err(|e| JsError::new(&format!("info decode: {e}")))?;
    if sk_bytes.len() != 32 + 2400 {
        return Err(JsError::new(&format!(
            "sk length {} (expected {})",
            sk_bytes.len(),
            32 + 2400
        )));
    }
    if ct_bytes.len() != 32 + 1088 {
        return Err(JsError::new(&format!(
            "ct length {} (expected {})",
            ct_bytes.len(),
            32 + 1088
        )));
    }
    let mut x_sk = [0u8; 32];
    x_sk.copy_from_slice(&sk_bytes[..32]);
    let sk = HybridSecretKey {
        x25519: x_sk,
        ml_kem: sk_bytes[32..].to_vec(),
    };
    let mut x_eph = [0u8; 32];
    x_eph.copy_from_slice(&ct_bytes[..32]);
    let ct = hybrid_kex::HybridCiphertext {
        x25519_eph_pk: x_eph,
        ml_kem_ct: ct_bytes[32..].to_vec(),
    };
    let shared = hybrid_kex::decapsulate(&sk, &ct, &info)
        .map_err(|e| JsError::new(&format!("decap: {e}")))?;
    let out = WasmKemShared {
        session_key_b64: B64.encode(shared.session_key),
        confirmation_b64: B64.encode(shared.confirmation),
    };
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Version-info struct surfaced to JS.
#[wasm_bindgen(js_name = version)]
#[must_use]
pub fn version_string() -> String {
    crate::VERSION.to_string()
}
