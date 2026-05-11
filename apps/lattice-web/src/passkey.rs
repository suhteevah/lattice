//! WebAuthn passkey ceremony (Phase ε / D-09).
//!
//! Implements the three-tier strategy from D-09:
//!
//! 1. **PRF tier** — `navigator.credentials.create` with the `prf`
//!    extension, then `.get` with `prf.eval.first = blake3("lattice
//!    persist v3 KEK")`. The PRF output is a stable 32-byte secret
//!    tied to that credential; it feeds [`super::persist`] as the
//!    AEAD KEK in a future `version: 3` blob (replacing the
//!    Argon2id-derived KEK from Phase δ.2).
//!
//! 2. **Passphrase + badge tier** — Phase δ.2 (already shipped).
//!    Users without PRF support can still encrypt at rest with a
//!    passphrase; the badge reminds them they're missing the
//!    hardware-bound KEK.
//!
//! 3. **Refuse tier** — if the browser exposes no `navigator.
//!    credentials` at all (Worker context, ancient browser), we
//!    decline to store secrets and fall back to ephemeral-only
//!    state.
//!
//! This module currently implements tier 1's *create* ceremony plus
//! capability detection. The PRF *eval* path (extract 32 bytes from
//! `.get` clientExtensionResults) is wired but not yet hooked into
//! `persist.rs` — the integration point is documented inline.
//!
//! ## Why raw JS interop and not `webauthn-rs`?
//!
//! Server-side WebAuthn libraries (`webauthn-rs`) are great for the
//! verifier role but the browser is the *prover* — we want the
//! native `navigator.credentials.create` ceremony plus its
//! browser-vendor extensions (PRF). That's a thin shim over
//! `js_sys`/`web_sys` rather than a 100K-LoC verifier crate.

use base64::Engine;
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

const RP_ID: &str = "localhost";
const RP_NAME: &str = "Lattice (dev)";
const PRF_KEK_INFO: &[u8] = b"lattice/persist/v3/kek";

/// Outcome of `create_passkey`. The credential_id is the opaque
/// browser-local handle we feed back into `.get` later to evaluate
/// PRF.
#[derive(Debug, Clone)]
pub struct CreatedPasskey {
    /// `PublicKeyCredential.rawId` as URL-safe base64. Pass back to
    /// `evaluate_prf` to recover the per-credential PRF output.
    pub credential_id_b64url: String,
    /// True if the authenticator reported PRF extension support in
    /// the assertion response. False means PRF isn't available — fall
    /// back to Phase δ.2 (passphrase) for at-rest encryption.
    pub prf_supported: bool,
}

/// Run the WebAuthn create() ceremony with the PRF extension
/// requested.
///
/// Uses RP id = `localhost` (matches the dev `trunk serve` host) and
/// a derived user_id stable across calls (BLAKE3 of `user_label`).
/// Authenticator picks itself; we don't pin platform vs. cross-
/// platform here, but `userVerification = "required"` ensures we get
/// a user gesture.
///
/// # Errors
///
/// Network / browser / user-cancel failures surface as `String`
/// describing the JS-side rejection reason.
pub async fn create_passkey(user_label: &str) -> Result<CreatedPasskey, String> {
    let credentials = credentials_container()?;

    let public_key = Object::new();

    // rp: { id, name }
    let rp = Object::new();
    set_str(&rp, "id", RP_ID)?;
    set_str(&rp, "name", RP_NAME)?;
    set_obj(&public_key, "rp", &rp)?;

    // user: { id (Uint8Array), name, displayName }
    let user_id_bytes = blake3::hash(user_label.as_bytes());
    let user_id = uint8_array_from(user_id_bytes.as_bytes());
    let user = Object::new();
    set_value(&user, "id", &user_id)?;
    set_str(&user, "name", user_label)?;
    set_str(&user, "displayName", user_label)?;
    set_obj(&public_key, "user", &user)?;

    // challenge: 32 random bytes
    let mut challenge_bytes = [0u8; 32];
    getrandom_into(&mut challenge_bytes)?;
    let challenge = uint8_array_from(&challenge_bytes);
    set_value(&public_key, "challenge", &challenge)?;

    // pubKeyCredParams: [{ alg: -8 (Ed25519), type: "public-key" }, { alg: -7 (ES256) }]
    let params = Array::new();
    params.push(&alg_param(-8)?);
    params.push(&alg_param(-7)?);
    set_value(&public_key, "pubKeyCredParams", &params)?;

    // authenticatorSelection: { userVerification: "required",
    //                           residentKey: "required" }
    let auth_sel = Object::new();
    set_str(&auth_sel, "userVerification", "required")?;
    set_str(&auth_sel, "residentKey", "required")?;
    set_obj(&public_key, "authenticatorSelection", &auth_sel)?;

    set_value(&public_key, "timeout", &JsValue::from(60_000.0))?;
    set_str(&public_key, "attestation", "none")?;

    // extensions: { prf: { eval: { first: salt } } }
    let prf_eval = Object::new();
    set_value(
        &prf_eval,
        "first",
        &uint8_array_from(&prf_salt()),
    )?;
    let prf = Object::new();
    set_obj(&prf, "eval", &prf_eval)?;
    let extensions = Object::new();
    set_obj(&extensions, "prf", &prf)?;
    set_obj(&public_key, "extensions", &extensions)?;

    let options = Object::new();
    set_obj(&options, "publicKey", &public_key)?;

    let credential = call_credentials_method(&credentials, "create", &options).await?;

    // credential.rawId is an ArrayBuffer; convert to Uint8Array → Vec<u8>.
    let raw_id_value = Reflect::get(&credential, &"rawId".into())
        .map_err(|e| format!("read rawId: {e:?}"))?;
    let raw_id_array = Uint8Array::new(&raw_id_value);
    let raw_id = raw_id_array.to_vec();

    // credential.getClientExtensionResults().prf.results.first — if
    // present, PRF is supported on this authenticator.
    let get_ext = Reflect::get(&credential, &"getClientExtensionResults".into())
        .map_err(|e| format!("read getClientExtensionResults: {e:?}"))?;
    let prf_supported = if get_ext.is_function() {
        let func: js_sys::Function = get_ext.unchecked_into();
        match func.call0(&credential) {
            Ok(ext_results) => {
                let prf = Reflect::get(&ext_results, &"prf".into()).unwrap_or(JsValue::UNDEFINED);
                !prf.is_undefined() && !prf.is_null()
            }
            Err(_) => false,
        }
    } else {
        false
    };

    Ok(CreatedPasskey {
        credential_id_b64url: B64URL.encode(&raw_id),
        prf_supported,
    })
}

/// Run a `navigator.credentials.get` ceremony pinned to a previously
/// `create_passkey`'d credential and pull 32 bytes of PRF output.
///
/// The output is suitable as a ChaCha20-Poly1305 KEK for the Phase
/// ε identity-at-rest envelope.
///
/// # Errors
///
/// Browser / user-cancel / missing-PRF failures surface as `String`.
pub async fn evaluate_prf(credential_id_b64url: &str) -> Result<[u8; 32], String> {
    let credentials = credentials_container()?;

    let public_key = Object::new();

    let mut challenge_bytes = [0u8; 32];
    getrandom_into(&mut challenge_bytes)?;
    let challenge = uint8_array_from(&challenge_bytes);
    set_value(&public_key, "challenge", &challenge)?;

    set_str(&public_key, "rpId", RP_ID)?;
    set_value(&public_key, "timeout", &JsValue::from(60_000.0))?;
    set_str(&public_key, "userVerification", "required")?;

    // allowCredentials: [{ id: <raw_id>, type: "public-key" }]
    let cred_id = B64URL
        .decode(credential_id_b64url)
        .map_err(|e| format!("decode credential_id: {e}"))?;
    let allow_entry = Object::new();
    set_value(&allow_entry, "id", &uint8_array_from(&cred_id))?;
    set_str(&allow_entry, "type", "public-key")?;
    let allow = Array::new();
    allow.push(&allow_entry);
    set_value(&public_key, "allowCredentials", &allow)?;

    // extensions: { prf: { eval: { first: salt } } }
    let prf_eval = Object::new();
    set_value(&prf_eval, "first", &uint8_array_from(&prf_salt()))?;
    let prf = Object::new();
    set_obj(&prf, "eval", &prf_eval)?;
    let extensions = Object::new();
    set_obj(&extensions, "prf", &prf)?;
    set_obj(&public_key, "extensions", &extensions)?;

    let options = Object::new();
    set_obj(&options, "publicKey", &public_key)?;

    let assertion = call_credentials_method(&credentials, "get", &options).await?;

    let get_ext = Reflect::get(&assertion, &"getClientExtensionResults".into())
        .map_err(|e| format!("read getClientExtensionResults: {e:?}"))?;
    let func: js_sys::Function = get_ext
        .dyn_into()
        .map_err(|_| "getClientExtensionResults not callable".to_string())?;
    let ext_results = func
        .call0(&assertion)
        .map_err(|e| format!("call getClientExtensionResults: {e:?}"))?;

    let prf = Reflect::get(&ext_results, &"prf".into())
        .map_err(|e| format!("read .prf: {e:?}"))?;
    if prf.is_undefined() || prf.is_null() {
        return Err("authenticator did not return PRF results".into());
    }
    let results = Reflect::get(&prf, &"results".into())
        .map_err(|e| format!("read .prf.results: {e:?}"))?;
    let first = Reflect::get(&results, &"first".into())
        .map_err(|e| format!("read .prf.results.first: {e:?}"))?;
    if first.is_undefined() || first.is_null() {
        return Err("PRF results.first missing".into());
    }
    let arr = Uint8Array::new(&first);
    let bytes = arr.to_vec();
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("PRF output length {} (expected 32)", bytes.len()))
}

fn prf_salt() -> [u8; 32] {
    *blake3::hash(PRF_KEK_INFO).as_bytes()
}

fn uint8_array_from(bytes: &[u8]) -> Uint8Array {
    let arr = Uint8Array::new_with_length(bytes.len() as u32);
    arr.copy_from(bytes);
    arr
}

fn set_str(obj: &Object, key: &str, value: &str) -> Result<(), String> {
    Reflect::set(obj, &key.into(), &value.into())
        .map(|_| ())
        .map_err(|e| format!("set {key}: {e:?}"))
}

fn set_value(obj: &Object, key: &str, value: &impl AsRef<JsValue>) -> Result<(), String> {
    Reflect::set(obj, &key.into(), value.as_ref())
        .map(|_| ())
        .map_err(|e| format!("set {key}: {e:?}"))
}

fn set_obj(obj: &Object, key: &str, value: &Object) -> Result<(), String> {
    Reflect::set(obj, &key.into(), value)
        .map(|_| ())
        .map_err(|e| format!("set {key}: {e:?}"))
}

fn alg_param(alg: i32) -> Result<JsValue, String> {
    let o = Object::new();
    set_str(&o, "type", "public-key")?;
    set_value(&o, "alg", &JsValue::from(alg))?;
    Ok(o.into())
}

fn getrandom_into(buf: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(buf).map_err(|e| format!("getrandom: {e}"))
}

/// Reach into `navigator.credentials` via JS reflection. web-sys's
/// `CredentialsContainer` typed wrapper doesn't expose
/// `create`/`get` with the option dict shapes we need for WebAuthn,
/// so we call them directly through `js_sys::Reflect`.
fn credentials_container() -> Result<JsValue, String> {
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let nav = Reflect::get(&window, &"navigator".into())
        .map_err(|e| format!("read navigator: {e:?}"))?;
    let creds = Reflect::get(&nav, &"credentials".into())
        .map_err(|e| format!("read navigator.credentials: {e:?}"))?;
    if creds.is_undefined() || creds.is_null() {
        return Err("navigator.credentials not available in this context".into());
    }
    Ok(creds)
}

/// Call `navigator.credentials.<method>(options)` and await the
/// returned Promise. `method` is either `"create"` or `"get"`.
async fn call_credentials_method(
    credentials: &JsValue,
    method: &str,
    options: &Object,
) -> Result<JsValue, String> {
    let func_value = Reflect::get(credentials, &method.into())
        .map_err(|e| format!("read credentials.{method}: {e:?}"))?;
    let func: Function = func_value
        .dyn_into()
        .map_err(|_| format!("credentials.{method} is not a function"))?;
    let promise_value = func
        .call1(credentials, options)
        .map_err(|e| format!("credentials.{method}(options): {e:?}"))?;
    let promise: Promise = promise_value
        .dyn_into()
        .map_err(|_| format!("credentials.{method} did not return a Promise"))?;
    JsFuture::from(promise)
        .await
        .map_err(|e| format!("await credentials.{method}: {e:?}"))
}
