//! Runtime Tauri detection + IPC bridge for the Leptos frontend.
//!
//! The browser and the Tauri desktop shell run the **same** Leptos
//! binary. At runtime we detect which container the WebView is in by
//! probing for `window.__TAURI_INTERNALS__` (Tauri 2's globally-injected
//! IPC handle); call-related buttons only enable themselves when that
//! handle is present.
//!
//! ## Why reflection instead of `tauri-sys` / typed bindings
//!
//! `tauri-sys` exists but adds an extra wasm-bindgen dep + bumps the
//! bundle size noticeably. The IPC surface we depend on is tiny —
//! `invoke(cmd, args) -> Promise<JsValue>` — so going through
//! `js_sys::Reflect` against the global handle keeps the dependency
//! graph small and avoids version pinning against `tauri-sys`'s own
//! release cadence.
//!
//! ## Threading
//!
//! Tauri's `invoke` returns a JS `Promise`. We adapt it with
//! `wasm_bindgen_futures::JsFuture` so callers can `.await` it from
//! inside `leptos::task::spawn_local`.

use js_sys::{Object, Promise, Reflect};
use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::window;

/// Probe for the Tauri 2 IPC handle. Returns `true` only when the
/// Leptos UI is hosted inside the Lattice desktop shell.
///
/// **Stability:** `__TAURI_INTERNALS__` is Tauri 2's documented
/// detection hook (the v1 sentinel was `__TAURI_IPC__`). Re-check
/// when bumping the Tauri major.
#[must_use]
pub fn is_tauri() -> bool {
    let Some(win) = window() else {
        return false;
    };
    let handle = Reflect::get(&win, &JsValue::from_str("__TAURI_INTERNALS__"))
        .unwrap_or(JsValue::UNDEFINED);
    !handle.is_undefined() && !handle.is_null()
}

/// IPC invocation against the desktop shell. Serializes `args` via
/// serde-json then `serde-wasm-bindgen`, calls
/// `window.__TAURI_INTERNALS__.invoke(cmd, args)`, awaits the returned
/// Promise, and deserializes the result.
///
/// # Errors
///
/// Returns a string error if any of:
/// - the global IPC handle isn't present (caller should check
///   [`is_tauri`] first);
/// - arg serialization to JS fails;
/// - the desktop side returns a rejected Promise (the error string is
///   surfaced verbatim);
/// - result deserialization fails.
pub async fn invoke<A: Serialize, T: DeserializeOwned>(cmd: &str, args: &A) -> Result<T, String> {
    let win = window().ok_or_else(|| "no window object".to_string())?;
    let internals = Reflect::get(&win, &JsValue::from_str("__TAURI_INTERNALS__"))
        .map_err(|e| format!("read __TAURI_INTERNALS__: {e:?}"))?;
    if internals.is_undefined() || internals.is_null() {
        return Err("__TAURI_INTERNALS__ missing; not in a Tauri WebView".to_string());
    }
    let invoke_fn = Reflect::get(&internals, &JsValue::from_str("invoke"))
        .map_err(|e| format!("read invoke fn: {e:?}"))?;
    let invoke_fn = invoke_fn
        .dyn_ref::<js_sys::Function>()
        .ok_or_else(|| "invoke is not a function".to_string())?;

    // Serialize args -> JsValue. We go through serde_json::Value as
    // an intermediate because that mapping is well-tested by gloo-net
    // elsewhere in the crate; serde_wasm_bindgen would be marginally
    // smaller, but this trade is acceptable for the IPC surface size.
    let json = serde_json::to_string(args)
        .map_err(|e| format!("serialize args: {e}"))?;
    let parsed: JsValue = js_sys::JSON::parse(&json)
        .map_err(|e| format!("JSON.parse args: {e:?}"))?;
    let args_obj: Object = parsed.dyn_into().map_err(|_| {
        "args must serialize to a JSON object (top-level struct, not bare value)".to_string()
    })?;

    let promise_jv = invoke_fn
        .call2(&internals, &JsValue::from_str(cmd), &args_obj)
        .map_err(|e| stringify_js(&e))?;
    let promise: Promise = promise_jv
        .dyn_into()
        .map_err(|_| "invoke did not return a Promise".to_string())?;

    let result = JsFuture::from(promise).await.map_err(|e| stringify_js(&e))?;

    // Round-trip through JSON for the response too, for the same
    // reason as the request path. Tauri serializes responses with
    // serde-json so this is faithful.
    let result_str = js_sys::JSON::stringify(&result)
        .map_err(|e| format!("JSON.stringify result: {e:?}"))?
        .as_string()
        .ok_or_else(|| "result not stringifiable".to_string())?;
    serde_json::from_str(&result_str).map_err(|e| format!("deserialize result: {e}"))
}

/// Mirror of `lattice_desktop_lib::commands::StartCallRequest` —
/// duplicated here because the desktop crate is native-only and we
/// can't pull it into the wasm32 build of `lattice-web`.
///
/// The shape MUST stay in sync; both sides go through serde-json so
/// drift would surface at runtime as an IPC deserialization error.
#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct StartCallRequest {
    /// 32-byte BLAKE3 user_id of the peer, hex-encoded. `None` is
    /// accepted by the loopback path; cross-machine signaling will
    /// require it.
    pub peer_user_id_hex: Option<String>,
    /// 32-byte group id, hex-encoded.
    pub group_id_hex: Option<String>,
}

/// Mirror of `lattice_desktop_lib::commands::StartCallReport`. See
/// the docstring on [`StartCallRequest`] for the sync caveat.
#[derive(Debug, Clone, serde::Deserialize, Serialize)]
pub struct StartCallReport {
    /// 16-byte CallId, hex-encoded.
    pub call_id_hex: String,
    /// Caller-side ICE host candidates observed.
    pub caller_candidates_seen: usize,
    /// Callee-side ICE host candidates observed.
    pub callee_candidates_seen: usize,
    /// First 4 bytes of the PQ-folded SRTP master, hex-encoded.
    pub srtp_master_prefix: String,
    /// Plain RTP packet length the caller fed into SRTP.
    pub plain_rtp_len: usize,
    /// Protected (encrypted) SRTP packet length on the wire.
    pub protected_rtp_len: usize,
    /// Recovered RTP packet length after the callee unwrapped SRTP.
    pub recovered_rtp_len: usize,
}

/// Mirror of `lattice_desktop_lib::commands::DesktopInfo`. Cheap
/// handshake the UI can fire on boot to confirm the IPC bridge.
#[derive(Debug, Clone, serde::Deserialize, Serialize)]
pub struct DesktopInfo {
    /// Human-readable banner from the shell.
    pub greeting: String,
    /// `lattice-core` version reported by the shell.
    pub core_version: String,
    /// `lattice-media` version reported by the shell.
    pub media_version: String,
}

/// Wrapper object Tauri expects when a command takes a struct as a
/// named arg. Tauri 2 spreads `args` as the parameters of the
/// `#[tauri::command]` fn; our `start_call(request: StartCallRequest, …)`
/// maps to `{ "request": { … } }`.
#[derive(Debug, Serialize)]
struct StartCallArgs<'a> {
    request: &'a StartCallRequest,
}

#[derive(Debug, Serialize)]
struct CallIdArgs<'a> {
    call_id_hex: &'a str,
}

#[derive(Debug, Serialize)]
struct NoArgs {}

/// Invoke the `desktop_info` Tauri command. Returns `None` when not
/// running inside the desktop shell.
pub async fn desktop_info() -> Result<Option<DesktopInfo>, String> {
    if !is_tauri() {
        return Ok(None);
    }
    let info: DesktopInfo = invoke("desktop_info", &NoArgs {}).await?;
    Ok(Some(info))
}

/// Invoke the `start_call` Tauri command. Phase F: runs the in-process
/// loopback orchestrator on the desktop side and returns its report.
pub async fn start_call(request: &StartCallRequest) -> Result<StartCallReport, String> {
    if !is_tauri() {
        return Err("start_call requires the Lattice desktop shell".to_string());
    }
    invoke("start_call", &StartCallArgs { request }).await
}

/// Invoke the `end_call` Tauri command. Returns `true` if the
/// shell had a record of the call_id.
pub async fn end_call(call_id_hex: &str) -> Result<bool, String> {
    if !is_tauri() {
        return Err("end_call requires the Lattice desktop shell".to_string());
    }
    invoke("end_call", &CallIdArgs { call_id_hex }).await
}

fn stringify_js(value: &JsValue) -> String {
    if let Some(s) = value.as_string() {
        return s;
    }
    js_sys::JSON::stringify(value)
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

// The `dyn_into` / `dyn_ref` calls require `JsCast`. wasm_bindgen
// re-exports it through its prelude; pull it in here explicitly so
// the bound is satisfied without polluting other modules.
use wasm_bindgen::JsCast;
