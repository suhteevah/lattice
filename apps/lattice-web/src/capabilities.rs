//! Capability detection for advanced browser features Lattice uses.
//!
//! `lattice-web` works on any modern Chromium/Firefox/Safari with
//! WASM + fetch + localStorage. Some features unlock additional
//! security/perf paths but are not yet universally shipped:
//!
//! * **WebAuthn passkeys** with the `prf` extension (Phase ε, D-09).
//!   Chrome 116+ / Edge 116+; Safari 17+; Firefox 122+. PRF output is
//!   a 32-byte secret per credential that we feed to
//!   `ChaCha20-Poly1305` for at-rest encryption, replacing Phase δ.2's
//!   Argon2id KEK.
//! * **WebTransport** (Phase γ.4, D-11). Chrome 97+. Firefox /
//!   Safari shipping behind flags. We prefer it when available for
//!   lower latency + native multiplexing; HTTP/fetch is the universal
//!   fallback (already wired in Phase γ.1-3).
//!
//! Detection is a single JS reachability probe per feature — no
//! actual ceremony or stream is opened, just `typeof` checks via
//! `js_sys::Reflect`. Results are reported through the demo UI so
//! Matt can see what the current browser supports without leaving
//! the page.

use js_sys::Reflect;
use wasm_bindgen::JsValue;

/// Snapshot of the browser's capabilities for the M4 demo. Read once
/// at boot, cached in the UI signal.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    /// `window.PublicKeyCredential` constructor present. Necessary
    /// (not sufficient) for WebAuthn passkeys.
    pub webauthn: bool,
    /// `window.WebTransport` constructor present. Necessary (not
    /// sufficient) for opening WT sessions.
    pub webtransport: bool,
    /// `navigator.credentials` container present. Required to call
    /// `.create()` / `.get()` for WebAuthn.
    pub credentials_container: bool,
}

impl Capabilities {
    /// Probe the current `window` object. Returns a struct of bools;
    /// missing `window` (e.g. Worker context) yields all `false`.
    #[must_use]
    pub fn probe() -> Self {
        let Some(window) = web_sys::window() else {
            return Self::default();
        };
        let window_value: JsValue = window.into();
        let webauthn = has_property(&window_value, "PublicKeyCredential");
        let webtransport = has_property(&window_value, "WebTransport");

        // navigator.credentials lives on Navigator (one level deeper).
        let credentials_container = match Reflect::get(&window_value, &"navigator".into()) {
            Ok(nav) if !nav.is_undefined() && !nav.is_null() => {
                has_property(&nav, "credentials")
            }
            _ => false,
        };

        Self {
            webauthn,
            webtransport,
            credentials_container,
        }
    }
}

fn has_property(target: &JsValue, name: &str) -> bool {
    match Reflect::get(target, &name.into()) {
        Ok(v) => !v.is_undefined() && !v.is_null(),
        Err(_) => false,
    }
}
