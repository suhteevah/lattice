//! `lattice-web` — browser client entrypoint.
//!
//! Compiles to `wasm32-unknown-unknown` via Trunk. Mounts the Leptos
//! [`App`] component into `#root` in `index.html`. No JavaScript in the
//! application code — `lattice-core` (and transitively `lattice-crypto`,
//! `lattice-protocol`) are called as regular Rust crates that happen to
//! compile to WASM alongside the UI.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod api;
mod app;
mod capabilities;
mod chat;
mod chat_state;
mod distrust;
mod notify;
mod passkey;
mod persist;
mod storage;
mod tauri;
mod ws_subscribe;

use leptos::prelude::*;

/// WASM entry point invoked by Trunk's generated bootstrap. Sets up a
/// panic hook that pipes Rust panics into the browser console + mounts
/// the Leptos app under `#root`.
fn main() {
    console_error_panic_hook::set_once();
    if let Err(e) = lattice_core::init() {
        web_sys::console::error_1(&format!("lattice-core init failed: {e}").into());
    }
    mount_to_body(app::App);
}
