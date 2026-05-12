//! Tauri 2 build script. Generates `tauri.conf.json`-derived bindings
//! (capabilities, icon manifest, runtime config) at compile time so the
//! main binary can boot without re-reading config from disk.
//!
//! Lives in the standard Tauri 2 location; the actual logic is owned
//! by upstream `tauri-build` and just needs to be invoked.

fn main() {
    tauri_build::build();
}
