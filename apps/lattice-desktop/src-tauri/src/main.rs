//! Lattice desktop shell entry point. Defers to
//! [`lattice_desktop_lib::run`] so Tauri Mobile (Phase H) can reuse
//! the same boot sequence behind a different binary or cdylib.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Suppress the OS-level console window on Windows release builds —
// Tauri opens its own WebView; a black console alongside is noise.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    lattice_desktop_lib::run();
}
