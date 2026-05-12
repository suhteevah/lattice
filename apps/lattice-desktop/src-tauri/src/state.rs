//! Mutable state owned by the Tauri app and shared across IPC commands.
//!
//! Phase F scope: a tiny call registry plus build-info constants. The
//! registry is keyed by [`CallId`] so future signaling can look up
//! in-flight calls without re-running the orchestrator.

use std::collections::HashMap;

use lattice_media::call::{CallId, CallOutcome};
use tokio::sync::Mutex;

/// Mutable application state shared across Tauri IPC commands.
///
/// Tauri's `manage` API stores this `Send + Sync` instance inside the
/// app handle; commands retrieve it via `tauri::State<DesktopState>`.
#[derive(Default)]
pub struct DesktopState {
    /// Completed-call outcomes, keyed by [`CallId`]. Right now Phase F
    /// only records the result of the loopback smoke run, but the
    /// shape generalizes — once cross-machine signaling lands, this
    /// is where in-progress calls live too.
    pub calls: Mutex<HashMap<CallId, CallOutcome>>,
}

impl DesktopState {
    /// Construct an empty `DesktopState`. Equivalent to `default()`;
    /// the named constructor makes call sites read clearly.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
