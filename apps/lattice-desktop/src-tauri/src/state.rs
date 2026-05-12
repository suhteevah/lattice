//! Mutable state owned by the Tauri app and shared across IPC commands.
//!
//! Phase F shipped the call registry; Phase G adds a `Keystore` handle
//! used by the new `keystore_*` IPC commands. Both are stored on the
//! same `DesktopState` so a single `State<'_, DesktopState>` injection
//! in any command can reach both.

use std::collections::HashMap;
use std::sync::Arc;

use lattice_media::call::{CallId, CallOutcome};
use lattice_media::keystore::Keystore;
use tokio::sync::Mutex;

/// Mutable application state shared across Tauri IPC commands.
///
/// Tauri's `manage` API stores this `Send + Sync` instance inside the
/// app handle; commands retrieve it via `tauri::State<DesktopState>`.
pub struct DesktopState {
    /// Completed-call outcomes, keyed by [`CallId`].
    pub calls: Mutex<HashMap<CallId, CallOutcome>>,
    /// Hardware-backed (or DPAPI-backed on Windows) identity keystore.
    /// Constructed once at boot in `lib.rs::run()`; the trait object is
    /// `Send + Sync` so it can move across Tauri's async runtime
    /// without locking.
    pub keystore: Arc<dyn Keystore>,
}

impl DesktopState {
    /// Construct a fresh `DesktopState` with an empty call registry and
    /// the supplied keystore.
    #[must_use]
    pub fn new(keystore: Arc<dyn Keystore>) -> Self {
        Self {
            calls: Mutex::new(HashMap::new()),
            keystore,
        }
    }
}
