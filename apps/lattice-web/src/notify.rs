//! OS-level notification helpers — chunk D.
//!
//! ## No-PII contract
//!
//! Signal's recent class of background-notification leaks came from
//! notification payloads containing sender names / group titles /
//! message previews that survive in OS notification history even
//! after the recipient app is wiped. Lattice deliberately makes the
//! notification body **content-free**: a fixed string with zero
//! parameters. Callers cannot pass through a sender label, a group
//! id, a message preview, or any other identifying string.
//!
//! The `show_generic_message_notification` function takes no
//! arguments by design. If a future caller wants per-conversation
//! titles they will have to add a new function and the no-PII review
//! gate forces an explicit DECISIONS change.
//!
//! Permission is requested once at bootstrap; a denial is permanent
//! until the user manually re-grants in browser settings. We do not
//! re-prompt.

use tracing::{debug, warn};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Notification, NotificationOptions, NotificationPermission};

/// Permission state for the browser's Notification API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyState {
    /// Permission granted; `show_generic_message_notification` will
    /// surface a notification.
    Granted,
    /// User has not yet been asked.
    Default,
    /// User actively denied. We do not re-prompt.
    Denied,
    /// Notification API unsupported on this browser (very rare on
    /// modern desktop builds; common on iOS Safari).
    Unsupported,
}

/// Returns the current permission state without prompting. Falls
/// back to `Unsupported` on engines that throw when the
/// Notification API isn't available (older WebViews, embedded
/// shells without the Notifications feature).
#[must_use]
pub fn current_state() -> NotifyState {
    match Notification::permission() {
        NotificationPermission::Granted => NotifyState::Granted,
        NotificationPermission::Default => NotifyState::Default,
        NotificationPermission::Denied => NotifyState::Denied,
        _ => NotifyState::Unsupported,
    }
}

/// Ask the user for notification permission if we haven't already.
/// Safe to call repeatedly; only the first call (in `Default` state)
/// produces a prompt.
pub async fn request_permission() -> NotifyState {
    match current_state() {
        NotifyState::Default => {}
        other => return other,
    }
    let Ok(promise) = Notification::request_permission() else {
        warn!("notify: request_permission threw — assuming Unsupported");
        return NotifyState::Unsupported;
    };
    match JsFuture::from(promise).await {
        Ok(val) => {
            // val is a `NotificationPermission` JsValue stringly-cast
            // ("granted" / "denied" / "default").
            let s = val.as_string().unwrap_or_default();
            debug!(result = %s, "notify: permission resolved");
            match s.as_str() {
                "granted" => NotifyState::Granted,
                "denied" => NotifyState::Denied,
                _ => NotifyState::Default,
            }
        }
        Err(e) => {
            warn!(error = ?e, "notify: request_permission rejected");
            NotifyState::Unsupported
        }
    }
}

/// **Generic** message notification. Fixed copy, zero parameters.
///
/// Title: `"Lattice"`. Body: `"New message"`. No sender, no group,
/// no preview, no tag, no icon URL. This is the *only* way to
/// surface a system notification from the chat shell.
///
/// No-ops if permission is not `Granted`.
pub fn show_generic_message_notification() {
    if current_state() != NotifyState::Granted {
        return;
    }
    let opts = NotificationOptions::new();
    opts.set_body("New message");
    // Silent + no tag is intentional: tag would let the OS group
    // notifications across multiple convos, which leaks "you have
    // an active Lattice chat". Silent avoids OS sound at-rest.
    opts.set_silent(Some(true));
    match Notification::new_with_options("Lattice", &opts) {
        Ok(_) => debug!("notify: surfaced generic notification"),
        Err(e) => warn!(error = ?e, "notify: failed to construct Notification"),
    }
}

/// Returns `true` when the document is currently hidden (the user
/// has tabbed away). Chunk D only surfaces notifications when this
/// is true — when the tab is visible the message is right there.
#[must_use]
pub fn document_hidden() -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    let Some(doc) = window.document() else {
        return false;
    };
    doc.hidden()
}
