//! Per-group WebSocket push subscriber — chunk D.
//!
//! Opens one WS connection per active conversation to
//! `/group/:gid/messages/ws`. Each frame carries `{seq, envelope_b64}`,
//! but **we ignore the payload** here on purpose: the only signal we
//! need is "something arrived on this group, go poll." Triggering the
//! existing `ChatState::poll_all` keeps the decrypt + scrollback +
//! sidebar-update path single-sourced and avoids a second decrypt
//! pipeline.
//!
//! ## Why per-group, not per-user
//!
//! The server already maintains a per-group broadcast channel
//! (`crates/lattice-server/src/state.rs::ServerState::subscribe`),
//! so attaching one WS per group reuses existing infrastructure
//! without inventing a per-user fan-out. The on-disk message log is
//! still the source of truth — WS push is just a latency optimisation
//! over the 5-second poll loop.
//!
//! ## No-PII boundary
//!
//! The WS frame itself contains nothing the OS sees: it lives inside
//! the Rust/JS WASM heap. The only thing that becomes visible to the
//! OS is the generic `Notification` surfaced by `notify::
//! show_generic_message_notification` — and that helper takes zero
//! parameters, so no caller can leak PII through it.
//!
//! ## Lifecycle
//!
//! - `subscribe_for(gid, server_url, on_wake)` opens a WS, installs
//!   `onmessage` / `onclose` / `onerror` handlers, and stashes the
//!   `WebSocket` handle in a thread-local map so it isn't dropped.
//! - `unsubscribe_for(gid)` closes the socket and forgets the handle.
//! - The thread-local is fine here because `lattice-web` is a single
//!   wasm32 thread; nothing else can race with it. It also keeps
//!   `web_sys::WebSocket` (`!Send + !Sync`) out of `ChatState`'s
//!   Send+Sync surface.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use tracing::{debug, warn};
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{CloseEvent, Event, MessageEvent, WebSocket};

use crate::api;
use crate::chat_state::GroupId;

thread_local! {
    /// Per-group live `WebSocket` handles. Holding them here keeps
    /// the underlying JS object alive (otherwise `Drop` closes the
    /// socket immediately). Indexed by `GroupId` so we can swap a
    /// dead socket for a fresh one on reconnect.
    static SUBSCRIPTIONS: RefCell<HashMap<GroupId, Subscription>>
        = RefCell::new(HashMap::new());
}

/// One live subscription's owned state. Closures must be retained
/// for the lifetime of the socket — `Closure::forget()` would leak
/// them; instead we drop them when the subscription drops.
///
/// The `socket` field is intentionally never read directly; holding
/// it here is what keeps the underlying JS `WebSocket` alive (Rust's
/// dead-code analysis can't see the JS-side keepalive contract).
#[allow(dead_code)]
struct Subscription {
    socket: WebSocket,
    on_message: Closure<dyn FnMut(MessageEvent)>,
    on_close: Closure<dyn FnMut(CloseEvent)>,
    on_error: Closure<dyn FnMut(Event)>,
}

/// Open a WS push subscription for `gid`. `on_wake` is invoked with
/// no arguments every time a frame lands — the caller then decides
/// whether to poll, notify, etc. Replaces any existing subscription
/// for this group.
///
/// Errors (URL malformed, mixed-content block, etc.) are logged via
/// `tracing::warn!` and silently dropped — the 5-second poll loop
/// is the fallback.
pub fn subscribe_for<F>(gid: GroupId, server_url: &str, on_wake: F)
where
    F: Fn() + 'static,
{
    let socket = match api::open_messages_ws(server_url, &gid) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, gid_prefix = ?&gid[..4], "ws_subscribe: open failed");
            return;
        }
    };

    // Shared invoker so message + close handlers can both trigger
    // a poll. close → trigger one more poll (so the user sees any
    // last message before reconnect) then attempt reconnect.
    let on_wake = Rc::new(on_wake);

    let on_wake_msg = on_wake.clone();
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
        // We don't care about the payload — just wake the poller.
        let _ = ev;
        debug!("ws_subscribe: frame received");
        on_wake_msg();
    });
    let on_wake_close = on_wake.clone();
    let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |ev: CloseEvent| {
        debug!(code = ev.code(), reason = %ev.reason(), "ws_subscribe: closed");
        // One last poll on close so the user catches anything that
        // landed during the disconnect.
        on_wake_close();
    });
    let on_error = Closure::<dyn FnMut(Event)>::new(move |_ev: Event| {
        warn!("ws_subscribe: socket error");
    });

    socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
    socket.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    let sub = Subscription {
        socket,
        on_message,
        on_close,
        on_error,
    };
    SUBSCRIPTIONS.with(|cell| {
        cell.borrow_mut().insert(gid, sub);
    });
    debug!(gid_prefix = ?&gid[..4], "ws_subscribe: subscription attached");
}

/// Drop any existing subscription for `gid`. No-op if none exists.
/// Currently no call sites — kept for the teardown path that will
/// land when group leave / delete UI lands. Marked `#[allow(dead_code)]`
/// so the public API is still discoverable.
#[allow(dead_code)]
pub fn unsubscribe_for(gid: GroupId) {
    SUBSCRIPTIONS.with(|cell| {
        if let Some(sub) = cell.borrow_mut().remove(&gid) {
            // CloseEvent code 1000 = normal closure.
            let _ = sub.socket.close_with_code(1000);
            debug!(gid_prefix = ?&gid[..4], "ws_subscribe: subscription dropped");
        }
    });
}
