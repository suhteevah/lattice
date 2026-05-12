//! Chat-app shell — chunks A + C of the post-Phase-F UX work.
//!
//! Renders the three classic panes of a chat client: a left sidebar
//! with conversations, a center thread with messages, and a composer
//! at the bottom. Chunk A shipped the layout against mock data;
//! chunk C plumbs real MLS state through it via [`crate::chat_state`].
//!
//! ## State plumbing
//!
//! - `ChatState` (in `chat_state.rs`) owns the MLS state — identity
//!   bundle + per-conversation `GroupHandle`. Methods are async
//!   because they touch the home server.
//! - This module owns the **view** signals (`conversations`,
//!   `messages`, `current_view`) and treats them as a derived
//!   projection of `ChatState`. The "Add conversation" submit /
//!   "Send" composer / polling loop all mutate `ChatState` first,
//!   then refresh the view signals from
//!   `ChatState::conversation_summaries()`.
//!
//! ## What chunk C ships
//!
//! - Identity bootstrap on first render (generate-and-register if
//!   no plaintext blob; load if there is one).
//! - "Add conversation" inline form (paste a peer's user_id hex +
//!   label) that either accepts a waiting Welcome (we're joining
//!   peer's group) or creates a group and posts a Welcome
//!   (we're inviting).
//! - Composer Send is wired to `ChatState::send_message`.
//! - Background 5-second polling loop pulls new messages.
//!
//! WebSocket push is chunk D. Encrypted-blob unlock UI is chunk B's
//! onboarding flow.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;
use lattice_crypto::credential::USER_ID_LEN;
use wasm_bindgen::JsCast;
use web_sys::HtmlInputElement;

use crate::chat_state::{ChatState, ConversationSummary, GroupId, PolledMessage};

/// One conversation in the sidebar.
#[derive(Clone, Debug, PartialEq)]
pub struct Conversation {
    /// 32-character hex of the 16-byte group id.
    pub id: String,
    /// Display name shown in the sidebar.
    pub name: String,
    /// Last message preview text.
    pub last_preview: String,
}

impl Conversation {
    fn from_summary(s: &ConversationSummary) -> Self {
        Self {
            id: hex::encode(s.group_id),
            name: s.label.clone(),
            last_preview: String::new(),
        }
    }
}

/// One message in a thread.
#[derive(Clone, Debug, PartialEq)]
pub struct ChatMessage {
    /// Who sent it. "me" identifies the local user; anything else
    /// is the peer's label.
    pub author: String,
    /// Plaintext body.
    pub body: String,
    /// Seconds since UNIX epoch.
    pub timestamp_unix: u64,
}

/// Where the user is in the chat shell.
#[derive(Clone, Debug, PartialEq)]
pub enum ChatView {
    /// No conversation selected.
    Empty,
    /// User has selected a conversation (id is the group_id hex).
    Conversation(String),
}

/// Default polling interval for new-message fetch.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Root chat-shell component. Takes a `ChatState` for real MLS
/// state and owns the view-projection signals internally.
#[component]
pub fn ChatShell(
    /// Shared chat state. Cloning is cheap (`Rc` inside).
    state: ChatState,
    /// Status bar reporter — same channel `app.rs` uses for the
    /// boot status line. Lets the chat shell surface bootstrap +
    /// add-conversation results without owning the page-level
    /// status signal directly.
    set_status: WriteSignal<String>,
) -> impl IntoView {
    let conversations: RwSignal<Vec<Conversation>> = RwSignal::new(Vec::new());
    let messages: RwSignal<HashMap<String, Vec<ChatMessage>>> =
        RwSignal::new(HashMap::new());
    let current_view = RwSignal::new(ChatView::Empty);
    let my_user_id_hex: RwSignal<String> = RwSignal::new(String::new());
    let add_form_open = RwSignal::new(false);
    let bootstrap_complete = RwSignal::new(false);

    // Bootstrap identity once at component mount. Direct spawn_local
    // (not Effect::new) because we only want this to fire once, even
    // if the component remounts. Concurrent calls are gated by
    // `ChatState::bootstrap_identity`'s internal in-flight flag.
    {
        let state = state.clone();
        spawn_local(async move {
            set_status.set("chat: bootstrapping identity…".to_string());
            let log = |msg: String| {
                web_sys::console::log_1(&msg.into());
            };
            match state.bootstrap_identity(log).await {
                Ok(()) => {
                    if let Some(uid) = state.my_user_id() {
                        my_user_id_hex.set(hex::encode(uid));
                    }
                    bootstrap_complete.set(true);
                    set_status
                        .set("chat: identity ready — add a contact to start".to_string());
                }
                Err(e) => {
                    set_status.set(format!("chat: identity bootstrap failed: {e}"));
                }
            }
        });
    }

    // Background polling task — single spawn_local at mount that
    // loops with a setTimeout-based sleep. Each iteration polls
    // every active conversation; new messages land in the messages
    // signal.
    {
        let state = state.clone();
        spawn_local(async move {
            loop {
                sleep(POLL_INTERVAL).await;
                if !state.has_identity() {
                    continue;
                }
                match state.poll_all().await {
                    Ok(polled) => {
                        if !polled.is_empty() {
                            apply_polled_messages(polled, &messages);
                        }
                    }
                    Err(e) => {
                        web_sys::console::warn_1(
                            &format!("chat: poll error {e}").into(),
                        );
                    }
                }
            }
        });
    }

    // Display name signal derived from my_user_id_hex.
    let display_name = Signal::derive(move || {
        let hx = my_user_id_hex.get();
        if hx.is_empty() {
            "me".to_string()
        } else {
            format!("me ({})", &hx[..6.min(hx.len())])
        }
    });

    // Refresh the conversations signal from ChatState.
    let refresh_conversations = {
        let state = state.clone();
        move || {
            let summaries = state.conversation_summaries();
            conversations.set(summaries.iter().map(Conversation::from_summary).collect());
        }
    };

    // Pull restored conversations into the sidebar after the bootstrap
    // task finishes — `bootstrap_identity` rebuilds the `active` map
    // from localStorage but the view signal needs an explicit poke.
    {
        let refresh = refresh_conversations.clone();
        Effect::new(move |_prev: Option<()>| {
            if bootstrap_complete.get() {
                refresh();
            }
        });
    }

    // Add-conversation submit handler.
    let on_add_submit = {
        let state = state.clone();
        let refresh = refresh_conversations.clone();
        move |peer_hex: String, label: String| {
            let state = state.clone();
            let refresh = refresh.clone();
            spawn_local(async move {
                let peer_user_id = match parse_user_id(&peer_hex) {
                    Ok(v) => v,
                    Err(e) => {
                        set_status.set(format!("chat: invalid peer user_id ({e})"));
                        return;
                    }
                };
                set_status.set("chat: adding conversation…".to_string());
                let log = |msg: String| {
                    web_sys::console::log_1(&msg.into());
                };
                match state.add_conversation(peer_user_id, label.clone(), log).await {
                    Ok(gid) => {
                        refresh();
                        let gid_hex = hex::encode(gid);
                        current_view.set(ChatView::Conversation(gid_hex.clone()));
                        add_form_open.set(false);
                        set_status.set(format!("chat: conversation ready ({label})"));
                    }
                    Err(e) => {
                        set_status.set(format!("chat: add_conversation failed: {e}"));
                    }
                }
            });
        }
    };

    // Composer send handler — used by ThreadPane.
    let on_send = {
        let state = state.clone();
        move |gid_hex: String, body: String| {
            if body.trim().is_empty() {
                return;
            }
            let display = display_name.get_untracked();
            // Optimistic local append so the user sees their own
            // message immediately even if the network is slow.
            let preview = body.chars().take(80).collect::<String>();
            let now = now_unix();
            messages.update(|m| {
                m.entry(gid_hex.clone()).or_default().push(ChatMessage {
                    author: display.clone(),
                    body: body.clone(),
                    timestamp_unix: now,
                });
            });
            conversations.update(|cs| {
                if let Some(c) = cs.iter_mut().find(|c| c.id == gid_hex) {
                    c.last_preview = preview;
                }
            });

            let state = state.clone();
            let gid_hex_for_async = gid_hex.clone();
            spawn_local(async move {
                let gid = match parse_gid(&gid_hex_for_async) {
                    Ok(v) => v,
                    Err(e) => {
                        set_status.set(format!("chat: bad group_id ({e})"));
                        return;
                    }
                };
                if let Err(e) = state.send_message(gid, body).await {
                    set_status.set(format!("chat: send failed: {e}"));
                }
            });
        }
    };

    view! {
        <div class="chat-shell">
            <ConversationSidebar
                conversations=conversations
                current_view=current_view
                add_form_open=add_form_open
                on_add=on_add_submit
                my_user_id_hex=my_user_id_hex.read_only()
                bootstrap_complete=bootstrap_complete.read_only()
            />
            <div class="chat-main">
                {move || match current_view.get() {
                    ChatView::Empty => view! {
                        <EmptyThreadPlaceholder/>
                    }.into_any(),
                    ChatView::Conversation(id) => {
                        let id_for_pane = id.clone();
                        let on_send_clone = on_send.clone();
                        view! {
                            <ThreadPane
                                conversation_id=id_for_pane
                                conversations=conversations
                                messages=messages
                                display_name=display_name
                                on_send=on_send_clone
                            />
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

#[component]
fn ConversationSidebar<F>(
    conversations: RwSignal<Vec<Conversation>>,
    current_view: RwSignal<ChatView>,
    add_form_open: RwSignal<bool>,
    on_add: F,
    my_user_id_hex: ReadSignal<String>,
    bootstrap_complete: ReadSignal<bool>,
) -> impl IntoView
where
    F: Fn(String, String) + Clone + Send + Sync + 'static,
{
    view! {
        <aside class="chat-sidebar" aria-label="conversations">
            <header class="chat-sidebar-header">
                <h2>"Conversations"</h2>
                <button
                    class="chat-sidebar-add"
                    on:click=move |_| add_form_open.update(|b| *b = !*b)
                    aria-label="add conversation"
                    disabled=move || !bootstrap_complete.get()
                >
                    "+"
                </button>
            </header>
            <Show
                when=move || !my_user_id_hex.get().is_empty()
                fallback=|| view! {}
            >
                <div class="chat-sidebar-userid muted" aria-label="my user id">
                    "you: "
                    <code>{move || short_user_id(&my_user_id_hex.get())}</code>
                </div>
            </Show>
            <Show
                when=move || add_form_open.get()
                fallback=|| view! {}
            >
                <AddConversationForm on_add=on_add.clone() on_cancel=move || add_form_open.set(false)/>
            </Show>
            <ul class="chat-conversation-list">
                {move || {
                    let convos = conversations.get();
                    if convos.is_empty() {
                        view! {
                            <li class="chat-conversation-empty muted">
                                "No conversations yet. Click + to add one."
                            </li>
                        }.into_any()
                    } else {
                        convos.into_iter().map(|c| {
                            let active = matches!(
                                current_view.get(),
                                ChatView::Conversation(ref id) if *id == c.id,
                            );
                            let id_for_click = c.id.clone();
                            view! {
                                <li
                                    class=move || if active { "chat-conversation-item active" } else { "chat-conversation-item" }
                                >
                                    <button
                                        class="chat-conversation-button"
                                        on:click=move |_| current_view.set(ChatView::Conversation(id_for_click.clone()))
                                    >
                                        <span class="chat-conversation-name">{c.name.clone()}</span>
                                        <span class="chat-conversation-preview muted">
                                            {if c.last_preview.is_empty() { "no messages yet".to_string() } else { c.last_preview.clone() }}
                                        </span>
                                    </button>
                                </li>
                            }.into_any()
                        }).collect_view().into_any()
                    }
                }}
            </ul>
        </aside>
    }
}

#[component]
fn AddConversationForm<F, C>(on_add: F, on_cancel: C) -> impl IntoView
where
    F: Fn(String, String) + Clone + Send + Sync + 'static,
    C: Fn() + Send + Sync + 'static + Copy,
{
    let peer_input: NodeRef<leptos::html::Input> = NodeRef::new();
    let label_input: NodeRef<leptos::html::Input> = NodeRef::new();
    let on_add_for_submit = on_add.clone();
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let peer = peer_input
            .get()
            .map(|n| n.unchecked_into::<HtmlInputElement>().value())
            .unwrap_or_default();
        let label = label_input
            .get()
            .map(|n| n.unchecked_into::<HtmlInputElement>().value())
            .unwrap_or_default();
        let label = if label.trim().is_empty() {
            format!("{}…", peer.chars().take(8).collect::<String>())
        } else {
            label.trim().to_string()
        };
        if peer.trim().is_empty() {
            return;
        }
        on_add_for_submit(peer.trim().to_string(), label);
    };
    view! {
        <form class="chat-add-form" on:submit=submit>
            <label for="chat-add-peer" class="chat-add-label">
                "Peer user_id (hex, 64 chars)"
            </label>
            <input
                node_ref=peer_input
                id="chat-add-peer"
                class="chat-add-input"
                type="text"
                placeholder="0123abcd…"
                autocomplete="off"
            />
            <label for="chat-add-label" class="chat-add-label">
                "Label (optional)"
            </label>
            <input
                node_ref=label_input
                id="chat-add-label"
                class="chat-add-input"
                type="text"
                placeholder="Bob"
                autocomplete="off"
            />
            <div class="chat-add-actions">
                <button class="button chat-add-submit" type="submit">
                    "Add"
                </button>
                <button
                    class="button chat-add-cancel"
                    type="button"
                    on:click=move |_| on_cancel()
                >
                    "Cancel"
                </button>
            </div>
        </form>
    }
}

#[component]
fn EmptyThreadPlaceholder() -> impl IntoView {
    view! {
        <div class="chat-thread-empty">
            <p class="muted">
                "Select a conversation, or click + in the sidebar to add a contact."
            </p>
        </div>
    }
}

#[component]
fn ThreadPane<F>(
    conversation_id: String,
    conversations: RwSignal<Vec<Conversation>>,
    messages: RwSignal<HashMap<String, Vec<ChatMessage>>>,
    display_name: Signal<String>,
    on_send: F,
) -> impl IntoView
where
    F: Fn(String, String) + Clone + Send + Sync + 'static,
{
    let id_for_header = conversation_id.clone();
    let title = Signal::derive(move || {
        conversations
            .get()
            .iter()
            .find(|c| c.id == id_for_header)
            .map_or_else(|| "Conversation".to_string(), |c| c.name.clone())
    });

    let id_for_messages = conversation_id.clone();
    let thread_messages = Signal::derive(move || {
        messages
            .get()
            .get(&id_for_messages)
            .cloned()
            .unwrap_or_default()
    });

    let gid_for_send = conversation_id.clone();
    let on_send_for_composer = on_send.clone();
    let composer_send = move |body: String| {
        on_send_for_composer(gid_for_send.clone(), body);
    };

    view! {
        <section class="chat-thread" aria-label="thread">
            <header class="chat-thread-header">
                <h2>{move || title.get()}</h2>
            </header>
            <ol class="chat-message-list" role="log" aria-live="polite">
                {move || {
                    let msgs = thread_messages.get();
                    if msgs.is_empty() {
                        view! {
                            <li class="chat-message-empty muted">
                                "No messages yet — say hello."
                            </li>
                        }.into_any()
                    } else {
                        let me_label = display_name.get_untracked();
                        msgs.into_iter().map(|m| {
                            let mine = m.author == me_label;
                            let cls = if mine { "chat-message me" } else { "chat-message them" };
                            view! {
                                <li class=cls>
                                    <span class="chat-message-author">{m.author.clone()}</span>
                                    <span class="chat-message-body">{m.body.clone()}</span>
                                    <span class="chat-message-time muted">
                                        {format_short_time(m.timestamp_unix)}
                                    </span>
                                </li>
                            }.into_any()
                        }).collect_view().into_any()
                    }
                }}
            </ol>
            <MessageComposer on_send=composer_send/>
        </section>
    }
}

#[component]
fn MessageComposer<F>(on_send: F) -> impl IntoView
where
    F: Fn(String) + Clone + Send + Sync + 'static,
{
    let input_ref: NodeRef<leptos::html::Input> = NodeRef::new();
    let on_send_for_submit = on_send.clone();
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        if let Some(node) = input_ref.get() {
            let dom: HtmlInputElement = node.unchecked_into();
            let value = dom.value();
            dom.set_value("");
            let cb = on_send_for_submit.clone();
            spawn_local(async move {
                cb(value);
            });
        }
    };
    view! {
        <form class="chat-composer" on:submit=submit>
            <label class="visually-hidden" for="chat-composer-input">
                "Message"
            </label>
            <input
                node_ref=input_ref
                id="chat-composer-input"
                class="chat-composer-input"
                type="text"
                placeholder="Write a message…"
                autocomplete="off"
            />
            <button class="button chat-composer-send" type="submit">
                "Send"
            </button>
        </form>
    }
}

fn apply_polled_messages(
    polled: Vec<PolledMessage>,
    messages: &RwSignal<HashMap<String, Vec<ChatMessage>>>,
) {
    messages.update(|map| {
        for m in polled {
            let gid_hex = hex::encode(m.group_id);
            map.entry(gid_hex).or_default().push(ChatMessage {
                author: m.sender_label,
                body: m.body,
                timestamp_unix: now_unix(),
            });
        }
    });
}

fn parse_user_id(hex_str: &str) -> Result<[u8; USER_ID_LEN], String> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if raw.len() != USER_ID_LEN {
        return Err(format!(
            "user_id must be {USER_ID_LEN} bytes (got {})",
            raw.len()
        ));
    }
    let mut out = [0u8; USER_ID_LEN];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_gid(hex_str: &str) -> Result<GroupId, String> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if raw.len() != 16 {
        return Err(format!("group_id must be 16 bytes (got {})", raw.len()));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn short_user_id(hex_str: &str) -> String {
    if hex_str.len() <= 16 {
        hex_str.to_string()
    } else {
        format!("{}…", &hex_str[..12])
    }
}

fn now_unix() -> u64 {
    let ms = js_sys::Date::now();
    (ms / 1000.0) as u64
}

fn format_short_time(unix: u64) -> String {
    let hours = (unix / 3600) % 24;
    let mins = (unix / 60) % 60;
    format!("{hours:02}:{mins:02} UTC")
}

async fn sleep(d: Duration) {
    // Pure-JS setTimeout-backed sleep so we don't pull tokio into the
    // WASM bundle. Promise resolves on the timeout callback.
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen_futures::JsFuture;

    let _ = JsFuture::from(js_sys::Promise::new(&mut |resolve, _reject| {
        let ms = d.as_millis() as i32;
        let cb = Closure::once_into_js(move || {
            let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
        });
        let _ = web_sys::window()
            .expect("window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.unchecked_ref(),
                ms,
            );
    }))
    .await;
}

// Kept as a stub for callers in app.rs that don't yet construct
// a ChatState — once chat chunk C is fully integrated the chat
// shell is the only entry point and this becomes unused. Marked
// `#[allow(dead_code)]` so the warning doesn't fire mid-transition.
#[allow(dead_code)]
#[must_use]
pub fn mock_seed() -> (
    Vec<Conversation>,
    HashMap<String, Vec<ChatMessage>>,
) {
    (Vec::new(), HashMap::new())
}

// Silence unused-import warning on `Rc<RefCell>` — they're imported
// by sibling modules pre-chunk-C; pinning the path keeps that surface.
#[allow(dead_code)]
fn _force_imports(_: Rc<RefCell<()>>) {}
