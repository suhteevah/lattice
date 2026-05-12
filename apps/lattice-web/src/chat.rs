//! Chat-app shell — chunk A of the post-Phase-F UX work.
//!
//! Renders the three classic panes of a chat client: a left sidebar
//! with conversations, a center thread with messages, and a composer
//! at the bottom. Designed to live above the existing button-grid
//! demo in [`crate::app::App`] so we don't lose the debug surface.
//!
//! ## Scope of chunk A
//!
//! Layout + signals + composer wiring. **Messages are local-only** —
//! chunk C wires this UI to the existing `crate::api` surface for
//! real MLS-routed DMs. Mock conversation seed exists so the panes
//! feel populated; remove the seed when chunk C lands.
//!
//! ## Why a single file
//!
//! Chunk A's surface is ~300 LOC. The split into `sidebar.rs` /
//! `thread.rs` / `composer.rs` becomes worthwhile when the state
//! plumbing grows in chunks B/C/D; for now keeping it together
//! keeps the data flow obvious.

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::JsCast;
use web_sys::HtmlInputElement;

/// One conversation in the sidebar.
#[derive(Clone, Debug, PartialEq)]
pub struct Conversation {
    /// Stable id — for chunk A this is just a synthetic counter;
    /// chunk C will replace it with the MLS group_id hex.
    pub id: String,
    /// Display name shown in the sidebar.
    pub name: String,
    /// Last message preview text, for the sidebar list. Empty until
    /// at least one message is sent.
    pub last_preview: String,
}

/// One message in a thread.
#[derive(Clone, Debug, PartialEq)]
pub struct ChatMessage {
    /// Who sent it. "me" identifies the local user; anything else
    /// is rendered as the contact's name.
    pub author: String,
    /// Plaintext body. Chunk A allows arbitrary UTF-8; chunk C will
    /// re-encrypt via lattice-crypto before send.
    pub body: String,
    /// Seconds since UNIX epoch.
    pub timestamp_unix: u64,
}

/// Where the user is in the chat shell.
#[derive(Clone, Debug, PartialEq)]
pub enum ChatView {
    /// No conversation selected yet — show the empty-state pane.
    Empty,
    /// User has selected a conversation; show the thread + composer.
    Conversation(String),
}

/// Root chat-shell component. Reads / writes signals owned by the
/// caller so the rest of the app (settings panel, status chip, etc.)
/// can see the same data.
#[component]
pub fn ChatShell(
    /// Conversation list (sidebar). Caller supplies an initial seed.
    conversations: RwSignal<Vec<Conversation>>,
    /// All messages, keyed by conversation id.
    messages: RwSignal<std::collections::HashMap<String, Vec<ChatMessage>>>,
    /// Currently-selected view.
    current_view: RwSignal<ChatView>,
    /// User-supplied display name surfaced when "me" sends a message.
    /// Chunk C replaces this with a stable identity prefix.
    display_name: Signal<String>,
) -> impl IntoView {
    view! {
        <div class="chat-shell">
            <ConversationSidebar
                conversations=conversations
                current_view=current_view
            />
            <div class="chat-main">
                {move || match current_view.get() {
                    ChatView::Empty => view! {
                        <EmptyThreadPlaceholder/>
                    }.into_any(),
                    ChatView::Conversation(id) => view! {
                        <ThreadPane
                            conversation_id=id.clone()
                            conversations=conversations
                            messages=messages
                            display_name=display_name
                        />
                    }.into_any(),
                }}
            </div>
        </div>
    }
}

#[component]
fn ConversationSidebar(
    conversations: RwSignal<Vec<Conversation>>,
    current_view: RwSignal<ChatView>,
) -> impl IntoView {
    view! {
        <aside class="chat-sidebar" aria-label="conversations">
            <header class="chat-sidebar-header">
                <h2>"Conversations"</h2>
            </header>
            <ul class="chat-conversation-list">
                {move || {
                    let convos = conversations.get();
                    if convos.is_empty() {
                        view! {
                            <li class="chat-conversation-empty muted">
                                "No conversations yet. Add a contact to start."
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
fn EmptyThreadPlaceholder() -> impl IntoView {
    view! {
        <div class="chat-thread-empty">
            <p class="muted">
                "Select a conversation, or add a contact to start a new one."
            </p>
        </div>
    }
}

#[component]
fn ThreadPane(
    conversation_id: String,
    conversations: RwSignal<Vec<Conversation>>,
    messages: RwSignal<std::collections::HashMap<String, Vec<ChatMessage>>>,
    display_name: Signal<String>,
) -> impl IntoView {
    // Find the conversation's display name for the header.
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

    let id_for_send = conversation_id.clone();
    let send = move |body: String| {
        let body = body.trim().to_string();
        if body.is_empty() {
            return;
        }
        let me = display_name.get_untracked();
        let timestamp_unix = now_unix();
        let preview = body.chars().take(80).collect::<String>();

        let id = id_for_send.clone();
        messages.update(|m| {
            m.entry(id.clone()).or_default().push(ChatMessage {
                author: me,
                body,
                timestamp_unix,
            });
        });
        conversations.update(|cs| {
            if let Some(c) = cs.iter_mut().find(|c| c.id == id) {
                c.last_preview = preview;
            }
        });
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
                        msgs.into_iter().map(|m| {
                            let mine = m.author == display_name.get_untracked();
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
            <MessageComposer on_send=send/>
        </section>
    }
}

#[component]
fn MessageComposer<F>(on_send: F) -> impl IntoView
where
    F: Fn(String) + 'static + Clone,
{
    let input_ref: NodeRef<leptos::html::Input> = NodeRef::new();
    let on_send_for_submit = on_send.clone();
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        if let Some(node) = input_ref.get() {
            // Cast the Leptos HtmlElement<Input> to a web_sys
            // HtmlInputElement to read its value. Both refer to the
            // same underlying DOM node.
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

fn now_unix() -> u64 {
    // `Date::now()` returns milliseconds since UNIX epoch — always
    // available in WASM, no `web-sys` feature gate needed.
    let ms = js_sys::Date::now();
    (ms / 1000.0) as u64
}

fn format_short_time(unix: u64) -> String {
    // Avoid pulling chrono into the wasm bundle just for HH:MM
    // formatting; do the math manually. UTC, since we don't have
    // a TZ store yet.
    let hours = (unix / 3600) % 24;
    let mins = (unix / 60) % 60;
    format!("{hours:02}:{mins:02} UTC")
}

/// Seed the chat shell with a single mock conversation so the empty
/// state is visible without writing logic for "add contact" up front.
/// Removed when chunk B (onboarding + contacts) lands.
#[must_use]
pub fn mock_seed() -> (
    Vec<Conversation>,
    std::collections::HashMap<String, Vec<ChatMessage>>,
) {
    let convo = Conversation {
        id: "mock-bob".to_string(),
        name: "Bob (mock)".to_string(),
        last_preview: String::new(),
    };
    (vec![convo], std::collections::HashMap::new())
}
