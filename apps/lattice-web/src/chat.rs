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

use crate::chat_state::{
    ChatState, Contact, ConversationSummary, ConvoKind, GroupId, PolledMessage,
    load_contacts, load_server_url, save_server_url,
};

/// One conversation in the sidebar.
#[derive(Clone, Debug, PartialEq)]
pub struct Conversation {
    /// 32-character hex of the 16-byte group id.
    pub id: String,
    /// Display name shown in the sidebar.
    pub name: String,
    /// Last message preview text.
    pub last_preview: String,
    /// Kind of conversation — drives whether the sidebar entry
    /// renders with a ★ server prefix.
    pub kind: ConvoKind,
    /// Peer's user_id (hex) — used to match contacts to existing
    /// 1:1 DMs. Empty for groups / servers / channels.
    pub peer_user_id_hex: String,
}

impl Conversation {
    fn from_summary(s: &ConversationSummary) -> Self {
        let peer_hex = match &s.kind {
            ConvoKind::OneOnOne => hex::encode(s.peer_user_id),
            _ => String::new(),
        };
        Self {
            id: hex::encode(s.group_id),
            name: s.label.clone(),
            last_preview: String::new(),
            kind: s.kind.clone(),
            peer_user_id_hex: peer_hex,
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
    let new_group_form_open = RwSignal::new(false);
    let new_server_form_open = RwSignal::new(false);
    let settings_open = RwSignal::new(false);
    let bootstrap_complete = RwSignal::new(false);
    // Chunk B: contacts directory. Seeded from localStorage on
    // bootstrap, refreshed after every successful add_conversation
    // (the backend's `save_contact` is also called there).
    let contacts: RwSignal<Vec<Contact>> = RwSignal::new(Vec::new());
    // Prefill seed for the AddConversation form when the user
    // clicks a contact whose DM doesn't exist yet.
    let add_form_prefill: RwSignal<Option<(String, String)>> = RwSignal::new(None);

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
    // signal AND the conversations sidebar is re-refreshed in case
    // a ServerStateOp::Init classify upgraded a convo's kind from
    // NamedGroup to ServerMembership.
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
                        // Re-snapshot conversation kinds (e.g.
                        // post-Init classification upgrade) into
                        // the sidebar signal. Inline closure here
                        // because `refresh_conversations` is
                        // defined further down in the component
                        // body, after this spawn_local.
                        let summaries = state.conversation_summaries();
                        conversations.set(
                            summaries.iter().map(Conversation::from_summary).collect(),
                        );
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
    // Also seed `messages` from persisted scrollback so reload
    // renders pre-reload thread history.
    {
        let refresh = refresh_conversations.clone();
        let state = state.clone();
        Effect::new(move |_prev: Option<()>| {
            if bootstrap_complete.get() {
                refresh();
                let summaries = state.conversation_summaries();
                let mut seeded: HashMap<String, Vec<ChatMessage>> = HashMap::new();
                for s in &summaries {
                    let gid_hex = hex::encode(s.group_id);
                    let history = load_history(&gid_hex).unwrap_or_default();
                    if !history.is_empty() {
                        seeded.insert(gid_hex.clone(), history);
                    }
                    // Also stamp the sidebar's last_preview from the
                    // most-recent persisted message.
                    if let Some(entries) = seeded.get(&gid_hex) {
                        if let Some(last) = entries.last() {
                            let preview =
                                last.body.chars().take(80).collect::<String>();
                            conversations.update(|cs| {
                                if let Some(c) = cs.iter_mut().find(|c| c.id == gid_hex) {
                                    c.last_preview = preview;
                                }
                            });
                        }
                    }
                }
                if !seeded.is_empty() {
                    messages.set(seeded);
                }
                // Chunk B: seed contacts directory from localStorage.
                contacts.set(load_contacts());
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
                        // Chunk B: pull the just-saved contact into
                        // the sidebar's contacts directory.
                        contacts.set(load_contacts());
                        let gid_hex = hex::encode(gid);
                        current_view.set(ChatView::Conversation(gid_hex.clone()));
                        add_form_open.set(false);
                        add_form_prefill.set(None);
                        set_status.set(format!("chat: conversation ready ({label})"));
                    }
                    Err(e) => {
                        set_status.set(format!("chat: add_conversation failed: {e}"));
                    }
                }
            });
        }
    };

    // Add-channel handler — called from the ThreadPane's "+
    // channel" button when the viewed convo is a
    // ServerMembership. `channel_name` comes from a prompt() on
    // the UI side. Routes through `ChatState::add_channel_to_server`
    // which enforces admin-only authorization locally.
    let on_add_channel = {
        let state = state.clone();
        move |server_id_hex: String, channel_name: String| {
            let state = state.clone();
            spawn_local(async move {
                let server_id = match parse_gid(&server_id_hex) {
                    Ok(v) => v,
                    Err(e) => {
                        set_status.set(format!("chat: bad server_id ({e})"));
                        return;
                    }
                };
                let trimmed = channel_name.trim().to_string();
                if trimmed.is_empty() {
                    set_status.set("chat: channel name required".to_string());
                    return;
                }
                set_status.set(format!("chat: adding channel '{trimmed}'…"));
                let log = |msg: String| {
                    web_sys::console::log_1(&msg.into());
                };
                match state
                    .add_channel_to_server(server_id, trimmed.clone(), log)
                    .await
                {
                    Ok(channel_gid) => {
                        let channel_hex = hex::encode(channel_gid);
                        // Pull the new channel into the
                        // conversations signal + open the thread.
                        let summaries = state.conversation_summaries();
                        conversations.set(
                            summaries.iter().map(Conversation::from_summary).collect(),
                        );
                        current_view.set(ChatView::Conversation(channel_hex));
                        set_status.set(format!("chat: channel '{trimmed}' ready"));
                    }
                    Err(e) => {
                        set_status.set(format!("chat: add_channel failed: {e}"));
                    }
                }
            });
        }
    };

    // New-server submit handler. Same textarea-of-peers shape as
    // the New Group form, but calls `ChatState::create_server`
    // which publishes a `ServerStateOp::Init` as the first app
    // message in the new group so joiners can classify it as a
    // server-membership group on first decrypt.
    let on_new_server_submit = {
        let state = state.clone();
        let refresh = refresh_conversations.clone();
        move |label: String, peers_text: String| {
            let state = state.clone();
            let refresh = refresh.clone();
            spawn_local(async move {
                let server_name = label.trim().to_string();
                if server_name.is_empty() {
                    set_status.set("chat: server needs a name".to_string());
                    return;
                }
                let mut peers: Vec<[u8; lattice_crypto::credential::USER_ID_LEN]> = Vec::new();
                for (idx, raw_line) in peers_text.lines().enumerate() {
                    let line = raw_line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    match parse_user_id(line) {
                        Ok(v) => peers.push(v),
                        Err(e) => {
                            set_status.set(format!(
                                "chat: bad peer on line {} ({e})",
                                idx + 1
                            ));
                            return;
                        }
                    }
                }
                if peers.is_empty() {
                    set_status.set("chat: paste at least one peer user_id".to_string());
                    return;
                }
                set_status.set(format!(
                    "chat: creating server {server_name:?} with {} peer(s)…",
                    peers.len()
                ));
                let log = |msg: String| {
                    web_sys::console::log_1(&msg.into());
                };
                match state.create_server(server_name.clone(), peers, log).await {
                    Ok(gid) => {
                        refresh();
                        let gid_hex = hex::encode(gid);
                        current_view.set(ChatView::Conversation(gid_hex.clone()));
                        new_server_form_open.set(false);
                        set_status.set(format!("chat: server ready ({server_name})"));
                    }
                    Err(e) => {
                        set_status.set(format!("chat: create_server failed: {e}"));
                    }
                }
            });
        }
    };

    // New-group submit handler. Parses a multi-line textarea of
    // peer user_id hex strings (one per line, blank lines + lines
    // starting with `#` ignored) and creates an N-party group via
    // `ChatState::create_group_conversation`.
    let on_new_group_submit = {
        let state = state.clone();
        let refresh = refresh_conversations.clone();
        move |label: String, peers_text: String| {
            let state = state.clone();
            let refresh = refresh.clone();
            spawn_local(async move {
                let label = label.trim().to_string();
                if label.is_empty() {
                    set_status.set("chat: group needs a name".to_string());
                    return;
                }
                let mut peers: Vec<[u8; lattice_crypto::credential::USER_ID_LEN]> = Vec::new();
                for (idx, raw_line) in peers_text.lines().enumerate() {
                    let line = raw_line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    match parse_user_id(line) {
                        Ok(v) => peers.push(v),
                        Err(e) => {
                            set_status.set(format!(
                                "chat: bad peer on line {} ({e})",
                                idx + 1
                            ));
                            return;
                        }
                    }
                }
                if peers.is_empty() {
                    set_status.set("chat: paste at least one peer user_id".to_string());
                    return;
                }
                set_status.set(format!("chat: creating group with {} peer(s)…", peers.len()));
                let log = |msg: String| {
                    web_sys::console::log_1(&msg.into());
                };
                match state
                    .create_group_conversation(label.clone(), peers, log)
                    .await
                {
                    Ok(gid) => {
                        refresh();
                        let gid_hex = hex::encode(gid);
                        current_view.set(ChatView::Conversation(gid_hex.clone()));
                        new_group_form_open.set(false);
                        set_status.set(format!("chat: group ready ({label})"));
                    }
                    Err(e) => {
                        set_status.set(format!("chat: create_group failed: {e}"));
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
            let entry = ChatMessage {
                author: display.clone(),
                body: body.clone(),
                timestamp_unix: now,
            };
            // Persist this outgoing message to localStorage so it
            // re-renders on the next page reload. Failure is
            // logged but non-fatal — the message still appears
            // optimistically in this session.
            let _ = append_history(&gid_hex, &entry);
            messages.update(|m| {
                m.entry(gid_hex.clone()).or_default().push(entry);
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

    // Chunk B: click handler invoked when the user clicks a contact
    // in the sidebar. If an existing 1:1 conversation matches the
    // contact's hex user_id, focus it. Otherwise open the
    // AddConversation form pre-filled with the contact's hex + label.
    let on_contact_click = {
        move |c: Contact| {
            let convos = conversations.get_untracked();
            if let Some(existing) = convos
                .iter()
                .find(|cv| cv.peer_user_id_hex == c.user_id_hex)
            {
                current_view.set(ChatView::Conversation(existing.id.clone()));
                return;
            }
            add_form_prefill.set(Some((c.user_id_hex.clone(), c.label.clone())));
            new_group_form_open.set(false);
            new_server_form_open.set(false);
            settings_open.set(false);
            add_form_open.set(true);
        }
    };

    view! {
        <div class="chat-shell">
            <ConversationSidebar
                conversations=conversations
                contacts=contacts
                current_view=current_view
                add_form_open=add_form_open
                new_group_form_open=new_group_form_open
                new_server_form_open=new_server_form_open
                settings_open=settings_open
                add_form_prefill=add_form_prefill.read_only()
                on_add=on_add_submit
                on_new_group=on_new_group_submit
                on_new_server=on_new_server_submit
                on_contact_click=on_contact_click
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
                        let on_add_channel_clone = on_add_channel.clone();
                        let current_view_clone = current_view;
                        view! {
                            <ThreadPane
                                conversation_id=id_for_pane
                                conversations=conversations
                                messages=messages
                                display_name=display_name
                                on_send=on_send_clone
                                on_add_channel=on_add_channel_clone
                                current_view=current_view_clone
                            />
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

#[component]
fn ConversationSidebar<F, G, S, K>(
    conversations: RwSignal<Vec<Conversation>>,
    contacts: RwSignal<Vec<Contact>>,
    current_view: RwSignal<ChatView>,
    add_form_open: RwSignal<bool>,
    new_group_form_open: RwSignal<bool>,
    new_server_form_open: RwSignal<bool>,
    settings_open: RwSignal<bool>,
    add_form_prefill: ReadSignal<Option<(String, String)>>,
    on_add: F,
    on_new_group: G,
    on_new_server: S,
    on_contact_click: K,
    my_user_id_hex: ReadSignal<String>,
    bootstrap_complete: ReadSignal<bool>,
) -> impl IntoView
where
    F: Fn(String, String) + Clone + Send + Sync + 'static,
    G: Fn(String, String) + Clone + Send + Sync + 'static,
    S: Fn(String, String) + Clone + Send + Sync + 'static,
    K: Fn(Contact) + Clone + Send + Sync + 'static,
{
    view! {
        <aside class="chat-sidebar" aria-label="conversations">
            <header class="chat-sidebar-header">
                <h2>"Conversations"</h2>
                <div class="chat-sidebar-header-actions">
                    <button
                        class="chat-sidebar-add"
                        on:click=move |_| {
                            new_group_form_open.set(false);
                            add_form_open.update(|b| *b = !*b);
                        }
                        aria-label="add 1:1 conversation"
                        title="Add 1:1 contact"
                        disabled=move || !bootstrap_complete.get()
                    >
                        "+"
                    </button>
                    <button
                        class="chat-sidebar-add chat-sidebar-newgroup"
                        on:click=move |_| {
                            add_form_open.set(false);
                            new_server_form_open.set(false);
                            new_group_form_open.update(|b| *b = !*b);
                        }
                        aria-label="new group"
                        title="New group chat"
                        disabled=move || !bootstrap_complete.get()
                    >
                        "👥"
                    </button>
                    <button
                        class="chat-sidebar-add chat-sidebar-newserver"
                        on:click=move |_| {
                            add_form_open.set(false);
                            new_group_form_open.set(false);
                            settings_open.set(false);
                            new_server_form_open.update(|b| *b = !*b);
                        }
                        aria-label="new server"
                        title="New Discord-style server"
                        disabled=move || !bootstrap_complete.get()
                    >
                        "★"
                    </button>
                    <button
                        class="chat-sidebar-add chat-sidebar-settings"
                        on:click=move |_| {
                            add_form_open.set(false);
                            new_group_form_open.set(false);
                            new_server_form_open.set(false);
                            settings_open.update(|b| *b = !*b);
                        }
                        aria-label="settings"
                        title="Settings"
                    >
                        "⚙"
                    </button>
                </div>
            </header>
            <Show
                when=move || !my_user_id_hex.get().is_empty()
                fallback=|| view! {}
            >
                <MyUserIdBlock my_user_id_hex=my_user_id_hex/>
            </Show>
            <Show
                when=move || add_form_open.get()
                fallback=|| view! {}
            >
                <AddConversationForm
                    on_add=on_add.clone()
                    on_cancel=move || add_form_open.set(false)
                    prefill=add_form_prefill.get().unwrap_or_default()
                />
            </Show>
            <Show
                when=move || new_group_form_open.get()
                fallback=|| view! {}
            >
                <NewGroupForm
                    on_submit=on_new_group.clone()
                    on_cancel=move || new_group_form_open.set(false)
                />
            </Show>
            <Show
                when=move || new_server_form_open.get()
                fallback=|| view! {}
            >
                <NewServerForm
                    on_submit=on_new_server.clone()
                    on_cancel=move || new_server_form_open.set(false)
                />
            </Show>
            <Show
                when=move || settings_open.get()
                fallback=|| view! {}
            >
                <SettingsForm on_close=move || settings_open.set(false)/>
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
                            let kind_prefix = match &c.kind {
                                ConvoKind::ServerMembership { .. } => "★ ",
                                ConvoKind::ServerChannel { .. } => "# ",
                                ConvoKind::NamedGroup => "# ",
                                ConvoKind::OneOnOne => "",
                            };
                            let display_name = format!("{kind_prefix}{}", c.name);
                            // Chunk F: avatar circle derived from
                            // blake3 of the conversation id so it's
                            // stable, with initials from the label.
                            let color = avatar_color(&c.id);
                            let initials = avatar_initials(&c.name);
                            view! {
                                <li
                                    class=move || if active { "chat-conversation-item active" } else { "chat-conversation-item" }
                                >
                                    <button
                                        class="chat-conversation-button"
                                        on:click=move |_| current_view.set(ChatView::Conversation(id_for_click.clone()))
                                    >
                                        <span
                                            class="chat-avatar"
                                            style=format!("background: {color};")
                                            aria-hidden="true"
                                        >
                                            {initials}
                                        </span>
                                        <span class="chat-conversation-name">{display_name}</span>
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
            <ContactsList contacts=contacts on_click=on_contact_click/>
        </aside>
    }
}

/// Chunk B: contacts directory rendered below the conversation list
/// in the sidebar. Click a contact to either open the existing 1:1
/// DM (if one exists) or open the AddConversation form prefilled
/// with their user_id + label.
#[component]
fn ContactsList<K>(
    contacts: RwSignal<Vec<Contact>>,
    on_click: K,
) -> impl IntoView
where
    K: Fn(Contact) + Clone + Send + Sync + 'static,
{
    view! {
        <section class="chat-sidebar-contacts" aria-label="contacts">
            <header class="chat-sidebar-contacts-header">
                <h3>"Contacts"</h3>
            </header>
            {move || {
                let list = contacts.get();
                if list.is_empty() {
                    view! {
                        <p class="chat-sidebar-contacts-empty muted">
                            "Contacts you DM appear here."
                        </p>
                    }.into_any()
                } else {
                    let on_click = on_click.clone();
                    view! {
                        <ul class="chat-contacts-list">
                            {list.into_iter().map(|c| {
                                let on_click = on_click.clone();
                                let c_for_click = c.clone();
                                let avatar_seed = c.user_id_hex.clone();
                                let color = avatar_color(&avatar_seed);
                                let initials = avatar_initials(&c.label);
                                let short = short_user_id(&c.user_id_hex);
                                view! {
                                    <li class="chat-contact-item">
                                        <button
                                            class="chat-contact-button"
                                            on:click=move |_| on_click(c_for_click.clone())
                                            title=c.user_id_hex.clone()
                                        >
                                            <span
                                                class="chat-avatar"
                                                style=format!("background: {color};")
                                                aria-hidden="true"
                                            >
                                                {initials}
                                            </span>
                                            <span class="chat-contact-name">{c.label.clone()}</span>
                                            <span class="chat-contact-id muted">{short}</span>
                                        </button>
                                    </li>
                                }
                            }).collect_view()}
                        </ul>
                    }.into_any()
                }
            }}
        </section>
    }
}

/// Sidebar block that displays the local user_id. Defaults to a
/// truncated 12-char prefix; clicking "show" expands the full
/// 64-char hex. A dedicated "copy" button writes the full hex to
/// the system clipboard so the user can paste it to a contact.
#[component]
fn MyUserIdBlock(my_user_id_hex: ReadSignal<String>) -> impl IntoView {
    let expanded = RwSignal::new(false);
    let copied = RwSignal::new(false);
    let copy_handler = move |_| {
        let hex = my_user_id_hex.get();
        let nav = web_sys::window().and_then(|w| Some(w.navigator()));
        if let Some(navigator) = nav {
            let clipboard = navigator.clipboard();
            let _ = clipboard.write_text(&hex);
            copied.set(true);
            // Clear the "copied!" flash after ~2 seconds.
            let copied_for_reset = copied;
            spawn_local(async move {
                sleep(Duration::from_millis(2000)).await;
                copied_for_reset.set(false);
            });
        }
    };
    view! {
        <div class="chat-sidebar-userid" aria-label="my user id">
            <div class="chat-sidebar-userid-row">
                <span class="muted chat-sidebar-userid-label">"your id:"</span>
                <button
                    type="button"
                    class="chat-sidebar-userid-toggle"
                    aria-label="expand user id"
                    on:click=move |_| expanded.update(|b| *b = !*b)
                >
                    {move || if expanded.get() { "▾" } else { "▸" }}
                </button>
                <button
                    type="button"
                    class="chat-sidebar-userid-copy"
                    aria-label="copy user id"
                    on:click=copy_handler
                    title="copy full user_id"
                >
                    {move || if copied.get() { "copied!" } else { "copy" }}
                </button>
            </div>
            {move || if expanded.get() {
                view! {
                    <code class="chat-sidebar-userid-full">
                        {my_user_id_hex.get()}
                    </code>
                }.into_any()
            } else {
                view! {
                    <code class="chat-sidebar-userid-short muted">
                        {short_user_id(&my_user_id_hex.get())}
                    </code>
                }.into_any()
            }}
        </div>
    }
}

#[component]
fn AddConversationForm<F, C>(
    on_add: F,
    on_cancel: C,
    /// `(peer_hex, label)` seed — populated when the user clicked a
    /// contact whose DM doesn't exist yet (chunk B). Empty tuple
    /// means start with blank fields.
    prefill: (String, String),
) -> impl IntoView
where
    F: Fn(String, String) + Clone + Send + Sync + 'static,
    C: Fn() + Send + Sync + 'static + Copy,
{
    let peer_input: NodeRef<leptos::html::Input> = NodeRef::new();
    let label_input: NodeRef<leptos::html::Input> = NodeRef::new();
    let (initial_peer, initial_label) = prefill;
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
                value=initial_peer
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
                value=initial_label
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
fn NewGroupForm<F, C>(on_submit: F, on_cancel: C) -> impl IntoView
where
    F: Fn(String, String) + Clone + Send + Sync + 'static,
    C: Fn() + Send + Sync + 'static + Copy,
{
    let label_input: NodeRef<leptos::html::Input> = NodeRef::new();
    let peers_input: NodeRef<leptos::html::Textarea> = NodeRef::new();
    let on_submit_for_submit = on_submit.clone();
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let label = label_input
            .get()
            .map(|n| n.unchecked_into::<HtmlInputElement>().value())
            .unwrap_or_default();
        let peers = peers_input
            .get()
            .map(|n| n.unchecked_into::<web_sys::HtmlTextAreaElement>().value())
            .unwrap_or_default();
        on_submit_for_submit(label, peers);
    };
    view! {
        <form class="chat-add-form chat-add-form-group" on:submit=submit>
            <label for="chat-newgroup-label" class="chat-add-label">
                "Group name"
            </label>
            <input
                node_ref=label_input
                id="chat-newgroup-label"
                class="chat-add-input"
                type="text"
                placeholder="design team"
                autocomplete="off"
            />
            <label for="chat-newgroup-peers" class="chat-add-label">
                "Peer user_ids (one hex per line)"
            </label>
            <textarea
                node_ref=peers_input
                id="chat-newgroup-peers"
                class="chat-add-input chat-add-input-peers"
                placeholder="0123abcd…\n4567efgh…"
                rows="4"
                autocomplete="off"
            ></textarea>
            <div class="chat-add-actions">
                <button class="button chat-add-submit" type="submit">
                    "Create group"
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
fn NewServerForm<F, C>(on_submit: F, on_cancel: C) -> impl IntoView
where
    F: Fn(String, String) + Clone + Send + Sync + 'static,
    C: Fn() + Send + Sync + 'static + Copy,
{
    let label_input: NodeRef<leptos::html::Input> = NodeRef::new();
    let peers_input: NodeRef<leptos::html::Textarea> = NodeRef::new();
    let on_submit_for_submit = on_submit.clone();
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let label = label_input
            .get()
            .map(|n| n.unchecked_into::<HtmlInputElement>().value())
            .unwrap_or_default();
        let peers = peers_input
            .get()
            .map(|n| n.unchecked_into::<web_sys::HtmlTextAreaElement>().value())
            .unwrap_or_default();
        on_submit_for_submit(label, peers);
    };
    view! {
        <form class="chat-add-form chat-add-form-group" on:submit=submit>
            <label for="chat-newserver-label" class="chat-add-label">
                "Server name (★ Discord-style)"
            </label>
            <input
                node_ref=label_input
                id="chat-newserver-label"
                class="chat-add-input"
                type="text"
                placeholder="Friends"
                autocomplete="off"
            />
            <label for="chat-newserver-peers" class="chat-add-label">
                "Initial members (one hex per line)"
            </label>
            <textarea
                node_ref=peers_input
                id="chat-newserver-peers"
                class="chat-add-input chat-add-input-peers"
                placeholder="0123abcd…\n4567efgh…"
                rows="4"
                autocomplete="off"
            ></textarea>
            <div class="chat-add-actions">
                <button class="button chat-add-submit" type="submit">
                    "Create server"
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

/// Settings panel — chunk E. Currently exposes the home-server
/// URL. Persisted to `lattice/server_url/v1`; a reload is
/// required for the polling task to pick up the new URL
/// (signaled by a notice under the input).
#[component]
fn SettingsForm<C>(on_close: C) -> impl IntoView
where
    C: Fn() + Send + Sync + 'static + Copy,
{
    let url_input: NodeRef<leptos::html::Input> = NodeRef::new();
    let saved_msg = RwSignal::new(String::new());
    let current = load_server_url(crate::app::DEFAULT_SERVER_URL);
    let initial = current.clone();
    let submit = move |ev: SubmitEvent| {
        ev.prevent_default();
        let val = url_input
            .get()
            .map(|n| n.unchecked_into::<HtmlInputElement>().value())
            .unwrap_or_default();
        let trimmed = val.trim().to_string();
        if trimmed.is_empty() {
            saved_msg.set("URL cannot be empty.".to_string());
            return;
        }
        match save_server_url(&trimmed) {
            Ok(()) => {
                saved_msg.set("Saved — reload the page to apply.".to_string());
            }
            Err(e) => {
                saved_msg.set(format!("Save failed: {e}"));
            }
        }
    };
    view! {
        <form class="chat-add-form" on:submit=submit>
            <label for="chat-settings-server" class="chat-add-label">
                "Home server URL"
            </label>
            <input
                node_ref=url_input
                id="chat-settings-server"
                class="chat-add-input"
                type="text"
                value=initial
                placeholder="http://127.0.0.1:8080"
                autocomplete="off"
            />
            <p class="chat-settings-hint muted">
                "Where this client publishes + fetches MLS state. \
                 Default is the local dev server. A reload is required \
                 to pick up changes — the polling loop captures the URL \
                 at construction time."
            </p>
            <Show
                when=move || !saved_msg.get().is_empty()
                fallback=|| view! {}
            >
                <p class="chat-settings-saved">{move || saved_msg.get()}</p>
            </Show>
            <div class="chat-add-actions">
                <button class="button chat-add-submit" type="submit">
                    "Save"
                </button>
                <button
                    class="button chat-add-cancel"
                    type="button"
                    on:click=move |_| on_close()
                >
                    "Close"
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
fn ThreadPane<F, C>(
    conversation_id: String,
    conversations: RwSignal<Vec<Conversation>>,
    messages: RwSignal<HashMap<String, Vec<ChatMessage>>>,
    display_name: Signal<String>,
    on_send: F,
    on_add_channel: C,
    current_view: RwSignal<ChatView>,
) -> impl IntoView
where
    F: Fn(String, String) + Clone + Send + Sync + 'static,
    C: Fn(String, String) + Clone + Send + Sync + 'static,
{
    let id_for_header = conversation_id.clone();
    let title = Signal::derive(move || {
        conversations
            .get()
            .iter()
            .find(|c| c.id == id_for_header)
            .map_or_else(|| "Conversation".to_string(), |c| c.name.clone())
    });

    // Resolve the current convo's kind so the header can render
    // server-specific affordances (+ channel button, channel
    // list) when we're viewing a server-membership group.
    let id_for_kind = conversation_id.clone();
    let convo_kind = Signal::derive(move || {
        conversations
            .get()
            .iter()
            .find(|c| c.id == id_for_kind)
            .map(|c| c.kind.clone())
    });

    let server_id_for_add = conversation_id.clone();
    let on_add_channel_for_btn = on_add_channel.clone();
    let add_channel_click = move |_| {
        let server_id = server_id_for_add.clone();
        let prompt_result = web_sys::window()
            .and_then(|w| w.prompt_with_message("Channel name (e.g. design)").ok())
            .flatten();
        if let Some(name) = prompt_result {
            on_add_channel_for_btn(server_id, name);
        }
    };

    let id_for_channels = conversation_id.clone();
    let channels_view = Signal::derive(move || {
        conversations.get().iter().find(|c| c.id == id_for_channels).and_then(|c| {
            if let ConvoKind::ServerMembership { channels, .. } = &c.kind {
                Some(channels.clone())
            } else {
                None
            }
        })
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
                <Show
                    when=move || matches!(convo_kind.get(), Some(ConvoKind::ServerMembership { .. }))
                    fallback=|| view! {}
                >
                    <button
                        class="chat-thread-add-channel"
                        on:click=add_channel_click.clone()
                        title="Add channel to this server"
                    >
                        "+ channel"
                    </button>
                </Show>
            </header>
            <Show
                when=move || channels_view.get().map_or(false, |c| !c.is_empty())
                fallback=|| view! {}
            >
                <nav class="chat-thread-channels" aria-label="server channels">
                    {move || {
                        let channels = channels_view.get().unwrap_or_default();
                        channels.into_iter().map(|ch| {
                            let gid_hex = ch.channel_group_id_hex.clone();
                            view! {
                                <button
                                    class="chat-thread-channel-pill"
                                    on:click=move |_| current_view.set(ChatView::Conversation(gid_hex.clone()))
                                    title=ch.channel_group_id_hex.clone()
                                >
                                    "# " {ch.name.clone()}
                                </button>
                            }.into_any()
                        }).collect_view().into_any()
                    }}
                </nav>
            </Show>
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
            let entry = ChatMessage {
                author: m.sender_label,
                body: m.body,
                timestamp_unix: now_unix(),
            };
            let _ = append_history(&gid_hex, &entry);
            map.entry(gid_hex).or_default().push(entry);
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

/// Derive an avatar color from a blake3 hash of the seed string
/// (typically a user_id hex or a label). Returns an HSL color
/// string. Stable across reloads — no UI flicker.
///
/// Chunk F.
pub fn avatar_color(seed: &str) -> String {
    let bytes = blake3::hash(seed.as_bytes());
    let h = u16::from_le_bytes([bytes.as_bytes()[0], bytes.as_bytes()[1]]) % 360;
    // Saturation + lightness fixed in the Lattice dark-mode
    // palette band so every color is legible against the ink-900
    // sidebar / thread surface.
    format!("hsl({h}, 55%, 55%)")
}

/// Two-letter initials for an avatar. Strips ASCII prefixes
/// (★ / # / "me (") and takes the first two graphemes that have
/// a letter or digit.
pub fn avatar_initials(label: &str) -> String {
    let cleaned: String = label
        .trim_start_matches('★')
        .trim_start_matches('#')
        .trim_start_matches("me (")
        .trim_start_matches(|c: char| c.is_whitespace() || !c.is_alphanumeric())
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(2)
        .collect();
    if cleaned.is_empty() {
        "??".to_string()
    } else {
        cleaned.to_uppercase()
    }
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

// ────────────────────────────────────────────────────────────────
// Scrollback / plaintext history persistence
// ────────────────────────────────────────────────────────────────
//
// MLS's per-epoch generation counter rejects re-decrypting a
// previously-seen ciphertext, so we can't replay scrollback by
// re-fetching + re-decrypting on reload. Instead we persist the
// **plaintext** of each sent / received message under
// `lattice/messages/{gid_b64url_pct_no_pad}/v1` as a JSON array.
//
// **Threat-model note.** Plaintext-on-disk is the same posture
// every chat app (Signal, Telegram, etc.) takes — at-rest
// encryption comes from full-disk encryption on the device.
// When v2/v3 identity-blob unlock UI lands in chunk B, we should
// wrap scrollback under the same KEK; for now, scrollback is
// only used when the identity blob is v1 plaintext.

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedMessage {
    author: String,
    body: String,
    ts: u64,
}

fn history_key(gid_hex: &str) -> String {
    format!("lattice/messages/{gid_hex}/v1")
}

fn append_history(gid_hex: &str, msg: &ChatMessage) -> Result<(), String> {
    let mut entries = load_history(gid_hex).unwrap_or_default();
    entries.push(msg.clone());
    save_history(gid_hex, &entries)
}

fn load_history(gid_hex: &str) -> Result<Vec<ChatMessage>, String> {
    let storage = match web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        Some(s) => s,
        None => return Err("localStorage unavailable".to_string()),
    };
    let Some(json) = storage
        .get_item(&history_key(gid_hex))
        .map_err(|e| format!("get history: {e:?}"))?
    else {
        return Ok(Vec::new());
    };
    let raw: Vec<PersistedMessage> =
        serde_json::from_str(&json).map_err(|e| format!("decode history: {e}"))?;
    Ok(raw
        .into_iter()
        .map(|p| ChatMessage {
            author: p.author,
            body: p.body,
            timestamp_unix: p.ts,
        })
        .collect())
}

fn save_history(gid_hex: &str, entries: &[ChatMessage]) -> Result<(), String> {
    let storage = match web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        Some(s) => s,
        None => return Err("localStorage unavailable".to_string()),
    };
    let raw: Vec<PersistedMessage> = entries
        .iter()
        .map(|m| PersistedMessage {
            author: m.author.clone(),
            body: m.body.clone(),
            ts: m.timestamp_unix,
        })
        .collect();
    let json = serde_json::to_string(&raw).map_err(|e| format!("encode history: {e}"))?;
    storage
        .set_item(&history_key(gid_hex), &json)
        .map_err(|e| format!("set history: {e:?}"))
}

// Silence unused-import warning on `Rc<RefCell>` — they're imported
// by sibling modules pre-chunk-C; pinning the path keeps that surface.
#[allow(dead_code)]
fn _force_imports(_: Rc<RefCell<()>>) {}
