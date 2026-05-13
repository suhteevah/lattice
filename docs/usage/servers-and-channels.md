# Servers and channels

A **server** in Lattice is the Discord analogue: a long-lived
collection of people you talk to, with one or more topic-scoped
channels inside it. Under the hood a server is just an MLS group
with a particular shape of application message; channels are
separate MLS groups federated by the server-membership group.

This page describes the model, what is shipped today, and what
is tracked for chunk 2.5 (multi-channel + admin enforcement). It
cross-references DECISIONS §D-24 (moderation model — per-server,
no global) throughout.

If you are new to Lattice, read [messaging.md](messaging.md) first
— it covers how a message gets from one client to another, which is
the underlying machinery for everything below.

---

## What's a server

In Lattice terminology, a **server-membership group** is:

- An MLS group like any other (same crypto, same wire format).
- Carries a `ServerStateOp::Init` as its very first application
  message.
- Renders with a `★` prefix in the sidebar and the server name
  as label.

The classification is purely client-side. There is no server-side
flag for "this group is a server-membership group" — the inviter's
client sends an `Init` op, and joiners' clients upgrade their local
classification when they decrypt it.

This means a server is, mechanically, a group chat with metadata.
The metadata model is the `ServerStateOp` state machine described
below.

---

## Server state machine

The `ServerStateOp` enum lives in `crates/lattice-protocol/src/
server_state.rs`. Variants:

| Variant | Carried payload | Use |
|---|---|---|
| `Init` | `{server_name, admins, channels}` | First message in a server-membership group. Establishes the server's name and initial admin roster. |
| `AddChannel` | `{channel_group_id, name}` | Announce a new channel. The channel's MLS group is created in a separate flow; this op only records its existence so clients can show it in the channel list. |
| `RemoveChannel` | `{channel_group_id}` | Mark a channel hidden. The underlying MLS group is not destroyed. |
| `RenameServer` | `{name}` | Update the server's display name. |
| `PromoteAdmin` | `{user_id}` | Add a user to the admin roster. |
| `DemoteAdmin` | `{user_id}` | Remove a user from the admin roster. |

Wire encoding is JSON via `serde_json` with `#[serde(tag = "op",
content = "data", rename_all = "snake_case")]`. The body of an MLS
application message is `Vec<u8>`; clients put the JSON-encoded
`ServerStateOp` bytes there directly. A regular chat message is
just UTF-8 plaintext that fails JSON-decode as a `ServerStateOp` —
the receiver falls through to plaintext rendering when classification
returns `None`.

Example `Init` payload encoded as the application-message body:

```json
{
  "op": "init",
  "data": {
    "server_name": "Friends",
    "admins": ["aa61...", "bb47..."],
    "channels": []
  }
}
```

### Why JSON

Server-state ops are infrequent — they fire on server lifecycle
events, not per-message. JSON keeps the encoding human-debuggable
in transit and avoids growing the capnp schema for what is still a
first-cut design. Future hardening can swap to Cap'n Proto once the
op set stabilises.

---

## Creating a server

In the chat shell, click the **★** button next to the sidebar header
(distinct from `+` for 1:1 and 👥 for N-party). The "New server" form
takes:

- A **server name** (will be the sidebar label and the `Init`
  payload's `server_name`).
- A comma-separated list of **initial member** user_id hex strings.

Submit and the client:

1. Generates a random 16-byte gid for the server-membership group.
2. Fetches each member's KeyPackage via `GET /key_packages/<uid>`.
3. Calls `create_group_with_storage(gid)` then `add_members` to
   produce a commit + per-joiner Welcomes.
4. Persists the `ConvoRecord` immediately with
   `ConvoKind::ServerMembership { server_name, admins: [creator],
   channels: [] }`.
5. POSTs commit + welcomes to `/group/<gid>/commit`.
6. Encrypts and POSTs the `Init` op as the **first application
   message** to `/group/<gid>/messages`.

Status line: `chat: server ready (Friends)`.

The creator's sidebar shows the server immediately (they know the
name locally). Joiners' clients discover it on the next bootstrap
via `GET /welcomes/pending/<uid>`; they classify as
`ConvoKind::NamedGroup` with a `group <prefix>` placeholder until the
next poll decrypts the `Init` and upgrades the classification to
`ConvoKind::ServerMembership { server_name }`.

End-to-end smoke transcript from HANDOFF §22, for reference:

```
Alice + Bob bootstrap fresh identities (separate origins).
Bob clicks ★ button, names "Friends", pastes Alice's hex.
Bob's sidebar:  ["★ Friends"]
Alice reloads → bootstrap discovers Bob's welcome → auto-joins.
Alice's sidebar (immediately):  ["# group b71f3220"]   (initial, pre-Init-decrypt)
Alice's sidebar (after 5s poll): ["★ Friends"]          (post-classify)
Alice sends "hi from Alice in ★ Friends server" → publishes.
Bob reloads + opens conversation → scrollback loads from localStorage:
  thread shows: [{author: "Friends", body: "hi from Alice in ★ Friends server"}]
```

---

## Channels (chunk 2 first cut)

The current chunk 2 first cut ships **one implicit channel per
server**. The server-membership group itself doubles as the chat
group. `AddChannel` ops decode but do not spin up separate MLS
groups. The full multi-channel architecture lives in chunk 2.5.

What that means today:

- Every message in a server lands in one shared thread.
- `Init`'s `channels` field is empty by convention; the server
  itself is the implicit `#general`.
- The chat UI doesn't render a channel list (yet).

Chunk 2.5 — multi-channel + admin enforcement — is the next-up work
in ROADMAP. The plan:

### Chunk 2.5 — per-channel MLS groups

Each channel becomes a **separate MLS group** with its own
group_id, own membership roster, own epoch counter. The
server-membership group remains as the "who is in this server at
all" root; channels are sub-groups whose membership is a subset of
the server membership.

Wire-level, this looks like:

1. Server admin (TBD per chunk 2.5 admin enforcement) sends
   `ServerStateOp::AddChannel { channel_group_id, name: "design"
   }` to the server-membership group.
2. All clients receive the op and add the channel to their local
   view of the server.
3. Admin creates the channel's MLS group separately:
   `create_group_with_storage(channel_group_id)` + `add_members`
   for the channel roster.
4. Clients join the channel's MLS group via the standard Welcome
   flow.

A late joiner sees `AddChannel` ops issued **after** their join
epoch only. Mitigation: the inviter sends a `SyncState` op (or
re-embeds the current channel list in the join-time application
message) immediately after admit. The exact mechanism is open per
HANDOFF §22 open questions.

### Per-channel private membership

Channels can have a strict subset of the server's roster. A user is
"in the server" without necessarily being "in #design." The UI must
track this — the future channel list will distinguish channels the
user has joined from channels they have not. The MLS-native
mechanism is straightforward (it is the same as N-party groups);
the UX wrinkle is communicating "you can see this channel exists but
you are not a member" without leaking unintended information.

### Late-joiner state sync

A late joiner only sees ops issued **after** their join epoch. The
two open mitigations:

- **Inviter snapshot.** The inviter sends a `SyncState` application
  message right after admit, carrying the current channel list, the
  current admin roster, and any pending state. The joiner replays
  the snapshot into their local view.
- **Re-embed in join.** The inviter embeds the current state in a
  dedicated extension on the MLS Welcome itself. Heavier protocol
  surface, but the joiner sees the state before they receive any
  application messages.

HANDOFF §22 leans toward the snapshot approach. Chunk 2.5 will pick
one when the work lands.

---

## Admin model

DECISIONS §D-24 locks the moderation model: per-server admin tools
in V1, no global moderation, no cross-server reputation. Each home
server's operator handles their own house.

### What admins can do (chunk 2 first cut)

Today, **everyone** is implicitly admin — MLS is flat, every member
can commit, every member can send any `ServerStateOp`. `PromoteAdmin`
and `DemoteAdmin` ops decode and persist locally but are not yet
enforced. This is the gap chunk 2.5 closes.

### What admins will be able to do (chunk 2.5)

- Send `AddChannel`, `RemoveChannel`, `RenameServer`, `PromoteAdmin`,
  `DemoteAdmin`. Non-admins' ops of these types will be rejected by
  receivers (client-side enforcement; see below).
- Remove members from the server-membership group via the MLS
  `Remove` proposal. The removed user's per-epoch keys stop working
  on next decrypt.
- Update the channel list and the admin roster.

Per-server admin UI for the home-server **operator** (not in-app
admins) is M5's work and lives at
[`crates/lattice-server/src/admin/`](../../crates/lattice-server)
when implemented. Operator powers include:

- Ban list (per home server: user_ids barred from registration).
- Message removal within own server's storage. Cannot recall
  ciphertext from peer servers (peers retain copies; this is a
  property of federation, not a bug).
- Group takedown for groups owned by this server (revokes all
  per-epoch certs from D-05; group can't issue new commits via
  this server).
- Federation peer blocklist (refuse to federate with named hosts).

### Client-side enforcement: "flat MLS + signed policy"

The recommended approach (HANDOFF §22 open questions): keep MLS flat
(every member technically able to commit) but each peer's local
client enforces an admin policy derived from the replay of
`PromoteAdmin` / `DemoteAdmin` ops. A non-admin's `AddChannel` op is
ignored locally; the admin roster is the union-of-promotes minus
the set-of-demotes for that user over the lifetime of the server.

The trade-off accepted: a malicious non-admin can still **emit** an
`AddChannel` op (MLS does not stop them), but every honest peer's
client will silently discard it. A non-honest peer who chooses to
honour it is non-conformant, not a protocol vulnerability.

The harder tamper-resistance upgrade is **MLS external senders** —
a roster-side restriction that mls-rs supports via the
`ExternalSendersExtension`. Two authorization models sketched in
HANDOFF §22; chunk 2.5 starts with client-side policy and upgrades
if tamper concerns surface.

---

## Federation across servers

A server-membership group can have members on different home
servers, just like any other MLS group. The federation mechanics
are identical to N-party groups:

- The inviter's home server stores the commit + welcomes.
- For each joiner not hosted by the inviter's home server, the
  inviter's home server POSTs to the joiner's home server's
  `/federation/inbox`.
- The joiner's home server pins the inviter server's federation
  pubkey on first contact (TOFU per DECISIONS §D-06 / §D-13).
- Subsequent messages are pushed similarly via
  `/federation/message_inbox`.

See [federation.md](federation.md) for the full federation flow,
including the cross-VPS smoke transcript from M3.

---

## Smoke test summary (chunk 2 first cut)

For the curious, the wire-level transcript of creating a server
between Alice (`localhost:5173` against `127.0.0.1:8080`) and Bob
(`127.0.0.1:5173` against the same server):

| Step | Wire call | Body shape |
|---|---|---|
| Bob bootstraps | `POST /register` | `{user_id_b64, claim_b64}` |
| Bob publishes KP | `POST /key_packages` | `{user_id_b64, key_package_b64}` |
| Alice bootstraps | `POST /register` + `POST /key_packages` | (same shape) |
| Bob creates server | `GET /key_packages/<alice_uid_b64>` | → `{key_package_b64, published_at}` |
| Bob's client locally | `create_group_with_storage` + `add_members` | (no wire call) |
| Bob commit fan-out | `POST /group/<gid_b64>/commit` | `{epoch, commit_b64, welcomes: [{joiner_user_id_b64, mls_welcome_b64, pq_payload_b64}]}` |
| Bob sends Init | `POST /group/<gid_b64>/messages` | `{envelope_b64}` (sealed envelope wrapping the JSON-encoded Init) |
| Alice reload | `GET /welcomes/pending/<alice_uid_b64>` | → `{welcomes: [{group_id_b64url, epoch, mls_welcome_b64, pq_payload_b64}]}` |
| Alice joins | `process_welcome_with_storage` locally | (no wire call) |
| Alice polls | `GET /group/<gid_b64>/messages?since=0` | → `{latest_seq, messages: [...]}` — decrypts Init |
| Alice's client | classifies as `ServerMembership { server_name }` | (purely local) |

Full route reference at [api-reference.md](api-reference.md).

---

## Cross-references

- DECISIONS §D-24 — moderation model. Per-server admin tools only;
  no global moderation; cross-server abuse mitigation depends on
  each peer admin's response plus the client-side distrust score
  (D-13).
- HANDOFF §22 — "Track 4 chunk 2 first cut — server-membership
  groups." The shipped surface and the open questions for chunk
  2.5.
- HANDOFF §21 — "Track 4 chunk 1 — N-party group chat." The
  underlying multi-Welcome plumbing.
- [security-model.md](security-model.md#hidden-membership) — the
  M6 hidden-membership extension applies to servers and channels
  the same way it applies to any MLS group.
