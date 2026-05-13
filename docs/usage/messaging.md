# Messaging

This page describes how Lattice's three conversation shapes — 1:1 DMs,
N-party groups, and Discord-style servers — actually work end to end.
The intent is that after reading this, the UI surface makes sense
mechanically, the wire bytes are no longer a black box, and you know
which features are shipped today versus tracked for later.

For the cryptographic primitives behind each step see
[security-model.md](security-model.md). For the network calls each
client makes see [api-reference.md](api-reference.md).

---

## Three conversation shapes

The Lattice chat UI distinguishes three flavours of conversation. All
three are MLS groups underneath; the difference is in the metadata
and the UI affordances.

| Shape | Sidebar prefix | group_id derivation | Discovery |
|---|---|---|---|
| 1:1 DM | `#` (rendered with peer name) | Deterministic: `blake3("lattice/dm/v1/" || sorted(uid_a, uid_b))[..16]` | Either side `add_conversation`; the second finds a pending Welcome |
| N-party group | `#` (rendered with group label) | Random 16 bytes | Inviter posts a multi-Welcome; joiners auto-discover via `GET /welcomes/pending/<uid>` |
| Server-membership group | `★ <server name>` | Random 16 bytes | Same as N-party; classification by `ServerStateOp::Init` decode on first message |

The shape is decided by the inviter at creation time. The receiving
client classifies on its own — if it decodes the first application
message as a `ServerStateOp::Init`, the conversation upgrades from
"N-party group with placeholder label" to "★ server with the
init-supplied name."

The full state machine for servers (`ServerStateOp::Init`,
`AddChannel`, `RemoveChannel`, `RenameServer`, `PromoteAdmin`,
`DemoteAdmin`) is documented at
[servers-and-channels.md](servers-and-channels.md).

---

## 1:1 DMs

### How a 1:1 DM is created

Both sides of a 1:1 DM derive the same group_id from the sorted pair
of user_ids. There is no canonical "owner" of a DM; whichever side
issues the **add conversation** action first creates the group and
posts the Welcome, and the other side discovers it.

The full sequence when Bob clicks `+` and pastes Alice's user_id:

1. Bob's client computes
   `gid = blake3("lattice/dm/v1/" || sorted(alice_uid, bob_uid))[..16]`.
2. Bob's client calls `GET /group/<gid>/welcome/<bob_uid>`. If a
   Welcome already exists, Bob is the **joiner** — he calls
   `process_welcome_with_storage`, persists the group state, and the
   conversation appears in his sidebar.
3. If no Welcome exists, Bob is the **inviter**. His client:
   - GETs `/key_packages/<alice_uid>` and decodes the response.
   - Calls `create_group_with_storage` to spin up the MLS group with
     `gid` as its group_id.
   - Calls `add_member` against Alice's KP, producing a commit + a
     Welcome + a `PqWelcomePayload` (ML-KEM-768 ciphertext for the
     joiner).
   - Calls `apply_commit` locally so Bob is at the new epoch.
   - POSTs `commit + welcomes` to `/group/<gid>/commit`.
   - Persists the `ConvoRecord` to
     `localStorage["lattice/conversations/v1"]`.

Status line after success: `chat: conversation ready (Alice)`.

On Alice's side, the conversation surfaces in two ways:

- **Reload-time discovery.** The bootstrap calls
  `GET /welcomes/pending/<alice_uid>`, finds the Welcome, joins.
- **Manual add.** Alice clicks `+`, pastes Bob's user_id, hits Add.
  Because both sides derive the same gid, her client tries
  `GET /group/<gid>/welcome/<alice_uid>` first; the Welcome is there
  and she joins.

Either path lands Alice at the same MLS epoch as Bob.

### Sending in a 1:1 DM

When Alice types `hi bob — first lattice message` and presses Enter:

1. The client calls `ChatState::send_message(gid, "hi bob — ...")`.
2. The message is JSON-not-decoded first to make sure it doesn't
   collide with a `ServerStateOp` (it won't — plain text isn't valid
   JSON for that enum).
3. The plaintext is fed to `encrypt_application` on the group,
   producing a ~3.6 KB MLS ciphertext.
4. The ciphertext is wrapped in a `SealedEnvelope` signed by Alice's
   per-epoch ephemeral Ed25519 key. The membership cert (D-05) was
   issued by the home server during the commit-acceptance flow.
5. The envelope is base64-encoded and POSTed to
   `/group/<gid>/messages`. The server returns a monotonic
   `seq`.
6. The message is **optimistically appended** to Alice's local thread
   immediately so the UI feels instant. It is also persisted to
   `localStorage["lattice/messages/<gid>/v1"]` before the HTTP call
   so a mid-send page reload does not lose it.

Bob's side:

1. The 5-second polling loop fires
   `GET /group/<gid>/messages?since=<last_seq>`.
2. For each returned envelope:
   - Verify the sealed-sender outer signature against the cert.
   - MLS-decrypt with `decrypt_with_sender` to get the plaintext +
     the sender's leaf index.
   - Try `ServerStateOp::try_decode(plaintext)` first; on miss,
     treat as a plain UTF-8 message.
   - Append to the in-memory thread signal and to
     `localStorage["lattice/messages/<gid>/v1"]`.
3. The UI re-renders with the new message.

WebSocket push (`/group/<gid>/messages/ws`) replaces the 5-second
poll for instant delivery; it is shipped server-side and used by the
"Live WS push (γ.4 fallback)" demo button. The chat shell still
polls by default — wiring the WS path into the shell is chunk D of
the chat-app work.

### Scrollback persistence

Pre-reload thread history renders on reload via plaintexts persisted
to `localStorage["lattice/messages/<gid>/v1"]`. The rationale for
persisting plaintexts rather than re-decrypting:

MLS application messages carry a per-epoch generation counter.
mls-rs's `Group::decrypt` rejects any ciphertext whose generation is
`≤ highest seen`. So we cannot replay scrollback by re-fetching the
server's `since=0` view and re-decrypting — the in-memory MLS state
restored from `LocalStorageGroupStateStorage` already knows it has
processed generations 0..N, and feeding the same ciphertexts back
errors out.

Pragmatic alternative: persist the **plaintexts** at decrypt time.
At-rest plaintext protection becomes the operating system's
full-disk encryption rather than the app's MLS layer, which is the
posture Signal and Telegram take. When chunk B's encrypted-unlock UI
lands, scrollback should wrap under the same Argon2id / PRF KEK as
the v2 / v3 identity blob.

Reload smoke transcript from HANDOFF §20, for reference:

```
fresh state — localStorage clear, server snapshot deleted
both tabs bootstrap fresh identities:
  Alice: 2828c1c9056298d5f61bf14e96fc8b5afe570befd4a4f58ced342242c74fe832
  Bob:   3a093cd15224f0dca8f3c52554314b91bf24686831fe4ed1baef848e7e556019
Bob invite Alice → conversation appears
Alice add Bob → joins
Bob send "msg1 from Bob" → Alice's poll decrypts ✓
Alice send "reply from Alice" → Bob's poll decrypts ✓

localStorage at this point on both:
  lattice/messages/{gid}/v1 = [
    {author: "...", body: "msg1 from Bob", ts: ...},
    {author: "...", body: "reply from Alice", ts: ...}
  ]

both tabs navigate (hard reload)
both tabs re-bootstrap + restore conversations + seed messages from history
  → sidebar shows the conversation
  → thread shows BOTH "msg1 from Bob" and "reply from Alice" immediately
```

Bounded retention (a per-conversation message-count or age cap) is
tracked as chat-app chunk E / F work. Today scrollback is unlimited.

---

## N-party groups

The N-party flow is identical to 1:1 except for two things:

- The inviter chooses a **random** group_id at creation time. There
  is no canonical sort across N user_ids, so the joiners cannot
  derive the gid locally.
- Multiple Welcomes are produced — one per joiner — and ride along
  with a single commit POST.

### How a group is created

In the chat shell, click 👥 instead of `+`. The form takes a label
(e.g. `design team`) and a comma-separated list of peer user_id hex.
Submit and:

1. Client generates a random 16-byte gid.
2. For each peer, `GET /key_packages/<peer_uid>` to fetch their KP.
3. Call `add_members` (the N-joiner variant of `add_member`) which
   produces:
   - One MLS commit.
   - One MLS Welcome per joiner.
   - One `PqWelcomePayload` per joiner (per-joiner ML-KEM-768
     ciphertext + a per-joiner AEAD-wrapped random secret `W` —
     see HANDOFF §5 multi-member section for the wire detail).
4. POST the bundle to `/group/<gid>/commit` as a single body with a
   `welcomes: [...]` array.
5. Persist the `ConvoRecord` with `ConvoKind::NamedGroup`.

### How joiners discover the invite

Because the inviter chose a random gid, joiners have no way to
derive it locally. The server enumerates pending welcomes on a
per-user basis:

```
GET /welcomes/pending/<joiner_uid>
→ [
    {
      group_id_b64url: "...",
      epoch: 1,
      mls_welcome_b64: "...",
      pq_payload_b64: "..."
    },
    ...
  ]
```

Each chat client calls this endpoint at bootstrap (and after any
identity-bound state change). For each entry it has not seen, it
calls `process_welcome_with_storage`, persists the `ConvoRecord`,
and surfaces the conversation in the sidebar.

The endpoint is **idempotent**. Re-fetching the same welcome is fine
— the second `process_welcome` fails cleanly inside mls-rs with
`WelcomeKeyPackageNotFound` (the leaf init key is already consumed)
and the client silently skips it.

### Multi-joiner Welcome construction

The wire format for N-party Welcomes deserves its own paragraph
because it is the M5 deliverable that bumped the protocol from
v1 → v2.

In a 1:1 invite, the `PqWelcomePayload` is a simple `(ml_kem_ct,
epoch)` pair. For N joiners, Alice (the inviter) does:

1. Generate one random 32-byte `W`.
2. For each joiner `i`:
   - `(ml_kem_ct_i, ss_i) = ML-KEM-768.encapsulate(joiner_i_kem_pk)`.
   - `K_i = HKDF-SHA-256(salt=epoch||idx, ikm=ss_i,
     info="lattice/wrap/v2", 32)`.
   - `wrap_ct_i = ChaCha20Poly1305.seal(W, AAD=epoch||idx, key=K_i,
     nonce=random_per_joiner)`.
3. The commit references one external PSK keyed on `W` under
   `psk_id_for_epoch(epoch)`.
4. Each joiner decapsulates their `ml_kem_ct_i`, derives `K_i`,
   AEAD-opens `W`, and registers `W` as the same PSK.

The wire payload per joiner is `(joiner_idx, ml_kem_ct, wrap_nonce,
wrap_ct)`. See `lattice-crypto/src/mls/welcome_pq.rs` for the
canonical encoding.

### Author display

Today the chat shell shows received messages as `from <label>` where
label is the conversation label, not the actual sender's user_id.
For 1:1 this is correct because the peer's label is the other party.
For N-party groups it is "placeholder" — mls-rs's `decrypt_with_sender`
does surface the sender's leaf index (which we can map to a
user_id), but the rendering layer doesn't use it yet. Chunk 2.5's
roster panel and this lookup go together.

---

## Servers (Discord-style)

A **server** in Lattice is an MLS group whose first application
message is a `ServerStateOp::Init`. Mechanically, server creation is
identical to N-party group creation; the only difference is that
the inviter sends an `Init` op as the first application message
**before** any chat text.

```rust
ServerStateOp::Init {
    server_name: "Friends",
    admins: vec![<creator_uid_hex>],
    channels: vec![],   // chunk 2 first-cut: one implicit channel
}
```

The receiving clients classify on first-`Init`-decrypt:

- Pre-decrypt, the sidebar shows `# group <prefix>` with a
  placeholder label.
- Post-decrypt, the kind upgrades to `ConvoKind::ServerMembership {
  server_name }`, label becomes the server name, and the sidebar
  prefix changes from `#` to `★`.

The full state machine and the multi-channel posture live at
[servers-and-channels.md](servers-and-channels.md).

---

## Sealed sender

Every message Lattice sends rides a `SealedEnvelope`. The construction
is documented in DECISIONS §D-05 and threat-modelled in
[security-model.md](security-model.md#sealed-sender); the short
version is:

- On group commit (new epoch), the owning home server issues a
  per-member `MembershipCert` carrying an ephemeral Ed25519 pubkey,
  the group id, the epoch, and a validity window (≤ 1 hour).
- The server signs the cert with its federation Ed25519 key.
- When sending, the member signs the outer `SealedEnvelope` with the
  private key matching `ephemeral_sender_pubkey`.
- The routing server verifies the cert signature against the issuing
  home server's pubkey, and verifies the outer envelope signature
  against the ephemeral pubkey. It learns "some valid group member
  sent this" without learning **which** member.
- The inner ApplicationMessage (encrypted under MLS) carries the
  real sender's leaf index. Recipients decrypt and learn the
  identity from there.

Wire size: a sealed envelope wrapping a 3,662-byte MLS ciphertext
comes out to 3,879 bytes — 217 bytes of envelope overhead.

---

## Message sizes (reference)

For a sense of the over-the-wire shape:

| Object | Size | Notes |
|---|---|---|
| KeyPackage | ~12,057 bytes | With `LatticeKemPubkey` extension |
| MLS commit (1 joiner) | ~15,601 bytes | |
| MLS Welcome (1 joiner) | ~19,819 bytes | |
| `PqWelcomePayload` (1 joiner) | 1,088 bytes | ML-KEM-768 ciphertext |
| MLS application ciphertext | ~3,662 bytes | For a short plaintext ("hello, lattice") |
| `SealedEnvelope` (D-05) | ~3,879 bytes | App ciphertext + sig + cert reference |
| Identity blob v1 | ~7,679 bytes | Plaintext |
| Identity blob v2 | ~7,756 bytes | Argon2id-keyed AEAD |

The MLS overhead does not scale linearly with plaintext size — most
of the ciphertext is framing and the AEAD tag.

---

## Padding

Application messages are padded to fixed buckets before encryption:
`{256, 1024, 4096, 16384, 65536, 262144}` bytes. The intent is to
make traffic-analysis-by-size impossible — every short message
between two users on the same server is the same size on the wire
regardless of content. AAD is pinned to `lattice/attachment/v1` for
attachments and `lattice/aead-nonce/v1` for the direction-specific
AEAD nonce derivation.

See `crates/lattice-crypto/src/padding.rs` for the bucket-lookup
implementation.

---

## Composer affordances

The composer at the bottom of the thread pane supports:

- **Enter** to send. **Shift+Enter** for a newline.
- Plain text only. No markdown, no rich-text, no HTML rendering of
  message content. This is a deliberate hardening choice (D-20):
  rendering HTML from message content would re-introduce an
  XSS-equivalent attack surface inside the chat shell.
- A future limited-markdown subset (bold, italic, code spans, code
  blocks, links with `nofollow`) is tracked but not shipped.

There is no file-upload affordance in the current chat shell. The
attachment crypto path is exercised in the legacy debug grid
(`try_attachment_demo`) and the wire format is locked
(`lattice/attachment/v1`); the server-side upload route is
post-M3 work.

---

## What's not yet shipped

- WebSocket push wired into the chat shell (today: 5-second poll).
- Sender attribution in received messages (today: shows label,
  not user_id).
- Encrypted scrollback at rest (today: plaintext alongside the
  v1 identity blob).
- Bounded scrollback retention (today: unlimited).
- File / image attachments in the chat shell.
- Reactions, typing indicators, read receipts.
- Search across history.
- Block / mute.

Most of the above live in chat-app chunks D / E / F in HANDOFF §1.
Track 4 chunk 2.5 covers the multi-channel and admin-enforcement
work for Discord-style servers.
