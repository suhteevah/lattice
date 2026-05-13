# API reference

Every HTTP endpoint exposed by `lattice-server`. This is a working
reference — every shape below comes from the source at
`crates/lattice-server/src/routes/` and is verified against the
shipped surface. The wire-protocol version is currently 4.

For higher-level flows that compose these endpoints (the chat client's
bootstrap, an invite, a federation push), see
[messaging.md](messaging.md) and [federation.md](federation.md). This
page is the request / response catalogue.

The server's base URL throughout these examples is
`http://127.0.0.1:8080`. Replace with your deploy's URL.

---

## Conventions

- **Encoding.** All binary fields are base64-encoded. Paths may use
  standard base64 or URL-safe base64 with no padding; the server
  tries both decoders.
- **Content-Type.** Requests use `application/json`. Responses are
  `application/json`. The WebSocket path is the only non-JSON
  surface.
- **Errors.** Non-2xx responses return a plain-text body with a
  short error description. The status code carries the category:
  - `400 Bad Request` — malformed body, base64 decode failure,
    wrong-length user_id, invalid JSON.
  - `404 Not Found` — user not registered, no pending welcome, no
    published KeyPackage.
  - `500 Internal Server Error` — unexpected server-side failure.
- **CORS.** `Access-Control-Allow-Origin: *` by default. See
  [self-hosting.md](self-hosting.md) for tightening.
- **Auth.** None today. The federation surface uses Ed25519
  signatures on TBS bodies; client routes are unauthenticated.
  Future work introduces signed-by-federation-cert HMACs.

---

## Health

### `GET /health`

Liveness probe. Always returns 200 if the server is reachable.

**Request body:** none.

**Response (200):**

```json
{
  "status": "ok",
  "service": "lattice-server",
  "version": "0.1.0",
  "wire_version": 4
}
```

The `wire_version` value comes from
`lattice_protocol::WIRE_VERSION` and bumps when the wire contract
changes.

---

## Federation discovery

### `GET /.well-known/lattice/server`

The federation descriptor. The server returns the minimal unsigned
shape; the full signed shape is future work.

**Request body:** none.

**Response (200):**

```json
{
  "wire_version": 4,
  "federation_pubkey_b64": "<base64-32-byte>",
  "server_version": "0.1.0"
}
```

`federation_pubkey_b64` is the Ed25519 pubkey peers TOFU-pin and
verify federation push signatures against.

---

## Identity

### `POST /register`

Register a user_id with the home server. Idempotent — re-registering
overwrites the claim in place.

**Request body:**

```json
{
  "user_id_b64": "<base64-32-byte user_id>",
  "claim_b64": "<base64-of-Prost-encoded IdentityClaim>"
}
```

The `IdentityClaim` is the Prost-encoded wire type with the
hybrid-signed identity bundle. Today the server accepts any
well-formed Prost claim and does not verify the hybrid signature;
future work introduces full signature verification.

**Response (200):**

```json
{
  "new_registration": true
}
```

`true` on first registration, `false` if the user_id was already
known and the claim was overwritten.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400` | `user_id_b64 decode: <err>` | Base64 decoding failed. |
| `400` | `user_id length N (expected 32)` | Wrong-length user_id. |
| `400` | `claim_b64 decode: <err>` | Base64 decoding failed for claim. |
| `400` | `claim decode: <err>` | Prost decode of the claim failed. |

---

### `POST /key_packages`

Publish a KeyPackage. Replaces any prior KP for this user_id; the
server holds the most recent one only.

**Request body:**

```json
{
  "user_id_b64": "<base64-32-byte user_id>",
  "key_package_b64": "<base64-of-MlsMessage-mls_encode_to_vec bytes>"
}
```

The KP itself is the output of
`lattice_crypto::mls::generate_key_package(&identity).mls_encode_to_vec()`.
Typical size: ~12,057 bytes.

**Response (200):**

```json
{
  "published_at": 1715520000
}
```

The Unix-epoch-seconds timestamp the server recorded.

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400` | `user_id_b64 decode: <err>` | Base64 issue. |
| `400` | `user_id length N (expected 32)` | Wrong length. |
| `400` | `key_package_b64 decode: <err>` | Base64 issue. |
| `404` | `user_id not registered — call /register first` | The user_id must be registered before publishing a KP. |

---

### `GET /key_packages/{user_id_b64}`

Fetch the most recently published KeyPackage for a user_id.

**Path parameter:** `user_id_b64` — standard or URL-safe base64.

**Response (200):**

```json
{
  "key_package_b64": "<base64-of-MlsMessage bytes>",
  "published_at": 1715520000
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400` | `user_id_b64 decode: <err>` | Base64 issue. |
| `400` | `user_id length N (expected 32)` | Wrong length. |
| `404` | `no published KeyPackage for that user` | User never published a KP, or it was consumed. |

---

## Group routes

### `POST /group/{gid_b64}/commit`

Submit an MLS commit + per-joiner welcomes. Persists to the
server's commit log and optionally fans out to remote peer servers
listed in `remote_routing`.

**Path parameter:** `gid_b64` — base64-encoded 16-byte group_id.

**Request body:**

```json
{
  "epoch": 1,
  "commit_b64": "<base64-of-MLS-commit-bytes>",
  "welcomes": [
    {
      "joiner_user_id_b64": "<base64-32-byte>",
      "mls_welcome_b64": "<base64-of-MLS-Welcome bytes>",
      "pq_payload_b64": "<base64-of-mls_encoded PqWelcomePayload>"
    }
  ],
  "origin_host": "home.you.example",
  "origin_base_url": "https://home.you.example",
  "remote_routing": [
    {
      "joiner_user_id_b64": "<base64-32-byte>",
      "home_server_base_url": "https://home.bob.example"
    }
  ]
}
```

`welcomes` is empty for self-commits and updates. `remote_routing`
lists peer base URLs for joiners hosted on other servers; the home
server federates-push to each.

**Response (200):**

```json
{
  "epoch": 1,
  "welcomes_accepted": 1
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400` | various base64 / length errors | Malformed input. |

---

### `GET /group/{gid_b64}/welcome/{user_id_b64}`

Fetch the most-recent pending Welcome addressed to the queried user
in this group.

**Path parameters:**
- `gid_b64` — group_id, base64.
- `user_id_b64` — user_id, base64.

**Response (200):**

```json
{
  "epoch": 1,
  "mls_welcome_b64": "<base64>",
  "pq_payload_b64": "<base64>"
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `404` | `no pending welcome for that user in this group` | No matching welcome on file. |

---

### `GET /welcomes/pending/{user_id_b64}`

Enumerate every group on this server that has a pending welcome
addressed to the queried user_id. Used by the chat shell at
bootstrap to discover N-party group invites where the inviter chose
a random group_id the joiner has no way to derive locally.

**Path parameter:** `user_id_b64`.

**Response (200):**

```json
{
  "welcomes": [
    {
      "group_id_b64url": "tQpZm-_hmUMuM7vrUHIKxg",
      "epoch": 1,
      "mls_welcome_b64": "<base64-standard>",
      "pq_payload_b64": "<base64-standard>"
    }
  ]
}
```

`group_id_b64url` uses URL-safe base64 (no padding) to match the chat
shell's `localStorage` key convention.

The endpoint is idempotent — repeated calls return the same set.
The client tracks which welcomes it has consumed; the server does
not prune.

---

### `POST /group/{gid_b64}/messages`

Publish an application message (or sealed envelope) to a group.

**Path parameter:** `gid_b64` — group_id.

**Request body:**

```json
{
  "envelope_b64": "<base64 — sealed envelope or raw MLS app message>",
  "remote_routing": [
    "https://home.bob.example",
    "https://home.carol.example"
  ],
  "origin_host": "home.you.example",
  "origin_base_url": "https://home.you.example"
}
```

`remote_routing` lists peer base URLs to federate-push to. If
omitted, the server falls back to the per-group replication-peer
list configured via `POST /group/<gid>/replication_peers`.

**Response (200):**

```json
{
  "seq": 42
}
```

The monotonic sequence number assigned to this message. Clients use
it as a cursor for `since` on the fetch endpoint.

---

### `GET /group/{gid_b64}/messages?since=N`

Fetch messages with `seq > since`. Default `since=0` returns
everything.

**Path parameter:** `gid_b64`.

**Query parameter:** `since` — u64.

**Response (200):**

```json
{
  "latest_seq": 42,
  "messages": [
    {
      "seq": 41,
      "envelope_b64": "<base64>"
    },
    {
      "seq": 42,
      "envelope_b64": "<base64>"
    }
  ]
}
```

`latest_seq` is the most-recent `seq` in the returned messages, or
the input `since` if no messages were returned. Clients save this
value and use it as `since` for the next call.

---

### `GET /group/{gid_b64}/messages/ws`

WebSocket upgrade. Each `(seq, envelope_bytes)` posted to the group
via `POST /group/<gid>/messages` after the connection is established
is pushed as a JSON text frame:

```json
{
  "seq": 43,
  "envelope_b64": "<base64>"
}
```

**Catch-up before subscribe:** the WebSocket only delivers messages
that arrive **after** the broadcast subscription attaches. Clients
should call `GET /group/<gid>/messages?since=N` once on connect to
fetch any messages they missed.

**Disconnect causes:**

- The client closes the socket.
- The server's broadcast channel is closed (process shutdown).
- The subscriber lags more than the broadcast buffer (default 64
  messages). The server emits `ws subscriber lagged` and closes;
  the client reconnects + replays from the last seen `since`.

---

### `POST /group/{gid_b64}/issue_cert`

Request a sealed-sender membership cert for the current epoch.

**Path parameter:** `gid_b64`.

**Request body:**

```json
{
  "epoch": 1,
  "ephemeral_pubkey_b64": "<base64-32-byte Ed25519 pubkey>",
  "valid_until": 1715523600
}
```

`valid_until` is Unix-epoch seconds. Recommended ≤ 1 hour from now.

**Response (200):**

```json
{
  "cert_b64": "<base64-Prost-encoded MembershipCert>"
}
```

The cert is signed by the server's federation Ed25519 key. The
client uses it to sign outgoing `SealedEnvelope`s; routing servers
verify the cert and the envelope's outer signature without learning
the sender's identity.

---

### `POST /group/{gid_b64}/replication_peers`

Set the per-group replication-peer list (store-and-forward replication).
Subsequent message publishes fan out to every URL in this list
when the per-message `remote_routing` is empty.

**Request body:**

```json
{
  "peers": [
    "https://peer-a.example:4443",
    "https://peer-b.example:4444"
  ]
}
```

**Response (200):**

```json
{
  "peers": [
    "https://peer-a.example:4443",
    "https://peer-b.example:4444"
  ]
}
```

Echoes the new list.

---

### `GET /group/{gid_b64}/replication_peers`

Read the current replication-peer list.

**Response (200):**

```json
{
  "peers": ["https://peer-a.example:4443"]
}
```

Empty if none configured.

---

## Federation routes

These are not meant to be called by clients. They are the
server-to-server surface. A peer's `lattice-server` POSTs here when
it has a commit or a message that mentions one of your users.

### `POST /federation/inbox`

Accept a federation commit push from a peer.

**Request body:**

```json
{
  "origin_host": "home.alice.example",
  "origin_base_url": "https://home.alice.example",
  "origin_pubkey_b64": "<base64-32-byte>",
  "group_id_b64": "<base64-16-byte>",
  "epoch": 1,
  "commit_b64": "<base64>",
  "welcomes": [
    {
      "joiner_user_id_b64": "<base64-32-byte>",
      "mls_welcome_b64": "<base64>",
      "pq_payload_b64": "<base64>"
    }
  ],
  "signature_b64": "<base64-64-byte Ed25519 sig over canonical TBS>"
}
```

The receiver verifies the signature against the cached or
TOFU-pinned `origin_pubkey`. On first contact, the pubkey is pinned.
On subsequent calls, a mismatch causes a 403 and a distrust-score
delta.

The canonical TBS is built by
`crates/lattice-server/src/routes/federation.rs::canonical_inbox_bytes`
— a Prost encoding of the request fields in fixed order, plus the
welcomes concatenated as `joiner_user_id_b64|mls_welcome_b64|pq_payload_b64\n`
lines.

**Response (200):**

```json
{
  "accepted": true
}
```

**Error responses:**

| Status | Body | Cause |
|---|---|---|
| `400` | various base64 / length errors | Malformed input. |
| `403` | `signature verification failed` | Wrong signature or wrong pinned pubkey. |

---

### `POST /federation/message_inbox`

Accept a federation message push from a peer. Similar shape to
`/federation/inbox` but for application messages instead of commits.

(Detailed shape mirrors the commit push minus the `welcomes` array,
plus an `envelope_b64` field. See
`crates/lattice-server/src/routes/federation.rs` for the canonical
TBS layout.)

---

## Push subscription routes

Registry-only today: the subscription record is stored on the
server, but the payload-emit hook is follow-on work.

### `POST /push/subscribe`

Register a Web Push API subscription for the user_id.

**Request body:**

```json
{
  "user_id_b64": "<base64-32-byte>",
  "endpoint": "https://push.example.com/...",
  "p256dh_b64": "<base64-P256-pubkey>",
  "auth_b64": "<base64-16-byte-auth-secret>",
  "distributor": "unifiedpush"
}
```

`distributor` is informational. Common values: `"unifiedpush"`,
`"fcm"`, `"apns"`, `"web-push"`.

Multiple endpoints per user are allowed (e.g. a primary UnifiedPush
distributor plus an FCM fallback).

**Response (200):**

```json
{
  "new_subscription": true,
  "total_subscriptions": 2
}
```

`new_subscription: true` if this `(user_id, endpoint)` pair was not
known before; `false` if the endpoint already existed and was
updated in place.

---

### `GET /push/subscriptions/{user_id_b64}`

Read the user's active subscriptions. Used by other services that
emit push payloads server-side. Clients normally don't query this.

**Response (200):**

```json
{
  "subscriptions": [
    {
      "endpoint": "https://push.example.com/...",
      "p256dh_b64": "<base64>",
      "auth_b64": "<base64>",
      "created_at": 1715520000,
      "distributor": "unifiedpush"
    }
  ]
}
```

Empty list if none registered.

---

## Wire-protocol versioning

The wire version negotiated at `GET /.well-known/lattice/server` is
4 today. Breaking wire changes bump this value. The version history:

| Version | Major change |
|---|---|
| 1 | Initial wire contract — Prost-encoded `IdentityClaim`, `KeyPackage`, `Welcome`, etc. Sealed-sender added. |
| 2 | N-party group Welcome — `PqWelcomePayload` extended with `joiner_idx`, `wrap_nonce`, `wrap_ct` for the multi-Welcome construction. |
| 3 | Prost → Cap'n Proto wire swap. Internal signing-transcript helpers (`sealed_sender`, `federation`) still use Prost; the on-the-wire types moved to capnp. |
| 4 | Call signalling types: `CallInvite`, `CallAccept`, `CallIceCandidate`, `CallEnd`, `CallSignal`. |

Future breaking bumps require an explicit re-open against the
locked design decisions in the source tree.

---

## Source pointers

If a request shape here disagrees with the server's behaviour, the
source is the source of truth:

| Concern | File |
|---|---|
| Route assembly | `crates/lattice-server/src/routes/mod.rs` |
| Health | `crates/lattice-server/src/routes/health.rs` |
| `/.well-known/lattice/server` | `crates/lattice-server/src/routes/well_known.rs` |
| Identity (`/register`, `/key_packages`) | `crates/lattice-server/src/routes/identity.rs` |
| Group (`/group/*`) | `crates/lattice-server/src/routes/groups.rs` |
| Federation (`/federation/*`) | `crates/lattice-server/src/routes/federation.rs` |
| Push (`/push/*`) | `crates/lattice-server/src/routes/push.rs` |
| Wire types | `crates/lattice-protocol/src/wire.rs`, `lattice_capnp.rs` |
| Sealed-sender | `crates/lattice-protocol/src/sealed_sender.rs` |
| Server state types | `crates/lattice-server/src/state.rs` |
