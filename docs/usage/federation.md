# Federation

Lattice does not have a central directory, a central message bus, or
a privileged operator. Every user lives on a **home server** of their
choice. Home servers federate with peer home servers on demand. This
page describes how that works, what trust assumptions hold, and how
to verify a working cross-server deploy.

If you have used Matrix's homeserver federation, the model is similar
in spirit: each user's account is anchored at one server, conversations
that span servers are replicated via server-to-server push, and the
trust between servers is bootstrapped via a `.well-known` descriptor.
The differences from Matrix are mostly that Lattice uses HTTP
(over QUIC + HTTP/3 once that lands) instead of a mesh protocol, and
that ciphertext-only storage is enforced at the schema level — there
is no plaintext message column anywhere in the federation surface.

---

## The federated model

Three node types, all present in the current build:

1. **Home server** (`lattice-server`). Holds your account registry,
   published KeyPackages, group commit logs, message inboxes,
   federation peer registry, push subscriptions. Federates with peer
   home servers over HTTP for now; QUIC + H3 is future work.
2. **Client** (browser PWA or Tauri shell). Holds your private keys
   and decrypted state. Talks to one home server at a time.
3. **Rendezvous node**. STUN/TURN-like service for P2P NAT
   traversal on voice/video. Sees connection-attempt metadata, never
   plaintext media.

For groups spanning multiple home servers, the MLS Delivery Service
responsibility is held by the **owning server** (the server that
hosts the group creator's user_id). Read replicas are pushed to
participating peer servers. Multi-server store-and-forward extends
this to multi-master so a single owning server going dark does not
kill the room.

---

## Server discovery — `.well-known/lattice/server`

A peer server discovers your home server by fetching:

```
GET https://<your-host>/.well-known/lattice/server
```

The response is:

```json
{
  "wire_version": 4,
  "federation_pubkey_b64": "<32-byte-base64>",
  "server_version": "0.1.0"
}
```

The current server returns the minimal JSON above without the
canonical-CBOR + Ed25519 signature wrapper. The fully signed
descriptor shape:

```json
{
  "version": "1",
  "server": {
    "host": "home.example.com",
    "quic_port": 4433,
    "federation_pubkey": "<base64-Ed25519-32-byte>",
    "min_wire_version": "0.1",
    "max_wire_version": "0.1"
  },
  "policy": {
    "registration_open": true,
    "federation_open": true,
    "contact": "admin@example.com"
  },
  "signed_at": "2026-05-10T12:00:00Z",
  "signature": "<base64-Ed25519-64-byte>"
}
```

The `signature` is an Ed25519 signature over the canonical CBOR
serialisation of every other field (alphabetical key order, no
indeterminate-length encodings). Peers verify on every fetch. The
fully signed descriptor is future work — the unsigned shape above
is what currently ships.

Cache TTL: 24 hours, refreshed on `signed_at` change. Peers cache
per host.

---

## Federation pubkey pinning (TOFU)

On first contact, a peer server **TOFU-pins** your `federation_pubkey`
— it stores the pubkey it saw the first time and refuses to accept a
federation push from your host signed with a different key.

A captured DNS path could serve a valid-looking descriptor with a
different `federation_pubkey`, redirecting federation to a hostile
server. Mitigations:

- DNSSEC where deployed.
- Manual operator key pinning where federation relationships are
  high-trust (operator hardcodes the peer's pubkey in config).
- Key transparency log inclusion proofs — a captured server cannot
  publish a substituted key without leaving an auditable trail.

The KT log machinery is shipped
(`crates/lattice-keytransparency/`); the client-side verification
path is follow-on work.

---

## Federation push — commits

When Alice (hosted on server A) invites Bob (hosted on server B) to
an MLS group, here is what happens:

1. **Alice's client** GETs `/key_packages/<bob_uid>` against server A.
2. Server A holds a federated copy of Bob's KP only if it has one;
   otherwise it returns 404. Cross-server KP fetch is **not** done by
   server A on behalf of Alice — that path is the federation-fetch
   pattern documented in ARCHITECTURE §"End-to-end message flow."
   In the current server, Alice's client knows it must fetch Bob's
   KP directly from Bob's home server: `GET https://<bob's
   host>/key_packages/<bob_uid>`.
3. Alice builds the MLS commit + Welcome locally.
4. Alice POSTs to server A's `/group/<gid>/commit` with a
   `remote_routing` field listing Bob's home server URL:

   ```json
   {
     "epoch": 1,
     "commit_b64": "...",
     "welcomes": [{"joiner_user_id_b64": "<bob>", ...}],
     "remote_routing": [
       {
         "joiner_user_id_b64": "<bob>",
         "home_server_base_url": "https://home.bob.example"
       }
     ],
     "origin_host": "home.alice.example",
     "origin_base_url": "https://home.alice.example"
   }
   ```

5. Server A appends the commit to its own log AND POSTs to server B's
   `/federation/inbox`:

   ```json
   {
     "origin_host": "home.alice.example",
     "origin_base_url": "https://home.alice.example",
     "origin_pubkey_b64": "<server-A's federation pubkey>",
     "group_id_b64": "<gid>",
     "epoch": 1,
     "commit_b64": "...",
     "welcomes": [...],
     "signature_b64": "<Ed25519 sig by server A over canonical TBS>"
   }
   ```

6. Server B verifies the signature against the cached / TOFU-pinned
   `origin_pubkey`. On success, appends to its own commit log.
7. Bob's client (next bootstrap or live WS) calls
   `GET /welcomes/pending/<bob_uid>` against server B and discovers
   the welcome. He joins.

The signed TBS is built by `canonical_inbox_bytes` in
`crates/lattice-server/src/routes/federation.rs`. It is a Prost
encoding of the request fields in fixed order — not JSON, because
JSON's serialisation ambiguity would let a hostile re-encoder break
signature stability.

---

## Federation push — messages

After the group is established, message fan-out works the same way:

1. Alice POSTs `/group/<gid>/messages` to server A with an optional
   `remote_routing` array listing peer base URLs.
2. Server A appends to its own message inbox AND POSTs to each
   peer's `/federation/message_inbox` with the same signed-TBS
   pattern.
3. Bob fetches from server B via `GET
   /group/<gid>/messages?since=<cursor>` or via the live WS push at
   `/group/<gid>/messages/ws`.

The fan-out list comes from one of two sources:

- The per-message `remote_routing` field (lets a client override
  topology per-send).
- The per-group replication-peer list stored via
  `POST /group/<gid>/replication_peers` (multi-server
  store-and-forward).

The per-group list is preferred for steady-state — clients
configure it once at group creation, and every subsequent message
fans out without per-send instrumentation.

---

## Distrust scoring

Lattice clients maintain a local distrust score per federated peer
server. The score is **local-only** — there is no gossip. Each
user's client builds its own picture.

Score sources:

| Event | Delta | Notes |
|---|---|---|
| Manual user flag | +50 | Decays linearly over 90 days |
| KT-log inconsistency | +100 | No decay until cleared by admin |
| Repeated invalid `.well-known` responses | +10 each | Capped at +50 |
| TLS / federation auth failures from peer | +5 each | Capped at +30 |

UI thresholds: yellow warning badge at score 30–70, red at 71+.
Users can manually clear or unblock; the score audit log is
preserved locally for transparency.

The chat client implements this as
`apps/lattice-web/src/distrust.rs`. The persisted ledger lives at
`localStorage["lattice/distrust/v1"]`.

---

## Cross-server smoke transcript

Two `lattice-server` instances, one DM round-trip across them. Server
hostnames below are placeholders — substitute your own.

| Node | Role |
|---|---|
| `server-a` (public, port 4443) | Alice's home server |
| `server-b` (behind NAT, reachable via SSH reverse tunnel) | Bob's home server |

`server-b` exposes itself to `server-a` via a persistent SSH reverse
tunnel, so from `server-a`'s perspective `http://127.0.0.1:4444` IS
the `server-b` peer.

Demo run:

```bash
~/lattice/target/release/lattice demo \
    --server-a http://server-a:4443 \
    --server-b http://localhost:4444 \
    --message cross-server-hello
```

Steps observed in the logs:

1. Alice's CLI registers against `server-a:4443`. `register_user`
   returns `new_registration: true`.
2. Alice publishes a KeyPackage (12,057 bytes) to `server-a`.
3. Bob's CLI registers against `server-b:4443` (via the tunnel as
   `localhost:4444`). `new_registration: true`.
4. Bob publishes a KeyPackage to `server-b`.
5. Alice creates a group, invites Bob.
6. Alice's commit POST to `server-a` carries `remote_routing`
   pointing at `server-b`'s base URL.
7. `server-a` POSTs the commit to `server-b`'s `/federation/inbox`.
   `server-b` verifies the signature against `server-a`'s federation
   pubkey (TOFU-pinned on this first contact).
8. `server-b` accepts, appends to its own log.
9. Bob's CLI calls `fetch_welcome` against `server-b`; `server-b`
   returns the pq-wrapped welcome.
10. Bob processes the welcome, MLS-joins.
11. Alice posts `cross-server-hello` via `server-a`.
12. `server-a` POSTs to `server-b`'s `/federation/message_inbox`.
13. `server-b` accepts, appends.
14. Bob fetches messages from `server-b`; decrypts; CLI prints
    `cross-server-hello`.

Exit code 0. The full log lines emit at `lattice_server=info` —
`federation push delivered` on the sender, `federation push accepted`
on the receiver.

### Persistence verification

After the round-trip, `server-a` was SIGTERMed. The graceful-shutdown
handler wrote a state JSON snapshot with all in-memory state:
registered users, published KPs, group commit logs, message inbox,
federation peer registry. On restart, the snapshot was reloaded and
`verify-persistence.ps1` confirmed that the same federation pubkey,
same group commits, and same message inbox were present.

---

## Joining a foreign server

If your friend operates `home.friend.example` and you want to join a
server they host:

1. Your home server (let's say `home.you.example`) needs to be
   reachable by `home.friend.example`. Either:
   - Both servers have public IPs and resolvable hostnames.
   - One server is behind NAT and maintains a persistent
     tunnel (SSH reverse-tunnel, Tailscale, Wireguard).
   - Both are behind NAT and share a Tailscale tailnet or similar
     overlay.

2. Your friend invites you via your hex user_id. Their client adds
   you to the server-membership group with `add_member`. The commit
   is posted to `home.friend.example/group/<gid>/commit` with
   `remote_routing` pointing at `home.you.example`.

3. `home.friend.example` POSTs the welcome to
   `home.you.example/federation/inbox`. Your server TOFU-pins their
   federation pubkey on first contact.

4. Your client at bootstrap calls `GET /welcomes/pending/<your_uid>`
   against your home server and finds the welcome. You join.

5. Subsequent messages fan out the same way — each home server
   POSTs to the others.

Your client only ever talks to **your** home server. It never makes
HTTP calls to foreign hosts. All cross-server communication rides
the federation pubkey-pinned signed push.

The cross-server round-trip described above has been verified working
over the public internet via SSH reverse tunnel.

---

## Server descriptor verification (manual)

The "I am paranoid and want to verify my friend's server is the one
I think it is" workflow:

1. Get the friend's expected `federation_pubkey` out of band (Signal
   message, voice call, in person).

2. Fetch the descriptor:

   ```bash
   curl -s https://home.friend.example/.well-known/lattice/server | jq .
   ```

3. Compare `federation_pubkey_b64` to the out-of-band value.

4. (Future work) Once the signed-descriptor wrapper lands, also verify
   the Ed25519 signature against the pubkey.

5. (Future work) Compare the KT log root from
   `/.well-known/lattice/kt-root` against the cross-server witnessed
   roots from your own home server. Drift triggers a +100 distrust
   delta and a red badge.

---

## Federation transport (current vs planned)

| Layer | Today | Planned |
|---|---|---|
| Transport | HTTP/1.1 via `reqwest`/`axum` | QUIC + HTTP/3 + WebTransport |
| TLS | Plain HTTP (dev) / operator-provided TLS reverse-proxy | ACME via `instant-acme`, Let's Encrypt |
| Auth | Federation Ed25519 signature on TBS | Same |
| Encoding | JSON envelope, base64 binary fields, Prost TBS | Same |
| Push | POST to `/federation/inbox` and `/federation/message_inbox` | Same paths over WT bidi streams |

The wire shape stays. The change is purely transport. Once the
QUIC + H3 + WT server-side stack lands, HTTP remains as the fallback
selected by `capabilities::Capabilities::probe()`.

The current HTTP server is single-process, in-memory, no rate limits.
A later milestone introduces:

- Rate limits per source IP and per user_id.
- Per-request auth via signed-by-federation-cert HMACs.
- Postgres-backed storage for users, KPs, group state, messages.
- ACME-driven TLS certificate management.

See [self-hosting.md](self-hosting.md) for the deploy-time
checklist.

---

## Cross-references

- [Architecture](/wiki/architecture/) — federation topology + end-to-end message flow.
- [self-hosting.md](self-hosting.md) — operator-focused guide.
