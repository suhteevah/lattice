# Lattice — ARCHITECTURE

How the pieces fit. Reference for readers who want to understand the
construction without reading the source.

## Layered view

```
┌─────────────────────────────────────────────────────────────┐
│  Application layer                                          │
│    • Solid + Tailwind UI (apps/lattice-web)                 │
│    • CLI (crates/lattice-cli)                               │
├─────────────────────────────────────────────────────────────┤
│  Client core (crates/lattice-core)                          │
│    • Session management, group operations, message routing  │
│    • Local-first CRDT reconciliation                        │
│    • Compiles to wasm32 (V1) and native (V2)                │
├─────────────────────────────────────────────────────────────┤
│  Crypto (crates/lattice-crypto)        Storage              │
│    • Hybrid KEX (X25519 + ML-KEM)      (crates/             │
│    • MLS group state (mls-rs)           lattice-storage)    │
│    • Sealed sender, padding             • IndexedDB (V1)    │
│    • AEAD (ChaCha20-Poly1305)           • SQLCipher (V2)    │
├─────────────────────────────────────────────────────────────┤
│  Protocol (crates/lattice-protocol)                         │
│    • Wire schemas (Cap'n Proto)                             │
│    • Envelope framing, version negotiation                  │
├─────────────────────────────────────────────────────────────┤
│  Transport                                                  │
│    • QUIC (quinn) for native peers                          │
│    • WebTransport for browser clients                       │
│    • HTTP/3 fallback                                        │
└─────────────────────────────────────────────────────────────┘
```

## Federation topology

Each user has a **home server**. Home servers federate with peer home servers
on demand — there is no central directory. Federation discovery uses
`.well-known/lattice/server` over HTTPS, identical in spirit to Matrix's
discovery but binary over QUIC instead of JSON over HTTPS.

```
   Alice's device                           Bob's device
        │                                        │
        │ WebTransport                           │ WebTransport
        ▼                                        ▼
  ┌──────────────┐    QUIC federation      ┌──────────────┐
  │ home.alice   │ ──────────────────────► │ home.bob     │
  │ .example     │ ◄────────────────────── │ .example     │
  └──────────────┘                         └──────────────┘
        │                                        │
        ▼                                        ▼
   Postgres                                  Postgres
   (ciphertext store, MLS state, accounts)
```

For groups spanning multiple servers, MLS Delivery Service responsibility is
held by the **owning server** (the server of the group creator), with read
replicas pushed to participating peer servers. V1.5 adds multi-master
store-and-forward so a single owning server going dark doesn't kill the room.

## End-to-end message flow (1:1 DM)

```
Alice (client)                   home.alice            home.bob             Bob (client)
     │                                │                    │                       │
     │ 1. fetch Bob's key bundle      │                    │                       │
     │ ──────────────────────────────►│                    │                       │
     │                                │ 2. federation fetch│                       │
     │                                │ ──────────────────►│                       │
     │                                │ 3. return bundle   │                       │
     │                                │◄────────────────── │                       │
     │ 4. bundle (ML-DSA pubkey, MLS  │                    │                       │
     │    KeyPackage, X25519+ML-KEM)  │                    │                       │
     │◄───────────────────────────────│                    │                       │
     │                                                                              │
     │ 5. Local: create MLS group, Welcome msg, encrypt "hi" as ApplicationMessage  │
     │                                                                              │
     │ 6. upload Welcome + AppMsg to home.alice                                     │
     │ ──────────────────────────────►│                    │                       │
     │                                │ 7. federate to home.bob                    │
     │                                │ ──────────────────►│                       │
     │                                │                    │ 8. push to Bob        │
     │                                │                    │ ─────────────────────►│
     │                                │                    │                       │
     │                                                       9. decrypt Welcome,   │
     │                                                          decrypt AppMsg,    │
     │                                                          render "hi"        │
```

Sealed sender wraps step 6's envelope so that `home.alice` cannot trivially
log the sender→recipient link in plaintext metadata. The mechanism uses
Signal-style per-MLS-epoch membership certificates issued by the owning
home server.

## Crypto handshake spec

Initial key exchange between Alice and Bob (PQXDH-style hybrid):

```
1. Alice fetches Bob's published bundle:
   - Bob's long-term ML-DSA-65 identity pubkey   (signs everything below)
   - Bob's long-term Ed25519 identity pubkey     (classical co-signature)
   - Bob's signed X25519 prekey                  (classical KEM)
   - Bob's signed ML-KEM-768 prekey              (PQ KEM)
   - Bob's one-time MLS KeyPackage

2. Alice generates an ephemeral X25519 keypair (ek_classical) and an
   ephemeral ML-KEM-768 ciphertext (encapsulated to Bob's PQ prekey).

3. Alice computes four DH/KEM secrets:
   K1 = X25519(ek_classical, Bob's X25519 prekey)
   K2 = X25519(Alice's identity X25519, Bob's X25519 prekey)
   K3 = X25519(ek_classical, Bob's identity X25519)
   K4 = ML-KEM-768 encapsulated shared secret to Bob's PQ prekey

4. Alice derives the initial session secret:
   SK = HKDF-SHA-256(salt=0x00..., ikm = K1 || K2 || K3 || K4, info="lattice/init/v1", L=64)

5. Alice signs the transcript with ML-DSA-65 + Ed25519 (both, for hybrid).

6. SK seeds the MLS group's init_secret, joining `mls-rs` to the existing
   group key schedule.
```

The construction follows [draft-mahy-mls-xwing] in spirit: classical and PQ
secrets are concatenated then fed through HKDF, so an attacker must break
both to recover SK.

## Storage model

### Client (`lattice-storage`)

V1 — IndexedDB:
```
db lattice-{user_id}
├── identity        { ml_dsa_priv (sealed), ed25519_priv (sealed), ... }
├── groups          { group_id -> serialized MLS state (sealed) }
├── messages        { (group_id, epoch, generation) -> ciphertext + plaintext }
├── peers           { user_id -> last-known key bundle + verification state }
└── meta            { version, last-commit-at, ... }
```

All `sealed` values are argon2id-derived-key AEAD-wrapped. The argon2id
parameters are pinned: m=64MiB, t=3, p=1. Re-deriving on session resume
adds ~250ms latency; acceptable.

V2 — SQLCipher with OS-keychain-held master key.

### Server (`lattice-server`)

Postgres schema (rough cut, will evolve):

```
accounts          (user_id PK, home_server, identity_ml_dsa_pub, identity_ed25519_pub, created_at)
key_bundles       (user_id FK, kid PK, x25519_pub, ml_kem_pub, ml_dsa_sig, ed25519_sig, expires_at)
mls_groups        (group_id PK, owning_server, current_epoch, created_at)
mls_messages      (group_id FK, epoch, generation, ciphertext, content_type, received_at)
federation_peers  (host PK, server_pubkey, distrust_score, last_seen)
```

The server stores ciphertext only. There is no plaintext message column;
schema migrations that would add one fail CI.

## Transport

QUIC connections are long-lived. Each client maintains one QUIC connection to
its home server (WebTransport in V1, native quinn in V2). Federation between
servers also uses QUIC. Browser clients probe WebTransport first and fall
back to WebSocket where unsupported. QUIC server certificates: `rcgen`
self-signed for dev (TOFU), ACME / Let's Encrypt for prod.

Streams within a connection:
- Stream 0: control (heartbeats, version negotiation, error notifications)
- Stream 1: outbound messages (client → server, MLS commits + app messages)
- Stream 2: inbound deliveries (server → client, push notifications of new
  group events)
- Stream 3+: bulk fetches (key bundles, historical messages on demand)

V1 keeps voice/video out of scope — V2 adds a dedicated media stream that
upgrades to direct P2P after rendezvous-assisted ICE.

## Code organization principles

- **Crypto code never imports protocol code.** The dependency graph runs
  protocol → crypto, never the reverse. This keeps `lattice-crypto`
  auditable in isolation.
- **No business logic in `lattice-crypto`.** It exposes primitives and
  group-state helpers; sequencing of operations lives in `lattice-core`.
- **`lattice-core` is the only crate that compiles to wasm32.** Server-only
  crates depend on tokio features unavailable in WASM.
- **`lattice-protocol` is the wire contract.** Any breaking change to wire
  format requires a version bump and a migration plan, even pre-1.0.

## Versioning policy

Pre-1.0: minor bumps may break wire compatibility, documented in
CHANGELOG.md. Post-1.0: semver strictly. Wire-format version is negotiated
on connect; servers maintain N-1 compatibility for one major version after
a breaking change.
