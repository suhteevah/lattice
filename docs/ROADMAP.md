# Lattice — ROADMAP

Living document. Sequenced by milestone, not by date. Update the **Status**
section as items ship; move shipped milestones into the historical record at
the bottom; cross-reference the **Mitigation index** when a security item
lands.

---

## Status

| Field | Value |
|---|---|
| Current milestone | **M3 — Vertical slice (CLI E2E)** (skeleton shipped 2026-05-11; polish items remain) |
| Last shipped | M2 — MLS + sealed sender + wire types (2026-05-10) |
| Blocker | None |
| Owner | Matt Gates (suhteevah) |

### M3 skeleton shipped 2026-05-11

`scripts\e2e-vertical-slice.ps1` brings up two `lattice-server`
instances on ports 4443/4444 and runs `lattice demo` to drive
Alice (server A) inviting Bob (server B) into a group and
exchanging an MLS-encrypted "hello, lattice". Federation push of
the welcome (A → B's `/federation/inbox`, signed by A's
federation key, TOFU-cached on B) works. Bob fetches the welcome
from B, joins the group, then fetches Alice's message from A
(message-federation push from A → B is still a follow-up; for the
skeleton Bob pulls from the group-owning server directly).

6 of 7 acceptance items from §M3 are met:

- ✅ Two `lattice-server` instances on different ports.
- ✅ Two clients register identity with their respective home servers.
- ✅ Client A creates a 1:1 MLS group with Client B across servers.
- ✅ Client A encrypts the message with the group's MLS state.
- ⚠️ Server A federates ciphertext to Server B — Welcome federation
   works; message-inbox federation is a follow-up.
- ✅ Client B decrypts and prints the plaintext.
- ✅ Structured tracing spans on every step.

Plus the "QUIC" requirement is currently met over HTTPS/HTTP-1.1
via `reqwest`/`axum`; QUIC migration is tracked as an M3 polish
item.

Read [`HANDOFF.md`](HANDOFF.md) §6 for the concrete first vertical slice
this roadmap sequences around. Read [`THREAT_MODEL.md`](THREAT_MODEL.md) for
the threats each milestone's mitigations defend against.

---

## Milestone overview

| ID | Name | Gate | Status |
|---|---|---|---|
| M0 | Scaffold | `cargo check --workspace` green; docs in place | ✅ shipped 2026-05-10 |
| M1 | Crypto primitives | identity + hybrid_kex + aead + padding tested green; no `todo!()` in those modules | ✅ shipped 2026-05-10 |
| M2 | MLS + sealed sender | create-group/invite/send/recv work in unit tests with custom hybrid ciphersuite | ✅ shipped 2026-05-10 |
| M3 | Vertical slice (CLI E2E) | HANDOFF §6 acceptance — two servers, two clients, "hello, lattice" across federation | 🟡 skeleton shipped 2026-05-11; polish items (QUIC, sqlx, per-action CLI, message federation) remain |
| M4 | Web client functional | passkey register → create DM → send → receive in two browser sessions | ⬜ blocked on M3 |
| M5 | V1 feature complete | usable for daily small-group use; sealed sender on every DM; bug bounty open | ⬜ blocked on M4 |
| M6 | V1.5 hardening | KT log + hidden membership + multi-server store-and-forward shipped | ⬜ blocked on M5 |
| M7 | V2 — Tauri + voice/video | native shells reach V1 parity; 1:1 PQ-DTLS-SRTP working | ⬜ blocked on M5 |

M6 and M7 may proceed in parallel after M5; they don't gate each other.

---

## M0 — Scaffold (shipped 2026-05-10)

Workspace, crates, docs, CI, design tokens, dev scripts. See HANDOFF §4.

Acceptance (met):
- `cargo check --workspace` compiles all 7 crate stubs
- `cargo check -p lattice-core --target wasm32-unknown-unknown` compiles
- Strict CSP and SRI tooling in place for `lattice-web`
- Design tokens in `design/tokens/{colors,typography,spacing}.json`
- `docs/{HANDOFF,ARCHITECTURE,THREAT_MODEL,ROADMAP}.md` written

Mitigations landed: workspace-wide `forbid(unsafe_code)`, CI lint gates
(`unwrap_used`, `expect_used`, `panic`, `pedantic`, `nursery`), strict CSP
scaffolding, SRI tooling.

---

## M1 — Crypto primitives

Replace every `todo!()` in `lattice-crypto::{identity,hybrid_kex,aead,padding}`
with audited implementations against the spec lock in HANDOFF §8.

### Deliverables

- **`identity`** — ML-DSA-65 + Ed25519 keypair gen, sign/verify, zeroize-on-drop,
  serde-friendly wire forms. Hybrid signature struct that requires *both* to
  validate.
- **`hybrid_kex`** — X25519 + ML-KEM-768 encap/decap with HKDF-SHA-256
  combiner per HANDOFF §8 + ARCHITECTURE §"Crypto handshake spec". Returns a
  64-byte session secret; KAT vectors in tests.
- **`aead`** — ChaCha20-Poly1305 wrapper with nonce-misuse-resistant nonce
  construction (counter + per-direction prefix). Rejects on AEAD failure
  without timing leak.
- **`padding`** — bucket lookup over `{256, 1024, 4096, 16384, 65536}`. Error
  on overflow.

### Acceptance gate

- `cargo test -p lattice-crypto -- identity hybrid_kex aead padding` green
- `cargo clippy -p lattice-crypto --all-targets -- -D warnings` clean
- Zero `todo!()` / `unimplemented!()` in the four target modules
- Property tests: encrypt-then-decrypt round-trips; sig-then-verify;
  hybrid-kex shared-secret agreement between two synthetic parties
- Known-answer-test vectors for ML-KEM-768 and ML-DSA-65 from FIPS 203/204

### Mitigations landed

- Hybrid X25519 + ML-KEM-768 KEX (harvest-now-decrypt-later)
- ML-DSA-65 identity signatures (future quantum sig forgery)
- Message padding to fixed buckets (size-based traffic analysis)
- `forbid(unsafe_code)` enforcement validated against real code, not just stubs

### Scope guards (NOT in M1)

- MLS — comes in M2
- Sealed sender — comes in M2
- Persistence — comes in M3
- Wire framing — comes in M2

### Decisions locked

See [`DECISIONS.md`](DECISIONS.md) §D-01 (RNG on wasm32), §D-02 (HKDF
info strings), §D-03 (hybrid signature serialization).

### Risks

- ML-KEM-768 / ML-DSA-65 crate maturity is moderate (`ml-kem = 0.2`,
  `ml-dsa = 0.1`). If we hit correctness bugs, fork-and-patch is acceptable
  but adds review burden. Have a fallback to RustCrypto's `pqcrypto` family
  if upstream stalls.

---

## M2 — MLS + sealed sender + protocol wire types

Build the group-key-agreement layer and the wire contract on top of M1's
primitives. **Highest-risk milestone** — the custom hybrid MLS ciphersuite
is non-standard.

### Deliverables

- **`lattice-crypto::mls`** — `mls-rs` wrapper exposing a thin **sync**
  API (sync chosen per implementation research — mls-rs `mls_build_async`
  cfg is workspace-wide; server uses `spawn_blocking`):
  `create_group`, `add_member`, `process_welcome`, `encrypt_app_message`,
  `decrypt_app_message`, `commit`. Custom `CipherSuiteProvider` impl
  wrapping base `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
  (0x0003) per D-04. ML-KEM-768 secret folded into the MLS key
  schedule via **per-epoch external PSK injection** (D-04 re-open
  2026-05-10) — not via `init_secret` rewrite (mls-rs has no public hook
  for that). Reference draft-mahy-mls-xwing for the security pattern;
  the PSK construction is mechanically different but achieves the same
  property of binding the PQ secret into the key schedule under
  HKDF-SHA-256. Fork as M6 fallback if PSK proves inadequate.
- **`lattice-crypto::sealed_sender`** — envelope type that hides sender
  identity from the routing server. Encrypt sender→recipient under a key
  derived from the recipient's current MLS epoch.
- **`lattice-protocol`** — concrete wire types: `IdentityClaim`,
  `KeyPackage`, `Welcome`, `Commit`, `ApplicationMessage`,
  `SealedEnvelope`. Prost-encoded (Cap'n Proto migration deferred to M5).
  Versioned envelope header.

### Acceptance gate

- `cargo test -p lattice-crypto --test mls_integration` covers:
  Alice creates group → invites Bob → both ratchet → both send and
  decrypt cross-direction app messages, no live server involved
- Sealed sender round-trip test with three parties (sender, server, recipient)
  where server never sees plaintext sender ID
- Wire types round-trip through Prost encode/decode with no field loss
- Custom ciphersuite has a written security argument in
  `crates/lattice-crypto/src/mls.rs` doc comment (citing the XWING-style
  construction)

### Mitigations landed

- MLS forward secrecy + post-compromise security (per-message)
- Sealed sender for 1:1 DMs (server learns sender)
- Wire envelope framing + version negotiation (forward compatibility)

### Scope guards (NOT in M2)

- Server endpoints — M3
- Federation — M3
- Persistence — M3
- Aggressive commit cadence policy — M5 (M2 just exposes commit; the
  scheduler comes later)

### Decisions locked

See [`DECISIONS.md`](DECISIONS.md) §D-04 (custom MLS ciphersuite
identifier `0xF000`), §D-05 (sealed sender via Signal-style per-epoch
membership certs).

### Risks

- **Custom MLS ciphersuite is the single biggest correctness risk in the
  project.** Plan a separate audit pass on this module before M5 ship.
- `mls-rs` API surface may not cleanly accept a fully custom ciphersuite;
  research confirmed `CipherSuiteProvider` + `CryptoProvider` are
  sufficient for the signature/AEAD/KDF override path, but the
  `init_secret` rewrite path is not exposed — PSK injection (D-04
  re-open) is the v0.1 workaround. If audit reveals PSK is inadequate,
  M6 vendors a fork of `mls/src/group/key_schedule.rs` with a
  `KeyScheduleHook` patch (~30 lines) as the hardening fallback.

---

## M3 — Vertical slice (CLI E2E)

The acceptance criteria in HANDOFF §6 verbatim. Two servers, two CLI
clients, "hello, lattice" delivered cross-server with full tracing.

### Deliverables

- **`lattice-server`** routes: `/register`, `/key_packages`,
  `/group/{id}/commit`, `/group/{id}/messages`, plus a WebTransport
  endpoint stub (unused by CLI clients, scaffolded for M4)
- **`lattice-server`** federation gossip over QUIC: peer connection
  lifecycle, signed federation messages, replay protection
- **`lattice-server`** Postgres schema per ARCHITECTURE §"Storage model"
  with sqlx migrations
- **`lattice-cli`** subcommands: `register`, `create-group`, `invite`,
  `send`, `recv` (plus `--server-url` and `--identity-path` flags)
- **`lattice-storage`** native-only path: file-backed encrypted store under
  argon2id-derived key. (IndexedDB path comes in M4.)

### Acceptance gate (HANDOFF §6)

1. Two `lattice-server` instances run on different ports
2. Two `lattice-cli` clients register identity with their respective home
   servers
3. Client A creates a 1:1 MLS group with Client B (across servers)
4. Client A encrypts "hello, lattice" with the group's MLS state
5. Server A federates ciphertext to Server B over QUIC
6. Client B decrypts and prints the plaintext
7. All steps emit structured tracing spans; `RUST_LOG=lattice=trace` shows
   the full key-exchange + ratchet flow

Plus:
- `.\scripts\test-all.ps1` green
- A scripted end-to-end test in `scripts/` that brings up two servers,
  registers two CLI clients, and exits 0 on successful message delivery

### Mitigations landed

- Federation distrust signaling (skeleton — full reputation scoring is M5)
- Sealed sender on DM path (server logs do not contain plaintext sender)
- Server stores ciphertext only — schema migrations adding a plaintext
  column fail CI

### Scope guards (NOT in M3)

- Web UI — M4
- Push notifications — M6
- Multi-member groups beyond 1:1 — M5
- File / image attachments — M5
- Aggressive commit cadence scheduler — M5

### Decisions locked

See [`DECISIONS.md`](DECISIONS.md) §D-06 (federation discovery JSON
schema), §D-07 (QUIC server cert handling — `rcgen` dev / ACME prod),
§D-08 (identity persistence via `directories` crate).

### Risks

- QUIC + federation is a lot of moving parts; budget extra time on
  connection-migration edge cases and Postgres reconnection logic
- `mls-rs` async API surface against tokio is non-trivial — be willing to
  buffer where the API is sync

---

## M4 — Web client functional

WASM + storage + UI + transport. Possibly the biggest single milestone.

### Deliverables

- **`lattice-core`** wasm32 build path verified — feature-gate any
  tokio-only utilities; expose a clean async API consumable from JS
- **`lattice-storage`** IndexedDB path: schema per ARCHITECTURE §"Client
  storage"; argon2id KDF over passphrase before any key material decrypts
- **`apps/lattice-web`** UI:
  - WebAuthn / passkey registration flow (PRF extension for KDF salt
    derivation)
  - Group/DM list pane
  - Message list with virtualization
  - Compose box with paste-into-rich (text only in M4)
  - Light/dark toggle (default dark)
  - Settings: identity export, device list, sign out
- **WebTransport client** in `lattice-core` talking to the M3 server
- **`scripts/verify-csp.ps1`** passing on every build

### Acceptance gate

- Browser session A: register passkey on home.alice → create DM with
  Bob's identity-hash (federated lookup) → send "hello, lattice"
- Browser session B: register passkey on home.bob → receive and render
  the message
- Refresh both tabs: state persists; passphrase re-prompt re-derives
  IndexedDB store key via argon2id
- Lighthouse a11y ≥ 95; no CSP violations in browser console; SRI hashes
  validated by `npm run build`

### Mitigations landed

- WebAuthn / passkey root identity
- argon2id-gated IndexedDB store
- Session timeout + key re-derive (default 24h, configurable)
- Strict CSP enforced at runtime, not just at build

### Scope guards (NOT in M4)

- Voice / video — V2 / M7
- Native shells — V2 / M7
- Encrypted push — M6
- Multi-member groups — M5
- File / image attachments — M5

### Decisions locked

See [`DECISIONS.md`](DECISIONS.md) §D-09 (PRF three-tier fallback with
"weaker auth" badge), §D-10 (SW scope `/` with stub push handler),
§D-11 (WT-preferred / WS-fallback negotiation order, cached 24h).

### Risks

- WebAuthn PRF support is uneven across platforms (especially older
  Android). The D-09 fallback covers this but surfaces a visible
  "weaker auth" badge in UI.
- WASM bundle size — keep `lattice-core` wasm binary under 4 MB
  uncompressed by feature-gating server-only code paths

---

## M5 — V1 feature complete

Round out everything users need for daily use of a small federated network.

### Deliverables

- Multi-member MLS groups (N ≥ 2). UI to invite, see roster, leave.
- File + image attachments: encrypted, padded to upload buckets,
  ciphertext stored on home server with retention policy
- Sealed sender on every DM envelope (not just M3's skeleton)
- Device revocation via MLS Remove proposal; UI to list and revoke devices
- Federation distrust scoring algorithm + UI warning badges for sketchy
  peer servers
- Aggressive commit cadence scheduler: every 50 messages OR every 5
  minutes, whichever comes first. Configurable per-server.
- Cap'n Proto migration from Prost (deferred from M2). Wire version bump.
- Bug bounty open; threat model section in user-facing docs

### Acceptance gate

- Self-hosted Lattice network used daily by Matt + 3-5 invitees for ≥ 2
  weeks without state-corruption bugs
- File upload + download round-trips reliably for ≤ 25 MB attachments
- Sealed sender verified by tcpdump of federation traffic: no recipient
  ID visible in plaintext
- Device-revocation flow tested: removed device's epoch keys stop
  working within one commit cycle

### Mitigations landed

- Aggressive MLS commit cadence (server-state-compromise read window)
- Device revocation via MLS Remove proposal (lost/stolen device)
- Federation distrust signaling (full reputation, not just skeleton)
- Sealed sender on every DM path (not just first delivery)

### Scope guards (NOT in M5)

- Key transparency log — M6
- Hidden group rosters — M6
- Encrypted push — M6
- Native shells — M7
- Voice / video — M7

### Decisions locked

See [`DECISIONS.md`](DECISIONS.md) §D-12 (hybrid TTL retention, default
90 days, early-delete on full ack), §D-13 (local-only distrust scoring),
§D-14 (self-hosted disclosure + credit-only bounty for now), §D-24
(per-server admin tools, no global moderation).

### Risks

- Cap'n Proto migration mid-flight may surface schema-evolution bugs that
  Prost masked. Plan one full integration-test sweep dedicated to this.
- Sealed sender + federation distrust + commit cadence all touch the
  server's hot path — performance regression risk; benchmark before each.

---

## M6 — V1.5 hardening

Real engineering lift; next defense tier after V1 stabilizes. Targetable
6-12 weeks post-V1.

### Deliverables

- Key transparency log (CONIKS-style append-only Merkle log) —
  `lattice-keytransparency` crate fleshed out; clients verify inclusion
  proofs on every key-bundle fetch
- Hidden group rosters (MLS hidden-membership extension) — custom
  extension impl in `lattice-crypto::mls`
- Multi-server store-and-forward for federated groups — owning-server
  outage no longer kills the room
- Out-of-band safety numbers (Signal-style fingerprint comparison UI)
- Encrypted push notifications via Web Push API — service worker decrypts
  sealed payload; no metadata visible to push provider

### Acceptance gate

- Silent-key-substitution attack simulated in test: malicious server
  swaps Bob's key bundle; client detects via KT log inclusion check
- Hidden roster test: server inspecting MLS state cannot enumerate group
  members beyond cardinality count
- Federation chaos test: kill owning server mid-conversation; messages
  still deliver via store-and-forward peers within the configured TTL
- Push notification arrives on a locked browser tab, decrypts, renders
  recipient-side preview without exposing content to the push relay

### Mitigations landed

- All four V1.5 entries from the original mitigation matrix below

### Scope guards (NOT in M6)

- Native shells — M7
- Voice / video — M7
- Mixnet routing — long-horizon

### Decisions locked

See [`DECISIONS.md`](DECISIONS.md) §D-15 (Trillian-style append-only log
with cross-server witnessing — not full CONIKS), §D-16 (hidden membership
as private MLS extension, wire bump to v0.2), §D-17 (UnifiedPush primary
+ FCM/APNS fallback).

### Risks

- Trillian-style log is simpler than CONIKS but still real engineering;
  budget conservatively
- Hidden-membership MLS extension may not be cleanly composable with
  the custom hybrid ciphersuite from M2 — verify early

### Fallback work carried from M2

- **mls-rs fork for `KeyScheduleHook`** — contingency from the D-04
  2026-05-10 re-open. M2 ships PSK injection as the PQ-secret folding
  mechanism; if V1 audit finds PSK injection inadequate, M6 vendors
  `mls-rs/src/group/key_schedule.rs` with a ~30-line patch exposing a
  hook on `from_epoch_secret`, then migrates groups by coordinated
  re-key. No action if PSK proves sufficient (which is the expected
  outcome).

---

## M7 — V2 — Tauri shells + voice/video

Parallel-track-able with M6. Native shells unlock hardware-backed keys
and OS keychain integration; voice/video unlocks the "Discord replacement"
positioning.

### Deliverables

- **Tauri desktop** (Win / macOS / Linux) wrapping `lattice-web`'s UI with
  `lattice-core` as a native dependency instead of WASM. Single codebase,
  feature-gated transport (quinn native instead of WebTransport).
- **Tauri mobile** (Android via tauri-mobile-android, iOS via tauri-mobile-ios)
- Hardware-backed key storage:
  - Secure Enclave (macOS, iOS)
  - StrongBox / Android Keystore (Android)
  - TPM 2.0 / Windows Hello (Windows)
- OS-keychain credential storage replacing IndexedDB path on native
- **`lattice-media`** crate: webrtc-rs + custom PQ-DTLS-SRTP handshake;
  1:1 voice and video calls
- Rendezvous node infrastructure (STUN/TURN-like; multi-server with
  rotation) for ICE candidate exchange
- Screen-recording blocking on mobile: `FLAG_SECURE` (Android), iOS
  equivalent
- Optional cover-traffic mode (opt-in toggle, fixed-cadence dummy frames)

### Acceptance gate

- Tauri desktop builds for all three OS targets and reaches V1 feature
  parity (text, files, groups, DM, sealed sender)
- Tauri mobile builds for Android + iOS and reaches V1 feature parity
- 1:1 voice call between Alice (Tauri desktop) and Bob (Tauri mobile)
  completes with PQ-hybrid DTLS-SRTP, audited handshake trace
- Hardware-backed key on each platform: identity private key never leaves
  the secure module; signing operations call into platform API
- Cover-traffic mode emits dummy frames at fixed cadence; user-visible
  toggle in settings

### Mitigations landed

- All V2 entries from the original mitigation matrix below

### Scope guards (NOT in M7)

- Group voice / video (≥ 3 participants) — long-horizon
- Mixnet integration — long-horizon
- Encrypted media transcoding without server seeing plaintext — long-horizon

### Decisions locked

See [`DECISIONS.md`](DECISIONS.md) §D-18 (vendor a fork of `webrtc-dtls`
for PQ-hybrid handshake), §D-19 (self-hosted STUN/TURN per home server,
no relay federation in V2). Tauri vs alternatives: locked at Step 1 per
HANDOFF §2 — do not re-litigate.

### Risks

- Tauri mobile is the youngest part of the Tauri ecosystem; expect
  platform-specific paper cuts
- PQ-DTLS-SRTP has minimal real-world deployment — handshake correctness
  is auditable but interop is non-existent (we control both ends)

---

## Long-horizon — tracked, not committed

Design with these in mind so we don't paint ourselves into a corner. Not
scheduled, not gated.

- **Mixnet routing** (Nym integration) for fully-anonymous metadata mode
- **Anonymous group join** via blind signatures or BBS credentials
- **Duress passphrase** — second passphrase unlocks innocuous decoy state
- **Compulsion-resistant message deletion** — cryptographic forget
- **Distributed federation discovery** (DHT-based) replacing `.well-known`
- **Encrypted media transcoding** server-side without server seeing
  plaintext (homomorphic-style or trusted-enclave; mostly research)
- **Group voice / video** (≥ 3 participants) — sFU vs full-mesh tradeoff
- **PQ-ratchet at the MLS layer** if/when IETF standardizes one

---

## How to mark something done

When a milestone ships:

1. Move its overview-table row to a `## Shipped` block at the bottom of
   this file with the ship date.
2. Move the per-milestone section into that block (truncated to just
   "Deliverables" and "Acceptance gate" — drop scope guards and open
   questions, those are noise post-ship).
3. Update the **Status** section at the top.
4. Update [`HANDOFF.md`](HANDOFF.md) §4 ("Current state").
5. Append commit/PR refs to the milestone block.
6. Update [`THREAT_MODEL.md`](THREAT_MODEL.md) if the threat model
   changes.
7. In the **Mitigation index** below, change each item's status column.

When a *mitigation* ships (without a whole milestone):

1. Cross-reference the milestone it shipped under in the index.
2. Append a one-line note to the milestone block.
3. Note any deviation from the original plan.

---

## Mitigation index — full matrix

Preserved from the prior version of this doc. Cross-referenced to
milestones so you can search by either axis.

### V1 — MVP (browser-only, text + images + files)

| Mitigation | Defends against | Lands in | Where it lives |
|---|---|---|---|
| Aggressive MLS commit cadence — every 50 msgs OR 5 min | Server-state compromise reading new messages | M5 | `lattice-crypto` background task |
| Sealed sender for 1:1 DMs | Server learning sender identity in DMs | M3 (skeleton) / M5 (universal) | `lattice-protocol` envelope |
| Message padding to fixed buckets (256B / 1KB / 4KB / 16KB / 64KB) | Size-based traffic analysis | M1 | Pre-AEAD in `lattice-protocol` |
| Strict CSP — no `unsafe-eval`, no `unsafe-inline`, allowlisted origins | Browser XSS / extension injection | M0 (build) / M4 (runtime) | `apps/lattice-web` HTTP headers + CI check |
| SRI hashes on every external script | Tampered CDN delivery | M0 (build) / M4 (runtime) | Build step pins; CI fails on miss |
| WebAuthn / passkey root identity | Browser key extraction | M4 | Root key never leaves authenticator; messaging keys derived |
| argon2id-gated IndexedDB store | Stolen device cold attack | M4 | Passphrase → KDF → store key |
| Session timeout + key re-derive (default 24h) | Stolen device warm attack | M4 | Memory wipe on inactivity |
| Device revocation via MLS Remove proposal | Lost or stolen device | M5 | Any sibling device can issue |
| Federation distrust signaling | Misbehaving / captured peer server | M3 (skeleton) / M5 (scoring) | Reputation tracking + user warning badges |
| Hybrid X25519 + ML-KEM-768 KEX | Harvest-now-decrypt-later | M1 | `lattice-crypto::hybrid_kex` |
| ML-DSA-65 identity signatures | Future quantum signature forgery | M1 | `lattice-crypto::identity` |
| `forbid(unsafe_code)` workspace-wide (except documented FFI) | Memory-safety bugs | M0 | Lint enforced in CI |

### V1.5 — Hardening pass (target: 6-12 weeks post-V1)

| Mitigation | Defends against | Lands in | Where it lives |
|---|---|---|---|
| Key transparency log (CONIKS-style append-only Merkle log) | Silent key substitution by malicious server | M6 | `lattice-keytransparency` — clients verify inclusion proofs |
| Hidden group rosters (MLS hidden-membership extension) | Server learning who's in a group | M6 | `lattice-crypto` MLS extension impl |
| Multi-server store-and-forward for federated groups | Single-server DoS | M6 | `lattice-server` federation layer |
| Out-of-band safety numbers (Signal-style fingerprint) | MITM during first contact | M6 | UI verification flow in `lattice-web` |
| Encrypted push notifications (Web Push API) | Push provider seeing message metadata | M6 | Service worker + sealed payload |

### V2 — Voice/video + native shells (Tauri desktop + mobile)

| Mitigation | Defends against | Lands in | Where it lives |
|---|---|---|---|
| PQ-DTLS-SRTP for voice/video | Voice stream interception | M7 | `lattice-media` via `webrtc-rs` + hybrid handshake |
| Hardware-backed keys (Secure Enclave / StrongBox / TPM) | Native client compromise | M7 | Tauri platform plugins; replaces WebAuthn path on native |
| Rendezvous node rotation + reputation | STUN/TURN operator traffic analysis | M7 | Multi-rendezvous picker in `lattice-media` |
| Optional cover-traffic mode | Timing-correlation attacks | M7 | Opt-in toggle, fixed-cadence dummy frames |
| OS-keychain-backed credential storage | Native client cold compromise | M7 | Replaces IndexedDB path on desktop/mobile |
| Screen-recording / screenshot blocking on mobile | Compromised OS-level screen capture | M7 | Platform APIs (FLAG_SECURE on Android, equivalent on iOS) |

---

## Shipped

### M2 — MLS + sealed sender + wire types (2026-05-10)

**Commits:** `fe8868e..2688b78` (11 commits on `main`).

Deliverables landed:

- `lattice-crypto::credential::LatticeCredential` (CredentialType
  `0xF001`) — user_id + Ed25519 + ML-DSA-65 packed credential,
  MLS-codec serialized.
- `lattice-crypto::mls::identity_provider::LatticeIdentityProvider` —
  `mls_rs_core::identity::IdentityProvider` impl. Validates
  signing_identity / credential binding, reports user-level identity
  (not device-level) so device rotation works via `valid_successor`.
- `lattice-crypto::mls::cipher_suite::LatticeHybridCipherSuite` —
  `CipherSuiteProvider` for ciphersuite `0xF000`
  (`LATTICE_HYBRID_V1`), wrapping base `0x0003` for KDF/AEAD/HPKE/KEM
  and overriding the four signature methods for packed hybrid
  Ed25519+ML-DSA-65.
- `lattice-crypto::mls::psk` — deterministic per-epoch `ExternalPskId`
  derivation + in-memory `LatticePskStorage`.
- `lattice-crypto::mls::leaf_node_kem` — `LatticeKemPubkey` MLS
  extension (id `0xF002`) carrying an ML-KEM-768 encapsulation key,
  plus per-device `KemKeyPair`. Attached at the KeyPackage level
  (`pub` `extensions` field) since `KeyPackage::leaf_node` is
  `pub(crate)` in mls-rs 0.55.
- `lattice-crypto::mls::welcome_pq` — `PqWelcomePayload` MLS
  extension (id `0xF003`) carrying a per-joiner ML-KEM ciphertext +
  epoch, with `seal_pq_secret` / `open_pq_secret` helpers.
- `lattice-crypto::mls` — high-level group ops: `create_group`,
  `generate_key_package`, `add_member`, `process_welcome`,
  `encrypt_application`, `decrypt`, `commit`, `apply_commit`.
  `GroupHandle` wraps `mls_rs::Group<LatticeMlsConfig>` plus the
  caller's PSK storage.
- `lattice-protocol::wire` — Prost-encoded `HybridSignatureWire`,
  `IdentityClaim`, `MembershipCert`, `SealedEnvelope`, `KeyPackage`,
  `Welcome`, `Commit`, `ApplicationMessage` + encode/decode helpers.
- `lattice-protocol::sig` — re-exports `HybridSignature` +
  `HybridSignatureWire` per D-03.
- `lattice-protocol::sealed_sender` — `seal` / `verify_at_router` /
  `open_at_recipient` / `issue_cert` per D-05. Plain Ed25519
  sign/verify (ed25519-dalek) over canonical Prost transcript bytes
  derived from inline `MembershipCertTbs` / `SealedEnvelopeTbs`
  structs.

Acceptance met:

- `cargo test --workspace`: **109 tests pass** (90 lattice-crypto + 19
  lattice-protocol). Integration test
  `lattice-crypto::tests::mls_integration` covers the M2 acceptance
  gate: Alice creates group → Bob publishes KeyPackage → Alice adds
  Bob (commit + PQ Welcome) → Alice applies commit → Bob joins via
  Welcome → cross-direction "hello, lattice" / "hello, alice"
  round-trip decrypts cleanly. Plus forward-secrecy, in-order
  ratchet, tampered-message rejection, deterministic PSK id matching.
- Sealed-sender 3-party tests confirm the routing server can verify
  authenticity without learning sender identity.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo fmt --all -- --check`: clean.
- `cargo check -p lattice-core --target wasm32-unknown-unknown
  --features lattice-crypto/wasm`: clean.
- Zero `todo!()` / `unimplemented!()` / `Error::*(_ not implemented)`
  in `lattice-crypto::mls::*` or `lattice-protocol::sealed_sender`.

Mitigations landed:

- MLS forward + post-compromise secrecy via the standard MLS commit
  ratchet, with the PQ secret folded in at each epoch via external
  PSK (D-04 2026-05-10 amendment — see DECISIONS.md).
- Sealed sender (skeleton, per M3 acceptance distinction) — routing
  servers can verify member-authenticity without learning sender
  identity. Universal-on-every-DM tightening is M5.
- Wire envelope framing + version negotiation: `WIRE_VERSION = 1`
  pinned in `lattice-protocol`.

Decisions taken during M2:

- **D-04 re-opened 2026-05-10** — PSK injection chosen over the
  original `init_secret`-folding construction. Fork-mls-rs path
  retained as M6 hardening fallback.
- **D-05 implementation pointer** — types live in
  `lattice-protocol::wire`, logic in `lattice-protocol::sealed_sender`
  (per the Phase F architecture decision). The original
  `lattice-crypto::sealed_sender` module was deleted as dead code
  along with the dead `HKDF_SEALED_SENDER` /
  `HKDF_SEALED_SENDER_MAC` D-02 constants (no inner-envelope key
  derivation, no HMAC under D-05).
- **Dep stack pinned to mls-rs 0.55 / mls-rs-core 0.27 /
  mls-rs-crypto-rustcrypto 0.22 / mls-rs-codec 0.7.** Required to
  resolve transitive version skew on `mls-rs-core` and
  `mls-rs-codec` that left `CryptoProvider` and
  `MlsCodecExtension` trait bounds unsatisfied across crate-version
  boundaries.

### M1 — Crypto primitives (2026-05-10)

`lattice-crypto::{constants, padding, aead, identity, hybrid_kex}` all
implemented with audited construction. MLS + sealed sender deferred to M2
as planned.

Acceptance met:
- `cargo test -p lattice-crypto`: 31 unit tests green (no
  `todo!()` / `unimplemented!()` in target modules)
- `cargo clippy -p lattice-crypto --all-targets -- -D warnings`: clean
- Property tests: sign/verify round-trip, AEAD encrypt/decrypt round-trip,
  hybrid encap/decap agreement
- Size pins verified: ML-DSA-65 sig 3309 B, pk 1952 B; ML-KEM-768 ek 1184
  B, dk 2400 B, ct 1088 B; Ed25519 sig 64 B, pk 32 B; X25519 keys 32 B
- Deterministic-from-seeded-RNG tests for identity + hybrid_kex
- HKDF info strings pinned in `lattice-crypto::constants` (D-02)

Mitigations: hybrid X25519 + ML-KEM-768 KEX (harvest-now-decrypt-later);
ML-DSA-65 identity signatures (future quantum sig forgery); message
padding to fixed buckets (size-based traffic analysis);
`forbid(unsafe_code)` validated against real implementation, not just stubs.

Workspace dep pinned: `ml-dsa = "=0.1.0-rc.11"` (no stable 0.1.0 release
yet). Bumps require explicit re-pin.

### M0 — Scaffold (2026-05-10)

Workspace, crate stubs, docs, CI, design tokens, dev scripts. See HANDOFF
§4 "Done" list for the full enumeration.

Acceptance met:
- `cargo check --workspace` green
- `cargo check -p lattice-core --target wasm32-unknown-unknown` green
- `.github/workflows/ci.yml` runs check / fmt / clippy / test / wasm32 / audit

Mitigations: workspace-wide `forbid(unsafe_code)`, CI lint gates, strict
CSP scaffolding, SRI tooling.
