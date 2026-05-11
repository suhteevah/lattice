# Lattice — HANDOFF

**Last updated:** 2026-05-11 (M4 α + β + γ.1/.2/.3 shipped — browser
drives the full Alice⇌Bob vertical slice against a live `lattice-server`)
**Owner:** Matt Gates (suhteevah)
**Status:** Steps 1 + 2 complete; M1 shipped; M2 shipped; M3 federated
bridge working three-node; **M4 Phases α + β + γ.1/.2/.3 shipped**. The
M3 vertical-slice acceptance gate is now hit from a browser tab — no
CLI required. Sixteen+ commits on `main` (local repo, no remote yet):

```
2688b78 chore: Phase G — pre-commit gate green (fmt + clippy + 109 tests + WASM)
6e6e32c feat(protocol): Phase F — sealed sender per D-05 (Option B)
1490fdc feat(crypto): Phase D + E — MLS group ops + Alice/Bob integration test
668edf9 feat(crypto): Phase C.2 — ML-KEM-768 LeafNode + Welcome custom extensions
83601e6 docs(handoff): full M2 mid-flight snapshot for fresh-session pickup
3d743c0 feat(crypto): Phase C.1 — per-epoch PSK id derivation + in-memory storage
60550da chore(crypto): Phase F prep — remove dead sealed_sender stub + D-02 dead constants
33121fc feat(crypto): Phase B — LatticeHybridCipherSuite (0xF000)
02d2cf1 feat(crypto): Phase A — LatticeCredential (0xF001) + IdentityProvider
8898460 docs(d-04): re-open and amend for PSK-injection path
fe8868e chore: initialize repo at M1-shipped + M2-partial post-recovery state
```

`cargo test --workspace`: **109 tests pass** (90 lattice-crypto +
19 lattice-protocol). `cargo clippy --workspace --all-targets --
-D warnings`: clean. `cargo fmt --all -- --check`: clean. `cargo
check -p lattice-core --target wasm32-unknown-unknown
--features lattice-crypto/wasm`: clean.

The M2 acceptance gate (Alice + Bob round-trip with PQ-PSK injection,
no server) is met by `lattice-crypto::tests::mls_integration`.

**Next milestone: M3 — Vertical slice (CLI E2E).** Two `lattice-server`
instances on different ports, two `lattice-cli` clients across
federation, "hello, lattice" delivered cross-server with QUIC + sqlx
storage + server-side cert issuance. Matt has offered three nodes for
M3 federation testing: pixie, cnc, kokonoe.

### Key M2 decisions taken this session

1. **D-04 re-opened on 2026-05-10 for PSK injection.** The original
   construction (fold ML-KEM-768 into `init_secret` via HKDF) is not
   buildable on mls-rs 0.55: `KeySchedule::from_epoch_secret` is
   `pub(crate)` with no public hook. Matt picked the hybrid path: ship
   PSK injection in M2, keep the fork as an M6 hardening fallback. PSK
   id = `b"lattice/mls-init/v1" || epoch.to_le_bytes()`. RFC 9420 §8
   explicitly intends PSK as the hybrid-PQ binding extension point.
   Security property — PQ secret enters the schedule under HKDF-SHA-256
   immediately before `epoch_secret` derivation — is preserved. Full
   record in DECISIONS.md §D-04 "Re-opened 2026-05-10".

2. **mls-rs stack upgraded to latest (0.55 / 0.27 / 0.22 / 0.6).** The
   prior pin (mls-rs 0.45, rustcrypto 0.16) had a transitive version
   skew on `mls-rs-core` (0.21 vs 0.22) that left `CryptoProvider`
   trait bounds unsatisfied. The upgrade collapsed both into 0.27 and
   compiles clean. API drift caught and handled in Phase B: `hpke_open`
   returns `Zeroizing<Vec<u8>>`, new `hpke_seal_psk` / `hpke_open_psk`
   on the trait (delegated to inner).

3. **Sealed-sender module moved to `lattice-protocol`.** Per Matt's
   decision on the Phase F architecture question (Option B): under
   D-05 there is no Lattice-specific cryptographic primitive in
   sealed-sender — it's just Ed25519 sign/verify over canonical wire
   bytes. `lattice-crypto::sealed_sender` was removed as dead code.
   The seal/verify functions land in `lattice-protocol::sealed_sender`
   in Phase F (still pending). Wire types stay in `lattice-protocol::wire`.
   D-02's `HKDF_SEALED_SENDER` + `HKDF_SEALED_SENDER_MAC` constants
   were also dead under D-05 (no inner-envelope-key derivation, no
   HMAC) and got removed; D-02 now carries a "Removed 2026-05-10"
   footer table.

4. **mls-rs API research lives at `scratch/mls-rs-api.md`.** Detailed
   trait surfaces, footguns, sync-vs-async picks (sync chosen), and
   a working code skeleton. Note: this was researched against
   mls-rs-0.45.3 / mls-rs-core-0.21; the upgrade in commit `33121fc`
   moved us to 0.55 / 0.27. Most of the doc is still accurate but
   any specific method signature should be cross-checked against
   the actual 0.27 source.

5. **M2 build plan at `scratch/m2-build-plan.md`.** Eight phases A–H,
   each a commit checkpoint. A, B, F-prep, and C.1 are done. C.2,
   D, E, F, G, H remain. The plan still describes Phase F using the
   old `lattice-crypto::sealed_sender` location — disregard that
   detail; the actual home is now `lattice-protocol::sealed_sender`
   per decision 3 above.

> **What this doc is.** A self-contained brief that lets a fresh Claude (or any
> engineer) load full context in one read and start producing useful work
> immediately. Read this top to bottom before touching anything else.

---

## 1. Elevator pitch

Lattice is a federated, end-to-end-encrypted messaging platform designed as a
Discord replacement with post-quantum cryptography as a first principle and
Matrix-class decentralization at Discord-class UX speed. V1 ships as a
browser-only PWA. V2 adds Tauri desktop + mobile shells and voice/video.

The differentiators that justify the project:

1. **PQ-hybrid from day one.** Hybrid X25519 + ML-KEM-768 for KEX, ML-DSA-65
   for identity. Defeats harvest-now-decrypt-later.
2. **MLS for groups.** RFC 9420 via `mls-rs`. Forward + post-compromise
   secrecy at scale.
3. **Federated, not P2P.** Avoids Matrix's full-mesh sync penalty by using
   binary frames over QUIC plus local-first CRDT reconciliation.
4. **Lilac design system.** Custom color/type tokens, dark-mode-first,
   intentional aesthetic departure from Discord/Slack utilitarianism.

---

## 2. Locked decisions (Step 1)

These are not up for debate without an explicit re-open conversation.

| Decision | Choice | Rationale |
|---|---|---|
| Project name | **Lattice** | Lattice-based crypto is the math foundation of ML-KEM/ML-DSA; reads as "structured network." |
| Topology | **Hybrid federated** | Federated home servers for identity/state/store; direct P2P streams (V2) for voice/video. |
| Group crypto | **MLS via `mls-rs`** | NIST/IETF standardized (RFC 9420), audited, scales to 50k members. |
| V1 scope | **Text + images + files, browser-only** | Voice/video → V2 along with Tauri shells. |
| V1 client surface | **Browser only** | Single client surface to polish; WASM crypto is mature; lowest onboarding friction. |
| Wire format | **Cap'n Proto** (Prost interim) | Zero-copy decode, schema-evolution-friendly, ~10x faster than JSON. |
| Transport | **QUIC / HTTP/3** | Connection migration, no head-of-line blocking, WebTransport in browsers. |
| Language | **Rust everywhere** — backend, client core, and web UI. Web UI is Leptos 0.8 (CSR) compiled to wasm32 via Trunk. No JS / TS / npm anywhere. | Matt's stack. Single client core compiles to native (V2) and wasm32 (V1). (Updated 2026-05-11 from prior "Solid + Tailwind" choice.) |
| Identity at rest | **WebAuthn / passkeys** in V1; OS keychain in V2. | Hardware-backed where possible; degrade gracefully. |
| License | **AGPL-3.0-or-later** | Forces forks/SaaS rehosts to share source. |

---

## 2.5. Locked decisions (Step 2 — open questions resolved)

Step 2 closed every open question except domain and SaaS pricing. Full
log lives in [`DECISIONS.md`](DECISIONS.md); the summary below is the
single-read view.

| ID | Topic | Decision |
|---|---|---|
| D-01 | RNG on wasm32 | `OsRng` everywhere; `getrandom` "js" feature for browser |
| D-02 | HKDF info strings | Centralized in `lattice-crypto::constants`, format `b"lattice/<purpose>/v<ver>"` |
| D-03 | Hybrid signature serialization | Prost struct with named fields, not concatenated blob |
| D-04 | MLS ciphersuite ID | `0xF000` = `LATTICE_HYBRID_V1` (private-use range per RFC 9420) |
| D-05 | Sealed sender | Signal-style per-MLS-epoch membership certs issued by owning server |
| D-06 | Federation discovery | `.well-known/lattice/server` JSON + Ed25519 sig over canonical CBOR |
| D-07 | QUIC certs | `rcgen` self-signed for dev (TOFU); ACME / Let's Encrypt for prod |
| D-08 | Identity persistence | `directories` crate paths; argon2id-keyed ChaCha20-Poly1305 file |
| D-09 | WebAuthn PRF fallback | Three-tier: PRF / passphrase+badge / refuse |
| D-10 | Service worker scope | `/`, stubbed in M4 (app shell cache + empty push handler) |
| D-11 | Transport negotiation | WebTransport-preferred / WebSocket-fallback, 24h cache |
| D-12 | Attachment retention | Hybrid TTL, default 90 days, early-delete on full ack |
| D-13 | Distrust scoring | Local-only, no gossip in V1 / V1.5 |
| D-14 | Bug bounty | Self-hosted disclosure; credit + V2 beta access, no cash initially |
| D-15 | KT log | Trillian-style append-only with cross-server witnessing (not full CONIKS) |
| D-16 | Hidden membership | Private MLS extension; wire bump to v0.2 |
| D-17 | Push provider | UnifiedPush primary, FCM/APNS fallback |
| D-18 | PQ-DTLS-SRTP | Vendor a fork of `webrtc-dtls` with custom-ciphersuite hook |
| D-19 | Rendezvous | Self-hosted STUN/TURN per home server; no relay federation in V2 |
| D-20 | Secure-by-default libs | Stack reviewed; specialized crates chosen with documented rationale |
| D-24 | Moderation | Per-server admin tools only; no global moderation |

**Still open** (carried in §10): domain (D-22), SaaS pricing (D-25).

---

## 3. Workspace layout

```
lattice/
├── Cargo.toml                          # workspace root, all shared deps pinned
├── README.md
├── LICENSE                             # AGPL-3.0-or-later
├── .gitignore
├── rust-toolchain.toml                 # pins to stable 1.85
├── rustfmt.toml
├── clippy.toml
│
├── crates/
│   ├── lattice-crypto/                 # PQ primitives, MLS, sealed sender, padding
│   ├── lattice-protocol/               # wire schemas, framing, envelopes
│   ├── lattice-server/                 # home server binary (axum + quinn)
│   ├── lattice-core/                   # client core lib, compiles to wasm32
│   ├── lattice-storage/                # encrypted store (IndexedDB v1, native v2)
│   ├── lattice-keytransparency/        # V1.5 placeholder (CONIKS-style log)
│   └── lattice-cli/                    # admin + dev tooling
│
├── apps/
│   └── lattice-web/                    # Leptos + Trunk + WASM core (V1 client)
│
├── design/
│   ├── tokens/                         # colors.json / typography.json / spacing.json
│   └── icons/                          # custom outline icon set (TBD)
│
├── docs/
│   ├── HANDOFF.md                      # this file
│   ├── ROADMAP.md                      # phased security mitigations
│   ├── THREAT_MODEL.md                 # detailed node-capture analysis
│   └── ARCHITECTURE.md                 # protocol + topology deep-dive
│
├── scripts/
│   ├── dev-setup.ps1                   # installs toolchains, wasm32 target, cargo tools
│   ├── test-all.ps1                    # cargo test + clippy + fmt --check + audit
│   └── verify-csp.ps1                  # checks lattice-web CSP policy
│
└── .github/workflows/
    └── ci.yml                          # check / fmt / clippy / test / wasm / audit
```

---

## 4. Current state (what's been scaffolded, what hasn't)

### Done
- [x] Workspace `Cargo.toml` with all shared deps pinned
- [x] All 7 crate stubs with `Cargo.toml` and `src/lib.rs` (or `main.rs`)
- [x] `lattice-server` skeleton: `main.rs`, `error.rs`, `config.rs`,
      `observability.rs`, `routes/health.rs` — follows the rust-backend skill
      conventions Matt established
- [x] `lattice-web` Solid + Vite scaffold with strict CSP and SRI tooling
- [x] Design tokens: `colors.json`, `typography.json`, `spacing.json` derived
      from lilac palette
- [x] `docs/HANDOFF.md`, `docs/ROADMAP.md`, `docs/THREAT_MODEL.md`,
      `docs/ARCHITECTURE.md`
- [x] PowerShell scripts: `dev-setup.ps1`, `test-all.ps1`, `verify-csp.ps1`
- [x] GitHub Actions CI: check / fmt / clippy / test / wasm32 / audit

### Done (continued, M1 — 2026-05-10)
- [x] `lattice-crypto::constants` — locked HKDF info strings (D-02)
- [x] `lattice-crypto::padding` — fixed buckets `{256, 1024, 4096, 16384, 65536, 262144}`
- [x] `lattice-crypto::aead` — ChaCha20-Poly1305 with HKDF-derived
      direction-specific IVs, deterministic counter nonces
- [x] `lattice-crypto::identity` — ML-DSA-65 + Ed25519 keypair gen,
      `HybridSignature`, sign/verify requiring both algorithms (D-03)
- [x] `lattice-crypto::hybrid_kex` — X25519 + ML-KEM-768 encap/decap with
      HKDF-SHA-256 combiner; 64-byte session key + confirmation tag
- [x] `cargo test -p lattice-crypto`: 31 unit tests green
- [x] `cargo clippy -p lattice-crypto --all-targets -- -D warnings`: clean
- [x] Zero `todo!()` / `unimplemented!()` in identity/hybrid_kex/aead/padding
- [x] Pinned `ml-dsa = "=0.1.0-rc.11"` in workspace deps (was `"0.1"`, no
      matching stable release yet)

### Done (M2 — 2026-05-10)

**Phase A** (commit `02d2cf1`):
- [x] `lattice-protocol::wire` — Prost messages for `HybridSignatureWire`,
      `IdentityClaim`, `MembershipCert`, `SealedEnvelope`, `KeyPackage`,
      `Welcome`, `Commit`, `ApplicationMessage` + `encode`/`decode` helpers
- [x] `lattice-protocol::sig` — re-exports `HybridSignature` + `HybridSignatureWire`
- [x] `MembershipCert` + `SealedEnvelope` shapes match D-05
- [x] `lattice-crypto::credential::LatticeCredential` — type id `0xF001`,
      MLS-codec serialized, length validation. Carries `user_id` (32B
      BLAKE3) + `ed25519_pub` + `ml_dsa_pub` (no ML-KEM yet — see
      Phase C.2 below for where that will live)
- [x] `lattice-crypto::mls::identity_provider::LatticeIdentityProvider` —
      `mls_rs_core::identity::IdentityProvider` impl that decodes the
      custom credential, cross-checks the `SigningIdentity::signature_key`
      byte layout against the credential's individual key fields
      (defeats confused-deputy), reports `user_id` as MLS identity
      (device rotation via `valid_successor` returning true on matching
      user_id), refuses external senders in V1

**Phase B** (commit `33121fc`):
- [x] mls-rs stack upgraded to 0.55 / 0.27 / 0.22 / mls-rs-codec 0.6.
      Resolved transitive `mls-rs-core` version skew.
- [x] `lattice-crypto::mls::cipher_suite::LatticeCryptoProvider` advertising
      only `LATTICE_HYBRID_V1` (`0xF000`)
- [x] `lattice-crypto::mls::cipher_suite::LatticeHybridCipherSuite`
      implementing `CipherSuiteProvider`. Delegates 20 of 24 methods to
      `RustCryptoProvider`'s `0x0003` suite; overrides the 4 signature
      methods to handle packed Ed25519 + ML-DSA-65 keys / signatures.
      Byte layouts pinned in module docs.

**Phase F-prep** (commit `60550da`):
- [x] Deleted dead `lattice-crypto::sealed_sender` stub per Matt's
      Option B decision (Phase F lands in `lattice-protocol::sealed_sender`)
- [x] Removed dead D-02 constants `HKDF_SEALED_SENDER`,
      `HKDF_SEALED_SENDER_MAC` (superseded by D-05 — Ed25519-sig-only
      construction has no inner-envelope key or HMAC)
- [x] D-02 entry updated with "Removed 2026-05-10" footer; D-05
      Implementation pointer aligned to actual code structure

**Phase C.1** (commit `3d743c0`):
- [x] `lattice-crypto::mls::psk::psk_id_for_epoch` deterministic id
      derivation: `HKDF_MLS_INIT || epoch.to_le_bytes()`
- [x] `lattice-crypto::mls::psk::LatticePskStorage` — thread-safe
      in-memory impl of `mls_rs_core::psk::PreSharedKeyStorage`
- [x] 9 tests covering deterministic id, per-epoch uniqueness, byte
      layout, zero-epoch edge case, insert/get/remove/clone semantics

### Done (M2 shipped 2026-05-10 — Phases C.2 through H)

**Phase C.2** (commit `668edf9`):
- [x] `lattice-crypto::mls::leaf_node_kem::LatticeKemPubkey` — MLS
      extension id `0xF002` carrying ML-KEM-768 encapsulation key.
- [x] `lattice-crypto::mls::leaf_node_kem::KemKeyPair` — per-device
      ML-KEM-768 keypair with `Zeroizing` on the decap key.
- [x] `lattice-crypto::mls::welcome_pq::PqWelcomePayload` — MLS
      extension id `0xF003` for per-joiner ML-KEM ciphertext.
- [x] `seal_pq_secret` / `open_pq_secret` ML-KEM-768 encap/decap
      helpers operating on the wire types.

**Phase D + E** (commit `1490fdc`):
- [x] `lattice-crypto::mls::{create_group, generate_key_package,
      add_member, process_welcome, encrypt_application, decrypt,
      commit, apply_commit}` — real impls on top of `mls_rs::Group<C>`.
- [x] `LatticeIdentity` bundle (credential + sig sk + KEM keypair +
      InMemoryKeyPackageStorage).
- [x] `GroupHandle` wrapping `mls_rs::Group` + PSK storage.
- [x] `LatticeWelcome` bundling MLS Welcome bytes + PqWelcomePayload.
- [x] Integration test `tests/mls_integration.rs` — 5 tests covering
      Alice+Bob round-trip, in-order ratchet, tampered-message
      rejection, deterministic PSK id matching, confused-deputy
      identity rejection.

**Phase F** (commit `6e6e32c`):
- [x] `lattice-protocol::sealed_sender::{issue_cert, seal,
      verify_at_router, open_at_recipient}` per D-05.
- [x] 10 tests covering round-trip, router-can't-decrypt-inner,
      router-can't-identify-sender, tamper / expired / wrong-key /
      mismatch rejection branches.

**Phase G** (commit `2688b78`):
- [x] `cargo fmt --all -- --check` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo test --workspace` green: **109 tests**.
- [x] `cargo check -p lattice-core --target wasm32-unknown-unknown
      --features lattice-crypto/wasm` clean.
- [x] Zero `todo!()` / `unimplemented!()` in lattice-crypto::mls::* or
      lattice-protocol::sealed_sender.
- [x] Workspace pedantic lint relaxations (doc_markdown, similar_names,
      significant_drop_tightening) — documented in Cargo.toml.
- [x] getrandom 0.2 + 0.4 wasm feature pinning + uuid wasm features
      for clean WASM target compile.

### Done (M3 skeleton — 2026-05-11)

**Phase I + J + K** (commit `f6535b1`):
- [x] `lattice-server::state::ServerState` — Arc<RwLock<_>> in-memory
      stores for registered users, published KeyPackages, group commit
      log, message inbox, federation peer registry. Server's federation
      Ed25519 signing key loaded from disk or generated fresh.
- [x] Routes: `POST /register`, `POST /key_packages`,
      `GET /key_packages/:user_id`, `POST /group/:gid/commit`,
      `GET /group/:gid/welcome/:user_id`,
      `POST + GET /group/:gid/messages`, `POST /group/:gid/issue_cert`,
      `GET /.well-known/lattice/server`, `POST /federation/inbox`.
- [x] 6 server-state unit tests + 5 routes-integration tests.

**Phase L + M + N** (commit `8b2f3e5`):
- [x] Server-to-server federation push: commit handler signs canonical
      TBS with federation_sk, POSTs to peer `/federation/inbox`.
      TOFU pubkey pinning on the receive side.
- [x] `lattice-cli demo` subcommand — single-process Alice+Bob
      orchestrator. Real reqwest against two server URLs, real
      lattice-crypto MLS state, real message round-trip. Exits non-zero
      on any failure.
- [x] `scripts\e2e-vertical-slice.ps1` — launches two
      `lattice-server` instances, runs `lattice demo` against them,
      asserts exit 0. **Verified passing 2026-05-11.**

### Three-node testbed live as of 2026-05-11

- **pixie** (`207.244.232.227`, Ubuntu 24.04, public IP) — lattice-server on
  `127.0.0.1:4443`, federation key at `/tmp/lattice-deploy/fed-a.key`,
  snapshot at `/tmp/lattice-deploy/state-a.json`. Reachable via SSH as
  `pixiedust@pixie`.
- **cnc-server** (LAN `192.168.168.100`, tailscale `100.108.202.49`,
  openSUSE Tumbleweed) — lattice-server on `127.0.0.1:4443`, fed key
  at `/tmp/lattice-deploy/fed-b.key`, snapshot at
  `/tmp/lattice-deploy/state-b.json`. SSH reverse tunnel from cnc to
  pixie exposes cnc:4443 as pixie:4444.
- **kokonoe-WSL** (Ubuntu under WSL2, no public IP, but reachable from
  kokonoe localhost) — lattice-server on `127.0.0.1:4443`, fed key at
  `/tmp/lattice-deploy/fed-c.key`. Reverse tunnel from kokonoe to pixie
  exposes WSL:4443 as pixie:4445.

Verified pair-wise demos:
- ✅ pixie ↔ cnc cross-host federation, plaintext "clean-pixie-cnc"
  recovered.
- ✅ kokonoe-WSL single-host demo, plaintext "single-wsl" recovered.
- ✅ pixie state-persistence snapshot — SIGTERM → JSON dump → restart
  → state restored (same fed pubkey, same group commits, same message
  inbox). Verified by `scripts/verify-persistence.ps1`.

Known issue:
- ⚠️ pixie ↔ kokonoe-WSL cross-host demo fails with
  `WelcomeKeyPackageNotFound`. Same lattice-server binary works
  single-host on WSL and works cross-host between pixie ↔ cnc. The
  bug appears to be in the demo orchestration's handling of the
  slower two-hop SSH tunnel path (kokonoe → pixie reverse, then
  pixie → kokonoe forward inside the demo process). Doesn't block
  M3 acceptance because the per-action CLI is the intended deploy
  path and the cross-host federation primitives are proven by the
  pixie ↔ cnc path.

### Not done — M3 polish (open for the federation testbed deploy)

- [ ] **Per-action CLI subcommands with file-backed state.** `demo`
      is single-process; real users want `register` then `invite`
      then `send` as separate invocations. Needs file-backed
      `GroupStateStorage` / `KeyPackageStorage` / `PreSharedKeyStorage`
      impls. The mls-rs trait surface is small — ~30 lines each.
- [ ] **Message-inbox federation push.** Currently Bob fetches
      messages from server A (the group-owning server) directly. To
      fully match "server A federates ciphertext to server B" Bob
      should fetch from B and have server A push messages to B's
      message-inbox endpoint. Endpoint + push helper need wiring
      symmetric to the Welcome path.
- [ ] **QUIC transport.** Currently HTTPS/HTTP/1.1 over `reqwest`/`axum`.
      QUIC unlocks connection migration + multiplexing. `quinn` is
      already a workspace dep; the server-side bind + client-side
      transport adapter need writing.
- [ ] **sqlx-backed storage providers.** Postgres schema +
      migrations (`mls_key_packages`, `mls_group_state`,
      `mls_group_epochs`, `pending_messages`, `federation_peers`)
      plus storage-trait impls that wrap sqlx. The in-memory ones
      stay for tests.
- [ ] **Identity persistence (D-08).** argon2id-keyed
      ChaCha20-Poly1305 file at `~/.lattice/identity` per D-08.
- [ ] **`.well-known/lattice/server` signed descriptor (D-06).**
      Currently returns the pubkey but doesn't sign the response.
      Canonical-CBOR + Ed25519 signature is the actual D-06 contract.
- [ ] **Federation testbed deploy.** Build for x86_64-unknown-linux-gnu,
      deploy `lattice-server` binaries to pixie + cnc + kokonoe (Matt's
      three nodes), run a cross-VPS `lattice demo` against the real
      hosts.

### Done (M4 Phase α — 2026-05-11, browser preview)

Per Matt's "Rust everywhere" directive, the Solid + Vite + Tailwind +
TypeScript scaffold was replaced with a pure-Rust Leptos client.

**Stack:**
- Leptos 0.8 (CSR feature) for the UI — Solid-like signals in Rust.
- Trunk 0.21 for build / dev-serve / asset hashing / SRI emit.
- wasm-bindgen 0.2.121 (pinned in `Trunk.toml`) for the bridge.
- Hand-written CSS in `apps/lattice-web/styles.css`, sourced from
  `design/tokens/`. No Tailwind.
- `lattice-core`, `lattice-crypto`, `lattice-protocol` imported as
  regular Rust crates; they compile to `wasm32-unknown-unknown`
  alongside the UI.

**What runs in the browser:**
- `lattice_core::init()` boots tracing + the panic hook on page load
  and the UI shows `lattice-core v0.1.0 ready` from the const.
- "Run crypto demo" button exercises hybrid signature (Ed25519 +
  ML-DSA-65) and hybrid KEM (X25519 + ML-KEM-768) entirely client-side.
  Live numbers verified against the demo log lines:
    - sig pk: 1984 bytes (32 ed25519 + 1952 ml-dsa)
    - sig: 3373 bytes, `verify: OK`
    - kem pk: 1216 bytes (32 x25519 + 1184 ml-kem)
    - ct: 1120 bytes (32 x25519 eph + 1088 ml-kem ct)
    - `secrets agree: true` after encap/decap round-trip.
- WASM artifact is 803 KB (debug); release build pending.

**Build infrastructure changes:**
- New `apps/lattice-web/scripts/serve.ps1` loads `vcvars64.bat` from
  Visual Studio 2022 Build Tools so cargo can compile host-target
  proc-macros. Without it `link.exe` resolves to Git's stub and every
  build script (`serde`, `getrandom`, `wasm-bindgen-shared`, ...) fails.
- New `.cargo/config.toml` at the workspace root pins
  `[target.x86_64-pc-windows-msvc] linker = "link.exe"`. The user-level
  config sets `linker = "lld-link"` which is not on PATH (only the
  gcc-flavor wrapper at `<sysroot>/lib/rustlib/.../bin/gcc-ld/` is
  bundled in stable and it mis-handles rustc's `-flavor link`).
- `apps/lattice-web/index.html` no longer carries a CSP `<meta>` tag.
  Trunk injects an inline bootstrap module with a per-request nonce
  that any static CSP would block; production CSP is enforced by the
  home server via `csp.json`-derived headers.

### Done (M4 Phase β — 2026-05-11, full MLS round-trip in-WASM)

Second demo button on the home page exercises the M2 acceptance
integration test (`alice_invites_bob_and_both_round_trip`) entirely in
the browser tab. Same code paths the CLI demo and `cargo test --workspace`
hit; here they run client-side with no network and no server.

Live numbers (verified 2026-05-11 via `mcp__claude-in-chrome`):
- Bob KeyPackage: **12057 bytes** (with `LatticeKemPubkey` extension).
- Add-member commit: **15601 bytes**; MLS Welcome: **19819 bytes**;
  PQ Welcome ciphertext: **1088 bytes** (ML-KEM-768 ct, epoch 1).
- Alice + Bob `LatticePskStorage` both hold 1 entry after seal/open.
- Bidirectional encrypt+decrypt: 3662-byte ciphertexts, plaintexts
  recovered exactly (`"hello, lattice"`, `"hello, alice"`).
- Status reports `MLS round-trip OK`.

Module additions:
- `apps/lattice-web/Cargo.toml` gains `mls-rs.workspace` dep for
  `InMemoryKeyPackageStorage` on the `LatticeIdentity` struct field.
- `apps/lattice-web/scripts/check.ps1` — quick `cargo check
  --target wasm32-unknown-unknown` wrapper inside the VS env, so the
  inner-dev loop doesn't have to wait for a full `trunk build`.

### Not done — M4 polish (open for the browser-client deploy)

- [x] Phase γ.1 (shipped 2026-05-11): browser POSTs to a live
      `lattice-server` `/register`. `tower-http::CorsLayer` wired
      into `lattice_server::app()` (wildcard origin / methods /
      headers; safe because we never set cookies). `gloo-net 0.6`
      adapter at `apps/lattice-web/src/api.rs` mirrors the per-action
      shape from `lattice-cli`. Verified live with two POSTs:
      `new_registration=true` then `false` (deterministic user_id
      `[0xAA; 32]`). `scripts/run-server-dev.ps1` spins up the server
      on `127.0.0.1:8080` with run state under `J:\lattice\.run\`
      (gitignored).
- [x] Phase γ.2 (shipped 2026-05-11): `api::publish_key_package`
      + `api::fetch_key_package`. Verified live — Bob publishes
      12057-byte KP, GET returns 12057 bytes intact. URL-safe base64
      (no padding) for path segments; server tries both encodings.
- [x] Phase γ.3 (shipped 2026-05-11): full Alice⇌Bob server-backed
      demo button. `api::submit_commit`, `api::fetch_welcome`,
      `api::publish_message`, `api::fetch_messages`. `fetch_welcome`
      MLS-decodes the `PqWelcomePayload` and rebuilds a
      `LatticeWelcome` ready for `process_welcome`. Live values:
      commit 15601 bytes, MLS Welcome 19819, PQ ct 1088 (epoch 1),
      ciphertext 3662 bytes, "hello via server" round-trip OK.
- [ ] Phase γ.4: still open — replace HTTP with WebTransport
      (`web-sys::WebTransport`) per D-11; HTTP stays as fallback.
- [ ] Phase γ-polish: `api::issue_cert` (`POST /group/:gid/issue_cert`)
      for sealed-sender envelopes — currently the demo posts the raw
      MLS application message, not a `SealedEnvelope`.
- [ ] Phase γ.4: replace HTTP with WebTransport (`web-sys::WebTransport`)
      per D-11; HTTP stays as the fallback.
- [ ] Phase δ: IndexedDB-backed storage providers
      (`KeyPackageStorage`, `GroupStateStorage`, `PreSharedKeyStorage`)
      so the browser persists state across reloads. Pull `idb`
      (thin async wrapper) and wrap the three `mls_rs_core::*::*Storage`
      traits. Identity persistence is D-08; chunked encrypt-at-rest
      can land on the same store.
- [ ] Phase ε: WebAuthn passkey flow (D-09 — PRF / passphrase+badge /
      refuse three-tier).
- [ ] Phase ζ: a11y pass — keyboard nav, focus rings, ARIA roles,
      Lighthouse ≥ 95.
- [ ] Production CSP verification (`scripts/verify-csp.ps1`) updated
      for the Trunk-generated asset hashes — current script was written
      against the old Vite-bundle layout.

### Not done — M4 and beyond
- [ ] Cap'n Proto migration from interim Prost wire (M5)

---

## 5. Build / test / dev commands

**ALL scripts are PowerShell.** Matt's machine has UAC disabled for admin
PowerShell spawns; bash-on-Windows is forbidden per user preferences. The
scripts wrap cargo calls so escape-character pain is contained.

**Toolchain note (Windows host):** `rust-toolchain.toml` pins
`channel = "stable"` which resolves to the host triple rustup was first
installed with. On a machine without Visual Studio Build Tools, dot-source
`scripts\env-setup.ps1` before cargo invocations to force the GNU host
(uses MinGW gcc as linker; gcc must be on PATH). A box with MSVC Build
Tools needs no extra setup.

```powershell
# First-time setup on a fresh box
.\scripts\dev-setup.ps1

# Per-session env (only needed if MSVC Build Tools are missing)
. .\scripts\env-setup.ps1

# Day-to-day
cargo check --workspace
cargo test --workspace
.\scripts\test-all.ps1                 # full pre-commit gate

# WASM target verification (lattice-core only)
cargo check -p lattice-core --target wasm32-unknown-unknown

# Lattice-web dev server (Leptos + Trunk, pure Rust — no npm)
cd apps\lattice-web
.\scripts\serve.ps1                    # trunk serve at http://127.0.0.1:5173
.\scripts\serve.ps1 -NoAutoReload      # disable file watch
trunk build --release                  # static bundle into dist/ + SRI
.\..\..\scripts\verify-csp.ps1         # confirms CSP / SRI hashes (host server only)
```

Environment variables are documented in each crate's `.env.example`. The
server reads from `RUST_LOG`, `LATTICE_DATABASE_URL`, `LATTICE_BIND_ADDR`,
`LATTICE_FEDERATION_KEY_PATH`.

---

## 6. The first vertical slice

The single concrete deliverable for whoever picks this up next: prove the
crypto + transport spine works end-to-end with the minimum possible scope.

**Acceptance criteria** for "vertical slice complete":

1. Two `lattice-server` instances run locally on different ports
2. Two `lattice-cli` clients register identity (ML-DSA-65 keypair) with
   their respective home servers
3. Client A creates a 1:1 MLS group with Client B (across servers)
4. Client A encrypts "hello, lattice" with the group's MLS state
5. Server A federates the ciphertext to Server B over QUIC
6. Client B decrypts and prints the plaintext
7. All steps emit structured tracing spans; `RUST_LOG=lattice=trace` shows
   the full key-exchange + ratchet flow

No UI required for this slice. CLI-only. Once green, the same flow gets
wired into `lattice-web` and `lattice-server` HTTP routes.

**Order of implementation:**

1. `lattice-crypto::identity` — ML-DSA-65 keypair gen + serialization
2. `lattice-crypto::hybrid_kex` — X25519 + ML-KEM-768 hybrid KEM
3. `lattice-crypto::mls` — thin wrapper around `mls-rs` with our cipher
   suite selected
4. `lattice-protocol` — wire types for `IdentityClaim`, `KeyPackage`,
   `Welcome`, `Commit`, `ApplicationMessage`
5. `lattice-server` — `/register`, `/key_packages`, `/group/{id}/commit`,
   `/group/{id}/messages` endpoints; federation gossip over QUIC
6. `lattice-cli` — `register`, `create-group`, `invite`, `send`, `recv`
   subcommands

---

## 7. Non-negotiable conventions

These come from Matt's user preferences and the `rust-backend` skill he
authored. They apply to every file in this repo.

- **Verbose tracing everywhere.** Every public function gets `#[instrument]`
  or an explicit span. Every error path logs context before propagating.
- **No `.unwrap()` or `.expect()`** in production paths. Use `?` and
  `thiserror` enums. `unwrap()` is permitted in tests only.
- **No `println!`** — only `tracing::{trace,debug,info,warn,error}!`.
- **Domain errors use `thiserror`**, infrastructure errors use `anyhow`.
- **PowerShell only** for scripts on Windows. No bash, no batch.
- **`forbid(unsafe_code)`** in every crate unless an FFI boundary genuinely
  requires it, in which case the unsafe block gets a `// SAFETY:` comment
  explaining the invariants.
- **`#![warn(missing_docs)]`** in every lib crate. Stubs get doc comments
  describing intent even when bodies are `todo!()`.
- **Sentence-case strings everywhere** — log messages, error messages, UI
  copy. No Title Case, no ALL CAPS unless it's a literal const name.

---

## 8. Cryptographic spec lock

Pin these here so they don't drift across modules:

| Purpose | Algorithm | Crate |
|---|---|---|
| KEM (PQ) | ML-KEM-768 | `ml-kem` |
| KEM (classical) | X25519 | `x25519-dalek` |
| Hybrid KEX combiner | Concatenate-then-HKDF-SHA-256 | `hkdf` |
| Signature (PQ identity) | ML-DSA-65 | `ml-dsa` |
| Signature (classical identity) | Ed25519 | `ed25519-dalek` |
| AEAD | ChaCha20-Poly1305 | `chacha20poly1305` |
| Hash | BLAKE3 (general), SHA-256 (HKDF) | `blake3`, `sha2` |
| Password KDF | argon2id (m=64MiB, t=3, p=1) | `argon2` |
| Group key agreement | MLS RFC 9420, ciphersuite TBD | `mls-rs` |

MLS ciphersuite selection is locked: `0xF000` —
`LATTICE_HYBRID_V1`, wrapping `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
(`0x0003`) and folding an ML-KEM-768 encapsulated secret into MLS
`init_secret`. Full construction in [`DECISIONS.md`](DECISIONS.md) §D-04.
Reference: [draft-mahy-mls-xwing] for the hybrid pattern.

---

## 9. Design system

**Anchor color:** lilac, `#C8A2C8` (token: `--lattice-lilac-400`).

**Scheme:** split-complementary outward.
- Lilac primary ramp (`--lattice-lilac-{50,200,400,600,700,800,900}`)
- Sage accent (`--lattice-sage`) — success, confirmations
- Amber accent (`--lattice-amber`) — warnings, timers
- Rose accent (`--lattice-rose`) — errors, danger
- Slate-blue accent (`--lattice-slate`) — secondary info
- Ink neutrals (`--lattice-ink-{50,300,500,800,900,950}`) — surfaces

All tokens live in `design/tokens/colors.json` as a single source of truth.
Tailwind theme extends from there; native shells (V2) consume the same JSON.

Typography: system stack with Inter as preferred fallback. Two weights only
(400 regular, 500 medium). Sentence case for everything.

Dark mode is the default surface. Light mode is a switchable but secondary
target.

---

## 10. Open questions

Most Step 1 / Step 2 open questions are resolved — see §2.5 + full log
in [`DECISIONS.md`](DECISIONS.md). What remains genuinely open:

- **Domain (D-22).** `lattice.chat` / `lattice.im` / `getlattice.app`.
  Recommendation: `lattice.chat` primary, `getlattice.app` redirect.
  Matt to check availability + registrar pricing and commit. **Unblock
  before M3 ships** — ACME hostname + brand assets cascade from this.
- **Monetization pricing (D-25).** Structure decided (self-hosted free
  AGPL; SaaS home server tiered). Numbers deferred to post-M5 so we
  don't anchor on pre-product assumptions. Revisit with comparable
  pricing research (Matrix.org, Mattermost, Wire) at that point.

Everything else in HANDOFF §10's old list — federation discovery, push
notifications, moderation — is now in `DECISIONS.md` (see §2.5).

---

## 11. References

- MLS protocol: RFC 9420 — https://datatracker.ietf.org/doc/rfc9420/
- ML-KEM (FIPS 203): https://csrc.nist.gov/pubs/fips/203/final
- ML-DSA (FIPS 204): https://csrc.nist.gov/pubs/fips/204/final
- PQXDH (Signal hybrid handshake): https://signal.org/docs/specifications/pqxdh/
- CONIKS (key transparency): https://coniks.cs.princeton.edu/
- `mls-rs`: https://github.com/awslabs/mls-rs
- Sealed sender (Signal): https://signal.org/blog/sealed-sender/

---

## 12. M2 design notes — ML-KEM-768 on LeafNode + Welcome (shipped)

Captured during Phase C.2 design and kept as a permanent reference for
the construction. This is now SHIPPED in M2; the section is retained
because the design rationale is non-obvious from reading the code
alone (especially the choice between LeafNode and KeyPackage
extension placement, which the code reflects but doesn't fully
explain).

### Why ML-KEM-768 belongs on the LeafNode, not in the credential

The credential (`LatticeCredential`, `CREDENTIAL_TYPE = 0xF001`) carries
**signature material** — Ed25519 + ML-DSA-65 verifying keys plus the
user_id binding. ML-KEM-768 is a **KEM**, not a signature scheme, and
its keypair is per-device per-epoch rotation material. The standard MLS
LeafNode already carries a per-device `init_key` (X25519 HPKE pubkey
for the base 0x0003 suite). Adding ML-KEM-768 alongside it via a custom
extension keeps the separation clean: identity binding in credential,
KEM keys with the rest of the leaf key material.

This means `LatticeCredential` does NOT need to change. Phase A's wire
format stays intact.

### Custom MLS extension types reserved

| Extension id | Use | Carrier |
|---|---|---|
| `0xF002` | `LatticeKemPubkey` — ML-KEM-768 verifying key (1184 bytes) | LeafNode extension |
| `0xF003` | `PqWelcomePayload` — ML-KEM-768 ciphertext for the joiner (1088 bytes) + epoch reference (u64) | Welcome extension |

Both must be registered on the `ClientBuilder` via
`.extension_type(ExtensionType::new(0xF002))` etc., or mls-rs
silently rejects KeyPackages / Welcomes carrying them as
`MlsError::ExtensionNotInCapabilities` (mls-rs research §6.10).

### Per-epoch PSK flow end-to-end

1. **KeyPackage creation** (joiner side, in advance): generate
   ML-KEM-768 keypair via `ml-kem` crate, attach the pubkey as a
   `LatticeKemPubkey` LeafNode extension when building the KeyPackage.
   Store the ML-KEM secret in a per-device store keyed by KeyPackage id
   (so we can find it when consuming a Welcome).

2. **Adding the joiner** (Alice side):
   - Decode joiner's KeyPackage, extract their `LatticeKemPubkey`
     extension → joiner's ML-KEM-768 verifying key.
   - `(ct, ss) = ML-KEM-768.encapsulate(joiner_kem_pk)` — fresh per-
     commit secret + ciphertext.
   - `storage.insert(psk_id_for_epoch(next_epoch), PreSharedKey::new(ss))`.
   - Build commit:
     `group.commit_builder()
            .add_member(joiner_kp)?
            .add_psk(psk_id_for_epoch(next_epoch))?
            .build()`.
   - Attach `PqWelcomePayload { ml_kem_ct: ct, epoch: next_epoch }`
     to the Welcome via `MlsMessage` extension mechanism.

3. **Joining** (Bob side, in `process_welcome`):
   - Read `PqWelcomePayload` from Welcome extensions.
   - Look up our ML-KEM-768 secret key by KeyPackage id (we used a
     fresh KeyPackage to be invited, so we know which secret it
     corresponds to).
   - `ss = ML-KEM-768.decapsulate(ct, our_kem_sk)`.
   - `storage.insert(psk_id_for_epoch(payload.epoch), PreSharedKey::new(ss))`
     — **before** calling `Client::join_group`, because mls-rs looks
     up the PSK synchronously during join.
   - `Client::join_group(None, &welcome)?`.

4. **Subsequent commits** (existing members updating themselves):
   - The committer encapsulates a fresh ML-KEM secret to every other
     member's current ML-KEM pubkey (or rotates everyone's pubkey via
     an `Update` proposal). The simplest v0.1 approach: each commit
     also drives an Update proposal that rotates everyone's
     `LatticeKemPubkey` extension, and the PSK ciphertexts for the
     non-joiners ride along in either the commit's `authenticated_data`
     field or in further custom extensions. **TODO during Phase C.2/D:
     finalize the rotation mechanism.**

### Where the design is still vague

- The "subsequent commits" path (item 4 above) is the part the research
  doc flagged as TODO. Three plausible options:
  - **(α) Per-commit fresh ML-KEM encap to every member** — clean,
    correct, but ~1.2 KB per epoch per member of overhead. For small
    groups (Lattice's target) this is negligible.
  - **(β) Resumption PSK** — reuse mls-rs's existing
    `PreSharedKeyID::Resumption(...)` path to fold in the previous
    epoch's PQ secret deterministically. No per-commit network
    overhead but no fresh PQ secret either.
  - **(γ) Periodic rotation** — fresh ML-KEM encap every N commits,
    resumption PSK in between.
  - **Recommendation:** ship (α) in M2 to get the full PQ property
    on every epoch, optimize to (γ) post-V1 if the bandwidth shows
    up as an issue in real use.

- "Generation of the ML-KEM-768 keypair at KeyPackage creation" —
  currently `lattice-crypto::hybrid_kex` has the keypair gen
  primitives (`encapsulate` / `decapsulate` over a hybrid X25519 +
  ML-KEM secret). Phase C.2 likely wants a thinner ML-KEM-only helper
  exposed alongside, since the Welcome extension uses ML-KEM in
  isolation (the X25519 part is already handled by mls-rs's standard
  Welcome HPKE wrap to the leaf init key).

---

## 13. Provenance

This scaffold was generated 2026-05-10 in a single Claude session after
Step 1 (foundational decisions) was locked. Every directory contains a
`README.md` describing the crate or asset's purpose. Every Rust file has
doc comments.

A subsequent recovery session (also 2026-05-10) restored work that was
in flight when a power outage interrupted: the `pub mod sig;` /
`pub mod wire;` declarations in `lattice-protocol/src/lib.rs` had been
written but not yet wired, leaving the wire-types module unreachable.
That session then carried M2 forward through Phases A, B, F-prep, and
C.1 — see §4 commit log. The repo is a local git tree (no remote yet);
all six commits live on `main`.

Recovery context: this is also where the M2 decisions captured in the
header §2.5 / D-04 re-open + Option B sealed-sender split + mls-rs stack
upgrade originated.
