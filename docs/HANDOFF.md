# Lattice — HANDOFF

**Last updated:** 2026-05-10
**Owner:** Matt Gates (suhteevah)
**Status:** Steps 1 + 2 complete; M1 (crypto primitives) shipped. Identity,
hybrid KEX, AEAD, padding, and HKDF constants all implemented and tested
(31 unit tests pass). Next: M2 (MLS + sealed sender + protocol wire types).

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
| Language | **Rust** for all backend + client core; **Solid + Tailwind** for web UI. | Matt's stack. Single client core compiles to native (V2) and wasm32 (V1). |
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
│   └── lattice-web/                    # Solid + Tailwind + WASM core (V1 client)
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

### Not done (next sessions pick from here)
- [ ] M2 — MLS + sealed sender + protocol wire types (custom hybrid
      ciphersuite per D-04, sealed sender per D-05). **Start here.**
- [ ] Cap'n Proto schema in `lattice-protocol/` (interim: define structs
      with Prost — deferred to M5 per roadmap)
- [ ] Server routes beyond `/health`: registration, MLS commit upload,
      message fetch, WebTransport endpoint (M3)
- [ ] Solid UI past the "Hello, Lattice" placeholder (M4)
- [ ] First end-to-end vertical slice (see §6) (M3)

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

# Lattice-web dev server
cd apps\lattice-web
npm install
npm run dev                            # vite at http://localhost:5173
npm run build                          # static bundle + SRI pinning
.\scripts\verify-csp.ps1               # confirms CSP policy is intact
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

## 12. Provenance

This scaffold was generated 2026-05-10 in a single Claude session after
Step 1 (foundational decisions) was locked. Every directory contains a
`README.md` describing the crate or asset's purpose. Every Rust file has
doc comments. No code has been compiled yet — running
`.\scripts\dev-setup.ps1` followed by `cargo check --workspace` is the
suggested first verification step.
