# Lattice — Project Instructions

Post-quantum encrypted federated messaging platform. Rust workspace + Solid
PWA. **Read [`docs/HANDOFF.md`](docs/HANDOFF.md) before touching anything.**
It is the single source of truth for status, locked decisions, the crypto
spec, and the next vertical slice. Do not re-derive any of that here.

This file captures only the conventions and gotchas that must be respected
on every edit. The rest is in `docs/`.

---

## Orientation

- **Status:** Step 1 scaffold complete. No business logic yet. Every
  `lattice-crypto/src/*.rs` body is `todo!()` with intent doc-comments.
- **Owner:** Matt Gates (suhteevah). AGPL-3.0-or-later. Repo:
  `github.com/suhteevah/lattice`.
- **Docs (read in this order):** `docs/HANDOFF.md` → `docs/DECISIONS.md`
  → `docs/ARCHITECTURE.md` → `docs/THREAT_MODEL.md` → `docs/ROADMAP.md`.
  `DECISIONS.md` is the authoritative log of every settled question;
  treat its entries as locked unless explicitly re-opened.
- **Workspace:** 7 Rust crates under `crates/`, 1 web app under
  `apps/lattice-web/`. See HANDOFF §3 for the layout table.

---

## Build / test commands (PowerShell, Windows-only)

```powershell
.\scripts\dev-setup.ps1                 # one-shot toolchain bootstrap
cargo check --workspace                 # fast iteration
cargo test --workspace
.\scripts\test-all.ps1                  # pre-commit gate (test + clippy + fmt + audit)
cargo check -p lattice-core --target wasm32-unknown-unknown  # WASM verify
.\scripts\verify-csp.ps1                # CSP integrity check for lattice-web

cd apps\lattice-web
npm run dev                             # vite dev server, http://localhost:5173
npm run build                           # static bundle + SRI pin
```

**No bash, no batch.** All automation lives in `.ps1` files. PowerShell
scripts run with `-ExecutionPolicy Bypass`. GitHub Actions exists in
`.github/workflows/ci.yml` for reference / contributors, but Matt's account
has CI banned — verify locally before claiming green.

---

## Non-negotiable code conventions

Enforced workspace-wide via `[workspace.lints]` in `Cargo.toml` and the
`rust-backend` skill conventions. **Do not silence these lints to make code
compile — fix the code.**

| Rule | Enforcement |
|---|---|
| `#![forbid(unsafe_code)]` in every crate (FFI exempted with `// SAFETY:`) | `unsafe_code = "forbid"` in workspace lints |
| `#![warn(missing_docs)]` in every lib crate. Stubs get intent doc-comments. | workspace lints |
| **No `.unwrap()` / `.expect()`** in production paths (tests OK) | `unwrap_used` / `expect_used` warned |
| **No `println!`** — use `tracing::{trace,debug,info,warn,error}!` | code review |
| `#[instrument]` on every public function. Log entry, exit, error paths. | code review |
| Domain errors via `thiserror`, infra errors via `anyhow` | code review |
| Sentence-case for all log/error/UI strings. No Title Case, no ALL CAPS except const names. | code review |
| **Never log key material** — log counts, lengths, identifiers only | crypto-specific |
| `clippy::pedantic` + `clippy::nursery` warn-level | workspace lints |

Rustfmt config (`rustfmt.toml`): edition 2024, max width 100, `Module`
import granularity, `StdExternalCrate` import grouping. Run `cargo fmt
--all` before committing.

---

## Crypto spec — frozen, do not drift

Algorithm choices are pinned in **HANDOFF §8** and re-implemented across
`lattice-crypto`, `lattice-protocol`, and `docs/ARCHITECTURE.md`. If you
change any of these, you must:

1. Update HANDOFF §8.
2. Bump the wire protocol version in `lattice-protocol`.
3. Update `docs/THREAT_MODEL.md` if the threat model changes.

Frozen primitives: **ML-KEM-768** (PQ KEM) · **X25519** (classical KEM) ·
**ML-DSA-65** (PQ sig) · **Ed25519** (classical sig) · **ChaCha20-Poly1305**
(AEAD) · **HKDF-SHA-256** (KDF) · **BLAKE3** (general hash) · **argon2id**
m=64MiB t=3 p=1 (password KDF) · **MLS RFC 9420** via `mls-rs` (group key
agreement, custom hybrid ciphersuite TBD).

**The server never stores plaintext.** Schema migrations that add a
plaintext message column fail CI by policy. If you find yourself reaching
for one, stop and re-read THREAT_MODEL §1.

---

## Architectural invariants

These are not suggestions. Breaking them silently corrupts the dependency
graph and the audit story.

- `lattice-crypto` never imports `lattice-protocol`. Dependency runs
  protocol → crypto, never the reverse.
- `lattice-crypto` contains primitives and group-state helpers only. No
  sequencing logic — that lives in `lattice-core`.
- `lattice-core` is the **only** crate that compiles to `wasm32-unknown-unknown`.
  Server-only crates may use tokio features unavailable in WASM; don't add
  them to `lattice-core`.
- `lattice-protocol` is the wire contract. Any breaking change requires a
  version bump and migration plan, even pre-1.0.
- Sealed-sender envelopes wrap server-routed messages. Don't add a
  plaintext sender field to any wire type.

---

## Design system (lattice-web)

Anchor color is lilac `#C8A2C8` (`--lattice-lilac-400`). Tokens live in
`design/tokens/` as a single source of truth — `colors.json`,
`typography.json`, `spacing.json`. Tailwind theme extends from them; the
future Tauri shell will consume the same JSON.

Dark mode default. Sentence case for all UI copy. Two type weights only
(400, 500). Inter as preferred fallback in a system stack.

Strict CSP — **no `unsafe-eval`, no `unsafe-inline`, allowlisted origins
only**. Run `.\scripts\verify-csp.ps1` after any change to
`apps/lattice-web/csp.json` or `index.html`. CI fails on SRI hash
mismatches in the built bundle.

---

## Where to start work

Per HANDOFF §6, the next concrete deliverable is the end-to-end vertical
slice: two `lattice-server` instances + two `lattice-cli` clients
exchanging one MLS-encrypted message across federation, CLI-only, no UI.

Order of implementation (HANDOFF §6):

1. `lattice-crypto::identity` — ML-DSA-65 + Ed25519 keypair gen
2. `lattice-crypto::hybrid_kex` — X25519 + ML-KEM-768 hybrid KEM
3. `lattice-crypto::mls` — `mls-rs` wrapper with custom hybrid ciphersuite
4. `lattice-protocol` — `IdentityClaim`, `KeyPackage`, `Welcome`, `Commit`,
   `ApplicationMessage` wire types
5. `lattice-server` — `/register`, `/key_packages`, `/group/{id}/commit`,
   `/group/{id}/messages`, QUIC federation gossip
6. `lattice-cli` — `register`, `create-group`, `invite`, `send`, `recv`

---

## What NOT to do

- Don't substitute crypto primitives without updating HANDOFF §8 + bumping
  the wire version.
- Don't add a plaintext message column to the server schema.
- Don't `unwrap()` / `expect()` / `println!` in production paths.
- Don't import `lattice-protocol` from `lattice-crypto`.
- Don't add server-only tokio features to `lattice-core` (breaks WASM build).
- Don't relax CSP (`unsafe-eval`, `unsafe-inline`, wildcard origins) to
  unblock a dependency — find a different dependency.
- Don't claim a subsystem is done while it still contains `todo!()`,
  `unimplemented!()`, or stub bodies. Grep before asserting completion.
- Don't write bash or batch scripts. PowerShell only.
- Don't add CI workflows that depend on GitHub Actions runtime —
  contributors-only; verify locally.
