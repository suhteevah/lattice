# Development

This page is the onboarding guide for someone who wants to build,
test, or contribute to Lattice. It covers the workspace layout, the
non-negotiable conventions enforced workspace-wide, the local CI
gates, and the Windows-specific build environment notes.

If you are looking for the user-facing flow, the rest of `docs/usage/`
covers that. This page is engineer-facing.

---

## Workspace layout

```
lattice/
├── Cargo.toml                          # workspace root, all shared deps pinned
├── README.md
├── LICENSE                             # AGPL-3.0-or-later
├── rust-toolchain.toml                 # pins to stable
├── rustfmt.toml                        # edition 2024, max width 100
├── clippy.toml
│
├── crates/
│   ├── lattice-crypto/                 # PQ primitives, MLS, sealed sender, padding
│   ├── lattice-protocol/               # wire schemas, framing, envelopes
│   ├── lattice-server/                 # home server binary (axum)
│   ├── lattice-core/                   # client core lib, compiles to wasm32
│   ├── lattice-storage/                # encrypted store (IndexedDB v1, native v2)
│   ├── lattice-keytransparency/        # Trillian-style transparency log
│   ├── lattice-media/                  # voice/video, keystore, PQ-DTLS-SRTP
│   └── lattice-cli/                    # admin + dev tooling
│
├── apps/
│   ├── lattice-web/                    # Leptos + Trunk + WASM (V1 client)
│   └── lattice-desktop/                # Tauri 2 desktop shell (V2)
│
├── design/
│   ├── tokens/                         # colors.json / typography.json / spacing.json
│   └── icons/                          # custom outline icon set
│
├── docs/
│   ├── ARCHITECTURE.md                 # protocol + topology deep-dive
│   ├── THREAT_MODEL.md                 # node-capture analysis
│   └── usage/                          # user-facing guide (this set)
│
└── scripts/
    ├── dev-setup.ps1                   # toolchain bootstrap
    ├── test-all.ps1                    # pre-commit gate
    ├── verify-csp.ps1                  # CSP / SRI verifier
    ├── run-server-dev.ps1              # local dev server
    └── *.ps1                           # everything else; no bash, no batch
```

The architectural invariants are documented at the top of CLAUDE.md
and enforced through the dependency graph:

- `lattice-crypto` never imports `lattice-protocol`. The graph runs
  protocol → crypto, never the reverse.
- `lattice-crypto` contains primitives and group-state helpers only.
  No sequencing logic — that lives in `lattice-core`.
- `lattice-core` is the **only** crate that compiles to
  `wasm32-unknown-unknown`. Server-only crates may use Tokio
  features unavailable in WASM; do not add them to `lattice-core`.
- `lattice-protocol` is the wire contract. Any breaking change
  requires a wire-version bump and a migration plan.

---

## First-time setup

On a fresh Windows box:

```powershell
git clone https://github.com/suhteevah/lattice.git
cd lattice
.\scripts\dev-setup.ps1
```

`dev-setup.ps1` does:

1. Verify `rustup` is installed. Pins the toolchain from
   `rust-toolchain.toml` (`stable-x86_64-pc-windows-gnu` on
   Matt's box; native `stable` everywhere else).
2. Install the `wasm32-unknown-unknown` target if missing.
3. Install `cargo-audit`, `cargo-deny`, `trunk`, `tauri-cli@^2`,
   `wasm-bindgen-cli` matching the pinned `Trunk.toml` version.
4. Verify `clippy` and `rustfmt` are present.
5. Test-build `cargo check --workspace`.

After it completes, every command below works.

On Linux / macOS, the equivalent is:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
source $HOME/.cargo/env
rustup target add wasm32-unknown-unknown
cargo install trunk cargo-audit cargo-deny tauri-cli@^2 wasm-bindgen-cli
```

Plus the OS-specific Tauri prereqs from
[installation.md](installation.md).

---

## Build / test commands

The day-to-day rhythm:

```powershell
cargo check --workspace                 # fast feedback (seconds)
cargo test --workspace                  # full test suite (~60s on warm cache)
.\scripts\test-all.ps1                  # pre-commit gate
```

`test-all.ps1` runs:

1. `cargo test --workspace` (with `LATTICE_NET_TESTS=1` set so the
   network-binding tests run their full payload).
2. `cargo clippy --workspace --all-targets -- -D warnings`.
3. `cargo fmt --all -- --check`.
4. `cargo audit`.

The whole thing takes ~90 seconds on a warm cache.

### Per-target verification

```powershell
# WASM target — lattice-core is the only crate that should compile here
cargo check -p lattice-core --target wasm32-unknown-unknown

# Browser web app
cd apps\lattice-web
trunk build --release
.\..\..\scripts\verify-csp.ps1

# Tauri desktop dev
cd apps\lattice-desktop\src-tauri
cargo tauri dev
```

### Web dev loop

```powershell
cd apps\lattice-web
.\scripts\serve.ps1
# trunk serve on http://127.0.0.1:5173 with HMR
```

`serve.ps1` pins `RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-gnu` and
prepends `C:\msys64\mingw64\bin` to PATH so the proc-macro host
build works without MSVC. On Linux / macOS, plain `trunk serve` is
sufficient.

### Lattice-media network tests

`crates/lattice-media/tests/*loopback.rs` bind UDP for ICE / DTLS
loopback. They are gated behind `LATTICE_NET_TESTS=1` so cross-host
check runs without a network stack do not fail spuriously:

```powershell
$env:LATTICE_NET_TESTS = '1'
cargo test -p lattice-media --test pq_dtls_srtp_loopback
```

---

## Non-negotiable conventions

Enforced workspace-wide via `[workspace.lints]` in `Cargo.toml` and
the `rust-backend` skill conventions. **Do not silence these lints
to make code compile — fix the code.**

| Rule | Enforcement |
|---|---|
| `#![forbid(unsafe_code)]` in every crate (FFI exempted with `// SAFETY:`) | `unsafe_code = "forbid"` in workspace lints |
| `#![warn(missing_docs)]` in every lib crate; stubs get intent doc comments | workspace lints |
| **No `.unwrap()` / `.expect()`** in production paths (tests OK) | `unwrap_used` / `expect_used` warned |
| **No `println!`** — use `tracing::{trace,debug,info,warn,error}!` | code review |
| `#[instrument]` on every public function — log entry, exit, error paths | code review |
| Domain errors via `thiserror`, infrastructure errors via `anyhow` | code review |
| Sentence-case for all log / error / UI strings; no Title Case, no ALL CAPS except const names | code review |
| **Never log key material** — log counts, lengths, identifiers only | crypto-specific |
| `clippy::pedantic` + `clippy::nursery` warn-level | workspace lints |
| PowerShell only for scripts on Windows; no bash, no batch | code review |
| `forbid(unsafe_code)` carve-out in `lattice-media` for keystore FFI; every `unsafe` block carries `// SAFETY:` | code review |

The `rustfmt.toml`:

```toml
edition = "2024"
max_width = 100
imports_granularity = "Module"
imports_granularity = "StdExternalCrate"
```

Run `cargo fmt --all` before commit. `test-all.ps1` checks.

---

## Verbose logging

Every project, every component, every function that touches I/O.
Log entry, exit, errors. Use `tracing` in Rust, `logging` module in
Python (n/a here — Lattice is pure Rust). Never reduce logging
verbosity. Make it flaggable via dev-mode toggle.

The pattern:

```rust
use tracing::instrument;

#[instrument(level = "debug", skip(self, large_arg))]
pub fn fn_name(&self, large_arg: SomeBigType, small_arg: u64) -> Result<Foo> {
    tracing::debug!(small_arg, "entering fn_name");
    let result = inner_work()?;
    tracing::debug!(?result.summary, "completed");
    Ok(result)
}
```

`skip` is used for arguments that would log too much (e.g. big
buffers, secrets). The function still emits an entry log; the
skipped arg is omitted.

---

## Crypto spec lock — do not drift

Algorithm choices are pinned. If you change any of these, you must:

1. Bump the wire protocol version in `lattice-protocol`.
2. Update `docs/THREAT_MODEL.md` if the threat model changes.

Frozen primitives: ML-KEM-768 (PQ KEM), X25519 (classical KEM),
ML-DSA-65 (PQ sig), Ed25519 (classical sig), ChaCha20-Poly1305
(AEAD), HKDF-SHA-256 (KDF), BLAKE3 (general hash), argon2id m=64MiB
t=3 p=1 (password KDF), MLS RFC 9420 via `mls-rs` (group key
agreement, custom hybrid ciphersuite `LATTICE_HYBRID_V1` =
`0xF000`).

**The server never stores plaintext.** Schema migrations that try
to add a plaintext message column fail CI by policy. If you find
yourself reaching for one, stop and re-read THREAT_MODEL §1.

---

## CSP and SRI

The browser PWA ships with a strict Content Security Policy: **no
`unsafe-eval`, no `unsafe-inline`, allowlisted origins only.**

CSP source: `apps/lattice-web/csp.json`. Trunk injects an inline
bootstrap module with a per-request nonce that any static CSP would
block; production CSP is enforced by the home server via
`csp.json`-derived headers (future work).

`scripts/verify-csp.ps1` is a pure-PowerShell pass that:

- Parses `csp.json` and dumps the assembled header.
- Checks for `'unsafe-eval'` / `'unsafe-inline'` / wildcard
  origins (rejects if any are present).
- Sweeps every `integrity="sha384-..."` in `dist/index.html` against
  the on-disk asset SHA-384.

Run after every change to `csp.json` or to the bundle:

```powershell
cd apps\lattice-web
trunk build --release
cd ..\..
.\scripts\verify-csp.ps1
```

---

## Cap'n Proto build

`lattice-protocol`'s `build.rs` runs the `capnp` compiler over
`schema/lattice.capnp` into `$OUT_DIR/lattice_capnp.rs`. The crate
includes it under the file-stem path the generated code expects.
The `capnp` binary lives via `choco install capnproto` on Windows,
or `apt install capnproto` on Debian/Ubuntu.

If `cargo build -p lattice-protocol` fails with
`capnp: command not found`, that's the missing dep. The build
script does **not** auto-install it.

---

## Pre-commit hooks

The repo does not ship a pre-commit hook by default — pre-commit
gates are intended to run via the explicit
`.\scripts\test-all.ps1` invocation, not silently on every commit.

If you want a hook, the simplest setup:

```powershell
# .git/hooks/pre-commit
#!/usr/bin/env pwsh
.\scripts\test-all.ps1
```

…but Matt's machine does not use git hooks (per workflow
preferences). The expectation is that you run `test-all.ps1`
manually before pushing.

---

## CI

`.github/workflows/ci.yml` exists as reference for external
contributors. Matt's GitHub account has CI banned per CLAUDE.md, so
the official "CI green" gate is **local**:

```powershell
.\scripts\test-all.ps1
```

If you submit a PR and want CI to run on your fork, enable Actions
on your fork and the workflow will execute. The owning repo does
not run it.

The full pre-commit gate:

- `cargo test --workspace` with `LATTICE_NET_TESTS=1` — **200
  workspace tests pass** as of the current handoff.
- `cargo check -p lattice-core --target wasm32-unknown-unknown`.
- `cargo check --target wasm32-unknown-unknown --bin lattice-web`.
- `cargo check -p lattice-desktop`.
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo fmt --all -- --check`.
- `cargo audit`.
- `.\scripts\verify-csp.ps1`.
- `trunk build --release` succeeds.

All green is the bar for merging to `main`.

---

## Test layout

Tests live alongside the code:

```
crates/lattice-crypto/
├── src/
│   ├── identity.rs        ← unit tests in #[cfg(test)] mod tests
│   ├── hybrid_kex.rs      ← unit tests in #[cfg(test)] mod tests
│   └── ...
└── tests/
    └── mls_integration.rs ← integration tests
```

Integration tests for inter-crate flows live at
`crates/<crate>/tests/`. Examples:

- `crates/lattice-crypto/tests/mls_integration.rs` — Alice + Bob
  full MLS round-trip.
- `crates/lattice-server/tests/routes_integration.rs` — every
  HTTP route exercised in-process.
- `crates/lattice-media/tests/pq_dtls_srtp_loopback.rs` — full
  PQ-DTLS-SRTP pipeline in a same-process loopback.

To run a specific test:

```powershell
cargo test -p lattice-crypto --test mls_integration alice_invites_bob
```

---

## Contributing

1. Read ARCHITECTURE.md and THREAT_MODEL.md to absorb the locked
   design surface.
2. Implement against the non-negotiable conventions above.
3. Run `.\scripts\test-all.ps1` until green.
4. Commit and open a PR (or attach the patch in an email — the
   project is not strictly GitHub-bound).

Pull requests are reviewed against the conventions, the crypto spec
lock, and the architectural invariants. PRs that silence a lint
to make code compile, that introduce `unwrap()` in a production
path, or that drift the crypto primitives without a wire-version
bump will not be merged.

The single largest risk surface is `crates/lattice-crypto/src/mls/`
— the custom hybrid ciphersuite. A separate audit pass on this
module is planned before any production-scale deploy.

---

## Cross-references

- [Architecture](/wiki/architecture/) — layered view, federation
  topology, and the hybrid PQXDH handshake.
- [Threat model](/wiki/threat_model/) — adversary classes and
  mitigations.
- [installation.md](installation.md) — runtime install paths.
- [troubleshooting.md](troubleshooting.md) — build / runtime error
  table.
