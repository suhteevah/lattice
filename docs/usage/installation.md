# Installation

Lattice ships in three client forms and one server form. This page
covers all four:

1. The **browser PWA** at `apps/lattice-web/` — no install, just a
   bookmark.
2. The **Tauri desktop shell** at `apps/lattice-desktop/` — an MSI on
   Windows, a `.app` bundle on macOS, a `.deb` or `AppImage` on
   Linux.
3. **Self-hosting a home server** — the `lattice-server` binary
   produced by `cargo build -p lattice-server --release`.
4. The **dev CLI** at `crates/lattice-cli/` — admin and smoke-test
   tool.

Mobile (iOS, Android) shells are tracked but not yet shipped.

---

## Browser PWA

The lattice-web bundle is a standard static SPA. There is no
installer. You either:

- Open the URL of a hosted instance. The reference public deploy
  hostname is not yet committed.
- Or run a dev server locally per [quickstart.md](quickstart.md).
- Or self-host the static bundle on any CDN / object store and point
  it at any reachable `lattice-server`. The client picks the home
  server URL via runtime configuration; the default
  `http://127.0.0.1:8080` is overrideable from the in-app settings
  panel.

The bundle compiles to a single `.wasm` file (~3 MB release, ~800 KB
debug compressed) plus a small JS shim, a CSS file, and an
`index.html`. Trunk produces the SRI hashes; `scripts/verify-csp.ps1`
verifies that every `integrity="sha384-..."` attribute in the built
`index.html` matches the on-disk asset.

### Browser support matrix

| Browser | Minimum | Notes |
|---|---|---|
| Chrome / Edge | 116 | Full WebAuthn PRF + WebTransport probe |
| Firefox | 122 | WebAuthn PRF only on platform authenticators |
| Safari | 17 | WebAuthn PRF on iOS 17+ |
| Brave / Vivaldi / Arc | Chromium 116+ | As Chrome |

The bundle is also runnable in Tor Browser. PRF is not available in
Tor by design (privacy reasons); the v2 Argon2id-keyed identity blob
is the fallback. See [identity-and-keys.md](identity-and-keys.md).

### Browser features used

- WebAssembly — mandatory.
- `localStorage` — mandatory. The identity blob, the MLS group
  state, the KeyPackage repo mirror, the conversation index, and the
  per-conversation scrollback all live there.
- `fetch` — mandatory. All HTTP calls to the home server.
- WebAuthn PRF — optional, recommended. Hardware-bound identity
  encryption.
- WebTransport — detected, not yet used. Server-side QUIC + H3 + WT
  is follow-up work; the browser already lights up the chip when
  it sees `window.WebTransport`.
- WebSocket — used by the live-push path
  (`/group/<gid>/messages/ws`).

There is no cookie. There is no third-party script. The strict CSP
forbids `unsafe-eval`, `unsafe-inline`, and wildcard origins; see
[development.md](development.md#csp-and-sri) for how Trunk's inline
bootstrap is reconciled with that policy.

### Service worker

The service worker is registered at `/sw.js` with scope `/`. It is
currently a two-responsibility stub: an app-shell cache for offline
draft compose, and an empty push handler scaffolded for future push
payloads.

---

## Tauri desktop shell

The desktop shell wraps the lattice-web bundle in a WebView2 (Windows)
/ WKWebView (macOS) / WebKitGTK (Linux) host and exposes a small IPC
surface for native operations — voice and video, the hardware-backed
keystore, and the OS keychain.

### Build prerequisites

| OS | Requirements |
|---|---|
| Windows | Rust GNU host toolchain (`rustup target install stable-x86_64-pc-windows-gnu`), MSYS2 with MinGW64 on PATH for `windres`, WebView2 runtime (preinstalled on Windows 10/11). MSVC Build Tools work if installed; the GNU path is the supported default per CLAUDE.md. |
| macOS | Xcode command-line tools (`xcode-select --install`). |
| Linux | `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`, `patchelf`, `build-essential`. On Debian/Ubuntu: `sudo apt install libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf build-essential`. |

In addition, Tauri's CLI:

```powershell
cargo install tauri-cli@^2 --locked
```

### Dev mode

Dev mode opens a Tauri window pointed at a live Trunk server so HMR
works during iteration:

```powershell
cd apps\lattice-desktop\src-tauri
cargo tauri dev
```

The first run takes several minutes because Tauri compiles
`webrtc-ice`, `dtls`, `webrtc-srtp`, and the keystore impls. Subsequent
incremental rebuilds are fast.

The Tauri host probes for `window.__TAURI_INTERNALS__` from the
Leptos bundle; when present, the UI flips a "Host: tauri-desktop"
chip on and unlocks the native buttons (Phase F PQ call demo,
keystore commands). Outside Tauri (in a plain browser tab) the same
buttons show "desktop only" rather than erroring.

### Production bundle

```powershell
cd apps\lattice-desktop\src-tauri
cargo tauri build
```

Output:

| OS | Artifact |
|---|---|
| Windows | `target\release\bundle\msi\lattice-desktop_0.1.0_x64_en-US.msi` |
| Windows (alt) | `target\release\bundle\nsis\lattice-desktop_0.1.0_x64-setup.exe` |
| macOS | `target/release/bundle/macos/lattice-desktop.app` plus `bundle/dmg/lattice-desktop_0.1.0_aarch64.dmg` |
| Linux | `target/release/bundle/deb/lattice-desktop_0.1.0_amd64.deb` plus `bundle/appimage/lattice-desktop_0.1.0_amd64.AppImage` |

The Windows MSI bundle path currently requires MSVC Build Tools on
the host (the WiX toolchain needs MSVC). If you only have the GNU
host installed, `cargo tauri build --target x86_64-pc-windows-gnu`
produces a working `.exe` you can ship as a portable binary; the MSI
wrapping is a follow-up. The dev binary (`cargo check -p
lattice-desktop`) compiles green on GNU.

### Code-signing

Unsigned. Lattice is AGPL; the security model assumes you either
build from source or trust your distributor. Code-signing
infrastructure is tracked but not yet shipped. Reproducible builds
are a long-horizon goal.

---

## Self-hosting a home server

The server is a single static binary. The reference deploy walkthrough
is at [`docs/DEPLOY.md`](../DEPLOY.md); the user-facing guide is at
[self-hosting.md](self-hosting.md). This section is a fast-path
"how do I get the binary" overview.

### Build

```powershell
# Windows host, native build for native deploy:
cargo build -p lattice-server --release

# Cross-compile for a Linux VPS from a Windows host:
.\scripts\check-server.ps1 build -p lattice-server `
    --release --bin lattice-server `
    --target x86_64-unknown-linux-gnu
```

The cross-compile path uses MinGW for the C linker. On a Linux host,
the native `cargo build -p lattice-server --release` is the supported
default.

Binary path:

| Host | Path |
|---|---|
| Windows native | `target\release\lattice-server.exe` |
| Linux cross | `target\x86_64-unknown-linux-gnu\release\lattice-server` |
| Linux native | `target/release/lattice-server` |

Size: ~5 MB stripped. The release profile already sets
`strip = "symbols"` in `Cargo.toml`.

### Runtime requirements

| Resource | Minimum | Notes |
|---|---|---|
| Memory | 64 MiB | More for larger groups; the current server keeps state in memory. |
| Disk | 64 MiB | Snapshot file scales with users + KPs + group commits. |
| Open ports | 1 (default 8080) | HTTPS via ACME (`instant-acme`) is future work. |
| Postgres | Optional | The current server uses in-memory state with JSON snapshot. sqlx integration is future work. |
| Federation | Outbound HTTP/1.1 | Peer fan-out goes over plain HTTP today; TLS lands with the ACME work. |

There is no daemon dependency — no Redis, no RabbitMQ, no S3. The
current server is intentionally minimal. Future work adds optional
Postgres-backed storage, ACME-driven TLS, sqlite-backed message
inbox, and rate limits.

### Systemd unit

A template lives at `scripts/lattice-server.service.template`.
Replace the placeholders and drop it into `/etc/systemd/system/`:

```ini
[Unit]
Description=Lattice home server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lattice
Group=lattice
WorkingDirectory=/var/lib/lattice
Environment=LATTICE__SERVER__BIND_ADDR=0.0.0.0:443
Environment=LATTICE__FEDERATION_KEY_PATH=/var/lib/lattice/federation.key
Environment=LATTICE__SNAPSHOT_PATH=/var/lib/lattice/snapshot.json
Environment=LATTICE__ENVIRONMENT=production
Environment=RUST_LOG=lattice_server=info,axum=warn
ExecStart=/usr/local/bin/lattice-server
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

`systemctl daemon-reload && systemctl enable --now lattice-server`.
Watch logs with `journalctl -u lattice-server -f`.

### Per-OS notes

**Linux.** Debian, Ubuntu, RHEL, openSUSE all work. The reference
testbed runs Ubuntu 24.04 and openSUSE Tumbleweed. The binary is
fully static for the runtime portion; only `glibc` is a system
dependency. If you target Alpine, build with the musl target
explicitly.

**macOS.** Untested but the workspace compiles. The server has no
macOS-specific code; the keystore for the desktop shell uses
`security-framework` for the user's login Keychain (see
[identity-and-keys.md](identity-and-keys.md#hardware-backed-storage)).

**Windows.** Works for self-hosting on the same machine you use; less
often deployed as a public-facing server. The reference testbed runs
on Linux for the public node.

---

## Dev CLI

The dev CLI is `lattice` (binary built from `crates/lattice-cli/`).
It exists to drive the same protocol surface the browser drives, for
smoke tests and admin operations.

```powershell
cargo build -p lattice-cli --release
.\target\release\lattice.exe --help
```

Subcommands implemented today:

| Command | Purpose |
|---|---|
| `register` | POST `/register` against a home server. |
| `publish-kp` | Generate + publish a KeyPackage. |
| `fetch-kp` | Fetch a peer's KeyPackage. |
| `submit-commit` | Submit an MLS commit + per-joiner welcomes. |
| `fetch-welcome` | Pull the pending Welcome for the local user_id. |
| `publish-message` | Send a sealed envelope. |
| `fetch-messages` | Poll the message inbox since a cursor. |
| `demo` | Single-process Alice + Bob smoke test against two server URLs. |
| `issue-cert` | Request a sealed-sender membership cert. |

The CLI uses a file-backed identity store under `~/.lattice/`.
Override the path with `--identity-path <file>`.

`demo` is the easiest way to verify a fresh server deploy. From any
host that can reach both servers:

```bash
~/lattice/target/release/lattice demo \
    --server-a http://server-a:4443 \
    --server-b http://server-b:4443 \
    --message cross-host-test
```

Exits zero if the round-trip succeeded.

---

## Verifying a working install

A clean install should produce green from these commands:

```powershell
cargo check --workspace
cargo test --workspace
cargo check -p lattice-core --target wasm32-unknown-unknown
.\scripts\test-all.ps1
```

`scripts/test-all.ps1` is the pre-commit gate: it runs the full test
suite, clippy with `-D warnings`, `rustfmt --check`, and
`cargo audit`. Locally green here is the equivalent of "CI green"
for Lattice; GitHub Actions exists in `.github/workflows/ci.yml` as
reference for external contributors, but the owning operator's
account does not use GitHub-hosted CI by policy.

If `cargo check --workspace` complains about linker errors, see
[troubleshooting.md](troubleshooting.md) — the Windows build-env
section walks through the GNU vs MSVC choice.

---

## Uninstall / clean state

There is no installer registry on Linux/macOS. To wipe everything
Lattice put on disk:

```powershell
# Repository (just delete the clone)
Remove-Item -Recurse -Force .\lattice

# Per-user CLI identity store
Remove-Item -Recurse -Force "$env:APPDATA\lattice"

# Browser local state — open DevTools > Application > Storage > "Clear site data"
# on http://localhost:5173 and http://127.0.0.1:5173.

# Tauri keystore (Windows DPAPI seals)
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\Lattice\keystore"
```

On macOS:

```bash
rm -rf ~/Library/Application\ Support/chat.lattice.lattice
# Remove keychain items if you created any:
security delete-generic-password -s 'chat.lattice.lattice'
```

On Linux:

```bash
rm -rf ~/.local/share/lattice
# Remove Secret Service items via seahorse / kwalletmanager
```

The home-server snapshot lives wherever `LATTICE__SNAPSHOT_PATH`
points (default `.\\.run\\dev-server\\snapshot.json` relative to the
repository root, for the dev script). Delete the file to reset the
server to empty state.
