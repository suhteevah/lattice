# Troubleshooting

Common failure modes and how to fix them. The error table below
covers what shows up in the chat shell's status line, in the
browser console, in the server's `tracing` log, and in `cargo build`
output. If something here is wrong or missing, file an issue — the
single source of truth is the source code, and the table drifts.

If you're hitting a problem that does not match anything below, the
fastest debugging path is usually to set `RUST_LOG=lattice_server=trace,lattice_crypto=trace`
on the server and watch what fires. The verbose-everywhere logging
convention is mandatory per CLAUDE.md.

---

## Chat shell errors

### `encrypted identity present; unlock via debug panel`

**Where:** Status line on app boot.

**Cause:** Your `localStorage["lattice/identity/v1"]` is a v2
(Argon2id-encrypted) or v3 (PRF-encrypted) blob, but the chat-shell
auto-bootstrap only handles v1 plaintext. The chat-shell flow for
encrypted unlock is chunk B work that has not yet landed.

**Fix (today):**

1. Expand `<details>Debug tools (legacy demo grid)</details>` below
   the chat shell.
2. Click **Load encrypted** (v2) or **Load with passkey** (v3).
3. Enter the passphrase or complete the WebAuthn ceremony.
4. The chat shell mounts after the legacy unlock completes.

**Fix (workaround):** delete the blob and start fresh.

```js
// In DevTools Console:
localStorage.removeItem('lattice/identity/v1');
location.reload();
```

You lose your existing identity and any conversations.

**Permanent fix:** chunk B integrates the unlock UI into the chat
shell directly. Tracked in HANDOFF §1.

---

### `WelcomeKeyPackageNotFound`

**Where:** Status line during `add_conversation` or after a reload.

**Cause:** mls-rs's `process_welcome` cannot find the leaf init key
that the Welcome is addressed to. Three possible reasons:

1. **You already consumed this Welcome.** MLS leaf init keys are
   one-shot — once `process_welcome` succeeds, the key is consumed.
   Re-attempting the same Welcome fails with this error. This is
   benign and the chat shell silently skips it.
2. **The Welcome predates your current identity.** If you cleared
   `localStorage` and regenerated your identity, the server still
   holds welcomes addressed to your **old** user_id. The new
   identity cannot consume them.
3. **The KP repo did not survive the reload.** This was a real bug
   pre-chunk-D. The chat shell now mirrors the in-memory
   `InMemoryKeyPackageStorage` to `localStorage["lattice/mls/kp/..."]`
   and restores it on bootstrap. If you see this error on a
   modern build, file an issue.

**Fix (cases 1 and 2):** ignore. The chat shell handles the case-1
race silently. For case 2, you have a new identity and need to
re-invite from the peer's side.

**Fix (case 3):** see HANDOFF §19 — the KP repo shadow-sync is
shipped. Confirm by inspecting
`localStorage["lattice/mls/kp_ids"]` in DevTools; it should
contain a non-empty JSON array.

---

### `send publish_message: Failed to fetch`

**Where:** Status line after pressing Send.

**Cause:** The browser cannot reach the home server URL. Common
sub-causes:

| Sub-cause | Symptom in console |
|---|---|
| Server is not running | `net::ERR_CONNECTION_REFUSED` |
| Server is on wrong port | `404` if a different service is listening |
| CORS mismatch | `has been blocked by CORS policy` |
| DNS failure | `net::ERR_NAME_NOT_RESOLVED` |
| Reverse proxy down | `502 Bad Gateway` from the proxy |

**Fix:**

1. Confirm the server is up:
   `curl http://127.0.0.1:8080/health`.
2. Confirm the chat shell is pointed at the right URL. The default
   is hardcoded to `http://127.0.0.1:8080` in
   `apps/lattice-web/src/app.rs::DEFAULT_SERVER_URL`. Editing it
   requires rebuilding (`trunk build`).
3. Confirm CORS is permissive on the server: it should reply with
   `Access-Control-Allow-Origin: *`. M3 ships this as the default.
4. Check the server log for the request — if it does not show up
   there, the problem is between the browser and the server, not
   in the server itself.

---

### `register HTTP 400 (user_id length N expected 32)`

**Where:** Status line during bootstrap.

**Cause:** Something corrupted the base64 of your user_id before it
got into the request body. Usually a paste-buffer accident.

**Fix:** clear `localStorage`, bootstrap fresh.

```js
localStorage.clear();
location.reload();
```

---

### Conversations show `# group <prefix>` instead of a label

**Where:** Sidebar.

**Cause:** You auto-joined an N-party group or a server-membership
group via `discover_pending_welcomes`. Welcomes do not carry the
group name (chunk 2 first-cut limitation). For server-membership
groups, the label upgrades to the server's name on the next 5-second
poll when the `ServerStateOp::Init` decrypts.

**Fix:** wait 5 seconds for the poll, or click into the conversation
to trigger a poll immediately.

If the placeholder persists for a regular N-party group: that is
the current behaviour. Chunk 2.5's server-membership group
application message carries both server name and inviter user_id;
similar metadata for N-party groups is tracked but unshipped.

---

### Two browser tabs see different identities

**Where:** Two browser tabs, both on `127.0.0.1:5173` (or both on
`localhost:5173`).

**Cause:** This is **wrong, the tabs should share an identity** —
they share `localStorage`. Most likely cause: one of the tabs ran
the bootstrap before the other persisted, so each generated a fresh
identity in parallel. The chunk-C bootstrap-in-flight guard
(`AtomicBool`) closed this race, but it is possible to hit it
manually by hard-reloading both tabs simultaneously before either
finished bootstrapping.

**Fix:** close one of the tabs, hard-reload the other so both share
the latest identity.

If you intended two distinct identities (Alice and Bob in two tabs
on one browser): use **different hostnames** so each tab gets its
own `localStorage` partition. The quickstart uses
`http://localhost:5173` for one and `http://127.0.0.1:5173` for the
other. Or use one regular window and one incognito window.

---

## Server errors

### `EpochNotFound` in client decrypt

**Where:** `decrypt_with_sender` throws.

**Cause:** The receiving client's MLS state is at an earlier epoch
than the message claims. Either the receiver missed a commit, or
the receiver was removed from the group in an earlier commit and is
trying to decrypt a post-removal message.

**Fix (receiver missed a commit):** the receiver should
re-fetch from `since=0` to pick up any missed messages. With the
current 5-second poll, this normally heals automatically.

**Fix (receiver was removed):** there is nothing to fix — this is
the device-revocation flow working correctly. The removed device
cannot decrypt post-revocation messages.

---

### `snapshot write failed path=X error=Y` in server log

**Where:** Server boot or graceful shutdown.

**Cause:** The server cannot write to
`LATTICE__SNAPSHOT_PATH`. Disk full, wrong permissions, or the
parent directory does not exist.

**Fix:**

```bash
# Verify the parent dir exists and is writable by the lattice user:
ls -ld /var/lib/lattice
# Should be: drwx------ lattice lattice

# If wrong:
sudo mkdir -p /var/lib/lattice
sudo chown lattice:lattice /var/lib/lattice
sudo chmod 0700 /var/lib/lattice
```

After fixing, send SIGTERM and let the server restart to verify the
snapshot writes.

---

### `signature verify failed origin_host=X` in federation

**Where:** Server log on inbound federation push.

**Cause:** A peer's federation signature does not validate against
the pubkey you have pinned for that host. Two possibilities:

1. **The peer rotated their federation key.** Rare and intentional;
   they should have coordinated.
2. **MITM or replay.** The peer's hostname is being impersonated by
   a hostile party.

**Fix:**

- Confirm by fetching `/.well-known/lattice/server` from the peer
  out-of-band (Signal, voice call). Compare to the pubkey you have
  pinned.
- If the peer legitimately rotated, manually update your pin (M5+
  config knob; pre-M5 requires editing the persisted peer registry
  by hand).
- If the change is unexpected, leave the pin alone and surface a
  distrust delta. Investigate the peer.

---

### `ws subscriber lagged missed=N` in server log

**Where:** Server log during heavy chat traffic.

**Cause:** The broadcast channel for the group's WebSocket push is
sized at 64 messages; a slow subscriber that misses 64+ messages
gets dropped. The client reconnects on its end and recovers via
`GET /group/<gid>/messages?since=N`.

**Fix:** none required — this is the protocol behaving correctly.
M5+ config tuning may bump the buffer size for high-traffic groups.

---

## Build environment errors

### `linker `link.exe` not found` on Windows

**Where:** `cargo build` on a Windows host.

**Cause:** Visual Studio Build Tools are not installed, but your
toolchain is the MSVC variant
(`stable-x86_64-pc-windows-msvc`). MSVC needs `link.exe` from
`vcvars64.bat`.

**Fix (preferred):** switch to the GNU host toolchain per CLAUDE.md.

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
# Ensure MSYS2's MinGW64 bin is on PATH for windres:
$env:PATH = "C:\msys64\mingw64\bin;" + $env:PATH
```

`apps/lattice-desktop/src-tauri/scripts/dev.ps1` does this pin
automatically.

**Fix (alternative):** install Visual Studio 2022 Build Tools (the
free Community / BuildTools SKU works) and let MSVC be the host.
Either is supported; the GNU path is the one Matt's box uses.

---

### `gcc.exe: error: missing operand` during a fresh build

**Where:** `cargo build` link step on Windows + GNU toolchain.

**Cause:** A `RUSTC_WRAPPER` (commonly `sccache`) is shimming the
linker call and producing a malformed command line. Seen on
openSUSE Tumbleweed's default config (HANDOFF §M3 deploy notes).

**Fix:** disable the wrapper for this build.

```powershell
$env:RUSTC_WRAPPER = $null
$env:CARGO_BUILD_RUSTC_WRAPPER = $null
cargo build --release
```

Or on Linux:

```bash
RUSTC_WRAPPER= CARGO_BUILD_RUSTC_WRAPPER= cargo build --release
```

---

### `cargo tauri build` fails with `ld.exe: export ordinal too large`

**Where:** `cargo tauri build` on Windows + GNU toolchain.

**Cause:** mingw `ld.exe` hits an "export ordinal too large"
failure on the cdylib variant of `lattice-desktop` because of the
transitive symbol count (Tauri + webrtc-rs + lattice-crypto +
lattice-server cross-deps under workspace unification).

**Fix:** the workspace pins `lattice-desktop`'s `[lib]` to `rlib`
only (HANDOFF §15). `cargo check -p lattice-desktop` and `cargo
tauri dev` both compile green. `cargo tauri build` for the MSI
bundle requires the MSVC toolchain. Reinstate
`["staticlib", "cdylib", "rlib"]` once you stand up an MSVC host.

---

### `CryptoProvider::get_default() panicked`

**Where:** First DTLS handshake in a process that pulls both
`lattice-server` and `lattice-media`.

**Cause:** The workspace's `rustls = { version = "0.23", features =
["ring"] }` declaration does not set `default-features = false`. So
rustls's `default` features (which include `aws-lc-rs`) remain
active. When the linker pulls both, `CryptoProvider::get_default()`
panics because two providers are registered.

**Fix:** `lattice_media::ensure_crypto_provider()` installs rustls's
`ring` provider once at boot via `std::sync::Once`. The orchestrator
and the Phase E.2 smoke test call it. The Tauri shell's `run()`
also calls it. If you write a new binary that uses both crates,
call it before any DTLS handshake.

---

## OS-keychain errors

### Linux dbus prompts

**Where:** Tauri shell on Linux on first keystore use.

**Cause:** `LinuxKeystore` talks to the FreeDesktop Secret Service
over D-Bus. On first use, KDE Wallet or GNOME Keyring prompts the
user to unlock the default keyring. Subsequent uses are silent for
the session.

**Fix:** unlock the keyring. The prompt is one-shot per session.

If no keyring service is running (headless box, fresh container),
`LinuxKeystore::new` returns an error and the shell falls back to
`MemoryKeystore` (volatile — keys are lost on process exit). The
fallback path is intentional for CI / sandbox environments; for a
real install, ensure `gnome-keyring-daemon` or `kwalletd` is
running.

---

### macOS Keychain prompts

**Where:** Tauri shell on macOS on first keystore use.

**Cause:** `MacosKeystore` uses `security-framework` against the
login Keychain. macOS prompts "lattice-desktop wants to access the
Keychain" on first use. You can "Always Allow" to silence further
prompts.

**Fix:** click Allow / Always Allow. If you accidentally click
Deny, you can revoke via Keychain Access → Edit → "Change Settings
for Keychain login..." → manage access.

---

### Windows DPAPI: file lives at `%LOCALAPPDATA%\Lattice\keystore\`

**Where:** Tauri shell on Windows.

**Cause:** Not an error — `WindowsKeystore` writes
`<handle>.dpapi` (sealed bytes) + `<handle>.pub` (sidecar metadata)
per identity under `%LOCALAPPDATA%\Lattice\keystore\`. If the
keystore is misbehaving, the first thing to check is whether the
folder exists and is writable by the current user.

**Fix:** ensure the folder exists; the keystore creates it on first
use. If access is denied, check the folder's ACL — DPAPI seals are
user-bound, so a sealed file written by user A cannot be unsealed
by user B.

---

## Connectivity errors

### Two browser tabs on the same hostname fail to share a conversation

**Where:** Quickstart step 5/6.

**Cause:** Browsers partition `localStorage` per **origin** (scheme +
host + port). `http://localhost:5173` and `http://127.0.0.1:5173`
are different origins and get separate identities — that is the
intended workflow for the quickstart.

If you opened **two tabs on the same origin**, they share
`localStorage`, which means they share an identity. They cannot
"talk to each other" because there is only one of them.

**Fix:** use two different hostnames, or one regular window plus one
incognito window.

---

### `gloo-net` error: `CORS preflight failed`

**Where:** Browser console during any API call.

**Cause:** The server's CORS layer is configured to allow any origin
by default. If you see this error, the server's CORS is **not**
allowing-any. Either you tightened it manually, or you have a
reverse proxy overlaying its own CORS policy.

**Fix:**

1. Verify the server reply headers:
   `curl -sI -X OPTIONS http://127.0.0.1:8080/register`. You
   should see `Access-Control-Allow-Origin: *`.
2. If the server is fine but the proxy isn't, fix the proxy. Caddy
   needs no extra config for the embedded `*` policy to pass
   through.
3. If the server is wrong, ensure
   `LATTICE__SERVER__CORS_ALLOW_ANY=true` (the default) and that
   you have not edited `lattice_server::app()` to remove the CORS
   layer.

---

## Diagnostic commands cheat-sheet

| Question | Command |
|---|---|
| Is my server alive? | `curl http://127.0.0.1:8080/health` |
| What's the server's federation pubkey? | `curl -s http://127.0.0.1:8080/.well-known/lattice/server \| jq` |
| Am I registered? | `curl http://127.0.0.1:8080/key_packages/<your_uid_b64>` (returns 404 if not) |
| Are there welcomes waiting for me? | `curl http://127.0.0.1:8080/welcomes/pending/<your_uid_b64> \| jq` |
| Verbose logs on the server | `RUST_LOG=lattice_server=trace,lattice_crypto=trace` env var |
| Snapshot contents | `cat /var/lib/lattice/snapshot.json \| jq` |
| Workspace lints clean | `.\scripts\test-all.ps1` (Windows) |
| WASM build clean | `cargo check -p lattice-core --target wasm32-unknown-unknown` |
| CSP / SRI hashes match | `.\scripts\verify-csp.ps1` |

---

## When all else fails

The repo's `SECURITY.md` describes the disclosure path for genuine
security findings. For regular bugs:

1. Capture the failing command and its output.
2. Note the commit hash (`git rev-parse HEAD`).
3. Note your platform + toolchain (`rustc --version`, OS, host
   triple).
4. Open an issue or pull request against
   `github.com/suhteevah/lattice`. The owner's GitHub Actions are
   not used (per Matt's policy); local verification gates are
   `scripts/test-all.ps1` and the explicit commands in
   [development.md](development.md).
