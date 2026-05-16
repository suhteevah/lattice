# Tauri updater — design

**Status:** Brainstorming complete, awaiting review. Author: Matt Gates (via
Claude). Date: 2026-05-16. Repo HEAD at design time: `74817ba`.

## Problem

Today the Lattice desktop app ships as a one-shot artifact:
`Lattice_0.1.0_amd64.deb`, the Windows `lattice-desktop.exe`, etc. There
is no in-app update path. To get the next release into a user's hands,
that user has to know there's a new build, find the link, download, and
install by hand. For a small private network that's tolerable. For
anything growing past 3–5 users, it isn't.

We need an in-app updater with cryptographic verification: the app
checks for new releases on its own schedule, downloads the new binary,
verifies a signature against a pinned pubkey, and restarts into the new
version. No CI / GitHub Actions involved — releases are signed and
uploaded by hand per `~/.claude/CLAUDE.md` ("GitHub CI banned").

## Goals (in scope)

1. In-app update check on launch + every 24 h while running.
2. User-visible "Check for updates" menu item.
3. Signed manifest + signed binary download. Pinned ed25519 pubkey in
   the client. Update rejected on signature mismatch.
4. Roll-forward only — no auto-rollback (manual fallback path
   documented below).
5. Windows MSI + Linux `.deb` for MVP. macOS / `.AppImage` / Android
   follow in separate spec.
6. A reproducible release-build script the operator runs by hand on
   kokonoe + cnc to produce + sign + upload artifacts.

## Non-goals (deferred)

- Delta / patch updates. Full binary replacement only.
- Channel selection (stable / beta / nightly). Single channel.
- Hardware-backed signing key (YubiKey via PKCS#11). Path documented,
  not implemented; ships with file-based key first.
- Telemetry / opt-in update-failure reporting.
- macOS / iOS / Android targets — those have their own platform
  packaging concerns and get separate specs.
- Forced update (server says "you MUST update"). Skip until threat
  model demands it.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ Release host (kokonoe for Windows, cnc/pixie for Linux)         │
│                                                                 │
│   scripts/release.ps1   NEW — orchestrates per-platform build,  │
│                         compute hash, call tauri signer, upload │
│                         to GitHub Release, push manifest        │
│                                                                 │
│   ~/.tauri/lattice-updater.key   NEW — file-based ed25519       │
│                                  signing key, passphrase-       │
│                                  protected. Generated once.     │
│                                  Backup to password manager.    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
        ┌──────────────────────┴────────────────────────┐
        │                                                │
        ▼                                                ▼
┌──────────────────────┐                ┌────────────────────────┐
│ GitHub Releases      │                │ apps/lattice-docs/      │
│ (artifact storage)   │                │ public/updater/         │
│                      │                │   manifest.json   NEW   │
│ - Windows MSI        │                │                         │
│ - Linux .deb         │                │ Served at:              │
│ - sha256 manifest    │                │ https://lattice-quantum │
│                      │                │ .vercel.app/updater/    │
│ Free, public, durable│                │ manifest.json           │
└──────────────────────┘                └──────────┬──────────────┘
        ▲                                          │
        │ HTTP GET (download new binary)           │ HTTP GET
        │                                          │ (poll for new ver)
        │                                          ▼
        │                          ┌─────────────────────────────┐
        │                          │ lattice-desktop (Tauri 2)    │
        └──────────────────────────┤                              │
                                   │ tauri-plugin-updater          │
                                   │   - launch + 24h poll         │
                                   │   - sig-verify against pinned │
                                   │     ed25519 pubkey            │
                                   │   - prompt user, download,    │
                                   │     install, restart          │
                                   └─────────────────────────────┘
```

### Trust path

1. The operator (Matt) generates an ed25519 keypair once via
   `cargo tauri signer generate -w ~/.tauri/lattice-updater.key`.
   Passphrase-protected; backed up to password manager.
2. The **public** key is hardcoded into `tauri.conf.json` under
   `plugins.updater.pubkey`. Every desktop build embeds it.
3. Every release manifest is signed with the **private** key. Every
   binary is also signed (sig is in the manifest, not in the
   binary). The Tauri client refuses any update whose signature
   doesn't verify against the embedded pubkey.
4. If the private key is lost: there is no remote-revoke path. New
   key, new pubkey, recompile + ship a one-time "manual update"
   build of the client. This is the only catastrophic-key-loss path.

This is the same trust model as Sparkle / Squirrel / Tauri's built-in
updater. The pubkey-in-binary plus sig-on-manifest combination means
a compromised manifest host cannot push a malicious update — the
attacker would need the private key.

### Why GitHub Releases for binaries

- Free, durable, public, large file support (2 GB per asset, way over
  our ~30 MB binaries).
- `gh release upload` is one CLI invocation per platform.
- Independent of Vercel's per-file size caps.
- Not CI — this is artifact storage. CLAUDE.md "GitHub CI banned"
  applies to GitHub Actions runners, not GitHub Release uploads.

The manifest stays on Vercel (`apps/lattice-docs/public/updater/`)
because it's the latest-version lookup; updating it is just a
redeploy of the Astro site, which is the natural cadence for "we
shipped a release."

## Components

### `apps/lattice-desktop/src-tauri/Cargo.toml` (extension)

```toml
[dependencies]
tauri-plugin-updater = "2"
```

### `apps/lattice-desktop/src-tauri/tauri.conf.json` (extension)

```jsonc
{
    "plugins": {
        "updater": {
            "endpoints": [
                "https://lattice-quantum.vercel.app/updater/manifest.json"
            ],
            "pubkey": "<base64 of the ed25519 public key>",
            "dialog": true,
            "windows": {
                "installMode": "passive"
            }
        }
    }
}
```

`dialog: true` shows the built-in Tauri update dialog ("New version
0.2.0 available. Notes: <release notes>. [Install now] [Later]").
`installMode: passive` on Windows skips UAC prompts when possible.

### `apps/lattice-desktop/src-tauri/src/lib.rs` (extension)

Wire the plugin into the Tauri builder:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_updater::Builder::new().build())
    // ... existing plugins ...
```

Add a periodic check in the existing app state:

```rust
// Spawn a tokio task that fires `updater().check()` every 24h.
// On launch, fire once 30s after window-shown so we don't block
// startup.
```

### `apps/lattice-docs/public/updater/manifest.json` (new)

Tauri 2 updater manifest shape:

```json
{
    "version": "0.2.0",
    "notes": "First updater-enabled release. See CHANGELOG.md.",
    "pub_date": "2026-05-16T12:00:00Z",
    "platforms": {
        "windows-x86_64": {
            "signature": "<base64 ed25519 sig over the MSI bytes>",
            "url": "https://github.com/suhteevah/lattice/releases/download/v0.2.0/Lattice_0.2.0_x64_en-US.msi"
        },
        "linux-x86_64": {
            "signature": "<base64 ed25519 sig over the .deb bytes>",
            "url": "https://github.com/suhteevah/lattice/releases/download/v0.2.0/Lattice_0.2.0_amd64.deb"
        }
    }
}
```

The Tauri client computes its own version (from `Cargo.toml`),
compares to `version` here. If newer is available, it downloads the
platform-matched URL, verifies the signature against the embedded
pubkey, executes install path (MSI on Windows, deb on Linux).

### `scripts/release.ps1` (new)

A PowerShell orchestration script. Pseudo-code:

```powershell
param(
    [Parameter(Mandatory)] [string]$Version,
    [Parameter(Mandatory)] [string]$Notes,
    [SecureString]$KeyPassphrase = (Read-Host -AsSecureString "Key passphrase")
)

# 1. Bump versions
#    - apps/lattice-desktop/src-tauri/Cargo.toml
#    - apps/lattice-desktop/src-tauri/tauri.conf.json
#    - workspace Cargo.toml [workspace.package].version
#    (Commits left to operator — script doesn't git-commit.)

# 2. Build per-platform
#    Windows:
$env:RUSTUP_TOOLCHAIN = 'stable-x86_64-pc-windows-gnu'
cargo tauri build --bundles msi   # → target/release/bundle/msi/...

#    Linux (delegate to cnc-server or pixie via ssh):
ssh cnc-server "cd ~/code/lattice && git fetch && git checkout v$Version && cargo tauri build --bundles deb"
scp cnc-server:.../target/release/bundle/deb/Lattice_${Version}_amd64.deb .\releases\

# 3. Sign each artifact
cargo tauri signer sign -k ~/.tauri/lattice-updater.key -p $KeyPassphrase `
    -- target/release/bundle/msi/Lattice_${Version}_x64_en-US.msi
# Output: .sig file next to the binary

# 4. Upload to GitHub Release
gh release create "v$Version" `
    --title "Lattice v$Version" `
    --notes $Notes `
    target/release/bundle/msi/Lattice_${Version}_x64_en-US.msi `
    releases/Lattice_${Version}_amd64.deb

# 5. Write the new manifest
$manifest = @{
    version = $Version
    notes = $Notes
    pub_date = (Get-Date -Format "o")
    platforms = @{
        "windows-x86_64" = @{
            signature = (Get-Content "...x64_en-US.msi.sig" -Raw)
            url = "https://github.com/suhteevah/lattice/releases/download/v$Version/Lattice_${Version}_x64_en-US.msi"
        }
        "linux-x86_64" = @{
            signature = (Get-Content "...amd64.deb.sig" -Raw)
            url = "https://github.com/suhteevah/lattice/releases/download/v$Version/Lattice_${Version}_amd64.deb"
        }
    }
}
$manifest | ConvertTo-Json -Depth 10 | Set-Content "apps/lattice-docs/public/updater/manifest.json"

# 6. Deploy the manifest
cd apps/lattice-docs
vercel deploy --prebuilt --prod
```

The script is operator-driven — no git commits, no auto-pushes. The
operator runs it locally with the keypassphrase in their head.

### Key generation (one-time bootstrap)

```powershell
cargo tauri signer generate -w "$env:USERPROFILE\.tauri\lattice-updater.key"
# Prompts for passphrase.
# Writes:
#   ~/.tauri/lattice-updater.key       (private; encrypted at rest by passphrase)
#   ~/.tauri/lattice-updater.key.pub   (public; goes into tauri.conf.json)
```

The private key file gets:

- `0600` permissions on Linux (kokonoe is Windows — DPAPI-equivalent
  via the file's ACL).
- A backup copy in your password manager (1Password / Bitwarden).
- A second printout on paper, sealed in an envelope, somewhere
  off-line.

The pubkey is non-secret. It goes into `tauri.conf.json` and ships
with every binary.

### YubiKey upgrade path (documented, not built)

When the user base grows past ~50 users, swap the file-based key for
a YubiKey 5 series via PKCS#11:

1. `cargo tauri signer` supports a PKCS#11 backend — point it at the
   YubiKey's slot via OpenSC.
2. Sign releases with the YubiKey inserted. Private key never leaves
   the hardware.
3. Rotate the embedded pubkey in `tauri.conf.json` to the YubiKey's
   pubkey. Ship a one-time "manual update" build of the client to
   migrate existing users (they install the new binary by hand once,
   then the new updater chain takes over).

This is a clean swap path — no Tauri-side code change needed beyond
the conf.json pubkey field.

## Data flow

### Build + ship a release

1. Operator runs `pwsh ./scripts/release.ps1 -Version 0.2.0
   -Notes "..."`.
2. Script bumps versions, builds Windows MSI on kokonoe, Linux .deb
   on cnc-server via ssh.
3. Script signs each artifact with `cargo tauri signer sign` and the
   private key.
4. Script `gh release create v0.2.0` and uploads both binaries +
   their .sig files to GitHub.
5. Script writes new manifest to
   `apps/lattice-docs/public/updater/manifest.json`.
6. Script `vercel deploy --prebuilt --prod` deploys the manifest.

### Client update check (on launch)

1. Tauri app boots. 30 s after the main window shows, plugin fires
   `updater().check()`.
2. Plugin GETs `https://lattice-quantum.vercel.app/updater/manifest.json`.
3. Plugin parses, compares `manifest.version` to its own
   `env!("CARGO_PKG_VERSION")`. If newer → trigger.
4. Plugin picks the right platform entry (e.g., `windows-x86_64`).
5. Plugin downloads the URL from `platforms.<target>.url`.
6. Plugin verifies the downloaded bytes against
   `platforms.<target>.signature` using the embedded pubkey.
7. Plugin shows the dialog: "Lattice 0.2.0 is available. [Install now]
   [Later]".
8. On user-confirm: plugin runs the install path (MSI on Windows,
   `dpkg -i` on Linux) and restarts.

Periodic check (every 24 h) does the same path silently — if no new
version, no UI; if newer, fires the dialog.

## Error handling

| Failure | Detection | Response |
|---|---|---|
| Manifest unreachable | network error or 5xx from Vercel | Silent retry on next 24 h tick. Manual menu surfaces error toast. |
| Manifest JSON malformed | parse error | Tracing error log, ignored. |
| Manifest version === ours | semver compare | No-op silently. |
| Manifest version older than ours | semver compare | No-op. We never downgrade. |
| Binary download fails | connection error | Toast "update download failed, retry?" |
| Binary signature mismatch | sig verify | **HARD FAIL.** Toast: "Update rejected — signature verification failed. Possible compromise. Notify operator." Log warn. Do NOT install. |
| Install command fails (MSI / dpkg) | exit code != 0 | Toast: "Install failed: <stderr>. Manual install required." |
| Pubkey lost on operator side | release.ps1 errors at signer step | Operator regenerates key + bootstraps clients via "manual update" rebuild. Documented. |

The **signature mismatch path is the most important.** It must not
fall back to "install anyway." Tauri's plugin defaults to abort on
mismatch — verify the abort is logged loudly during integration test.

## Testing

| Layer | Coverage |
|---|---|
| Unit (lattice-desktop) | Trivial — the plugin is third-party. Test the wiring (plugin builder, periodic-check tokio task spawn). |
| Manifest smoke | A test harness that writes a manifest, serves it on localhost, points the dev build at it, confirms version detection + signature verify pass. |
| Cross-version | Ship 0.1.0 to a test machine. Run `release.ps1 -Version 0.1.1`. Verify the test machine prompts for the update + installs + relaunches at 0.1.1. |
| Tamper test | Modify a signed `.msi` after signing. Re-host the manifest. Verify the client REJECTS the update with the signature-mismatch error path. |
| Manifest hosting | Verify `https://lattice-quantum.vercel.app/updater/manifest.json` returns the file with `Content-Type: application/json`, no auth gate, cache-control short (5 min). |

The tamper test is the one that confirms the trust model isn't
theatrical. Do it once at v0.2.0 ship-time and at every key rotation.

## Open questions

None — every branch has a documented answer above.

## Files to be touched

```
apps/lattice-desktop/src-tauri/Cargo.toml      modified (+ tauri-plugin-updater)
apps/lattice-desktop/src-tauri/tauri.conf.json modified (+ plugins.updater)
apps/lattice-desktop/src-tauri/src/lib.rs      modified (plugin wiring + periodic task)

apps/lattice-docs/public/updater/manifest.json new (first release populates it)

scripts/release.ps1                            new
```

Plus one-time, ungitted:

```
~/.tauri/lattice-updater.key       generated (NOT in repo, NEVER committed)
~/.tauri/lattice-updater.key.pub   generated (its base64 goes into tauri.conf.json)
```

## Deployment

The first release is the bootstrap:

1. Operator generates the key on kokonoe.
2. Copy `lattice-updater.key.pub` contents → paste into
   `tauri.conf.json` `plugins.updater.pubkey`.
3. Commit `tauri.conf.json` (pubkey is non-secret).
4. Run `release.ps1 -Version 0.2.0 -Notes "first updater release"`.
5. Smoke: install the 0.2.0 binary on a fresh test box. Confirm it
   boots, federates, registers (with v2 invite token). Verify the
   updater plugin's launch check sees the same version and doesn't
   prompt.
6. Bump to 0.2.1 on a side branch, run `release.ps1 -Version 0.2.1`.
7. On the test box, force an update check via menu. Confirm prompt,
   confirm install, confirm relaunch at 0.2.1.

After that, every release is one `release.ps1` invocation.

## Rollback

If a bad update ships to users:

1. Operator runs `release.ps1 -Version 0.2.X` where 0.2.X > the bad
   version, with the previous-known-good code. (You can't ship a
   lower version number — that's the no-auto-downgrade rule.)
2. Users running the bad version's auto-check pick up 0.2.X within
   24 h. Manual menu pulls it sooner.

For really catastrophic releases (the bad build can't even start —
no chance for the in-app updater to fire): the user re-downloads
the previous-known-good MSI / deb manually from
`https://github.com/suhteevah/lattice/releases` and installs over the
broken one. Document that link prominently in the README.

## Estimate

One implementation session:

1. Add the plugin + tauri.conf.json + lib.rs wiring (~30 min).
2. Generate the key, set the pubkey in conf (~10 min).
3. Write `release.ps1` end-to-end (~2 hours).
4. First release dry-run: 0.1.0 → 0.1.1 against a test box
   (~1 hour).
5. Tamper-test (~30 min).

Total: ~4 hours of focused work.
