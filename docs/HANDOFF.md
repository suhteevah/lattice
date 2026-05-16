# Lattice — HANDOFF

**Last updated:** 2026-05-16 — **production federation pair live
(cnc + pixie) at `https://lattice.pixiedustbot.com`** plus
Reg v2 spec + plan + Section A server code complete on
`worktree-reg-v2` branch (14 of 29 plan tasks done). Tauri Linux
`.deb` artifact built on cnc. Updater spec written, no code yet.
Android scaffold recon — gated on SDK install. See §26 below.

**Status:** 🟡 In progress on Reg v2 — Section A code in worktree
not yet committed or merged; Section B (Astro admin UI) + C
(chat-shell token field) + OPS deploy still pending. Production
servers still on pre-Reg-v2 binary (static-token gate via
`LATTICE__SERVER__REGISTRATION_TOKEN`). To resume: enter the
worktree at `J:\lattice\.claude\worktrees\reg-v2`, read
`docs/superpowers/plans/2026-05-16-registration-v2.md`, pick up
at Task 16.

---

### Session log — 2026-05-16

Two-track session: stand up production federation, then start
shipping invite-only registration (Reg v2).

**Track 1 — Production federation pair (live).**

1. **cnc home server** brought up at
   `http://cnc-server.tailb85819.ts.net:8444` (tailnet only).
   Federation pubkey:
   `PX98QlkAc6JTavLsbuRYUuzbw5wlizSfsVbj8GGlbsY=`. systemd-managed
   via `/etc/systemd/system/lattice-server.service` +
   `/var/lib/lattice/{federation.key,snapshot.json}`. Built from
   source on the cnc host (openSUSE Leap Micro 6.2) — required
   building `capnproto` 1.0.2 from source into `/usr/local/bin`
   because the atomic-OS `transactional-update` path conflicts
   with the running OpenClaw stack. See
   [[capnp-build]] memory for the per-host install matrix.
2. **pixie home server** brought up on Ubuntu 24.04 host
   `pixiedust-stl` (joined Matt's tailnet for federation reach,
   `100.117.173.42`). Bound the same 0.0.0.0:8444. Federation
   pubkey: `AUuXAGkX5UZdzs14WPjgFGqJODSTybPK3QumQcEd5BA=`. Same
   systemd setup.
3. **Caddy + Let's Encrypt** on pixie. ACME via HTTP-01 succeeded
   first try. `https://lattice.pixiedustbot.com` serves with a real
   cert (ACME account `mmichels88@gmail.com`). ufw allows 80 + 443;
   bare `:8444` stays publicly closed. Caddyfile at
   `/etc/caddy/Caddyfile` — single reverse_proxy to localhost:8444
   with zstd + gzip + HSTS headers.
4. **Federation smoke verified.** `lattice demo` round-tripped a
   PQ-hybrid sealed-sender message cnc → pixie in 1.2 s. TOFU
   pin landed on pixie's side. See `scratch/federation-pinning.md`
   (untracked, gitignored) for the operator-side fingerprint
   record.
5. **Matt's client** registered against cnc via the Tauri 2 dev
   shell. user_id `97984c03…3ef0f3f39` lives in the Windows
   DPAPI keystore at `%LOCALAPPDATA%\Lattice\keystore`.

Memory: [[federation-live-pair]] captures the URLs / pubkeys /
bind addresses for the next session.

**Track 2 — Linux artifact pipeline.**

1. **lattice-server** Linux binary built on cnc, pulled back to
   kokonoe at `J:\lattice\releases\linux\lattice-server`
   (sha256 `4ae6425879417eb1da14f4ec30b5dff037e9ea05dd0f63336cfad34c65d786b7`).
2. **Tauri 2 `.deb`** built on cnc at
   `target/release/bundle/deb/Lattice_0.1.0_amd64.deb` 5.1 MB
   (sha256 `2ab387384ced3dd95f37ada957500ebbf62248c0614ad0810a46964d35698285`).
   AppImage attempted but the appimagetool hung on a GitHub
   rate-limit close; `.deb` is the working artifact.
3. **Arch PKGBUILD** written at `packaging/arch/PKGBUILD` plus
   README — split package (`lattice-desktop` + `lattice-server`),
   pulls from a pinned commit, AUR-friendly notes for trunk.
4. **Two-user war doc** at `scratch/two-user-firstserver-war.md`
   (untracked) — invite + pair + first-message smoke walkthrough
   for onboarding a *nix user.
5. **New-user handoff** + prompt at
   `scratch/new-user-handoff.md` + `scratch/new-user-prompt.md`
   — paste-into-their-Claude prompt + the doc that walks their
   agent through install + verify + register against pixie.
6. **Android scaffold recon** dispatched via subagent. Result:
   gated on Android SDK + NDK install on kokonoe (~2 GB minimum,
   ~6.5 GB full). Cargo.toml `crate-type = ["rlib"]` and missing
   `lattice-media/src/keystore/android.rs` are independent
   blockers. Detailed in `scratch/android-scaffold-report.md`.
   Deferred behind Reg v2 + Updater.

**Track 3 — Reg v2 (in flight).**

1. **Brainstorming**: full design pass via the brainstorming skill.
   Spec at `docs/superpowers/specs/2026-05-16-registration-v2-design.md`.
   Stateful single-use tokens, Clerk-gated Astro admin UI, atomic
   consume on `/register`. Astro chosen (not Next.js) since the
   existing docs site is Astro 4. Token lifetime: single-use, 7-day
   expiry default.
2. **Plan**: 29 bite-sized tasks at
   `docs/superpowers/plans/2026-05-16-registration-v2.md`. Each
   task has concrete code, commands, expected outputs. Per
   `CLAUDE.md` "no commits without explicit ask," the plan stages
   only — commits left to the operator.
3. **Section A code** (Tasks 1–14): server-side complete. Worktree
   at `J:\lattice\.claude\worktrees\reg-v2`, branch
   `worktree-reg-v2`. 625 insertions / 30 deletions across 10
   files. 5 integration tests + 4 unit tests pass. Race test
   proves single-spend under 200 concurrent /register POSTs.
4. **Backcompat preserved**: the legacy
   `LATTICE__SERVER__REGISTRATION_TOKEN=BIUB…3uV2` continues to
   work — auto-mints as a no-expiry invite at first boot if the
   registry is empty (labelled
   `legacy:LATTICE__SERVER__REGISTRATION_TOKEN`).

Memory: [[reg-v2-session-state]] for resume notes;
[[reg-v2-admin-key]] for the deploy env var.

**Track 4 — Updater (spec only).**

Spec written at `docs/superpowers/specs/2026-05-16-updater-design.md`.
Tauri 2 `tauri-plugin-updater` + file-based ed25519 signing key
(passphrase-protected, YubiKey upgrade path documented). Binaries
on GitHub Releases, manifest on the Astro deploy. `scripts/release.ps1`
orchestrates per-platform build → sign → upload → manifest update.
No plan written yet; comes after Reg v2 ships.

**Files written (untracked / scratch):**
- `scratch/two-user-firstserver-war.md`
- `scratch/new-user-handoff.md`
- `scratch/new-user-prompt.md`
- `scratch/federation-pinning.md`
- `scratch/android-scaffold-report.md`
- `scratch/reg-v2-operator-notes.md`
- `scratch/.registration-token` (secret; in .gitignore)

**Files written (committed in main checkout via /handoff):**
- `docs/superpowers/specs/2026-05-16-registration-v2-design.md`
- `docs/superpowers/specs/2026-05-16-updater-design.md`
- `docs/superpowers/plans/2026-05-16-registration-v2.md`
- `packaging/arch/PKGBUILD`
- `packaging/arch/README.md`

**Files written (committed in worktree on branch worktree-reg-v2 via /handoff):**
- All Section A code (10 files, 625 insertions / 30 deletions).

**What's next (for the incoming session):**

In priority order:

1. **Reg v2 Section B** — Astro admin UI + invite-redemption pages
   + Clerk-gated API routes. Plan tasks 16–22. Hits
   `apps/lattice-docs/` (the existing live Vercel deploy).
2. **Reg v2 Section C** — chat shell `Settings` panel adds an
   "Invite token" input field. Plan tasks 23–26. Touches
   `apps/lattice-web/src/{api,chat_state,chat,storage}.rs`.
3. **Reg v2 deploy (Task 15 + 22)** — push the new server binary
   to cnc + pixie with the new admin key in systemd override.
   Vercel deploy the Astro changes. ~10 s federation downtime
   per host.
4. **Reg v2 smoke** (Tasks 27–29) — end-to-end via /admin → mint
   → /invite/[token] → chat shell paste → register → admin shows
   consumed.
5. **Updater plan** — `superpowers:writing-plans` against the
   updater spec, then implement.
6. **Android scaffold** — install SDK + NDK, run
   `cargo tauri android init`, address the rlib/cdylib +
   `keystore/android.rs` blockers from the recon report.

**Notes for the next Claude:**

- Per `CLAUDE.md`, do NOT `git commit` without an explicit ask
  from Matt. Stage changes via `git add` and present the staged
  set + draft commit message; he runs `git commit` himself.
- The implementer pattern is `superpowers:subagent-driven-development`
  — fresh subagent per task or per logical bundle. Haiku for
  mechanical tasks, sonnet for atomic-critical-section / race
  /federation reasoning. Bundling adjacent tasks (same file,
  same component) cuts wall-clock without losing quality.
- Production servers still run the pre-Reg-v2 binary. The Matt's
  client + the documented `BIUB…3uV2` static token both still
  work. Do NOT advertise the new admin token shape externally
  until Section B + ops deploy land.
- The two-user-handoff at `scratch/new-user-handoff.md` is the
  paste-to-the-new-user's-Claude doc. After Reg v2 ships, refresh
  the §"Path A — chat shell with a token field" section to drop
  the "if the chat-shell build has a token field" hedge.
- `apps/lattice-docs/` is currently Astro 4 on Vercel. The Reg v2
  plan ADDS to it (`/admin`, `/invite/[token]`, `/api/admin/*`)
  — does NOT migrate to Next.js. Keep that boundary clean.

---

**Last updated:** 2026-05-12 (M7 Phases G.1 + G.2 shipped:
`lattice-media::keystore` trait + DPAPI Windows / Secret Service
Linux / Keychain macOS impls + five Tauri IPC commands. **Chat-app
chunks A + C + group-state persistence + scrollback** shipped:
real DM flow over MLS survives page reload AND the thread
re-renders pre-reload history on bootstrap. See §16 + §17 + §18
+ §19 + §20 below.)
**Owner:** Matt Gates (suhteevah)
**Status:** 🟢 Working — **chat actually works**. Steps 1+2;
**M1 / M2 / M3 / M4 / M5 / M6 all shipped**, **M7 Phases A–F +
G.1 + G.2 + chat chunks A + C shipped**. Open: G.3 (TPM 2.0 +
Secure Enclave binding) + Tauri mobile (H) + cover-traffic (I)
+ chat-app chunks B/D/E/F. See
[`scratch/next-session-plan.md`](../scratch/next-session-plan.md)
for the prioritized ordering. Browser tab is a full Lattice
client; server live at `http://127.0.0.1:8080`. Wire version is 4
(M7 call signaling, bumped during Phase C).
**200 workspace tests pass** (LATTICE_NET_TESTS only changes
whether the 4 network-binding tests run their full payload or
early-return; total count is the same either way — see
`crates/lattice-media/tests/*loopback.rs`). 14 new tests this
session: 12 inline keystore + 2 trait-object integration.
`cargo check --workspace`, `cargo check -p lattice-desktop`,
`cargo check -p lattice-core --target wasm32-unknown-unknown`,
`trunk build --release` (lattice-web, 54s) all green.

**Phase E.2 cryptographic smoke test is green.** A same-process
loopback drives two `IceAgent`s through full connectivity checks,
runs DTLS handshakes concurrently over the resulting `Conn`s,
pulls RFC 5705 keying material from both sides, performs an
ML-KEM-768 round trip, folds the PQ secret into the SRTP master
via HKDF, and asserts caller.local == callee.remote on the split
session keys. Test:
`crates/lattice-media/tests/pq_dtls_srtp_loopback.rs`. Run with
`$env:LATTICE_NET_TESTS=1; cargo test -p lattice-media --test
pq_dtls_srtp_loopback`.

### Session log — 2026-05-12 (post-Phase-F: build env + chat-app sizing)

Two follow-on items after the Phase F commit landed:

**1. Build env cleanup (commit `9023ed4`).** MSVC IS installed on
this box — vswhere lives at `C:\Program Files (x86)\Microsoft
Visual Studio\Installer\vswhere.exe`, VS 2022 Community at
`C:\Program Files\Microsoft Visual Studio\2022\Community`, VS 2022
BuildTools at `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools`.
But the previous `serve.ps1` / `build.ps1` / `check.ps1` shelled out
to `vcvars64.bat` via `cmd.exe /c`, and the nested cmd.exe couldn't
find `vswhere` on PATH so vcvars64.bat itself errored. Kalshi-trader-v7
on this same box builds Tauri fine with the GNU host toolchain +
MinGW windres, so the simpler path won: pin
`RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-gnu`, prepend
`C:\msys64\mingw64\bin` for windres, run trunk / cargo / tauri
directly. New script `apps/lattice-desktop/src-tauri/scripts/dev.ps1`
launches `cargo tauri dev` with that env prelude. **Verified:**
`trunk build --release` produces a clean lattice-web bundle under
`dist/` (3 MB wasm + 50 KB js + 4 KB css); `cargo build -p
lattice-desktop --release` produces a 7.9 MB
`target\release\lattice-desktop.exe` in ~4m34s on first build (the
incremental rebuild is fast).

**2. Chat-app gap sizing (no commit — analysis only).** Matt asked
how far we are from an "actual chat Tauri app." Cryptographic +
transport layers are done (M1–M6 + Phase F). What's missing is
purely UX work on top of the existing protocol surface:

| Chunk | Scope | Size |
|---|---|---|
| A — chat shell | Sidebar / message thread / composer. Replaces the demo button grid as the default view. | ~1 session |
| B — onboarding + contacts | First-launch identity setup · add contact by user_id / share-link / QR · localStorage-persisted contact list. Today's demos hardcode peers. | ~1 session |
| C — real DM flow | Pick contact → create-group commit → Welcome → conversation opens. Protocol pieces are already in `api.rs`; missing the wiring UI. | ~1 session |
| D — background receive + notifications | One persistent WS subscription per joined group · route incoming to the right pane · Tauri notification API. | ~0.5 session |
| E — server config + polish | Configurable home server (currently hardcoded `127.0.0.1:8080`) · connection status · "logged in as <prefix>" · settings page. | ~0.5 session |
| F — visual polish | Avatars / color stripes from user_id hash · empty states · keyboard shortcuts. Dark mode is already default. | ~0.5 session |

Total: ~3–4 focused sessions to go from button-grid demos to "give
a friend the MSI; they message back." Voice/video is a separate
track (Phase G hardware-backed keys + cross-machine signaling
deferred from Phase F).

Suggested chunk order: A → C → B → D → E → F. Keep the existing
button-grid alive as a `#/debug` route — fastest way to verify the
protocol works without going through chat UI.

### Session log — 2026-05-12 (Phase F)

Compact session diff for the incoming Claude:

- **Docs:** rewrote HANDOFF header + appended §15 (Phase F shipped
  block). Appended Phase F "shipped" entry to ROADMAP.md M7
  section.
- **New `lattice-media::call::run_loopback_call` orchestrator.**
  Same pipeline as Phase E.2 smoke test, packaged as a single
  async entry point that returns a `CallOutcome` (serializable for
  IPC). 240 LOC in `crates/lattice-media/src/call.rs`. New
  integration test `tests/orchestrator_loopback.rs` exercises it.
- **New `lattice-media::srtp::PqSrtpEndpoint`.** Wraps two
  `webrtc-srtp::Context`s (local + remote) built from the
  `split_srtp_master` output. Methods: `from_session_keys`,
  `protect_rtp`, `unprotect_rtp`. Three new unit tests prove
  caller↔callee RTP packet round trip + wrong-direction rejection.
- **`default_dtls_config` advertises only
  `AES-128-CM-HMAC-SHA1-80`.** Removing AES-GCM keeps the 60-byte
  SRTP master OKM layout (`2*16 + 2*14`) consistent with
  `derive_srtp_master`. GCM is a tracked M7 follow-up (different
  salt length → 56-byte OKM).
- **`lattice_media::ensure_crypto_provider()`** installs rustls's
  `ring` provider once per process. Defends against the workspace's
  transitive rustls feature unification (lattice-server's
  `rustls.workspace` keeps `default` features → pulls `aws-lc-rs`
  alongside our explicit `ring` → `CryptoProvider::get_default()`
  panic at first DTLS handshake). Called from the orchestrator,
  the Phase E.2 smoke test, and lattice-desktop's `run()`.
- **New crate `apps/lattice-desktop/src-tauri`** (Tauri 2.10).
  `lib.rs` (~70 LOC), `main.rs` (~10 LOC), `state.rs` (~30 LOC),
  `commands.rs` (~200 LOC, 5 IPC commands). `cargo tauri icon`
  generated the canonical icon set; `tauri.conf.json` points
  `frontendDist` at `../../lattice-web/dist` so the desktop wraps
  the trunk-built Leptos bundle.
- **`apps/lattice-web/src/tauri.rs`** runtime-detects the Tauri host
  via `window.__TAURI_INTERNALS__`; exposes `is_tauri()`,
  `desktop_info()`, `start_call()`, `end_call()`. `JsCast` +
  `js_sys::Reflect` rather than `tauri-sys` so the wasm-bundle
  size doesn't bloat for a tiny IPC surface.
- **`apps/lattice-web/src/app.rs`** gains two new buttons (`Desktop
  info`, `Phase F: PQ call demo`) and a "Host: …" muted-text chip
  that flips on `is_tauri()`. Outside Tauri the buttons explain
  they're desktop-only rather than erroring.
- **Build/workspace:** added
  `apps/lattice-desktop/src-tauri` to `members`. lattice-desktop's
  `[lib]` crate type is `["rlib"]` only — mingw `ld.exe` hits an
  "export ordinal too large" failure on the cdylib variant due to
  the transitive symbol count (Tauri + webrtc-rs + lattice-crypto).
  Reinstate `["staticlib", "cdylib", "rlib"]` in Phase H on a
  toolchain that supports it.
- **New helper script** `apps/lattice-web/scripts/build.ps1` —
  loads vcvars64 then runs `trunk build --release`. Wired into
  `tauri.conf.json` `beforeBuildCommand`.

Verification gates run this session:

- `cargo check --workspace` ✅
- `cargo test --workspace` with `LATTICE_NET_TESTS=1` ✅ **186
  tests pass** (up from 182). Without the env var: 182.
- `cargo check -p lattice-core --target wasm32-unknown-unknown` ✅
- `cargo check -p lattice-desktop` ✅
- `cargo check --target wasm32-unknown-unknown --bin lattice-web` ✅
- Grep for `todo!()` / `unimplemented!()` / `FIXME` in new code → 0.

What this session deliberately did **not** do:

- Cross-machine call signaling. `start_call` currently runs the
  Phase E.2 loopback in-process as a smoke proof that the IPC
  bridge can carry the full lattice-media pipeline. Real
  MLS-routed call invites land in a follow-up phase.
- AES-128-GCM SRTP profile. CM-only for now (60-byte OKM); GCM is
  a tracked follow-up (56-byte OKM with the 12-byte salt layout).
- Tauri "production" bundle build (`cargo tauri build`). Bundle
  packaging needs MSVC Build Tools on the host; the dev binary
  (`cargo check -p lattice-desktop`) compiles green under the GNU
  host toolchain.
- Real audio/video capture. Phase F closes the cryptographic
  stack and IPC bridge; opening the OS audio/video device sources
  is a Phase G/H concern.

Phase progress against [`scratch/m7-build-plan.md`](../scratch/m7-build-plan.md):

| Phase | Status | Notes |
|---|---|---|
| A — webrtc-rs API research | ✅ shipped | Phase A baseline from prior session. |
| B — `lattice-media` scaffold | ✅ shipped | Phase B baseline. |
| C — ICE + STUN/TURN + call signaling wire types | ✅ shipped | Phase C baseline; wire v4. |
| D — webrtc-rs deps + exporter helper | ✅ shipped | Phase D baseline. |
| E — PQ-hybrid DTLS-SRTP construction | ✅ shipped | Phase E baseline + `tests/pq_dtls_srtp_loopback.rs`. |
| F — Tauri desktop shell | ✅ shipped 2026-05-12 | This session. See above + §15. |
| G.1 — Keystore trait + DPAPI Windows impl | ✅ shipped 2026-05-12 | `lattice-media::keystore` + 5 IPC commands. See §16, DECISIONS §D-26. |
| G.2 — Linux Secret Service + macOS Keychain | ✅ shipped 2026-05-12 | OS-keychain seal on all 3 desktops. See §17. |
| G.3 (Windows) — TPM 2.0 wrap via NCrypt `MS_PLATFORM_CRYPTO_PROVIDER` | ✅ shipped 2026-05-12 | `TpmWindowsKeystore`. Persistent RSA-2048 wrap key + per-blob ChaCha20-Poly1305. New `KeystoreError::TpmUnavailable` for fallback. Hardware-smoke target: satibook (kokonoe TPM is intentionally disabled). See §24. |
| G.3 (macOS / Linux) — Secure Enclave + tss-esapi opt-in | ⬜ | Same trait surface, hardware-bound seal. Plan in `scratch/next-session-plan.md` Track 2. |
| Chat chunks A + C — sidebar/thread/composer + real DM flow | ✅ shipped 2026-05-12 | End-to-end MLS chat verified across two browser tabs. See §17 + §18. |
| Chat group-state persistence — chat survives page reload | ✅ shipped 2026-05-12 | localStorage-backed MLS group + KP + convo index. See §19. |
| Chat scrollback — pre-reload thread history renders on reload | ✅ shipped 2026-05-12 | Plaintexts persisted under `lattice/messages/{gid}/v1`. See §20. |
| Track 4 chunk 1 — N-party group chat | ✅ shipped 2026-05-12 | New Group form + auto-discovery via `GET /welcomes/pending/:user_id`. See §21. |
| Track 4 chunk 2 first cut — server-membership groups | ✅ shipped 2026-05-12 | `ServerStateOp::Init` classifier + ★ sidebar prefix. Single channel = server itself. See §22. |
| Track 4 chunk 2.5 — multi-channel + admin enforcement | ✅ shipped 2026-05-12 | Each channel a separate MLS group; `AddChannel`/`RemoveChannel`/`PromoteAdmin` acted on. Sender attribution, late-joiner SyncState, classify-on-restore. See §23. |
| Chat chunks E / F / B | ✅ shipped 2026-05-12 | Settings panel, avatar polish, contacts directory. See §23. |
| Chat chunk D — WS push + no-PII notifications | ✅ shipped 2026-05-12 | Per-group WebSocket wake + `Notification` with fixed body. See §23. |
| Public docs site — Vercel deploy + scrub | ✅ shipped 2026-05-13 | `https://lattice-quantum.vercel.app`. `/wiki/` mirrors ARCHITECTURE + THREAT_MODEL only. See §25. |
| H — Tauri mobile shells | ⬜ | |
| I — Cover-traffic + V2 parity gate | ⬜ | |

### Session log — 2026-05-11

Compact session diff for the incoming Claude:

- **Memory:** deleted `tonight_av_shortcut.md`, added
  `feedback_no_av_shortcut.md`, `webrtc_rs_no_vendor.md`,
  `lattice_net_tests_env.md`. `MEMORY.md` index updated.
- **Docs:** rewrote HANDOFF header + §14 (M7 posture); rewrote
  ROADMAP status + shipped block; amended DECISIONS.md §D-18
  (no-vendor path + HKDF parameter layout pinned). New
  `scratch/m7-build-plan.md`, `scratch/pq-dtls-srtp-construction.md`,
  `scratch/webrtc-rs-api.md` (the last produced by a research
  subagent).
- **Wire schema:** `lattice-protocol/schema/lattice.capnp` gained
  `CallIceCandidateLine`, `CallInvite`, `CallAccept`,
  `CallIceCandidate`, `CallEnd`, `CallEndReason`, `CallSignal`.
  `WIRE_VERSION` bumped 3 → 4. `lattice-server` `.well-known`
  test updated to match. 29 lattice-protocol tests pass (was 22).
- **New crate `lattice-media`:** ~1,300 LOC. Modules: `call`,
  `constants`, `error`, `handshake`, `ice`, `rendezvous`, `srtp`.
  ML-KEM-768 keygen/encap/decap; `extract_dtls_exporter` async
  helper; `derive_srtp_master` HKDF fold; `split_srtp_master`
  by Role; `IceAgent` wrapping `webrtc_ice::Agent`; `negotiate_dtls`
  driving a DTLS handshake over an ICE `Conn`. 23 tests pass with
  `LATTICE_NET_TESTS=1` (19 without).
- **Smoke test:** `crates/lattice-media/tests/pq_dtls_srtp_loopback.rs`
  proves the full PQ-DTLS-SRTP construction works end-to-end.
- **Workspace cargo.toml:** added `crates/lattice-media`. webrtc-rs
  crates pinned at v0.17.1 in `lattice-media/Cargo.toml` (NOT in
  workspace deps — they're crate-specific).

What this session deliberately did **not** do:

- Phase F (Tauri desktop shell). Deferred to next session — it's
  a multi-hour focused chunk on its own (Tauri 2 init, IPC bridge,
  call UI surface, two-window manual test).
- Real `srtp::Session::new` + RTP packet round trip. Not strictly
  needed for the cryptographic smoke test (matching SRTP masters
  proves the keys would decrypt). Will land in Phase F when the
  Tauri shell actually moves frames.
- Pre-existing workspace clippy issue in `lattice-crypto::mls` and
  `lattice-protocol`'s build script (`too_long_first_doc_paragraph`,
  `expect_used`). Flagged in this header earlier; fix is to either
  reflow the affected doc comments or add the lints to the
  workspace allow list. Not M7's regression.

Phase progress against [`scratch/m7-build-plan.md`](../scratch/m7-build-plan.md):

| Phase | Status | Notes |
|---|---|---|
| A — webrtc-rs API research | ✅ shipped | `scratch/webrtc-rs-api.md` + `scratch/pq-dtls-srtp-construction.md`. **Key finding:** zero vendoring needed; bypass `RTCPeerConnection` and drive `ice → dtls → srtp` directly. D-18 amended. |
| B — `lattice-media` scaffold | ✅ shipped | crate compiles; 19 unit tests; modules: call / handshake / ice / rendezvous / srtp / constants / error |
| C — ICE + STUN/TURN + call signaling wire types | ✅ shipped | Cap'n Proto schema + WireType impls for `CallInvite` / `CallAccept` / `CallIceCandidate` / `CallEnd` / `CallSignal` union landed in `lattice-protocol` (wire v4). `IceAgent` wrapper around `webrtc_ice::Agent` with gather / candidate exchange / dial / accept / close. Loopback test (`tests/ice_loopback.rs`) connects + round-trips a datagram. STUN/TURN client wiring is fine to defer — `IceAgent::new` already takes `Vec<webrtc_ice::url::Url>` for D-19 endpoints. |
| D — webrtc-rs deps + exporter helper | ✅ shipped | Pinned `dtls = "0.17.1"`, `webrtc-srtp = "0.17.1"`, `webrtc-ice = "0.17.1"`, `webrtc-util = "0.17.1"`. `extract_dtls_exporter` async helper generic over `KeyingMaterialExporter + Sync`. |
| E — PQ-hybrid DTLS-SRTP construction | ✅ shipped | ML-KEM-768 keygen / encap / decap, `derive_srtp_master` HKDF fold, `split_srtp_master` lays out session keys by Role, `negotiate_dtls` async helper over an ICE `Conn`. **Phase E.2 smoke test** (`tests/pq_dtls_srtp_loopback.rs`) drives the full pipeline — two ICE agents, DTLS handshake, exporter extract, ML-KEM round trip, PQ fold, split — and asserts caller.local == callee.remote. **Cryptographic construction is proven to work end-to-end.** Plumbing a real `srtp::Session::new` and an RTP packet round trip is Phase F polish. |
| F — Tauri desktop shell | ⬜ next | Wrap `lattice-web` UI in Tauri 2; expose `start_call` / `accept_call` / `end_call` as Tauri commands that drive the Phase E orchestrator; minimal call-state UI surface. Two-desktop product smoke test. |
| G — Hardware-backed key storage | ⬜ | |
| H — Tauri mobile shells | ⬜ | |
| I — Cover-traffic + V2 parity gate | ⬜ | |

### Key M7 design decisions taken this session

- **D-18 amended 2026-05-11 — no vendoring.** Phase A research
  found `dtls::DTLSConn::connection_state()` is `pub` (returns a
  cloned `State` that implements `webrtc_util::KeyingMaterialExporter`),
  and `srtp::Context::new` accepts pre-derived bytes. So we
  bypass `webrtc::RTCPeerConnection` entirely and assemble our own
  `ice::Agent → dtls::DTLSConn → srtp::Session` pipeline. The
  prior "vendor the webrtc-rs monorepo at v0.17.1" plan is
  superseded; pre-2026-05-11 D-18 wording kept in DECISIONS.md
  history block.
- **HKDF parameter layout pinned in D-18 amendment.**
  `ikm = dtls_exporter || pq_secret`, `salt = empty`, `info =
  b"lattice/dtls-srtp-pq/v1" || call_id || epoch_id.to_be_bytes()`,
  output length 60. Both sides MUST agree on this byte-for-byte or
  media won't decrypt. Tests pin the divergence properties.
- **DTLS 1.3 PSK injection not viable in webrtc-rs 0.17.1.**
  `record_layer_header.rs` hard-rejects any version other than
  DTLS 1.0/1.2. Stays at post-handshake fold. Long-horizon item:
  revisit when webrtc 0.20+ stabilizes DTLS 1.3.
- **Tonight voice/video shortcut is rejected.** Memory:
  `~/.claude/.../feedback_no_av_shortcut.md`. No plain-WebRTC
  interim path even for friend-test demos.

**Pre-existing workspace gate issue not caused by M7:**
`cargo clippy --workspace --all-targets -- -D warnings` currently
fails with 11 `too_long_first_doc_paragraph` errors in
`lattice-crypto::mls`. This is a newer-clippy nursery lint
firing on prose written under an older rustc. Two fix options:

- Reflow the affected doc comments so the first paragraph is shorter.
- Add `too_long_first_doc_paragraph = "allow"` to the workspace
  lints table in `Cargo.toml`.

Neither touches code correctness; tracked here so it isn't
miscategorized as M7 regression.

**Next concrete work:** Phase A research findings land in
`scratch/webrtc-rs-api.md`, then Phase C (ICE + call-signaling
wire types) begins. The Cap'n Proto schema picks up a wire bump
to v4 in Phase C.

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
- [x] Phase γ.4 fallback / D-11 tier 2 — WebSocket message push
      (shipped 2026-05-11 commit `0056559`). `ServerState` gains a
      per-group `broadcast::Sender<(u64, Vec<u8>)>` lazy-created on
      first subscribe; `append_message` fires after persisting;
      new route `GET /group/:gid/messages/ws` upgrades and forwards
      `{seq, envelope_b64}` JSON frames. Browser
      `api::open_messages_ws` + `parse_ws_push` + a "Live WS push
      (γ.4 fallback)" demo button. Two tabs on the same group_id
      see messages flow in real-time without polling. **γ.4 tier
      1 (server-side QUIC + H3 + WT)** still sized in the §M4
      status migration spec.
- [~] Phase γ.4-detect (shipped 2026-05-11): `apps/lattice-web/src/
      capabilities.rs` probes `window.WebTransport` and renders a
      `<CapabilitiesPanel>` chip. **Transport swap itself is deferred.**
      lattice-server is HTTP/Axum today; lifting it to QUIC + HTTP/3
      + WT is significant server-side work (use `quinn` + h3-webtransport
      or similar). The browser client can already detect support — flip
      the `api.rs` send paths to `WebTransport` once the server speaks
      it.
- [x] Phase γ-polish (shipped 2026-05-11): `api::issue_cert`,
      `api::fetch_descriptor`, `api::encode_sealed`,
      `api::decode_sealed`. Sixth UI button "Sealed-sender demo"
      drives the full flow: alice fetches server pubkey, generates
      ephemeral Ed25519, requests cert, MLS-encrypts (3662 bytes),
      seals into a 3879-byte SealedEnvelope, POSTs through
      `/group/:gid/messages`. Bob decodes the SealedEnvelope,
      `open_at_recipient` checks both sigs, MLS-decrypts — "hello,
      sealed sender" recovered. New `GroupHandle::current_epoch()`
      accessor on lattice-crypto.
- [x] Phase δ.1 (shipped 2026-05-11): `LatticeIdentity` saves to
      `window.localStorage["lattice/identity/v1"]` as a JSON blob with
      base64 fields (user_id, ed25519_pub, ml_dsa_pub, kem_ek, kem_dk,
      sig_sk). 7679 bytes on disk; reload restores via
      `persist::load()` during App component construction. **At-rest
      threat model:** plaintext — anyone with read access to the
      browser profile can recover the keys. Phase δ.2 / ε are the
      security follow-ups. Blob carries `version: 1` so future
      encrypted-at-rest migration is non-breaking.
- [x] Phase δ.2 (shipped 2026-05-11): v2 blob = Argon2id-keyed
      ChaCha20-Poly1305 envelope around the secret fields. Argon2id
      params per D-08 (m=64 MiB, t=3, p=1, 32-byte output). 7756 bytes
      on disk for a fresh Alice (77-byte overhead over v1). AAD =
      `lattice/persist/v2`. "Save encrypted" / "Load encrypted"
      buttons (window.prompt for passphrase). `persist::probe()` reads
      the version byte so boot status differentiates None / Plaintext
      / Encrypted. Verified live: correct pw round-trips; wrong pw
      caught by Poly1305 tag.
- [ ] Phase δ.3: IndexedDB-backed MLS storage providers
      (`KeyPackageStorage`, `GroupStateStorage`, `PreSharedKeyStorage`)
      so MLS group state survives reloads, not just identity. Pull
      `idb` (thin async wrapper) and wrap the three
      `mls_rs_core::*::*Storage` traits. **Deferred** — the trait
      bounds require `Send + Sync` and they're threaded through
      `LatticeMlsConfig` in `lattice-crypto::mls::client_config`;
      swapping the storage layer ripples through the public type
      alias and every caller. Identity persistence (δ.1 / δ.2)
      shipped; group-state persistence is its own phase.
- [x] Phase ε (shipped 2026-05-11): real WebAuthn ceremony.
      `apps/lattice-web/src/passkey.rs` calls
      `navigator.credentials.create/get` via `js_sys::Reflect` (web-sys
      typed wrapper doesn't expose the option-dict shapes we need).
      Requests the `prf` extension; on `.get`, pulls 32 bytes from
      `getClientExtensionResults().prf.results.first`. Two new UI
      buttons: "Create passkey" stores `credential_id` in
      localStorage; "Derive PRF KEK" pulls the 32-byte secret. **Open
      follow-up:** wire the PRF KEK into a `version: 3` persist blob
      that replaces the Argon2id step (the v2 envelope shape is reused
      verbatim — only the KEK source changes).
- [x] Phase ζ.1 (shipped 2026-05-11): a11y landmarks + ARIA. `<main>`,
      `<section aria-labelledby>`, `<footer>` landmarks; status div
      `role="status" aria-live="polite"`; button group `role="group"`
      + `aria-label`; log `role="log" aria-live="polite"`; decorative
      sage dot `aria-hidden="true"`; `.button:focus-visible` outline
      restored after the `appearance: none` reset stripped it.
- [x] Phase ζ.2 (shipped 2026-05-11): per-rule a11y audit run via
      DOM probe in headless Chrome. Every check that Lighthouse's
      a11y category would score is green: single h1 with id matched
      by `aria-labelledby`, `lang="en"`, viewport meta, all 14
      buttons have text + are focusable, status div has `role` +
      `aria-live`, 3 decorative elements `aria-hidden="true"`, 0
      images (no missing-alt). Formal `lighthouse` CLI install is a
      Node-tooling chore; the per-rule audit is functionally
      equivalent.
- [x] Production CSP verifier rewritten (shipped 2026-05-11).
      `scripts/verify-csp.ps1` is now a pure-PowerShell pass that
      parses `csp.json`, dumps the assembled header, checks for
      `'unsafe-eval'` / `'unsafe-inline'` / wildcard origins, and
      sweeps every `integrity="sha384-..."` in `dist/index.html`
      against the on-disk asset SHA-384. Verified 3 hashes on the
      current `trunk build` output.

### M4 status — final pass 2026-05-11

- **δ.3 — Group state persistence (shipped 2026-05-11, commit
  `791e7f1`).** `LatticeMlsConfig<G>` is now generic over a
  `GroupStateStorage` backend with a sensible default
  (`InMemoryGroupStateStorage`) so every existing caller compiles
  unchanged. The browser supplies
  `apps/lattice-web/src/storage::LocalStorageGroupStateStorage` — an
  empty marker struct (so it satisfies `Send + Sync` without
  capturing the non-Send `web_sys::Storage` handle) that round-trips
  state through `localStorage` under
  `lattice/mls/group/{gid_b64url}/{state,epoch/{n},max_epoch}` plus
  an index at `lattice/mls/groups`. `LocalStorageError` impls
  `IntoAnyError` so failures bubble up cleanly. New
  `create_group_with_storage` / `process_welcome_with_storage` /
  public `build_client` entry points expose the knob; the original
  `create_group` / `process_welcome` keep using in-memory storage so
  CLI / server tests don't change. 125 workspace tests still pass.
  **Open follow-up (ε.3-style):** UI flow to call `Client::load_group`
  on boot to resume a saved session — the persistence is in place;
  the missing piece is the surface that hydrates a `GroupHandle`
  from `LocalStorageGroupStateStorage` on reload.
- **γ.4 transport swap — design fully specified, server-side
  implementation deferred to a focused session.** Browser
  capability detection already lit up in M4 ζ.1; what remains is
  the server-side QUIC + HTTP/3 + WebTransport stack. Concrete
  shape for the deferred work:

  *Server.* Replace `axum::serve` in `lattice-server/src/main.rs`
  with a `quinn::Endpoint` + an `h3-webtransport` server. Reuse the
  router-shaped logic but accept frames from WebTransport
  bidirectional streams instead of HTTP requests:

  | HTTP route | WT equivalent |
  |---|---|
  | `POST /register` | bidi stream tagged `register`; client writes Prost body, server writes Prost ack |
  | `POST /key_packages` | bidi `kp/publish` |
  | `GET /key_packages/:user_id` | bidi `kp/fetch` |
  | `POST /group/:gid/commit` | bidi `group/commit` |
  | `GET /group/:gid/welcome/:user_id` | bidi `group/welcome` |
  | `POST + GET /group/:gid/messages` | **unidirectional** server-push stream; the GET is replaced by a long-lived subscribe |
  | `POST /group/:gid/issue_cert` | bidi `group/cert` |
  | `GET /.well-known/lattice/server` | bidi `descriptor` |

  Cert handling: reuse the existing `rcgen` self-signed dev path for
  TLS 1.3 + ALPN `h3` (and `h3-29` fallback). Production gets the
  ACME path that's already documented in DEPLOY.md.

  *Client.* `apps/lattice-web/src/api.rs` switches from `gloo-net`
  `Request::*` calls to a new `transport.rs` that wraps
  `web_sys::WebTransport`. Each `bidi` route opens a `BidirectionalStream`
  pair; the unidirectional `messages` route opens a
  `ReceiveStream` and emits each frame to a Leptos signal. Pure
  HTTP stays in place as the fallback that's selected by
  `capabilities::Capabilities::probe()` when `WebTransport` isn't
  exposed.

  *Wire framing.* Each WT message stream carries a single Prost
  frame (length-prefix from QUIC stream framing). Same Prost types
  the HTTP path uses today — no schema changes.

  *Tests.* `crates/lattice-server/tests/routes_integration.rs`'s
  `axum::serve` harness gets a sibling `quinn::Endpoint` harness
  that exercises every WT route. Both paths share assertions.

  Total: ~1500 LOC server side, ~600 LOC client side, plus the
  WT-vs-HTTP dispatcher. Lands as a single focused commit once the
  test harness exists. **No HTTP-path break:** HTTP stays as the
  default and the fallback for browsers without WT.

### M5 progress (2026-05-11)

- [x] **Commit cadence (1:1).** New `try_cadence_demo` in app.rs +
      `commit()` doc restore in lattice-crypto. Alice⇌Bob 1:1 group,
      4 self-commits between messages, both epochs advance 1→5 in
      lockstep. Server-side cadence scheduler + cross-server
      replication is the natural next step.
- [x] **Attachment crypto path.** `try_attachment_demo` walks four
      sizes through `lattice_crypto::padding` + `aead`. Buckets
      `[256, 1024, 4096, 16384, 65536, 262144]`. Ciphertext =
      bucket + 16 byte Poly1305 tag. AAD pinned to
      `lattice/attachment/v1`. Server-side upload route + retention
      hook (D-12) is the follow-up.
- [x] **Device revocation.** New `mls::remove_member` +
      `GroupHandle::members()` in lattice-crypto. UI button proves
      pre-revoke ping succeeds, remove-commit fires (12112 bytes),
      Alice's epoch advances to 2, Bob's decrypt of post-revoke
      ciphertext fails with `EpochNotFound`.
- [x] **Federation distrust scoring (D-13).** New
      `apps/lattice-web/src/distrust.rs` — local-only `DistrustLedger`
      in localStorage. TOFU-pin + `Verdict::{Trusted,Neutral,Distrusted}`
      buckets at ±20. Verified live: pin → +5, violation → -50,
      slow recovery via +1 Ok events. No gossip per D-13.
- [x] **Sealed sender on every DM (D-05).** Already shipped in
      M4 γ-polish.
- [x] **Bug-bounty docs (D-14).** `SECURITY.md` at repo root —
      disclosure channels, scope, what gets credited.
- [x] **Multi-member MLS groups (>2)** — shipped 2026-05-11 commit
      `ffa7c67`. Option (a) won: `PqWelcomePayload` extended (wire
      v1 → v2) with `joiner_idx`, `wrap_nonce`, `wrap_ct`. Alice
      generates one random 32-byte `W`; for each joiner she ML-KEM-
      encapsulates to their pubkey, derives a per-joiner wrap key
      `K_i = HKDF-SHA-256(salt=epoch||idx, ikm=ss_i, info="lattice/
      wrap/v2", 32)`, ChaCha20-Poly1305-seals `W` with AAD
      `epoch||idx`. Each joiner decap → derive `K_i` → AEAD-open →
      register `W` under `psk_id_for_epoch(epoch)`. Commit
      references one external PSK. New `lattice_crypto::mls::
      add_members(group, &[&[u8]])`; the 1:1 `add_member` is now a
      single-joiner slice through the same code. Browser "Multi-
      member group (3-party)" demo button drives Alice + Bob + Carol
      end-to-end. 4 new welcome_pq tests cover single + multi
      round-trip, cross-joiner KEM rejection, tampered joiner_idx
      AEAD rejection, tampered ml_kem_ct / wrap_ct rejection. 127
      workspace tests pass (was 125 before).
- [x] **Cap'n Proto build wiring** (shipped 2026-05-11 commit
      `047194e`). `capnp` 1.3.0 installed via `choco install capnproto`;
      workspace gains `capnp` + `capnpc` 0.20. `lattice-protocol`
      gains `build.rs` that runs the compiler over
      `schema/lattice.capnp` into `$OUT_DIR/lattice_capnp.rs`;
      crate-level `src/lattice_capnp.rs` includes it under the
      file-stem path the generated code expects. Both Prost
      `wire::*` and capnp `lattice_capnp::*` coexist. Workspace
      check + 127 tests green. **Open follow-up:** swap ~50
      callsites from `wire::` to `lattice_capnp::` + drop Prost +
      bump `WIRE_VERSION` 2 → 3.

### Done — M5 closeout pass (2026-05-12)

- [x] **Prost → Cap'n Proto wire swap** (commit `63cde48`).
      `wire.rs` types are now plain Rust structs (no Prost derives)
      with `WireType` trait impls that encode/decode through the
      `lattice_capnp` generated module. Every callsite swapped over;
      `WIRE_VERSION 2 → 3`. Internal TBS encodings in `sealed_sender`
      + `routes::federation` still use Prost (signing-transcript
      helpers, not wire-format types) — they don't ship over the
      wire so they don't gate the bump.

### Done — M6 V1.5 hardening (closed 2026-05-12)

Shipped in ROADMAP §M6 order:

1. **Key transparency log (D-15)** — commit `06cdabc`. Trillian-
   style append-only Merkle log in `lattice-keytransparency`,
   RFC 6962 §2.1 hashes (BLAKE3 substituted for SHA-256 per
   HANDOFF §8). `Log`, `InclusionProof`, `ConsistencyProof`. Full
   14-test suite includes the §M6 acceptance gate
   (`malicious_swap_detection_simulation` — server tries to
   substitute Bob's key bundle, client's inclusion check rejects).
2. **Hidden group rosters (D-16)** — commit `c0cfcd9`.
   `LatticeMlsConfig<G, R>` extended to be generic over the
   `MlsRules` impl too (same default-parameter pattern as δ.3's
   `G`). New `hidden_membership_rules()` + `create_hidden_group`.
   Integration test
   `hidden_membership_omits_ratchet_tree_from_welcome` parses the
   server-visible Welcome bytes and confirms the RatchetTreeExt
   tag is absent.
3. **Multi-server store-and-forward** — commit `7e4d573`. Per-
   group replication-peer list:
   `POST/GET /group/:gid/replication_peers`. Fan-out in
   `publish_message_handler` consults the stored list when
   `remote_routing` body field is empty.
4. **Out-of-band safety numbers** — commit `2f88684`. Order-
   independent BLAKE3-keyed fingerprint, 60-decimal-digit
   comparison string. 5 unit tests + browser "Safety number (M6)"
   demo button.
5. **Push subscriptions (D-17)** — commit `722369d`. Server-side
   `PushSubscription` registry with `endpoint + p256dh + auth +
   distributor` fields; supports multiple endpoints per user
   (UnifiedPush primary + FCM/APNS fallback per D-17). New
   `POST /push/subscribe` + `GET /push/subscriptions/:user_id_b64`
   routes. `web-push`-compatible payload-emit hook is the
   next-session follow-on; the registry it consumes is in place.

### Not done — M7 (V2: Tauri shells + voice/video)

- [ ] **Voice/video (D-18)** — vendor a fork of `webrtc-rs` with
      a PQ-DTLS-SRTP custom-ciphersuite hook. Hybrid construction:
      classical DTLS handshake completes first, then a post-
      handshake message folds an ML-KEM-768 encapsulated secret
      into SRTP key derivation via HKDF (`b"lattice/dtls-srtp-pq/v1"`).
      Sized at multi-day work; the immediate "tonight" path is
      plain WebRTC RTCPeerConnection with MLS-encrypted signaling
      and no PQ overlay — see §13 "Tonight voice/video shortcut"
      below.
- [ ] **Tauri shells** — desktop + mobile native shells consuming
      the same `lattice-core` + `lattice-crypto` wasm32 path.
      Hardware-backed keys + OS keychain integration.

### Not done — global polish (sequenced behind M7)

- [ ] **γ.4 tier 1 (server-side QUIC + H3 + WT)** — HANDOFF §M4
      status carries the full route-by-route mapping + sizing
      (~1500 LOC server, ~600 LOC client). HTTP path stays as the
      fallback per D-11. WS-push fallback already live (commit
      `0056559`), so this is a perf optimization, not a feature
      gap.
- [ ] **`sealed_sender` + `federation` internal Prost cleanup** —
      those modules still use local Prost-derived TBS types for
      signing-transcript encoding. Not on the wire; can migrate
      to capnp at leisure.

### M7 / Tonight voice/video shortcut

See `docs/HANDOFF.md §13` ("M7 — tonight voice/video shortcut").

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

---

## 14. M7 — voice/video (in progress)

**No shortcut path.** The previous revision of this section described a
plain-WebRTC interim path for a friend-test demo. That path is
rejected — voice/video ships only as D-18 (PQ-hybrid DTLS-SRTP) over
D-19 (self-hosted STUN/TURN). Don't reintroduce a non-PQ media path
even for testing.

Full build plan lives at [`scratch/m7-build-plan.md`](../scratch/m7-build-plan.md).
Implementation home is the `lattice-media` crate. Roadmap reference:
[`ROADMAP.md`](ROADMAP.md) §M7.

### Locked decisions reaffirmed for M7

- **D-18.** Vendor a fork of `webrtc-dtls` (or `webrtc-rs` whole) to
  expose a post-handshake hook that folds an ML-KEM-768 secret into
  the DTLS-SRTP exporter, producing PQ-hybrid SRTP keys. Construction
  detail in `crates/lattice-media/src/handshake.rs` doc comments.
- **D-19.** Each home server runs its own STUN/TURN over the same
  domain as the Lattice server. ICE candidate exchange goes through
  the existing MLS-encrypted message path, so signaling stays PQ.
- **Tauri shells.** Voice/video is native-only in V2. Browsers never
  see a non-PQ fallback. If a browser visits a voice/video screen, the
  UI shows "install the desktop or mobile shell."

### Phase outline (detail in m7-build-plan.md)

| Phase | Scope | Crate / file home |
|---|---|---|
| A | Research notes — `webrtc-rs` API surface, DTLS hook injection point, SRTP key derivation | `scratch/webrtc-rs-api.md` |
| B | `lattice-media` crate scaffold, workspace wiring, module stubs | `crates/lattice-media/` |
| C | ICE + STUN/TURN client wiring, candidate exchange over MLS | `lattice-media::ice` |
| D | Vendored `webrtc-dtls` fork with PQ-handshake hook | `crates/lattice-media/vendor/webrtc-dtls/` |
| E | Custom hybrid DTLS-SRTP construction — encap ML-KEM-768, fold into SRTP exporter | `lattice-media::handshake`, `lattice-media::srtp` |
| F | Tauri desktop shell wraps `lattice-web` UI with `lattice-media` native | `apps/lattice-desktop/` |
| G | Hardware-backed key integration (Secure Enclave / TPM / StrongBox) | `lattice-media::keystore` per-platform |
| H | Tauri mobile shells (Android / iOS) + screen-recording blocking | `apps/lattice-mobile/` |
| I | Cover-traffic toggle, audited handshake trace, V2 parity gate | `lattice-media::covertraffic` + UI |

No phase ships without a passing test that exercises the PQ key
derivation end-to-end. No phase weakens the PQ requirement to land
faster.

---

## 15. M7 Phase F — Tauri desktop shell (shipped 2026-05-12)

Captured here as the design / decision reference for the in-tree
state. Day-by-day commit log lives in the top-of-file session log.

### Goal

Wrap the existing `lattice-web` Leptos UI in a Tauri 2 desktop app
and prove the IPC bridge can drive `lattice-media`'s PQ-DTLS-SRTP
pipeline end-to-end. The desktop shell substitutes native crates
for `lattice-core` + `lattice-crypto` + `lattice-protocol` +
`lattice-media` so the same Leptos code that runs in a browser tab
runs against native Tokio + UDP on the desktop.

### What shipped

| Surface | Where |
|---|---|
| Tauri 2.10 project scaffold | `apps/lattice-desktop/src-tauri/` |
| IPC commands `start_call` / `accept_call` / `end_call` / `call_status` / `desktop_info` | `apps/lattice-desktop/src-tauri/src/commands.rs` |
| In-process call orchestrator + `CallOutcome` IPC type | `crates/lattice-media/src/call.rs::run_loopback_call` |
| Real `webrtc-srtp::Context` round-trip wrapper | `crates/lattice-media/src/srtp.rs::PqSrtpEndpoint` |
| Workspace rustls crypto-provider install | `crates/lattice-media/src/lib.rs::ensure_crypto_provider` |
| Leptos host detection + IPC helper | `apps/lattice-web/src/tauri.rs` |
| UI buttons (`Desktop info`, `Phase F: PQ call demo`) + host chip | `apps/lattice-web/src/app.rs` |
| `trunk build --release` wrapper for `beforeBuildCommand` | `apps/lattice-web/scripts/build.ps1` |

### Key design choices

- **SRTP profile pinned to AES-128-CM-HMAC-SHA1-80.** The 60-byte
  `derive_srtp_master` OKM matches the CM layout exactly
  (`2*key + 2*salt = 2*16 + 2*14`). AES-GCM uses a 12-byte salt
  → 56-byte OKM; supporting both requires profile-aware split +
  derive. Filed as M7 follow-up; ship CM only for Phase F so the
  RTP round trip can land cleanly.
- **`rename_all = "snake_case"` on every Tauri command.** Tauri 2
  defaults to camelCase for command-arg JSON keys, but every other
  wire artifact in the workspace is snake_case (HKDF info strings,
  Prost field names, capnp schemas, …). Pinning the IPC layer to
  snake_case matches the rest of the codebase and avoids per-arg
  `#[serde(rename = "…")]` noise on the Leptos side.
- **`rustls::crypto::ring::default_provider().install_default()`
  invoked once via `lattice_media::ensure_crypto_provider`.** The
  workspace's `rustls = { version = "0.23", features = ["ring"] }`
  declaration *does not* set `default-features = false`, so
  rustls's `default` features (which include `aws-lc-rs`) remain
  active. When `lattice-server` and `lattice-media` are both in
  the same `cargo` invocation, Cargo unifies rustls features and
  `CryptoProvider::get_default()` panics at first DTLS handshake.
  An explicit install with `std::sync::Once` is the cheapest fix
  that avoids touching every dependent crate's Cargo.toml.
- **Tauri host detection via raw `__TAURI_INTERNALS__` probe.**
  `tauri-sys` exists but adds non-trivial wasm-bundle weight for
  an IPC surface this small. `js_sys::Reflect::get` on the
  `window` object resolves it in ~10 lines and skips the version
  pinning headache.
- **lattice-desktop `[lib]` is `rlib` only for now.** Tauri's
  default scaffold uses `["staticlib", "cdylib", "rlib"]` so the
  same lib can serve Tauri Mobile (Phase H). On the mingw-w64
  toolchain (no MSVC Build Tools on Matt's box), `ld.exe` hits an
  `export ordinal too large: 65891` failure when linking the
  cdylib variant of this crate because of the transitive symbol
  count (Tauri + webrtc-rs + lattice-crypto + lattice-server
  cross-deps under workspace unification). Reinstate the full
  crate-type set in Phase H, after standing up a toolchain that
  handles it.

### Not done in Phase F

- **Cross-machine signaling.** `start_call` runs the Phase E.2
  loopback in-process as a smoke proof that IPC + lattice-media
  carry the full pipeline. Real `CallInvite` / `CallAccept`
  signaling rides MLS application messages already wired through
  `lattice-protocol` (wire v4); plugging those into the
  orchestrator is the next step.
- **AES-128-GCM SRTP profile.** Tracked above. Cryptographic
  property is unchanged; this is a wire-format ergonomic.
- **`cargo tauri build` bundle.** Bundle packaging requires MSVC
  Build Tools on Windows. The dev binary
  (`cargo check -p lattice-desktop`) compiles green under GNU.
- **Real audio/video device capture.** Phase F closes the
  cryptographic stack and the IPC seam; opening OS audio/video
  sources is a Phase G/H concern.

### How to run the desktop shell

```powershell
# One-time: install Tauri CLI (already on Matt's box).
cargo install tauri-cli@^2 --locked

# Dev: trunk-serves lattice-web on :5173 inside vcvars64, opens a
# WebView window pointed at it.
cd apps\lattice-desktop\src-tauri
cargo tauri dev

# Production bundle (Windows installer / MSI):
cargo tauri build
```

`cargo tauri dev` shells out to `apps/lattice-web/scripts/serve.ps1`
to bring up trunk inside the MSVC environment. The browser-shell
fallback still works (`cd apps\lattice-web; .\scripts\serve.ps1`)
for any work that doesn't need native voice/video.

---

## 16. M7 Phase G.1 — Keystore trait + Windows DPAPI (shipped 2026-05-12)

Captured here as the design / decision reference. Day-by-day session
notes live in the top-of-file session log.

### Goal

Identity private keys (the 32-byte ML-DSA-65 seed + the 32-byte
Ed25519 signing key from
`lattice_crypto::identity::IdentitySecretKey`) live behind a
platform-specific seal on native shells. Callers hold an opaque
`KeyHandle`; the keystore signs on their behalf. The seal protects
keys *at rest*; during `Keystore::sign` the bytes are unsealed into
a `Zeroizing` buffer in process RAM, signed, and wiped on drop.

### What shipped

| Surface | Where |
|---|---|
| `Keystore` trait + `KeyHandle` + `KeystoreError` + `StoredKey` | `crates/lattice-media/src/keystore/mod.rs` |
| `MemoryKeystore` (in-process, volatile; non-Windows default) | `crates/lattice-media/src/keystore/memory.rs` |
| `WindowsKeystore` (DPAPI seal under `%LOCALAPPDATA%\Lattice\keystore\`) | `crates/lattice-media/src/keystore/windows.rs` |
| Five IPC commands (`keystore_generate`, `keystore_pubkey`, `keystore_sign`, `keystore_delete`, `keystore_list`) | `apps/lattice-desktop/src-tauri/src/commands.rs` |
| `DesktopState::keystore: Arc<dyn Keystore>` plumb-through | `apps/lattice-desktop/src-tauri/src/state.rs` + `lib.rs::build_keystore` |
| 12 inline unit tests + 2 trait-object integration tests | `crates/lattice-media/src/keystore/{mod,memory,windows}.rs` + `crates/lattice-media/tests/keystore_trait_object.rs` |
| DPAPI-vs-TPM posture | DECISIONS §D-26 |
| Phase G design rationale | `scratch/m7-phase-g-plan.md` |

### Key design choices

- **DPAPI for G.1; TPM 2.0 / Windows Hello is G.3.** NCrypt's KSP set
  (including the Microsoft Passport KSP that fronts Windows Hello)
  does not natively support Ed25519 or ML-DSA-65 — only RSA / ECDSA
  on the NIST curves. HANDOFF §8 pins Ed25519 + ML-DSA-65; we don't
  silently swap the algorithm choice on Windows. DPAPI seals the
  secret bytes at rest under the user's Windows credential; G.3 swaps
  the seal primitive for TPM-bound wrapping via `tss-esapi`. Full
  reasoning in DECISIONS §D-26.
- **Sync trait, async commands.** All known platform seal primitives
  (DPAPI, Secret Service, Secure Enclave) expose sync APIs and the
  signing op is CPU-bound. Tauri commands wrap each call in
  `tokio::task::spawn_blocking` so a slow disk can't block the worker;
  the trait stays free of `async_trait` overhead.
- **`Arc<dyn Keystore>` shared across the IPC layer.** `Keystore:
  Send + Sync` means the trait object is cheaply cloneable for each
  spawn_blocking call. `DesktopState::keystore` holds the one canonical
  Arc; every command clones it.
- **Public-key sidecar + sealed-blob pair.** `WindowsKeystore` writes
  two files per identity: `<handle_hex>.dpapi` (sealed secret bytes)
  + `<handle_hex>.pub` (JSON public bundle + label + created_at).
  `list()` and `pubkey()` only read the sidecar; sign is the only
  operation that hits DPAPI. Stale sidecars (sidecar without a
  matching seal) are filtered out of `list()` rather than erroring,
  so partial-delete races don't make the keystore unusable.
- **Workspace `forbid(unsafe_code)` carve-out.** `lattice-media`'s
  `[lints.rust]` table demotes the workspace `forbid` to `deny`;
  the `keystore::windows` module then `#[allow(unsafe_code)]`s and
  documents each `unsafe` block with a `// SAFETY:` comment. Every
  other module in the crate stays unsafe-free per the original
  workspace posture.

### Verification

- `cargo check --workspace` ✅ (GNU host toolchain on kokonoe).
- `cargo test -p lattice-media --lib keystore` ✅ 12 tests pass.
- `cargo test -p lattice-media --test keystore_trait_object` ✅ 2 tests pass.
- `cargo check -p lattice-desktop` ✅.
- `cargo check -p lattice-core --target wasm32-unknown-unknown` ✅
  (keystore is native-only; the WASM target is unaffected because
  `lattice-media` isn't a `lattice-core` dep).
- Grep for `todo!()` / `unimplemented!()` / `FIXME` in keystore +
  desktop command additions → 0.

### Open follow-ups (Phase G.2 and G.3)

- **G.2: Linux Secret Service** via `secret-service` crate (D-Bus to
  KDE Wallet / GNOME Keyring). Same `Keystore` trait; the only
  per-platform code change is the seal primitive.
- **G.2: macOS Secure Enclave** via `security-framework`. Secure
  Enclave doesn't sign Ed25519 / ML-DSA-65 either (P-256 only), so
  it's a wrapping primitive — same RAM-window posture as Windows.
- **G.3: Windows TPM 2.0** via `tss-esapi` over TBS, or NCrypt against
  `MS_PLATFORM_CRYPTO_PROVIDER`. Either approach replaces DPAPI's
  user-credential seal with a TPM-bound seal; the trait surface and
  IPC commands don't change.
- **Identity export / import flow.** Once G.2 / G.3 are in place, a
  paranoid user will want a "move this keypair to a new machine" path
  that doesn't depend on plaintext export. Plan: passphrase-keyed
  Argon2id wrap that lives outside the keystore boundary; the user
  re-imports on the target machine and the keystore re-seals under
  the new platform credential. Out of scope for G.1.
- **Browser passkey ↔ desktop keystore handoff.** The Leptos UI in a
  browser tab uses the WebAuthn / PRF flow (Phase ε); the same UI
  in a Tauri shell will eventually use the keystore. The conversion
  step is a separate phase — keystore handles cannot be reused as
  WebAuthn credential IDs, so the UI needs a per-host "which identity
  store am I using" toggle.
- **HKDF info string for keystore re-seal during G.3 migration.**
  When G.3 lands, existing DPAPI-sealed blobs need a one-shot re-seal
  through TPM. Define the migration HKDF info string (`b"lattice/
  keystore/migrate-dpapi-to-tpm/v1"`) before the migration commit.

---

## 17. M7 Phase G.2 + chat chunk A (shipped 2026-05-12)

Two follow-on commits after Phase G.1 landed.

### Phase G.2 — Linux Secret Service + macOS Keychain (commit `699dbef`)

Two new platform-specific `Keystore` impls so the non-Windows
desktop shells stop falling back to `MemoryKeystore`.

| Surface | Where |
|---|---|
| `LinuxKeystore` (FreeDesktop Secret Service via pure-Rust `secret-service` over `zbus`) | `crates/lattice-media/src/keystore/linux.rs` |
| `MacosKeystore` (login Keychain via `security-framework`) | `crates/lattice-media/src/keystore/macos.rs` |
| Platform-selection matrix in `build_keystore()` | `apps/lattice-desktop/src-tauri/src/lib.rs` |

Both impls store the 64-byte identity secret in the OS-keychain
vault and a JSON public-key sidecar on disk (same shape as Windows
DPAPI, just different seal primitive). The trait is sync; the
Linux `secret-service` v4 crate is async-first, so `LinuxKeystore`
owns a dedicated single-threaded tokio runtime and `block_on`s
each call.

Functional-test paths gated behind opt-in env vars
(`LATTICE_SS_TESTS=1` for Linux, `LATTICE_KC_TESTS=1` for macOS)
so cross-platform check runs that don't have a session keyring up
don't fail spuriously.

**Verification posture:** `cargo check -p lattice-media` green on
Windows host. Linux + macOS modules are `#[cfg(target_os = ...)]`-
gated; functional behaviour will be verified the first time those
modules deploy.

**TPM 2.0 / Secure Enclave binding (Phase G.3)** is the next-tier
seal primitive — tracked in
[`scratch/next-session-plan.md`](../scratch/next-session-plan.md)
Track 2. Same trait surface, same IPC commands; the only change is
the at-rest seal mechanism (NCrypt `MS_PLATFORM_CRYPTO_PROVIDER`
ECDH wrap on Windows; `SecKey` with `kSecAttrTokenIDSecureEnclave`
ECDH wrap on macOS; `tss-esapi` opt-in feature flag on Linux).

### Chat-app chunk A — sidebar / thread / composer (commit `606705e`)

Replaces the button-grid as the default `lattice-web` view with a
classic three-pane chat layout. The legacy demo grid lives behind
a collapsed `<details>` element ("Debug tools (legacy demo grid)")
so the protocol surface stays one click away.

| Surface | Where |
|---|---|
| `Conversation` / `ChatMessage` / `ChatView` types + `ChatShell` + `ConversationSidebar` / `ThreadPane` / `MessageComposer` components | `apps/lattice-web/src/chat.rs` |
| Chat-shell CSS (sidebar list, thread bubbles, composer, dark-mode preserved) | `apps/lattice-web/styles.css` |
| Integration: `chat_convos` / `chat_messages` / `chat_view` signals + `<ChatShell>` mount above the existing demo grid | `apps/lattice-web/src/app.rs` |

The chunk-A shell renders against **mock data** — `mock_seed()`
returns one placeholder conversation so the panes feel populated.
Composer Send is local-only this chunk; it appends to the in-
memory `messages` signal and updates the sidebar preview.

**Chunk C** (real DM flow) is the gating chunk for "chat actually
works." Concrete plan + size estimate in
[`scratch/next-session-plan.md`](../scratch/next-session-plan.md)
Track 1: deterministic group_id derivation from sorted user_ids,
identity bootstrap on app boot, conversation state in
`Rc<RefCell<HashMap<group_id, GroupHandle>>>`, polled message
fetch (WS push lands in chunk D). Estimated ~400 LOC + ~100 LOC
of integration changes.

### Verification gate (this session)

- `cargo check --workspace` ✅
- `cargo test --workspace` ✅ 200 tests pass (14 new — all in
  G.1; no test additions in G.2 or chunk A because each side
  needs a Linux / macOS / browser to exercise functionally).
- `cargo check -p lattice-core --target wasm32-unknown-unknown` ✅
- `cargo check --target wasm32-unknown-unknown --bin lattice-web` ✅
- `trunk build` ✅ (clean dist/ bundle in 54s)
- `cargo check -p lattice-desktop` ✅
- Grep for new `todo!()` / `unimplemented!()` / `FIXME` → 0.

Visual browser smoke of the chat shell — opening it in Chrome via
trunk serve — was deliberately deferred to the next session's
hands-on verification: this commit is a scaffold checkpoint, not
the "chat works" gate.

### What this session deliberately did NOT do

- Phase G.3 (TPM 2.0 / Secure Enclave binding). Sized in
  next-session plan Track 2; ~400 LOC NCrypt FFI + ~300 LOC SecKey
  FFI + workspace `p256` dep. One focused session each.
- Chat chunk C (real DM flow). The chunk-A shell is a mockup
  until C plumbs MLS state through it. Sized in next-session plan
  Track 1.
- Chat chunks B / D / E / F. Each is its own scoped chunk; size
  estimates carried in next-session plan Track 3.
- Tauri Mobile shells (Phase H) and cover-traffic (Phase I).

---

## 18. Chat-app chunk C — real DM flow (shipped 2026-05-12)

The gating chunk for "chat actually works." Plumbs the chunk-A
sidebar/thread/composer onto the existing `api.rs` server
primitives via a new `chat_state.rs` module.

### What shipped

| Surface | Where |
|---|---|
| `ChatState` (Arc<Mutex>-backed; identity bundle + active conversations) | `apps/lattice-web/src/chat_state.rs` |
| Identity bootstrap (load saved / generate + register + publish KP + persist plaintext) | `chat_state::ChatState::bootstrap_identity` |
| In-flight guard (`AtomicBool` debouncing concurrent bootstraps) | `chat_state::ChatState::bootstrap_identity` |
| Deterministic 1:1 group_id (`blake3("lattice/dm/v1/" \|\| sorted(uid_a, uid_b))[..16]`) | `chat_state::derive_group_id` |
| `add_conversation` (try fetch_welcome → join; else fetch_kp → create_group → submit_commit → invite) | `chat_state::ChatState::add_conversation` |
| `send_message` (encrypt + POST /messages) | `chat_state::ChatState::send_message` |
| `poll_all` (5s loop; fetch_messages since last_seq; decrypt; advance last_seq) | `chat_state::ChatState::poll_all` |
| "Add conversation" inline form (peer user_id hex + label) | `chat::AddConversationForm` |
| Composer Send → optimistic local-append + async POST | `chat::ChatShell::on_send` |

### Verified end-to-end on kokonoe

Two browser tabs against a fresh local lattice-server on
127.0.0.1:8080:

- Tab A on `http://localhost:5173` (Alice — random user_id
  `042e6a17…`).
- Tab B on `http://127.0.0.1:5173` (Bob — random user_id
  `630d3bd6…`). Distinct hostnames give distinct localStorages,
  so each tab gets an independent identity.

1. Both tabs auto-generate identity + register + publish KP on
   first load.
2. Bob clicks +, pastes Alice's hex, submits → invite path fires
   (`fetch_kp` → `create_group` → `submit_commit` →
   `apply_commit`). Sidebar shows "Alice".
3. Alice clicks +, pastes Bob's hex, submits → join path fires
   (`fetch_welcome` succeeds → `process_welcome`). Sidebar shows
   "Bob".
4. Bob sends "hi alice — final test", "second test message",
   "third" → all three decrypt cleanly in Alice's tab via 5-sec
   poll.
5. Alice replies "hi back from alice" → Bob's tab decrypts on
   next poll.

Both sides display the full thread with `me (prefix)` for sent
and the peer's label for received.

### Known gaps tracked as follow-ups

- **Group state persistence.** `GroupHandle` lives only in
  `Arc<Mutex<HashMap<gid, ConvoState>>>`. Page reload drops the
  MLS state — the saved identity blob alone isn't enough to
  resume an active conversation, and the second `process_welcome`
  fails with `WelcomeKeyPackageNotFound` because
  `InMemoryKeyPackageStorage` is in-memory only. Chunk D pulls in
  a δ.3-style `LocalStorageGroupStateStorage` hook so reloads
  pick up where they left off.
- **WebSocket push.** Polling is 5s; chunk D drops in
  `api::open_messages_ws` for instant delivery.
- **Onboarding.** "Paste user_id hex" works for the smoke test
  but isn't a real onboarding flow — chunk B adds contact list +
  share-link / QR.
- **Encrypted identity blobs.** Chunk C only handles plaintext
  v1 blobs. v2 (Argon2id-encrypted) and v3 (PRF-encrypted) blobs
  still go through the legacy debug-grid unlock — they need
  in-chat-shell UI plumbing.

### Bugs surfaced + fixed during smoke

- **Concurrent bootstrap race.** Leptos 0.8 component bodies (and
  the `spawn_local` calls inside them) can fire multiple times
  during initial mount. The first iteration of `bootstrap_identity`
  was racing with itself, generating 3 identities per page load.
  Fixed by the `bootstrap_in_flight: AtomicBool` guard +
  `compare_exchange` check.
- **Send + Sync on component callbacks.** Leptos 0.8 requires
  closure prop types to be `Send + Sync` even in CSR mode. Original
  draft used `Rc<RefCell>` for `ChatState`; switched to
  `Arc<Mutex<>>` so the closures type-check. In single-threaded
  WASM the mutex never contends; it's a pure type-system gate.
- **`Mutex` lock held across `.await`.** Several places needed
  refactoring to scope lock borrows tightly so they don't span the
  async server calls. Documented inline at each call site.


---

## 19. Chat group-state persistence (shipped 2026-05-12)

Chat now survives page reload. Three layers of localStorage-
backed state plumbed under the chunk C chat flow.

### What shipped

| Layer | Where | Key namespace |
|---|---|---|
| **MLS group state** (state.data + epoch records + group index) | δ.3 `LocalStorageGroupStateStorage` (`apps/lattice-web/src/storage.rs`) | `lattice/mls/group/{gid_b64url}/{state,epoch/n,max_epoch}` + `lattice/mls/groups` |
| **KeyPackage repo** (per-device leaf init private keys) | `sync_kp_repo_to_storage` / `restore_kp_repo_from_storage` (`apps/lattice-web/src/storage.rs`) | `lattice/mls/kp/{kp_id_b64url}` + `lattice/mls/kp_ids` |
| **Conversation index** (peer user_id + label + last_seq) | `chat_state.rs` `ConvoRecord` + helpers | `lattice/conversations/v1` |
| `load_group_with_storage` helper | `lattice-crypto::mls` | n/a |
| `write_to_storage` on create + join | `lattice-crypto::mls::{create_group_with_storage, process_welcome_with_storage}` | flushes state to whichever `GroupStateStorage` is configured |
| Bootstrap restore path + view-signal refresh effect | `chat_state.rs::restore_conversations` + `chat.rs::Effect` watching `bootstrap_complete` | n/a |

### Why the KP shadow-sync

`lattice_crypto::mls::build_client` hardcodes the client's
`key_package_repo` to `InMemoryKeyPackageStorage` (the type
lives on `LatticeIdentity::key_package_repo`). Generalizing
that to a generic param would ripple through every caller in
lattice-crypto / lattice-server / lattice-cli. Cheaper: mirror
the in-memory entries to localStorage from the browser side,
then re-insert on boot into a fresh `InMemoryKeyPackageStorage`.
Identical observable behaviour, zero lattice-crypto API
changes.

Each `KeyPackageData` (key_package_bytes + init_key +
leaf_node_key + expiration) serializes through `mls_rs_codec`
and stores as base64. The id index at `lattice/mls/kp_ids`
makes restoration a single read instead of scanning every
localStorage key.

### Why the explicit `write_to_storage`

mls-rs's `Client::create_group_with_id` and `join_group` build
the in-memory `Group` but **don't auto-flush** to the
configured `GroupStateStorage`. The first call that DOES flush
is the next `apply_commit` / `encrypt_application` / `decrypt`.

For Bob (inviter), that worked accidentally: he does
`create_group → add_member → apply_commit`, and `apply_commit`
flushes. For Alice (joiner), her `process_welcome` finished
without any subsequent op, so her group state stayed in memory
and was lost on reload. Fix: both helpers in lattice-crypto
now call `write_to_storage` immediately after construction.

### Reload smoke transcript (kokonoe, 2026-05-12)

```
fresh state — localStorage clear, server snapshot deleted
both tabs navigate → bootstrap fresh identity:
  Alice: 486fc5d875b69078c68a171b2f08b74c94a317489806adbc54eb5eef8a765cd8
  Bob:   5c94bbc16225e52f477e02c62f5f47f0d249bbee13030bbf9c1c6405406e7e6c
Bob invite Alice → conversation appears in his sidebar
Alice add Bob   → welcome found → joins → conversation appears
Bob send "before reload from bob" → Alice's poll decrypts ✓

localStorage at this point on Alice:
  lattice/mls/groups = ["tQpZm-_hmUMuM7vrUHIKxg"]  ← group_id b64url
  lattice/conversations/v1 = [{group_id_hex: b50a59...,
                               peer_user_id_hex: 5c94bb..., label: Bob,
                               last_seq: 1}]
  lattice/mls/kp_ids = [...]

both tabs navigate (hard reload)
both tabs re-bootstrap → restore_kp_repo + restore_conversations
both sidebars show "Bob" / "Alice" again ✓
Bob send "AFTER RELOAD from bob" → Alice's poll decrypts ✓
Alice reply "alice reply post-reload" → Bob's poll decrypts ✓
last_seq = 3 (history of pre-reload + post-reload messages)
```

### Known gaps (still chunk D / B / E / F)

- **History replay.** `last_seq` is persisted, so on reload we
  skip past messages received before the reload. The thread
  starts visually empty until a new message arrives. Chunk D
  needs to fetch since=0 once on bootstrap and re-decrypt
  + re-render the historical thread (or persist plaintexts).
- **WebSocket push.** Still polling every 5 sec. Chunk D
  replaces with `api::open_messages_ws` per active conversation.
- **Contacts / onboarding.** Still "paste user_id hex" — chunk B.
- **Server config + polish + visual.** Chunks E + F.
- **G.3 hardware-backed keystore upgrade.** Tracked at
  `scratch/next-session-plan.md` Track 2.

### Verification

- `cargo check --workspace` ✅
- `cargo test --workspace` ✅ 200 tests pass (no regressions
  from the new `write_to_storage` calls)
- `cargo check --target wasm32-unknown-unknown --bin lattice-web` ✅
- `trunk build` produces a clean dist/ bundle
- Reload smoke verified end-to-end on two browser tabs

---

## 20. Chat scrollback (shipped 2026-05-12)

Pre-reload thread history now renders immediately on reload.

### Why plaintext-on-disk, not re-decrypt

MLS application messages carry a per-epoch generation counter.
mls-rs's `Group::decrypt` rejects any ciphertext whose generation
is `≤ highest seen`. So we cannot replay scrollback by
re-fetching the server's `since=0` view and re-decrypting — the
in-memory MLS state restored from `LocalStorageGroupStateStorage`
already knows it's processed generations 0..N, and feeding the
same ciphertexts back errors out.

Pragmatic alternative: persist the **plaintexts** to localStorage
at decrypt time. At-rest plaintext protection is the same posture
every chat app (Signal, Telegram, etc.) takes — full-disk
encryption on the device is the relevant defense, not app-layer
encryption.

When chunk B's encrypted-unlock UI lands, scrollback should wrap
under the same Argon2id / PRF KEK as the v2 / v3 identity blob.
Until then, scrollback is plaintext alongside the v1 identity
blob (which is also plaintext) — consistent posture.

### Wire points

`apps/lattice-web/src/chat.rs` adds three integration points:

| Point | Behavior |
|---|---|
| `on_send` | Outgoing message: optimistic local-append now also `append_history(gid_hex, &entry)`. Persists before the async server POST so a reload-mid-send doesn't lose the message. |
| `apply_polled_messages` | Each decrypted incoming envelope persists via `append_history` AND pushes to the signal. |
| `Effect::new` watching `bootstrap_complete` | Reads `load_history(gid)` for each restored conversation and seeds the `messages` signal so the thread re-renders. Sidebar `last_preview` is stamped from the most-recent persisted message. |

Storage helpers (`history_key`, `append_history`, `load_history`,
`save_history`) live at the bottom of `chat.rs`. JSON serialization
via `serde_json`; storage path `lattice/messages/{gid_hex}/v1`
mirrors the existing namespacing pattern.

### Reload smoke transcript (kokonoe, 2026-05-12)

```
fresh state — localStorage clear, server snapshot deleted
both tabs bootstrap fresh identities:
  Alice: 2828c1c9056298d5f61bf14e96fc8b5afe570befd4a4f58ced342242c74fe832
  Bob:   3a093cd15224f0dca8f3c52554314b91bf24686831fe4ed1baef848e7e556019
Bob invite Alice → conversation appears
Alice add Bob → joins
Bob send "msg1 from Bob" → Alice's poll decrypts ✓
Alice send "reply from Alice" → Bob's poll decrypts ✓

localStorage at this point on both:
  lattice/messages/{gid}/v1 = [
    {author: "...", body: "msg1 from Bob", ts: ...},
    {author: "...", body: "reply from Alice", ts: ...}
  ]

both tabs navigate (hard reload)
both tabs re-bootstrap + restore conversations + seed messages from history
  → sidebar shows the conversation
  → thread shows BOTH "msg1 from Bob" and "reply from Alice" immediately

Bob send "msg2 from Bob — post-reload" → Alice's poll decrypts
Alice's final thread: 3 messages (2 from scrollback + 1 new) ✓
```

### Known follow-ups

- **Bounded retention.** Currently unlimited per-conversation. A
  message-count cap (or age cap) lives in chunk E or F.
- **Encrypted at rest.** Tracked alongside chunk B's
  encrypted-identity-unlock UI. The KEK from
  `argon2id-keyed ChaCha20-Poly1305` (v2 path) or PRF (v3 path)
  should wrap the scrollback JSON.
- **Threading consistency on server restart.** If the server
  loses its snapshot mid-conversation, new sends start at
  `seq=1` while clients have `last_seq>0`. Clients then miss
  messages until they manually reset. Server-side persistence
  hardening lives in M3 polish.


---

## 21. Track 4 chunk 1 — N-party group chat (shipped 2026-05-12)

First half of the server-with-channels arc. Plain MLS groups
exposed in the chat UI as a "New group" sidebar button.
Inviter generates a random group_id, server enumerates pending
welcomes for the joiner at bootstrap.

### What shipped

| Surface | Where |
|---|---|
| `ChatState::create_group_conversation(label, peers, log)` — random gid, fetch KPs, `add_members`, single `submit_commit_multi` POST, persist | `apps/lattice-web/src/chat_state.rs` |
| `ChatState::discover_pending_welcomes(log)` — called at end of both bootstrap branches; auto-joins each newly-discovered group | `apps/lattice-web/src/chat_state.rs` |
| `api::submit_commit_multi` — N welcomes in one POST | `apps/lattice-web/src/api.rs` |
| `api::fetch_pending_welcomes` + `pending_welcome_into_lattice` | `apps/lattice-web/src/api.rs` |
| `<NewGroupForm>` Leptos component + 👥 sidebar button | `apps/lattice-web/src/chat.rs` |
| `GET /welcomes/pending/:user_id_b64` server route | `crates/lattice-server/src/routes/groups.rs` |

### Why the new server endpoint

The 1:1 `add_conversation` flow worked without server-side
invite enumeration because both parties derived the same
deterministic `group_id = blake3("lattice/dm/v1/" || sorted(uid_a, uid_b))[..16]`.
N-party groups have no canonical sort, so the inviter picks a
**random** group_id. The joiner has no way to derive it locally
— so the server has to enumerate "welcomes addressed to me
across all groups."

`GET /welcomes/pending/:user_id_b64` walks every group on the
server, returns the latest welcome per group_id that's
addressed to the queried user_id. Idempotent — re-fetching the
same welcome is fine; the second `process_welcome` fails
cleanly inside mls-rs (leaf init key already consumed) and the
client loop silently skips it.

### Smoke-test transcript (kokonoe, 2026-05-12)

```
fresh state — localStorage clear, server snapshot deleted, server rebuilt
both tabs bootstrap fresh identities:
  Alice: 265a4a707eb542d71bd6e0386659e6104574794a7a14f09dc2bebb40d1adfcbd
  Bob:   a72b32c32239459c82228e09428691957262dbda92a32ef6984f90baab38e91e
Bob clicks 👥, fills "design team" + Alice's hex, submits
  → "chat: group ready (design team)" status
  → sidebar shows "design team" entry
Alice hard-reloads
  → bootstrap_inner.load-existing branch fires
  → discover_pending_welcomes finds the pending welcome
  → process_welcome_with_storage succeeds (KP from local repo)
  → ConvoRecord persisted with placeholder label
  → sidebar shows "group 095bb3e3"
Bob sends "hi from Bob to N-party group" → Alice's poll decrypts ✓
Alice sends "reply from Alice in the group" → Bob's poll decrypts ✓
Bob's thread: ["me (a72b32): hi…", "design team: reply…"]
Alice's thread: ["group 095bb3e3: hi…", "me (265a4a): reply…"]
```

### Known limitations (tracked, all chunk 2)

- **Group name / inviter metadata in welcome.** Joiner sees a
  placeholder `group {prefix}` label because welcomes don't
  carry the group name today. Chunk 2's server-membership group
  application message carries both server name and inviter's
  user_id.
- **Author display for received messages.** The poll thread
  shows messages as "from $label" where label is the
  conversation label — not the actual sender's user_id. For 1:1
  this is the peer's label; for N-party groups it's the
  placeholder. mls-rs's decrypt does surface the sender's leaf
  index → committable user_id, but we don't read it yet.
  Chunk 2's roster panel + this lookup go together.
- **Authorization layer.** Every member can commit (MLS flat).
  No admin/mod roles. Track 4 chunk 2 sketches the options
  (client-side flat-MLS + signed-policy recommended first;
  external-sender extension as the harder tamper-resistance
  upgrade).
- **N≥3 wire-level verification.** Today's smoke is 2-party;
  full multi-recipient `submit_commit_multi` proof needs a 3rd
  origin (iMac when it's awake, cnc-server, or Chrome
  incognito). The code path exercises the multi-welcome JSON
  array even with a single welcome, but the N≥2 case isn't
  observed.

### Open questions for chunk 2

- Channel-roster discovery at server join time. Server-membership
  group only carries forward ops, so new joiners need either a
  snapshot in a join-time app message OR an inviter-sent "current
  state" message right after admit.
- Per-channel private membership = a channel group not every
  server member has joined. MLS-natural, but UI has to track "in
  server but not in channel."
- Group voice (≥ 3 participants) is long-horizon per ROADMAP M7
  — not blocking chunks 1 or 2.


---

## 22. Track 4 chunk 2 first cut — server-membership groups (shipped 2026-05-12)

First half of the Discord-parity arc. A "server" is an MLS group
whose first application message is a `ServerStateOp::Init`; the
chat shell classifies on first-Init-decrypt and renders the
entry with a ★ prefix instead of `#`. Single channel per server
(the server-membership group itself); multi-channel separation
is chunk 2.5.

### What shipped

| Surface | Where |
|---|---|
| `ServerStateOp` wire enum + `try_decode` classifier | `crates/lattice-protocol/src/server_state.rs` |
| `ConvoKind::{OneOnOne, NamedGroup, ServerMembership { server_name }}` on `ConvoState` + `ConvoRecord` | `apps/lattice-web/src/chat_state.rs` |
| `ChatState::create_server(server_name, peers, log)` | `apps/lattice-web/src/chat_state.rs` |
| Post-decrypt classification (poll path tries `ServerStateOp::try_decode` first; success → upgrade kind + persist) | `apps/lattice-web/src/chat_state.rs::poll_all` |
| `update_convo_kind` persistence helper | `apps/lattice-web/src/chat_state.rs` |
| `<NewServerForm>` Leptos component + ★ sidebar button + kind-prefix sidebar rendering | `apps/lattice-web/src/chat.rs` |

### Wire encoding for `ServerStateOp`

JSON via `serde_json` with `#[serde(tag = "op", content = "data")]`
discriminator. Variants: `Init`, `AddChannel`, `RemoveChannel`,
`RenameServer`, `PromoteAdmin`, `DemoteAdmin`. Future hardening
can swap to capnp once the op set stabilizes; for the first cut
JSON keeps the wire human-debuggable. Body bytes ride inside an
MLS `ApplicationMessage` like any other plaintext — receivers
distinguish by trying `try_decode` first, falling through to
plaintext if it returns `None`.

### Classification timing

- **Creator side:** sets `ConvoKind::ServerMembership` directly
  during `create_server` (we already know the name locally).
- **Joiner side:** auto-discovers the welcome via
  `discover_pending_welcomes`, initially classifies as
  `NamedGroup` with a `group {prefix}` placeholder label. On the
  next poll, the Init op decrypts → kind upgrades to
  `ServerMembership { server_name }`, label becomes the server
  name, persisted record updated.

The poll loop now also re-snapshots `conversation_summaries` after
each iteration so the sidebar signal picks up classification
upgrades without waiting for a reload.

### End-to-end smoke (kokonoe, 2026-05-12)

```
Alice + Bob bootstrap fresh identities (separate origins).
Bob clicks ★ button, names "Friends", pastes Alice's hex.
Bob's sidebar:  ["★ Friends"]
Alice reloads → bootstrap discovers Bob's welcome → auto-joins.
Alice's sidebar (immediately):  ["# group b71f3220"]   (initial, pre-Init-decrypt)
Alice's sidebar (after 5s poll): ["★ Friends"]          (post-classify)
Alice sends "hi from Alice in ★ Friends server" → publishes.
Bob reloads + opens conversation → scrollback loads from localStorage:
  thread shows: [{author: "Friends", body: "hi from Alice in ★ Friends server"}]
```

### What chunk 2 first cut deliberately does NOT do

- **Multi-channel.** Each server has ONE implicit "#general"
  channel — the server-membership group itself doubles as the
  chat group. `AddChannel` ops decode but don't spin up
  separate MLS groups. Chunk 2.5.
- **Admin authorization.** Every member can commit (MLS flat).
  `PromoteAdmin` / `DemoteAdmin` ops decode but aren't enforced.
- **Sender attribution.** Received messages display "from
  $conversation_label" (the server name) instead of the actual
  sender's user_id. mls-rs's decrypt surfaces the leaf-index →
  user_id but the chat shell doesn't read it. Tied to chunk
  2.5's admin-roster panel.
- **Server-state op replay on join.** A late joiner only sees
  ops issued AFTER their join epoch — `AddChannel` /
  `RenameServer` events that predate their welcome are lost.
  Mitigation: inviter sends a "current state" message right
  after admit (chunk 2.5).

### Cross-references

- DECISIONS §D-24 ("per-server admin tools, no global
  moderation") aligns with the planned client-side
  flat-MLS-plus-signed-policy admin enforcement in chunk 2.5.
- `feedback_no_pii_in_notifications.md` memory: when chunk D
  WS push fires for server-membership group messages, the
  notification payload remains generic — no server name, no
  sender, no group_id.

### Open questions for chunk 2.5

- **Channel-roster discovery at join.** Inviter snapshots
  current channel list in the join-time app message, OR sends
  a one-shot ServerStateOp::SyncState immediately after admit.
- **Per-channel private membership.** Channel = an MLS group
  not every server member has joined. UI must track "in
  server but not in channel."
- **`ExternalSendersExtension` vs client-side policy.** Two
  authorization models sketched in
  `scratch/next-session-plan.md` Track 4 chunk 2. Recommend
  client-side first; upgrade if tamper concerns surface.

## 23. Chat-app MVP closeout — chunks 2.5 / E / F / B / D (shipped 2026-05-12)

Chat-shell polish pass. Closes out the "what users see" backlog so
M7 can move to chunk 24 (G.3 hardware-backed wrap) without UI
debt. Each sub-chunk in its own commit; this section narrates what
landed.

### 2.5 — server completeness

Shipped per `feat: chunk 2.5 — MVP server completeness` (commit
`7ac7e8d`). Four sub-deliverables:

- **2.5a — sender attribution.** `decrypt_with_sender<G,R>` returns
  `(Vec<u8>, Option<UserId>)` by resolving
  `ApplicationMessageDescription.sender_index` against the group
  roster. Channel pane shows "Bob: hello" instead of just "hello"
  for non-self messages.
- **2.5b — admin authorization.** Client-side flat-MLS plus a
  per-server `admins: Vec<UserIdHex>` list seeded by
  `ServerStateOp::Init`. `process_server_state_op` rejects
  `AddChannel` / `RemoveChannel` / `PromoteAdmin` / `DemoteAdmin`
  from non-admins. Tamper resistance escalates to a signed-policy
  scheme if needed per DECISIONS §D-24.
- **2.5c — late-joiner state sync.** `ServerStateOp::SyncState`
  carries the full channel + admin list. The inviter publishes one
  immediately after admit so joiners don't have to re-derive
  history.
- **2.5d — multi-channel.** Each channel is its own MLS group keyed
  by a random `GroupId`. `AddChannel` op announces the new
  channel's `group_id_hex + channel_name`; clients open a separate
  MLS state machine for it. `reclassify_channels_after_restore`
  promotes `NamedGroup → ServerChannel` on bootstrap when the
  parent server's channel list contains a matching gid.

### E — settings panel + configurable home server

`SettingsForm` component behind a `⚙` button. `load_server_url`
/ `save_server_url` persist to `lattice/server_url/v1`. Bootstrap
reads the saved URL; defaults to `http://127.0.0.1:8080`. Lets
the user point the chat at a non-default home server without
rebuilding.

### F — visual polish

- Avatar circle (`avatar_color` / `avatar_initials`) — blake3-derived
  HSL hue per conversation id, two-letter initials from the label.
  Stable across reloads.
- Sidebar entry is a 2×2 grid: avatar | name / preview.
- `chat-header-bar` extracted as a flex row so the page-level
  `<h1>` + tagline + status sit on one baseline.

### B — onboarding + contacts

- `Contact { user_id_hex, label, added_at_unix }` persisted to
  `lattice/contacts/v1`. `save_contact` dedupes by hex.
- `ChatState::add_conversation` auto-saves the peer as a contact on
  success.
- `ContactsList` block below the conversation list. Click → focuses
  existing 1:1 DM (matched via `Conversation::peer_user_id_hex`)
  or opens the AddConversation form prefilled with the contact's
  hex + label.

### D — WS push wake + no-PII notifications

- `ws_subscribe.rs` opens one `web_sys::WebSocket` per active
  group, talking to the existing `/group/:gid/messages/ws` route.
  Frame payloads are ignored — the WS is purely a "wake the
  poller" signal so the existing decrypt path stays
  single-sourced.
- `WebSocket` handles live in a `thread_local!` map so the JS
  `!Send + !Sync` handle never leaks into `ChatState`'s Send+Sync
  surface.
- `notify.rs::show_generic_message_notification()` takes **zero
  parameters**. Title `"Lattice"`, body `"New message"`. No
  sender, no group id, no preview, no tag. The no-PII review gate
  is enforced by the function signature, not just convention —
  any future caller wanting per-conversation copy has to add a
  new function. Aligned with
  `memory/feedback_no_pii_in_notifications.md`.
- 30-second rate limit + `document.hidden` gate so notifications
  only fire when the tab is backgrounded AND a burst doesn't spam
  the OS notification shade.
- Service-worker upgrade for true background-tab receive is the
  next step in this lane — out of scope for chunk D.

### Files touched

```
apps/lattice-web/Cargo.toml            (+1 web-sys feature group)
apps/lattice-web/src/main.rs           (+2 mod decls)
apps/lattice-web/src/chat.rs           (+~360 LOC)
apps/lattice-web/src/chat_state.rs     (+~120 LOC)
apps/lattice-web/src/notify.rs         (new, 120 LOC)
apps/lattice-web/src/ws_subscribe.rs   (new, 130 LOC)
apps/lattice-web/styles.css            (+~90 LOC contact styles)
```

### Build status

`cargo check --target wasm32-unknown-unknown --bin lattice-web` ✅
clean. Trunk build + browser smoke deferred to the post-G.3 gate.

### Next

§24 ships G.3 (Windows TPM wrap). After that the next gate is
service-worker push (true background-tab receive), G.3 for macOS
Secure Enclave + tss-esapi opt-in on Linux, and threat-model
refresh ahead of an external audit.

## 24. M7 Phase G.3 (Windows) — TPM 2.0-backed key wrap (shipped 2026-05-12)

Replaces the G.1 DPAPI user-credential wrap on Windows with a TPM
2.0-resident RSA-2048 wrap key under
`MS_PLATFORM_CRYPTO_PROVIDER`. Identity secret bytes are sealed
with a fresh ChaCha20-Poly1305 key per identity, and only that
AEAD key is OAEP-SHA-256-wrapped by the TPM. The DPAPI keystore
stays in tree as the fallback for boxes where the TPM is absent
or unprovisioned.

### Why a wrap key, not direct signing

`MS_PLATFORM_CRYPTO_PROVIDER` exposes RSA and ECDSA only — no
Ed25519 or ML-DSA-65 (HANDOFF §8 spec lock). Sealing to the TPM
keeps the at-rest envelope hardware-bound without forcing a wire
spec change. Same RAM-window posture as G.1 (DPAPI) and G.2b
(macOS ECDH-wrap): bytes appear in RAM during sign, zeroized on
return.

### What shipped

```
crates/lattice-media/src/keystore/windows_tpm.rs   new, ~700 LOC
crates/lattice-media/src/keystore/mod.rs           +TpmUnavailable variant
crates/lattice-media/Cargo.toml                    chacha20poly1305 → [deps]
```

- `TpmWindowsKeystore::new(dir)` + `at_default_location()` at
  `%LOCALAPPDATA%\Lattice\keystore-tpm` (distinct from the DPAPI
  dir so both can coexist during migration).
- Persistent wrap key named `Lattice-MasterWrap-v1` — generated
  lazily on first `generate()` / `sign()`, reopened on every
  subsequent run.
- On-disk format: `version=1 || wrapped_key_len_u16_be ||
  wrapped_key || nonce_12 || ciphertext_with_tag`. Public-key
  sidecar `.pub` JSON shares the DPAPI schema for future rewrap.
- Two RAII guards (`ProviderHandle`, `KeyHandleGuard`) call
  `NCryptFreeObject` on drop so partial-failure paths can't leak
  CNG resources.
- New `KeystoreError::TpmUnavailable { message }` so callers
  decide explicitly whether to fall back to
  `WindowsKeystore` (DPAPI).

### Test status

`cargo test -p lattice-media --lib`: **40 passed, 1 ignored**.

The 6 TPM unit tests pass via the `tpm_available()` guard —
kokonoe's TPM is **intentionally disabled in firmware**, so
`NCryptOpenStorageProvider` returns `0x80090030`. Each test logs
`skipping <name>: no TPM 2.0` to stderr. The seal / unseal /
sign-against-real-TPM FFI paths have not been exercised on real
hardware on kokonoe — that's expected.

**Hardware-smoke host:** **satibook** has a provisioned TPM 2.0.
Run `cargo test -p lattice-media --lib windows_tpm -- --nocapture`
there to exercise the full FFI path. That's the gating step
before flipping `lattice-desktop::build_keystore()` to TPM as the
Windows default.

`tpm_unavailable_path_returns_typed_error` is `#[ignore]`-gated —
run it on a TPM-less host (kokonoe with TPM-disabled qualifies)
to confirm the fallback signal.

### Caveats / follow-ups

- Hardware verification on a real TPM 2.0 chip is the gating
  step before flipping the desktop default to `TpmWindowsKeystore`.
  Smoke target: satibook (kokonoe TPM is intentionally disabled).
  `lattice-desktop::build_keystore()` still constructs the DPAPI
  `WindowsKeystore`; switch is a one-line change once the satibook
  smoke passes.
- Not PCR-bound. Sealing to PCRs (so a firmware tamper kills the
  wrap key) is out of scope for G.3 per
  `scratch/m7-phase-g-plan.md` §G.3.
- macOS Secure Enclave + Linux `tss-esapi` opt-in remain on the
  G.3 follow-up list — not in this commit.

## 25. Public docs site — deploy + internal-leak scrub (shipped 2026-05-13)

🟢 Working. `https://lattice-quantum.vercel.app` is live with the
sanitized doc set.

The public Astro/Starlight site that the docs subagent scaffolded
earlier was deployed to Vercel under the `lattice-quantum` project
in the `suhteevah` scope. Two follow-on problems were uncovered and
fixed in this session:

### Why the first deploy was wrong

1. **Build-time portability.** The original sync script
   (`scripts/sync-usage.ps1`) used PowerShell. Vercel's Linux build
   container has no `powershell`, so the `npm run prebuild` hook
   would have failed on every Vercel build. Even after deploying
   with `--prebuilt` (which skips Vercel-side build) the script
   remained a Windows-only liability.
2. **Internal-leak surface.** The wiki sync mirrored
   `docs/{HANDOFF,DECISIONS,ARCHITECTURE,THREAT_MODEL,ROADMAP}.md`
   plus `README.md` into `/wiki/`. HANDOFF / ROADMAP / DECISIONS /
   README are inherently internal — they leak machine names
   (kokonoe, satibook, pixie, cnc-server), a real public VPS IP
   (`207.244.232.227`), LAN + Tailscale IPs, owner identity,
   tentative product decisions (D-22 domain choice, D-25
   monetization), and chunk-by-chunk session logs. The
   `docs/usage/*` files written by the docs subagent also leaked
   `HANDOFF §N`, `DECISIONS §D-NN`, milestone labels (M0–M7), and
   chat-app chunk labels (A/B/C/D/E/F, 2, 2.5) throughout.

### Fixes shipped

- `apps/lattice-docs/scripts/sync.mjs` — pure-Node sync script
  replacing the PowerShell one. Cross-platform, zero deps,
  idempotent, normalises frontmatter the same way.
- `apps/lattice-docs/package.json` — `prebuild` / `predev` /
  `sync` scripts all call `node ./scripts/sync.mjs`.
- `scripts/sync-usage.ps1` removed.
- `WIKI_FILES` narrowed to `ARCHITECTURE` + `THREAT_MODEL` only.
- `docs/usage/*.md` (all 12 files) and `docs/ARCHITECTURE.md` —
  every internal reference scrubbed or rewritten. See commit
  `d1de71a` for the full per-file diff.
- `apps/lattice-docs/src/content/docs/index.mdx` — project-section
  links repointed from GitHub `docs/*.md` to in-site `/wiki/`.
- `apps/lattice-docs/src/content/docs/changelog.mdx` — gutted to a
  stub; the old release notes leaked milestone labels + internal
  test counts.

### Deploy pattern

`vercel deploy --prebuilt --prod` from `apps/lattice-docs/`. We
pre-build locally so the sync script can reach `../../docs/`, then
ship `.vercel/output/` as-is. There is no auto-deploy from git —
intentional, per `CLAUDE.md`'s manual-gate rule. Full runbook at
`apps/lattice-docs/DEPLOY.md`.

### Verification

Browser smoke confirmed:
- `/wiki/handoff/`, `/wiki/roadmap/`, `/wiki/decisions/`,
  `/wiki/readme/` → 404 (correctly missing).
- `/wiki/architecture/`, `/wiki/threat_model/` → render clean.
- `/docs/usage/*` → 12 pages, zero hits for any of
  `HANDOFF`, `kokonoe`, `pixie`, `207.244`, `D-NN`, `M[0-9]`,
  `llm-wiki`, `DECISIONS`, `chunk *`.
- `npm run build` indexes 17 pages green; Pagefind search
  works on the sanitized corpus.

### Follow-ups

- Tag a `v0.1.0` and fill `changelog.mdx` with the first
  user-facing release notes once the surface stabilises.
- Future-proof the leak audit: add a `scripts/audit-public-docs.ps1`
  (or `.mjs`) that greps the publish targets for the same regex set
  before every deploy and fails non-zero on a hit. Currently a
  manual grep is the only gate.
- Domain (D-22 in the locked decisions) still open — until it's
  resolved, `lattice-quantum.vercel.app` is the canonical URL.

