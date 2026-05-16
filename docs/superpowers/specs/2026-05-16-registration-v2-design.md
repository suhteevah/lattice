# Registration v2 — design

**Status:** Brainstorming complete, awaiting review. Author: Matt Gates (via
Claude). Date: 2026-05-16. Repo HEAD at design time: `74817ba`.

## Problem

`lattice-server` currently authenticates `POST /register` with one static
bearer token configured via `LATTICE__SERVER__REGISTRATION_TOKEN`. Today's
posture is "operator hand-shares one token, everyone who has it can sign
up." This was a stop-gap during the cnc + pixie federation bring-up. For
SaaS-mode rollout we need:

- Invite-only onboarding with per-user single-use tokens.
- An admin UI for issuing + revoking those tokens.
- A redemption landing page so a recipient can verify their invite is
  real and unconsumed before installing anything.
- Backwards compatibility so the existing deployment keeps working
  during the swap.

## Goals (in scope)

1. Multiple coexisting invite tokens on one home server, each with its
   own expiry + label + consumed-state.
2. Web admin surface gated by Clerk; the operator (Matt) mints + revokes
   invites without shell access to pixie.
3. Public read-only landing page at `/invite/<token>` that surfaces
   "valid / expired / consumed" without requiring sign-in.
4. Atomic single-use consumption — two simultaneous `/register` POSTs
   with the same token: exactly one succeeds.
5. Backwards compat: existing `LATTICE__SERVER__REGISTRATION_TOKEN`
   continues to work; old `snapshot.json` v1 loads cleanly.

## Non-goals (deferred)

- Open public sign-up (anyone can register). This spec is invite-only.
- Email-driven magic links. The redemption URL is the carrier.
- Per-token rate limits / abuse detection.
- Stripe / billing surfaces.
- Multi-server token federation — each home server's tokens are local.
- A second admin user. Single-operator (Matt) only for now.
- Replacing the existing `apps/lattice-docs/` Astro stack — we extend
  it, not migrate to Next.js.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ apps/lattice-docs/ (Astro on lattice-quantum.vercel.app)         │
│                                                                  │
│   /docs/*                       — existing, untouched           │
│   /invite/[token]               — PUBLIC: redemption landing    │
│   /admin                        — CLERK-gated: mint / list /    │
│                                   revoke invites                │
│   /api/admin/tokens             — server endpoint; forwards to  │
│                                   lattice-server with admin key │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTPS, X-Lattice-Admin-Key: <env>
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ crates/lattice-server/                                           │
│   routes/admin.rs           NEW — /admin/tokens (CRUD)           │
│   routes/identity.rs        EXTENDED — /register consumes token  │
│   state::InviteToken        NEW struct                           │
│   state::ServerState        + invite_tokens, admin_api_key       │
│   StateSnapshot v2          + invites: Vec<InviteSnap>           │
└─────────────────────────────────────────────────────────────────┘
                             │ POST /register with Bearer <token>
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ apps/lattice-web/ (Leptos PWA wrapped by Tauri)                  │
│   chat.rs::SettingsForm     EXTENDED — adds "Invite token" field │
│   chat_state.rs             EXTENDED — loads + attaches to       │
│                                        /register Authorization   │
│   localStorage              NEW key: lattice/invite_token/v1     │
└─────────────────────────────────────────────────────────────────┘
```

### Boundaries

- Astro never sees user identity material. Only mints tokens and
  renders pages.
- `lattice-server` is the single source of truth for token state. Vercel
  KV / Clerk session data is not used for token bookkeeping.
- The chat-shell change is additive — a settings field that's optional.
  Empty token = unauthenticated `/register`, which still works iff the
  server's invite registry is empty AND `admin_api_key` is unset
  (preserves dev-mode behavior).

## Components

### `crates/lattice-server/src/state.rs` (extension)

```rust
/// One outstanding or consumed invite. Persisted in StateSnapshot v2.
pub struct InviteToken {
    /// ~32-char URL-safe base64 of 24 random bytes.
    pub token: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub label: Option<String>,
    pub consumed_at: Option<i64>,
    pub consumed_by: Option<[u8; 32]>,
}

pub struct ServerState {
    // ... existing fields ...
    /// Keyed by the token string. Single write-lock for both mint and
    /// consume — see register_handler's atomic critical section.
    pub invite_tokens: Arc<RwLock<HashMap<String, InviteToken>>>,
    /// `None` = `/admin/*` routes return 503. `Some` = constant-time
    /// header compare. Loaded from `LATTICE__SERVER__ADMIN_API_KEY`.
    pub admin_api_key: Option<Arc<String>>,
}
```

`StateSnapshot` gets `invites: Vec<InviteSnap>` (mirror of the
HashMap values). `snapshot_version` increments from 1 → 2. v1
snapshots load with `invites` defaulted to empty.

### `crates/lattice-server/src/config.rs` (extension)

`ServerConfig` gains:

```rust
/// Optional shared secret for /admin/* routes. Empty = admin disabled.
/// Set via LATTICE__SERVER__ADMIN_API_KEY.
#[serde(default)]
pub admin_api_key: String,
```

Set default `""`. Plumbed into `ServerState::with_admin_api_key`.

### `crates/lattice-server/src/routes/admin.rs` (new module)

```rust
POST   /admin/tokens          // body: { label?: string, ttl_secs?: i64 }
                              // resp: { token, expires_at }
GET    /admin/tokens          // resp: [ { token, created_at, expires_at,
                              //          label, consumed_at,
                              //          consumed_by_prefix } ]
GET    /admin/tokens/:token   // single lookup (PUBLIC: no admin key
                              //   required, returns same shape minus
                              //   the consumed_by user_id, for the
                              //   /invite/<t> public page)
DELETE /admin/tokens/:token   // 204 / 404
```

All routes except the single-lookup require `X-Lattice-Admin-Key:
<value>` matching `state.admin_api_key`. Constant-time compare via
`subtle::ConstantTimeEq`. Mismatch or absent header → 401 with body
`admin authentication required`. `admin_api_key` unset → 503 with
body `admin disabled on this server`.

The single-lookup GET deliberately bypasses auth so the public
landing page can read its own invite. The data returned is non-
sensitive (expiry, validity, label) and the token itself was already
in the URL.

### `crates/lattice-server/src/routes/identity.rs` (extension)

`register_handler` swap: lookup-in-set instead of static-bytes-compare.
Atomic critical section:

```rust
let supplied = extract_bearer(&headers).ok_or((401, "no token"))?;
let mut guard = state.invite_tokens.write().await;
let token = guard.get_mut(&supplied).ok_or((401, "unknown token"))?;
ensure!(token.expires_at > now, (401, "token expired"));
ensure!(token.consumed_at.is_none(), (401, "token already consumed"));

token.consumed_at = Some(now);
token.consumed_by = Some(user_id);

match register_user(&state, /* … */).await {
    Ok(_) => Ok(...),
    Err(e) => {
        // Revert tentative consumption so a transient register_user
        // failure doesn't burn the invite.
        token.consumed_at = None;
        token.consumed_by = None;
        Err(e)
    }
}
// write-lock released
```

The lock spans check → mark → user-insert, which is the entire reason
double-spend is impossible: a second concurrent register would block on
the lock and find `consumed_at.is_some()` when it gets through.

### Backwards-compat path

On startup, if `LATTICE__SERVER__REGISTRATION_TOKEN` is non-empty AND
the invite registry is empty (fresh boot or v1 snapshot load), the
server auto-mints an invite with that exact string and `expires_at =
i64::MAX`. Existing deployments keep onboarding new users without
config change. Operators (Matt) cut over to the new minting flow by
revoking that auto-minted token after the v2 deploy is in place.

### `apps/lattice-docs/src/pages/` (new Astro routes)

```
src/pages/invite/[token].astro       — public landing
src/pages/admin/index.astro          — Clerk-gated dashboard
src/pages/api/admin/tokens.ts        — Astro server endpoint forwarder
src/pages/api/admin/tokens/[id].ts   — revoke forwarder
```

- `/invite/[token]` server-renders by fetching `GET /admin/tokens/:token`
  on the home server (no admin key needed — the home server allows
  single-lookup unauthenticated). Renders one of three states:
  valid (show install instructions + token + URL), expired, consumed.
- `/admin/*` requires a Clerk session. Astro middleware checks
  `user.id` matches an env-var allowlist (initially `MATT_CLERK_USER_ID`).
- `/api/admin/tokens` (POST / GET) and `/api/admin/tokens/[id]` (DELETE)
  validate the Clerk session, then forward to the home server with
  `X-Lattice-Admin-Key`. The admin key never reaches the browser.

The `@clerk/astro` package is the integration of record. Vercel
Marketplace install (one-click) provisions the Clerk env vars to the
Vercel project automatically.

### `apps/lattice-web/` (chat-shell change, ~40 lines)

- `chat_state.rs`: add `pub fn load_invite_token() -> Option<String>`
  + `pub fn save_invite_token(&str)` keyed at
  `lattice/invite_token/v1`. Add `invite_token: Option<String>` field
  on `ChatState`. On bootstrap, read it, attach to register call.
- `api.rs::register`: signature gains `invite_token: Option<&str>`;
  attaches `Authorization: Bearer <t>` when `Some`.
- `chat.rs:1207` (`SettingsForm`): add a second `<input>` labelled
  "Invite token". Same save/reload-required semantics as the URL field.
- On successful register, drop `lattice/invite_token/v1` from
  localStorage — a spent token is just clutter.

## Data flow

A complete happy-path registration is 8 hops:

1. Matt → `/admin` on lattice-quantum.vercel.app, signed into Clerk.
   Clicks "Mint invite", label "alice", TTL 7 d, submits.
2. Browser → POST `/api/admin/tokens`. Astro validates Clerk session.
3. Astro server → `POST https://lattice.pixiedustbot.com/admin/tokens`
   with `X-Lattice-Admin-Key`. Server returns
   `{ token: "Yx7nQk…", expires_at }`.
4. Admin UI displays the redemption URL
   `https://lattice-quantum.vercel.app/invite/Yx7nQk…`. Matt shares
   out-of-band.
5. Alice opens the URL. Astro server-renders by calling
   `GET /admin/tokens/Yx7nQk…` on the home server. Renders install
   instructions + the token string + the home-server URL.
6. Alice installs the client, sets home-server URL via ⚙ panel,
   pastes the token into the new ⚙ token field, reloads.
7. Chat shell → `POST /register` with `Authorization: Bearer Yx7nQk…`
   and the user_id + claim. Server's atomic critical section validates
   + consumes + inserts. Returns `new_registration: true`.
8. Chat shell wipes `lattice/invite_token/v1`. Continues with
   `publish_key_package`, `welcomes/pending` polling, etc. Admin UI
   reflects consumption on next refresh.

## Error handling

| Failure | Detection | Response |
|---|---|---|
| Token unknown | `guard.get(t).is_none()` | 401 `unknown token` + log |
| Token expired | `t.expires_at <= now` | 401 `token expired` + log |
| Token already consumed | `t.consumed_at.is_some()` | 401 `token already consumed` + log |
| Two simultaneous `/register` | write-lock holds | Loser gets 401 |
| `register_user()` errors after mark | revert inside lock | Token re-usable |
| Admin API key wrong | header check | 401 + log |
| `admin_api_key` unset | `state.admin_api_key.is_none()` | 503 `admin disabled` |
| Snapshot write fails | `save_snapshot` err | Warn only; state correct in memory |
| Astro → server unreachable | timeout in `/api/admin/tokens` | 502 to admin browser |
| Invite never redeemed | nothing | Sweeper task removes expired+consumed entries older than 30 d every 5 min |

## Testing

| Layer | Coverage |
|---|---|
| Unit (lattice-server) | `state::tests::invite_token_lifecycle` — mint, lookup, expire, double-use, revoke, snapshot round-trip. Race test: 200 concurrent `/register` POSTs same token, 1 wins. |
| Integration (lattice-server) | `tests/registration_v2.rs` — in-process axum, full mint→register→list cycle. Backcompat test: env-var-token still works on a fresh server. |
| Smoke (Astro) | Manual until a test target exists — visit `/admin` (Clerk), mint, visit `/invite/[t]`, register from chat shell, confirm consumed state. |
| Backcompat | Boot with old `LATTICE__SERVER__REGISTRATION_TOKEN="foo"`. Verify auto-mint, `/register` with `Bearer foo` succeeds once. Confirm v1 snapshot loads cleanly into v2. |

Clippy / fmt / `cargo audit` per the existing pre-commit gate
(`scripts/test-all.ps1`).

## Open questions

None. All branches explored during brainstorming have been resolved
above.

## Files to be touched

```
crates/lattice-server/Cargo.toml             modified (subtle was added in pre-v2 work)
crates/lattice-server/src/config.rs          modified (+ admin_api_key)
crates/lattice-server/src/state.rs           modified (+ InviteToken, snapshot v2)
crates/lattice-server/src/main.rs            modified (plumb admin_api_key)
crates/lattice-server/src/lib.rs             modified (merge admin router)
crates/lattice-server/src/routes/admin.rs    new
crates/lattice-server/src/routes/identity.rs modified (consume token)
crates/lattice-server/tests/registration_v2.rs new

apps/lattice-docs/package.json               modified (+ @clerk/astro)
apps/lattice-docs/astro.config.mjs           modified (+ clerk integration)
apps/lattice-docs/src/pages/invite/[token].astro new
apps/lattice-docs/src/pages/admin/index.astro new
apps/lattice-docs/src/pages/api/admin/tokens.ts new
apps/lattice-docs/src/pages/api/admin/tokens/[id].ts new
apps/lattice-docs/src/middleware.ts          new (Clerk gate on /admin)

apps/lattice-web/src/api.rs                  modified (register sig + Bearer)
apps/lattice-web/src/chat_state.rs           modified (token plumbing)
apps/lattice-web/src/chat.rs                 modified (settings field)
apps/lattice-web/src/storage.rs              modified (load/save_invite_token)
```

## Deployment

- Add `LATTICE__SERVER__ADMIN_API_KEY=<random 32 bytes URL-safe>` to
  `/etc/systemd/system/lattice-server.service.d/auth.conf` on both cnc
  and pixie. Same key on both (operator convenience).
- Add `LATTICE_ADMIN_API_KEY` + Clerk env vars to the Vercel project for
  `lattice-quantum.vercel.app`.
- Install `@clerk/astro` via the Vercel Marketplace one-click integration
  (provisions Clerk env vars onto the Vercel project automatically).
- Roll new lattice-server binary to both nodes (replace
  `/usr/local/bin/lattice-server`, `systemctl restart lattice-server`).
- Deploy the Astro changes via `vercel deploy --prebuilt --prod` from
  `apps/lattice-docs/`.
- Smoke: `curl https://lattice.pixiedustbot.com/admin/tokens` returns
  401 (no key); with key returns `[]`. Mint via `/admin`, open
  `/invite/<token>`, register from chat shell.

## Rollback

The change is additive. If the v2 server has bugs:

1. `systemctl stop lattice-server`
2. Restore the previous binary at `/usr/local/bin/lattice-server`
   (kept as `lattice-server.v1` after the first redeploy).
3. `systemctl start lattice-server`. v1 reads its v1-format snapshot
   from disk; v2 invites silently disappear.

The v2 snapshot is forward-compatible (v1 only reads the fields it
knows), so a stop-the-world rollback loses only the post-v2 invite
records, not any user / KP / group state.

## Estimate

Roughly two implementation sessions:

1. Server-side (state + admin routes + register-handler swap + tests
   + backcompat). ~5–6 hours.
2. Astro-side (Clerk wiring, three pages, two API routes, chat-shell
   token field). ~3–4 hours.

Plus ~1 hour for deployment + smoke against the live federation pair.
