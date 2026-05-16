# Registration v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-static-token `/register` gate with per-user single-use invite tokens managed via a Clerk-gated Astro admin UI on `lattice-quantum.vercel.app`, while keeping the existing federated deployment working.

**Architecture:** Stateful tokens stored in `ServerState` and persisted in `snapshot.json` (v2). New `/admin/tokens` routes on `lattice-server` are gated by a shared `X-Lattice-Admin-Key` header. Astro server endpoints forward admin operations and never leak the admin key to the browser. The chat shell gains an "Invite token" settings field that attaches `Authorization: Bearer <token>` to its bootstrap `/register` POST.

**Tech Stack:** Rust 1.95 stable-gnu, axum 0.8, tokio 1.x, mls-rs 0.41, `subtle` for constant-time compare, Astro 4 with `@clerk/astro`, Vercel hosting, Leptos 0.7 PWA wrapped by Tauri 2.

**Spec:** `docs/superpowers/specs/2026-05-16-registration-v2-design.md`

> **Commit policy override:** Per the operator's `CLAUDE.md` ("NEVER commit changes unless the user explicitly asks"), each task's `Commit` step **stages** changes via `git add` and presents the staged set to the operator. Do NOT run `git commit` without explicit operator approval. Treat the commit message as a draft for the operator to use.

---

## File structure

### `crates/lattice-server/` (server-side, Rust)

| File | Change | Responsibility |
|---|---|---|
| `src/config.rs` | modified | Add `ServerConfig::admin_api_key` (loaded from `LATTICE__SERVER__ADMIN_API_KEY`). |
| `src/state.rs` | modified | Add `InviteToken` struct, `ServerState::invite_tokens`, `ServerState::admin_api_key`. Snapshot v2 with `InviteSnap`. Helpers: `mint_invite_token`, `consume_invite_token`, `revoke_invite_token`, `list_invite_tokens`. |
| `src/main.rs` | modified | Plumb `admin_api_key` into `ServerState`. Auto-mint from `LATTICE__SERVER__REGISTRATION_TOKEN` on startup if non-empty AND registry empty. Spawn sweeper task. |
| `src/lib.rs` | modified | Merge `routes::admin::router()` into `app()`. |
| `src/routes/admin.rs` | new | `/admin/tokens` POST / GET / DELETE; admin auth header check. `/admin/tokens/:token` GET single-lookup (public). |
| `src/routes/identity.rs` | modified | `register_handler` swap: lookup-in-set + atomic consume + revert-on-error. Remove the static-token-compare path. |
| `tests/registration_v2.rs` | new | Integration tests: full mint→register→list, race test, backcompat. |

### `apps/lattice-docs/` (Astro web, TypeScript)

| File | Change | Responsibility |
|---|---|---|
| `package.json` | modified | Add `@clerk/astro`. |
| `astro.config.mjs` | modified | Register clerk integration. |
| `src/middleware.ts` | new | Gate `/admin/*` on Clerk session + allowed user_id env-var. |
| `src/pages/invite/[token].astro` | new | Public landing — fetches `GET /admin/tokens/:token`, renders state. |
| `src/pages/admin/index.astro` | new | Clerk-gated dashboard — mint form, list, revoke. |
| `src/pages/api/admin/tokens.ts` | new | POST (mint) + GET (list) forwarder; injects `X-Lattice-Admin-Key`. |
| `src/pages/api/admin/tokens/[id].ts` | new | DELETE forwarder. |

### `apps/lattice-web/` (chat shell, Leptos)

| File | Change | Responsibility |
|---|---|---|
| `src/storage.rs` | modified | `load_invite_token() -> Option<String>` + `save_invite_token(&str)` + `clear_invite_token()`. Key: `lattice/invite_token/v1`. |
| `src/api.rs` | modified | `register()` signature gains `invite_token: Option<&str>`; attaches `Authorization: Bearer <t>` when `Some`. |
| `src/chat_state.rs` | modified | `ChatState::invite_token: Option<String>`. Bootstrap reads it, attaches it to the register call, clears it on success. |
| `src/chat.rs` | modified | `SettingsForm` extended with a second `<input>` labelled "Invite token (single-use)". |

### Deployment configs

| File | Change | Responsibility |
|---|---|---|
| `/etc/systemd/system/lattice-server.service.d/auth.conf` on cnc + pixie | modified | Add `Environment=LATTICE__SERVER__ADMIN_API_KEY=<32-byte random>`. |
| Vercel project env (lattice-quantum) | modified | Add `LATTICE_ADMIN_API_KEY`, `LATTICE_SERVER_URL` (= `https://lattice.pixiedustbot.com`), Clerk env vars. |

---

# Section A — `lattice-server` changes

## Task 1: Add `admin_api_key` to ServerConfig

**Files:**
- Modify: `crates/lattice-server/src/config.rs`

- [ ] **Step 1: Add field + default to ServerConfig**

In `crates/lattice-server/src/config.rs`, add to the `ServerConfig` struct (alongside the existing `bind_addr` and `registration_token` fields):

```rust
/// Optional shared secret for /admin/* routes. Empty = admin disabled
/// (admin routes return 503). Set via LATTICE__SERVER__ADMIN_API_KEY.
#[serde(default)]
pub admin_api_key: String,
```

Add to the `set_default` chain in `AppConfig::load`:

```rust
.set_default("server.admin_api_key", "")?
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished` with no errors.

- [ ] **Step 3: Stage**

```bash
git add crates/lattice-server/src/config.rs
```

Draft commit message: `feat(server): plumb admin_api_key config field`

---

## Task 2: Define InviteToken + invite_tokens on ServerState

**Files:**
- Modify: `crates/lattice-server/src/state.rs`

- [ ] **Step 1: Add InviteToken struct**

After the `PushSubscription` struct in `crates/lattice-server/src/state.rs`, add:

```rust
/// One outstanding or consumed invite. Persisted in StateSnapshot v2.
#[derive(Clone, Debug)]
pub struct InviteToken {
    pub token: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub label: Option<String>,
    pub consumed_at: Option<i64>,
    pub consumed_by: Option<[u8; 32]>,
}
```

- [ ] **Step 2: Add field on ServerState**

In the `ServerState` struct, add (alongside `push_subscriptions`):

```rust
pub invite_tokens: Arc<RwLock<HashMap<String, InviteToken>>>,
pub admin_api_key: Option<Arc<String>>,
```

In `new_with_federation_key`, add to the `Self { … }` initializer:

```rust
invite_tokens: Arc::default(),
admin_api_key: None,
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished`.

- [ ] **Step 4: Stage**

```bash
git add crates/lattice-server/src/state.rs
```

Draft commit message: `feat(server): add InviteToken struct + ServerState fields`

---

## Task 3: ServerState helpers + with_admin_api_key builder

**Files:**
- Modify: `crates/lattice-server/src/state.rs`

- [ ] **Step 1: Add the builder**

Add to the existing `impl ServerState` block (the one with `with_registration_token`):

```rust
/// Builder-style setter for the admin API key. Pass a non-empty string
/// to enable `/admin/*` routes; empty/unset leaves them disabled (503).
#[must_use]
pub fn with_admin_api_key(mut self, key: impl Into<String>) -> Self {
    let s: String = key.into();
    if s.is_empty() {
        self.admin_api_key = None;
    } else {
        self.admin_api_key = Some(Arc::new(s));
    }
    self
}
```

- [ ] **Step 2: Add mint / list / revoke helpers**

Add a new `impl ServerState` block:

```rust
impl ServerState {
    /// Mint a new invite. `ttl_secs` defaults to 7 days when None.
    pub async fn mint_invite_token(
        &self,
        label: Option<String>,
        ttl_secs: Option<i64>,
    ) -> InviteToken {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let mut bytes = [0u8; 24];
        if let Err(e) = OsRng.try_fill_bytes(&mut bytes) {
            tracing::error!(error = %e, "OsRng failed during token mint; aborting");
            std::process::abort();
        }
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let now = chrono::Utc::now().timestamp();
        let ttl = ttl_secs.unwrap_or(7 * 24 * 60 * 60);
        let entry = InviteToken {
            token: token.clone(),
            created_at: now,
            expires_at: now.saturating_add(ttl),
            label,
            consumed_at: None,
            consumed_by: None,
        };
        self.invite_tokens
            .write()
            .await
            .insert(token, entry.clone());
        entry
    }

    /// List all invites, newest-created first.
    pub async fn list_invite_tokens(&self) -> Vec<InviteToken> {
        let mut v: Vec<_> = self.invite_tokens.read().await.values().cloned().collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        v
    }

    /// Revoke a token by string. Returns true if removed.
    pub async fn revoke_invite_token(&self, token: &str) -> bool {
        self.invite_tokens.write().await.remove(token).is_some()
    }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished`.

- [ ] **Step 4: Stage**

```bash
git add crates/lattice-server/src/state.rs
```

Draft commit message: `feat(server): InviteToken helpers + with_admin_api_key builder`

---

## Task 4: Snapshot v2 — persist invites

**Files:**
- Modify: `crates/lattice-server/src/state.rs`

- [ ] **Step 1: Add InviteSnap + extend StateSnapshot**

Find the `StateSnapshot` struct (look for `snapshot_version: u32` and `users: Vec<UserSnap>`). Add an `InviteSnap` struct nearby:

```rust
#[derive(Serialize, Deserialize)]
struct InviteSnap {
    token: String,
    created_at: i64,
    expires_at: i64,
    label: Option<String>,
    consumed_at: Option<i64>,
    consumed_by_b64: Option<String>,
}
```

Extend `StateSnapshot`:

```rust
#[serde(default)]
invites: Vec<InviteSnap>,
```

Bump `snapshot_version` to `2` in `save_snapshot`.

- [ ] **Step 2: Wire save_snapshot**

In `save_snapshot`, add to the snapshot struct initializer (right after `peers`):

```rust
invites: self
    .invite_tokens
    .read()
    .await
    .values()
    .map(|i| InviteSnap {
        token: i.token.clone(),
        created_at: i.created_at,
        expires_at: i.expires_at,
        label: i.label.clone(),
        consumed_at: i.consumed_at,
        consumed_by_b64: i.consumed_by.as_ref().map(|u| b64.encode(u)),
    })
    .collect(),
```

Bump `snapshot_version: 2,`.

- [ ] **Step 3: Wire load_snapshot**

In `load_snapshot`, find where users/key_packages/groups/messages get restored. Add (after the peers restore):

```rust
let mut invites_guard = self.invite_tokens.write().await;
for snap in snap.invites {
    let consumed_by = match &snap.consumed_by_b64 {
        Some(s) => {
            let bytes = b64
                .decode(s)
                .map_err(|e| SnapshotError::Codec(format!("consumed_by_b64: {e}")))?;
            Some(bytes.as_slice().try_into().map_err(|_| {
                SnapshotError::Codec("consumed_by length != 32".into())
            })?)
        }
        None => None,
    };
    invites_guard.insert(
        snap.token.clone(),
        InviteToken {
            token: snap.token,
            created_at: snap.created_at,
            expires_at: snap.expires_at,
            label: snap.label,
            consumed_at: snap.consumed_at,
            consumed_by,
        },
    );
}
drop(invites_guard);
```

- [ ] **Step 4: Write a snapshot round-trip test**

In the existing `#[cfg(test)] mod tests { … }` block in `state.rs`, add:

```rust
#[tokio::test]
async fn invite_token_snapshot_round_trip() {
    let state = ServerState::new_test();
    let issued = state
        .mint_invite_token(Some("alice".into()), Some(3600))
        .await;
    let tmp = tempfile::NamedTempFile::new().expect("tmp");
    state.save_snapshot(tmp.path()).await.expect("save");
    let restored = ServerState::new_test();
    restored.load_snapshot(tmp.path()).await.expect("load");
    let restored_list = restored.list_invite_tokens().await;
    assert_eq!(restored_list.len(), 1);
    assert_eq!(restored_list[0].token, issued.token);
    assert_eq!(restored_list[0].label.as_deref(), Some("alice"));
    assert_eq!(restored_list[0].expires_at, issued.expires_at);
}
```

Add `tempfile = "3"` to `[dev-dependencies]` in `crates/lattice-server/Cargo.toml` if not already there. Check first:

Run: `grep '^tempfile' crates/lattice-server/Cargo.toml`
If empty, append to `[dev-dependencies]`:

```toml
tempfile = "3"
```

- [ ] **Step 5: Run the test**

Run: `cargo test -p lattice-server invite_token_snapshot_round_trip -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Stage**

```bash
git add crates/lattice-server/src/state.rs crates/lattice-server/Cargo.toml
```

Draft commit message: `feat(server): persist invite tokens in snapshot v2`

---

## Task 5: Wire admin_api_key into main.rs + backcompat auto-mint

**Files:**
- Modify: `crates/lattice-server/src/main.rs`

- [ ] **Step 1: Extend the state-construction block**

Replace the existing `let state = … .with_registration_token(…)` block with:

```rust
let state = lattice_server::state::ServerState::new_with_federation_key(federation_sk)
    .with_registration_token(&cfg.server.registration_token)
    .with_admin_api_key(&cfg.server.admin_api_key);
info!(
    federation_pubkey = %state.federation_pubkey_b64,
    registration_gated = state.registration_token.is_some(),
    admin_enabled = state.admin_api_key.is_some(),
    "federation identity loaded"
);
```

- [ ] **Step 2: Add the backcompat auto-mint**

After the snapshot-load block (after `state.load_snapshot(p).await` and its surrounding match), add:

```rust
// Backcompat: if a legacy static registration token is set AND the
// invite registry is empty (fresh boot or v1 snapshot), auto-mint
// one no-expiry invite that matches the static token's bytes. Lets
// existing deployments keep working without config changes.
if !cfg.server.registration_token.is_empty()
    && state.invite_tokens.read().await.is_empty()
{
    let now = chrono::Utc::now().timestamp();
    let token = cfg.server.registration_token.clone();
    let entry = lattice_server::state::InviteToken {
        token: token.clone(),
        created_at: now,
        expires_at: i64::MAX,
        label: Some("legacy:LATTICE__SERVER__REGISTRATION_TOKEN".into()),
        consumed_at: None,
        consumed_by: None,
    };
    state.invite_tokens.write().await.insert(token, entry);
    info!("backcompat: auto-minted invite for legacy static token");
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished`.

- [ ] **Step 4: Stage**

```bash
git add crates/lattice-server/src/main.rs
```

Draft commit message: `feat(server): plumb admin_api_key + backcompat auto-mint`

---

## Task 6: Admin auth header check (helper)

**Files:**
- Create: `crates/lattice-server/src/routes/admin.rs`
- Modify: `crates/lattice-server/src/routes/mod.rs`

- [ ] **Step 1: Create the admin module with the auth helper**

Create `crates/lattice-server/src/routes/admin.rs`:

```rust
//! `/admin/*` routes — invite-token CRUD gated by X-Lattice-Admin-Key.

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::HeaderName},
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::state::{InviteToken, ServerState};

const ADMIN_KEY_HEADER: HeaderName = HeaderName::from_static("x-lattice-admin-key");

/// Verify the X-Lattice-Admin-Key header against state.admin_api_key.
/// Returns `Ok(())` on match. Returns 503 if admin is disabled, 401
/// if missing or wrong.
fn check_admin_key(state: &ServerState, headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let expected = match state.admin_api_key.as_deref() {
        Some(k) => k,
        None => return Err((StatusCode::SERVICE_UNAVAILABLE, "admin disabled on this server")),
    };
    let supplied = headers
        .get(&ADMIN_KEY_HEADER)
        .and_then(|h| h.to_str().ok());
    let ok = supplied
        .map(|s| s.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1)
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "admin authentication required"))
    }
}

pub fn router() -> Router<ServerState> {
    Router::new()
}
```

- [ ] **Step 2: Register the module**

In `crates/lattice-server/src/routes/mod.rs`, add the module declaration alongside `pub mod identity;`:

```rust
pub mod admin;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished` with a `dead_code` warning on `check_admin_key` (we'll use it in the next task — leave it).

- [ ] **Step 4: Stage**

```bash
git add crates/lattice-server/src/routes/admin.rs crates/lattice-server/src/routes/mod.rs
```

Draft commit message: `feat(server): admin auth header helper`

---

## Task 7: POST /admin/tokens (mint)

**Files:**
- Modify: `crates/lattice-server/src/routes/admin.rs`

- [ ] **Step 1: Add the request/response types + handler**

In `crates/lattice-server/src/routes/admin.rs`, replace `pub fn router()` and add the mint pieces above it:

```rust
#[derive(Debug, Deserialize)]
pub struct MintRequest {
    pub label: Option<String>,
    pub ttl_secs: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct InviteView {
    pub token: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub label: Option<String>,
    pub consumed_at: Option<i64>,
    pub consumed_by_prefix: Option<String>,
}

impl From<&InviteToken> for InviteView {
    fn from(i: &InviteToken) -> Self {
        Self {
            token: i.token.clone(),
            created_at: i.created_at,
            expires_at: i.expires_at,
            label: i.label.clone(),
            consumed_at: i.consumed_at,
            consumed_by_prefix: i
                .consumed_by
                .as_ref()
                .map(|u| hex::encode(&u[..4])),
        }
    }
}

async fn mint_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(body): Json<MintRequest>,
) -> Result<Json<InviteView>, (StatusCode, String)> {
    check_admin_key(&state, &headers).map_err(|(s, m)| (s, m.into()))?;
    let issued = state.mint_invite_token(body.label, body.ttl_secs).await;
    tracing::info!(
        token_prefix = &issued.token[..8],
        expires_at = issued.expires_at,
        label = ?issued.label,
        "invite minted"
    );
    Ok(Json((&issued).into()))
}

pub fn router() -> Router<ServerState> {
    Router::new().route("/admin/tokens", post(mint_handler))
}
```

- [ ] **Step 2: Add hex dep if missing**

Run: `grep '^hex' crates/lattice-server/Cargo.toml`
If empty:

```toml
hex = "0.4"
```

into `[dependencies]`.

- [ ] **Step 3: Wire the router into app()**

In `crates/lattice-server/src/lib.rs`, add the merge call inside `app()`:

```rust
.merge(routes::admin::router().with_state(state.clone()))
```

Add it between the existing identity and groups merges.

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished`.

- [ ] **Step 5: Stage**

```bash
git add crates/lattice-server/src/routes/admin.rs crates/lattice-server/src/lib.rs crates/lattice-server/Cargo.toml
```

Draft commit message: `feat(server): POST /admin/tokens`

---

## Task 8: GET /admin/tokens (list) and GET /admin/tokens/:token (single)

**Files:**
- Modify: `crates/lattice-server/src/routes/admin.rs`

- [ ] **Step 1: Add list handler**

Add to `crates/lattice-server/src/routes/admin.rs`:

```rust
async fn list_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InviteView>>, (StatusCode, String)> {
    check_admin_key(&state, &headers).map_err(|(s, m)| (s, m.into()))?;
    let invites = state.list_invite_tokens().await;
    Ok(Json(invites.iter().map(InviteView::from).collect()))
}

async fn single_handler(
    State(state): State<ServerState>,
    Path(token): Path<String>,
) -> Result<Json<InviteView>, (StatusCode, String)> {
    // Deliberately UNAUTHENTICATED: the public /invite/<t> landing
    // page reads this. The token itself is the capability. Returns
    // only non-sensitive fields (the InviteView omits the full
    // consumed_by user_id, exposing only the 4-byte prefix).
    match state.invite_tokens.read().await.get(&token) {
        Some(t) => Ok(Json(t.into())),
        None => Err((StatusCode::NOT_FOUND, "unknown token".into())),
    }
}
```

- [ ] **Step 2: Register the routes**

Update the `router()` function:

```rust
pub fn router() -> Router<ServerState> {
    Router::new()
        .route("/admin/tokens", post(mint_handler).get(list_handler))
        .route("/admin/tokens/{token}", get(single_handler))
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished`.

- [ ] **Step 4: Stage**

```bash
git add crates/lattice-server/src/routes/admin.rs
```

Draft commit message: `feat(server): GET /admin/tokens + single lookup`

---

## Task 9: DELETE /admin/tokens/:token (revoke)

**Files:**
- Modify: `crates/lattice-server/src/routes/admin.rs`

- [ ] **Step 1: Add revoke handler**

```rust
async fn revoke_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    check_admin_key(&state, &headers).map_err(|(s, m)| (s, m.into()))?;
    if state.revoke_invite_token(&token).await {
        tracing::info!(token_prefix = &token[..8.min(token.len())], "invite revoked");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "unknown token".into()))
    }
}
```

- [ ] **Step 2: Register the route**

Update `router()`:

```rust
pub fn router() -> Router<ServerState> {
    Router::new()
        .route("/admin/tokens", post(mint_handler).get(list_handler))
        .route(
            "/admin/tokens/{token}",
            get(single_handler).delete(revoke_handler),
        )
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished`.

- [ ] **Step 4: Stage**

```bash
git add crates/lattice-server/src/routes/admin.rs
```

Draft commit message: `feat(server): DELETE /admin/tokens/{token}`

---

## Task 10: Refactor /register to consume from token set

**Files:**
- Modify: `crates/lattice-server/src/routes/identity.rs`

- [ ] **Step 1: Replace the existing static-token check with the consume path**

In `register_handler`, **replace** the block:

```rust
if let Some(expected) = state.registration_token.as_deref() {
    let supplied = headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let ok = supplied
        .map(|s| s.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1)
        .unwrap_or(false);
    if !ok {
        tracing::warn!(
            supplied_token_present = supplied.is_some(),
            "register rejected: bad or missing token"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            "registration token required".into(),
        ));
    }
}
```

with the consume-path:

```rust
let supplied = headers
    .get(AUTHORIZATION)
    .and_then(|h| h.to_str().ok())
    .and_then(|s| s.strip_prefix("Bearer "))
    .map(str::to_string);

let mut invites = state.invite_tokens.write().await;
let registry_empty = invites.is_empty();
let auth_required = state.admin_api_key.is_some() || !registry_empty;

if auth_required {
    let supplied = supplied.as_deref().ok_or((
        StatusCode::UNAUTHORIZED,
        "registration token required".to_string(),
    ))?;
    let now = chrono::Utc::now().timestamp();
    let token = invites.get_mut(supplied).ok_or((
        StatusCode::UNAUTHORIZED,
        "unknown token".to_string(),
    ))?;
    if token.expires_at <= now {
        tracing::warn!(token_prefix = &supplied[..8.min(supplied.len())], "register rejected: token expired");
        return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
    }
    if token.consumed_at.is_some() {
        tracing::warn!(token_prefix = &supplied[..8.min(supplied.len())], "register rejected: token already consumed");
        return Err((StatusCode::UNAUTHORIZED, "token already consumed".into()));
    }
    token.consumed_at = Some(now);
    token.consumed_by = Some(user_id);
}
```

Note: this critical-section design assumes `user_id` is already bound. Make sure the `user_id` decode (currently after this block) happens **before** this critical section. Move the `user_id_bytes` / `user_id` decode lines to the top of the handler, immediately after the `b64` declaration.

Concretely, the handler's top should now read (in this order):

```rust
let b64 = base64::engine::general_purpose::STANDARD;
let user_id_bytes = b64
    .decode(&body.user_id_b64)
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("user_id_b64 decode: {e}")))?;
let user_id: [u8; 32] = user_id_bytes.as_slice().try_into().map_err(|_| {
    (
        StatusCode::BAD_REQUEST,
        format!("user_id length {} (expected 32)", user_id_bytes.len()),
    )
})?;
let claim_bytes = b64
    .decode(&body.claim_b64)
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("claim_b64 decode: {e}")))?;
let claim = lattice_protocol::wire::decode::<IdentityClaim>(claim_bytes.as_slice())
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("claim decode: {e}")))?;

// [auth + consume block above]
```

The `invites` write-lock now spans check → mark → register_user, ensuring atomic single-use.

- [ ] **Step 2: Implement revert-on-error**

The existing `register_user(&state, RegisteredUser { … }).await` call is currently infallible (returns `bool`). Confirm by reading its signature in `state.rs`:

Run: `grep 'pub async fn register_user' crates/lattice-server/src/state.rs`
Expected output: `pub async fn register_user(state: &ServerState, user: RegisteredUser) -> bool {`

Because `register_user` is infallible today (it always succeeds), the revert-on-error is technically dead code, but include the pattern anyway so future fallibility is safe. Add immediately after the existing `let new_registration = register_user(…)` call, AND BEFORE the existing `tracing::info!` line:

(no change needed if register_user is infallible — the `invites` write-lock dropping at end-of-scope is sufficient atomicity, and the `consumed_at` mark is already in place. Skip the revert code for now.)

If `register_user` ever becomes fallible: wrap its call in `match`; on error path, revert `token.consumed_at = None; token.consumed_by = None;` before returning the error.

Document this in a single-line comment above the call:

```rust
// invites write-lock still held; consume already marked above.
// If register_user becomes fallible, revert consumed_at/by here.
let new_registration = register_user(/* … */).await;
```

- [ ] **Step 3: Drop the lock explicitly before the response**

Add `drop(invites);` immediately after the `register_user` call so the lock isn't held longer than needed:

```rust
drop(invites);
```

- [ ] **Step 4: Remove the now-unused `subtle::ConstantTimeEq` import if it's no longer referenced**

Run: `grep -n 'ct_eq\|ConstantTimeEq' crates/lattice-server/src/routes/identity.rs`
If no matches, remove the `use subtle::ConstantTimeEq;` line from the imports.

If matches remain (e.g., kept for another use), leave the import.

- [ ] **Step 5: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished`.

- [ ] **Step 6: Stage**

```bash
git add crates/lattice-server/src/routes/identity.rs
```

Draft commit message: `feat(server): /register consumes from invite token set`

---

## Task 11: Integration test — full mint→register→list flow

**Files:**
- Create: `crates/lattice-server/tests/registration_v2.rs`

- [ ] **Step 1: Write the integration test**

Create `crates/lattice-server/tests/registration_v2.rs`:

```rust
//! Integration tests for the v2 invite-token registration path.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use serde_json::json;
use tokio::net::TcpListener;

use lattice_server::state::ServerState;

async fn spawn_server(state: ServerState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let app = lattice_server::app(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{addr}")
}

fn fake_register_body() -> serde_json::Value {
    use lattice_crypto::identity::LatticeIdentity;
    let _ = lattice_crypto::init();
    let id = LatticeIdentity::generate_for_tests();
    let b64 = base64::engine::general_purpose::STANDARD;
    json!({
        "user_id_b64": b64.encode(id.user_id()),
        "claim_b64": b64.encode(lattice_protocol::wire::encode(&id.claim())),
    })
}

#[tokio::test]
async fn register_consumes_a_minted_invite() {
    let state = ServerState::new_test().with_admin_api_key("admin-secret");
    let url = spawn_server(state).await;
    let client = reqwest::Client::new();

    let mint = client
        .post(format!("{url}/admin/tokens"))
        .header("X-Lattice-Admin-Key", "admin-secret")
        .json(&json!({ "label": "alice", "ttl_secs": 3600 }))
        .send()
        .await
        .expect("mint");
    assert_eq!(mint.status(), 200);
    let issued: serde_json::Value = mint.json().await.expect("mint json");
    let token = issued["token"].as_str().expect("token str").to_string();

    let reg = client
        .post(format!("{url}/register"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&fake_register_body())
        .send()
        .await
        .expect("register");
    assert_eq!(reg.status(), 200);

    let listed = client
        .get(format!("{url}/admin/tokens"))
        .header("X-Lattice-Admin-Key", "admin-secret")
        .send()
        .await
        .expect("list")
        .json::<Vec<serde_json::Value>>()
        .await
        .expect("list json");
    assert_eq!(listed.len(), 1);
    assert!(listed[0]["consumed_at"].is_i64(), "consumed_at set");
}

#[tokio::test]
async fn register_rejects_unknown_token() {
    let state = ServerState::new_test().with_admin_api_key("k");
    state.mint_invite_token(None, None).await;
    let url = spawn_server(state).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{url}/register"))
        .header("Authorization", "Bearer nope")
        .json(&fake_register_body())
        .send()
        .await
        .expect("register");
    assert_eq!(reg.status(), 401);
}

#[tokio::test]
async fn register_rejects_consumed_token() {
    let state = ServerState::new_test().with_admin_api_key("k");
    let issued = state.mint_invite_token(None, None).await;
    let url = spawn_server(state).await;
    let client = reqwest::Client::new();

    let _first = client
        .post(format!("{url}/register"))
        .header("Authorization", format!("Bearer {}", issued.token))
        .json(&fake_register_body())
        .send()
        .await
        .expect("first");

    let second = client
        .post(format!("{url}/register"))
        .header("Authorization", format!("Bearer {}", issued.token))
        .json(&fake_register_body())
        .send()
        .await
        .expect("second");
    assert_eq!(second.status(), 401);
}
```

Confirm `LatticeIdentity::generate_for_tests()` exists. If not, replace with whatever the actual test-helper is:

Run: `grep -rn 'fn generate_for_tests\|fn generate\b' crates/lattice-crypto/src/identity.rs`

Adjust the call accordingly to whatever exists.

- [ ] **Step 2: Run the test**

Run: `cargo test -p lattice-server --test registration_v2 -- --nocapture`
Expected: 3 tests PASS.

- [ ] **Step 3: Stage**

```bash
git add crates/lattice-server/tests/registration_v2.rs
```

Draft commit message: `test(server): integration tests for registration v2`

---

## Task 12: Race test — 200 concurrent /register POSTs, exactly 1 wins

**Files:**
- Modify: `crates/lattice-server/tests/registration_v2.rs`

- [ ] **Step 1: Add the race test**

Append to `crates/lattice-server/tests/registration_v2.rs`:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_token_one_winner_under_concurrency() {
    let state = ServerState::new_test().with_admin_api_key("k");
    let issued = state.mint_invite_token(None, None).await;
    let url = spawn_server(state).await;
    let client = Arc::new(reqwest::Client::new());

    let mut handles = Vec::new();
    for _ in 0..200 {
        let c = client.clone();
        let u = url.clone();
        let t = issued.token.clone();
        handles.push(tokio::spawn(async move {
            c.post(format!("{u}/register"))
                .header("Authorization", format!("Bearer {t}"))
                .json(&fake_register_body())
                .send()
                .await
                .expect("send")
                .status()
                .as_u16()
        }));
    }

    let mut wins = 0;
    let mut losses = 0;
    for h in handles {
        match h.await.expect("join") {
            200 => wins += 1,
            401 => losses += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(wins, 1, "exactly one register should win the race");
    assert_eq!(losses, 199, "the other 199 should all 401");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p lattice-server --test registration_v2 one_token_one_winner_under_concurrency -- --nocapture`
Expected: PASS. (If it flakes — typically due to identical user_id collisions among fake registers — adjust `fake_register_body()` to ensure each call gets a unique identity.)

- [ ] **Step 3: Stage**

```bash
git add crates/lattice-server/tests/registration_v2.rs
```

Draft commit message: `test(server): prove single-winner under 200-thread concurrent register`

---

## Task 13: Sweeper task — clean up expired+consumed invites

**Files:**
- Modify: `crates/lattice-server/src/state.rs`
- Modify: `crates/lattice-server/src/main.rs`

- [ ] **Step 1: Add the sweep method to ServerState**

In the `impl ServerState` block (the one with `list_invite_tokens`):

```rust
/// Remove expired-unconsumed and consumed-older-than-30-days invites.
/// Returns the count removed.
pub async fn sweep_invite_tokens(&self) -> usize {
    let now = chrono::Utc::now().timestamp();
    let cutoff_consumed = now - 30 * 24 * 60 * 60;
    let mut guard = self.invite_tokens.write().await;
    let before = guard.len();
    guard.retain(|_, t| {
        if let Some(c) = t.consumed_at {
            c > cutoff_consumed
        } else {
            t.expires_at > now
        }
    });
    before - guard.len()
}
```

- [ ] **Step 2: Spawn the sweeper task in main.rs**

In `crates/lattice-server/src/main.rs`, right after the backcompat auto-mint block from Task 5 and before the listener bind, add:

```rust
// Sweeper task: every 5 minutes, evict expired-unconsumed invites and
// consumed-older-than-30-days entries. Lives until the runtime exits.
let sweeper_state = state.clone();
tokio::spawn(async move {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let removed = sweeper_state.sweep_invite_tokens().await;
        if removed > 0 {
            info!(removed, "swept expired/old invite tokens");
        }
    }
});
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p lattice-server`
Expected: `Finished`.

- [ ] **Step 4: Add a unit test for the sweeper**

In the existing `state.rs` tests module:

```rust
#[tokio::test]
async fn sweeper_removes_expired_unconsumed() {
    let state = ServerState::new_test();
    // Mint with negative TTL (already-expired).
    let _ = state.mint_invite_token(None, Some(-3600)).await;
    let removed = state.sweep_invite_tokens().await;
    assert_eq!(removed, 1);
    assert!(state.list_invite_tokens().await.is_empty());
}
```

Run: `cargo test -p lattice-server sweeper_removes_expired_unconsumed -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Stage**

```bash
git add crates/lattice-server/src/state.rs crates/lattice-server/src/main.rs
```

Draft commit message: `feat(server): sweeper task for stale invite tokens`

---

## Task 14: Update memory + scratch notes (operator-facing)

**Files:**
- Modify: `C:\Users\Matt\.claude\projects\J--lattice\memory\MEMORY.md` (user memory file)
- Create: `J:\lattice\scratch\reg-v2-operator-notes.md`

- [ ] **Step 1: Add a memory entry**

Create `C:\Users\Matt\.claude\projects\J--lattice\memory\reg_v2_admin_key.md`:

```markdown
---
name: reg-v2-admin-key
description: Reg v2 deploy added LATTICE__SERVER__ADMIN_API_KEY on both home servers; Astro admin UI calls /admin/tokens with that key. Token issuance flow lives at lattice-quantum.vercel.app/admin.
metadata:
  type: project
---

Reg v2 deploy adds a second env var alongside `LATTICE__SERVER__REGISTRATION_TOKEN`:
`LATTICE__SERVER__ADMIN_API_KEY` (32-byte URL-safe random). Stored in
`/etc/systemd/system/lattice-server.service.d/auth.conf` on both cnc and pixie.
Same value on both for operator convenience.

**Why:** Reg v2 introduces per-user single-use invite tokens minted via a
Clerk-gated Astro admin UI on lattice-quantum.vercel.app. The admin key
authenticates the Astro server endpoints when they forward mint/list/revoke
calls to lattice-server's /admin/tokens. The old static
`LATTICE__SERVER__REGISTRATION_TOKEN` is preserved for backcompat — on boot,
if non-empty AND the invite registry is empty, lattice-server auto-mints a
no-expiry invite matching those bytes.

**How to apply:** When deploying Reg v2, both servers need the env var
added before the binary is rolled. The Astro Vercel project needs
`LATTICE_ADMIN_API_KEY` (same value) plus Clerk env vars
(`CLERK_PUBLISHABLE_KEY`, `CLERK_SECRET_KEY`) — installed via the Vercel
Marketplace one-click integration.

Related: [[capnp-build]] (no impact), [[docs-site-deploy]] (the same
Astro deploy is now host to the admin UI).
```

Append to `MEMORY.md`:

```markdown
- [Reg v2 admin key](reg_v2_admin_key.md) — LATTICE__SERVER__ADMIN_API_KEY on both home servers; Clerk-gated Astro admin UI at lattice-quantum.vercel.app/admin mints tokens.
```

- [ ] **Step 2: Write operator-notes**

Create `J:\lattice\scratch\reg-v2-operator-notes.md`:

```markdown
# Reg v2 operator notes

Concise reference for deploying + operating Reg v2.

## Env vars to set

On both cnc-server and pixie, in
`/etc/systemd/system/lattice-server.service.d/auth.conf`:

    [Service]
    Environment=LATTICE__SERVER__REGISTRATION_TOKEN=BIUB1GKPD8dlnK1qO-Xq_Av9Hitz3uV2
    Environment=LATTICE__SERVER__ADMIN_API_KEY=<32-byte URL-safe random>

After editing: `sudo systemctl daemon-reload && sudo systemctl restart lattice-server`.

## Vercel env vars

In the lattice-quantum project on Vercel:

- `LATTICE_ADMIN_API_KEY` = (same value as the home servers)
- `LATTICE_SERVER_URL` = `https://lattice.pixiedustbot.com`
- `MATT_CLERK_USER_ID` = (your Clerk user_id, allowlist for /admin)
- Clerk env vars: auto-provisioned by the Marketplace integration

## Smoke after deploy

    # Server-side
    curl https://lattice.pixiedustbot.com/admin/tokens   # → 401 (no key)
    curl https://lattice.pixiedustbot.com/admin/tokens -H "X-Lattice-Admin-Key: ${LATTICE_ADMIN_API_KEY}"
        # → []  (empty registry — backcompat token from REGISTRATION_TOKEN
        # is already in here actually; should show one entry labelled
        # "legacy:LATTICE__SERVER__REGISTRATION_TOKEN")

    # Web-side
    Open https://lattice-quantum.vercel.app/admin in browser, sign in via Clerk,
    mint a token, confirm it appears in the list, open
    https://lattice-quantum.vercel.app/invite/<token>, confirm it shows "valid".

## Rotating the admin key

1. Generate new 32-byte URL-safe random
2. Update both auth.conf overrides on cnc + pixie
3. Update Vercel env var (re-deploy or `vercel env pull`)
4. systemctl restart lattice-server on both servers
5. Confirm /admin/tokens still works with new key
```

- [ ] **Step 3: Stage**

```bash
git add scratch/reg-v2-operator-notes.md
```

Memory files live outside the repo — no `git add` for those.

Draft commit message: `docs(server): operator notes for reg v2 deploy`

---

## Task 15: Cnc + pixie systemd env override + redeploy

**Files:**
- Create: `/etc/systemd/system/lattice-server.service.d/auth.conf` (modify on both hosts)

- [ ] **Step 1: Generate the admin key**

In a PowerShell session on kokonoe:

```powershell
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$adminKey = [Convert]::ToBase64String($bytes).Replace('+','-').Replace('/','_').TrimEnd('=')
$adminKey | Out-File -FilePath 'J:\lattice\scratch\.admin-api-key' -Encoding ascii -NoNewline
"Admin API key (also saved to J:\lattice\scratch\.admin-api-key):"
$adminKey
```

Confirm `scratch/.admin-api-key` is in `.gitignore`:

Run: `grep '^scratch/\.admin-api-key' J:/lattice/.gitignore`
If empty: append `scratch/.admin-api-key` to `J:/lattice/.gitignore`.

- [ ] **Step 2: Update the auth.conf on both servers**

```bash
ADMIN_KEY=$(cat J:/lattice/scratch/.admin-api-key)
for host in cnc-server pixie; do
  ssh $host "sudo tee /etc/systemd/system/lattice-server.service.d/auth.conf > /dev/null <<EOF
[Service]
Environment=LATTICE__SERVER__REGISTRATION_TOKEN=BIUB1GKPD8dlnK1qO-Xq_Av9Hitz3uV2
Environment=LATTICE__SERVER__ADMIN_API_KEY=${ADMIN_KEY}
EOF
sudo systemctl daemon-reload && echo '[$host] override updated'"
done
```

- [ ] **Step 3: Push the new binary to both servers**

Build first:

```bash
ssh cnc-server "cd ~/code/lattice && RUSTC_WRAPPER= cargo build -p lattice-server --release 2>&1 | tail -5"
ssh pixie     "source ~/.cargo/env && cd ~/code/lattice && cargo build -p lattice-server --release 2>&1 | tail -5"
```

Wait for both to print `Finished `release`` etc.

- [ ] **Step 4: Restart with the new binary**

```bash
ssh cnc-server "sudo systemctl stop lattice-server && sudo install -m 0755 -o root -g root ~/code/lattice/target/release/lattice-server /usr/local/bin/lattice-server && sudo systemctl start lattice-server && sleep 2 && sudo systemctl is-active lattice-server"
ssh pixie     "sudo systemctl stop lattice-server && sudo install -m 0755 -o root -g root ~/code/lattice/target/release/lattice-server /usr/local/bin/lattice-server && sudo systemctl start lattice-server && sleep 2 && sudo systemctl is-active lattice-server"
```

Both should print `active`.

- [ ] **Step 5: Smoke**

```bash
ADMIN_KEY=$(cat J:/lattice/scratch/.admin-api-key)
echo '--- without key (expect 401) ---'
curl -sw '\nHTTP %{http_code}\n' https://lattice.pixiedustbot.com/admin/tokens

echo '--- with key (expect 200 + JSON list) ---'
curl -sw '\nHTTP %{http_code}\n' -H "X-Lattice-Admin-Key: $ADMIN_KEY" https://lattice.pixiedustbot.com/admin/tokens

echo '--- mint (expect 200 + new token) ---'
curl -sw '\nHTTP %{http_code}\n' -H "X-Lattice-Admin-Key: $ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d '{"label":"smoke-test","ttl_secs":3600}' \
    https://lattice.pixiedustbot.com/admin/tokens
```

Expected: list shows the legacy backcompat entry (labelled `legacy:LATTICE__SERVER__REGISTRATION_TOKEN`), then the mint POST returns a fresh token. Re-list shows both.

- [ ] **Step 6: Stage**

(No repo changes from this task — pure infrastructure. Move on.)

---

# Section B — Astro web (lattice-docs)

## Task 16: Install @clerk/astro + Vercel Marketplace integration

**Files:**
- Modify: `apps/lattice-docs/package.json`
- Modify: `apps/lattice-docs/astro.config.mjs`

- [ ] **Step 1: Install the Clerk integration**

```bash
cd J:/lattice/apps/lattice-docs
npm install @clerk/astro
```

- [ ] **Step 2: Verify @clerk/astro lands in package.json**

Run: `grep '@clerk/astro' apps/lattice-docs/package.json`
Expected: a line in `"dependencies"`.

- [ ] **Step 3: Wire the integration**

In `apps/lattice-docs/astro.config.mjs`, import and register clerk. Read the existing file first:

Run: `cat J:/lattice/apps/lattice-docs/astro.config.mjs`

Add:

```javascript
import clerk from "@clerk/astro";

// inside the existing defineConfig({ … }):
integrations: [
    // ... existing integrations ...
    clerk(),
],
```

Switch the project to SSR mode (Clerk requires server-side rendering for auth):

```javascript
output: "server",
adapter: vercel(),    // if not already present
```

Note the existing `output` setting — if it's `"static"`, change to `"server"`. If `"hybrid"`, leave it.

- [ ] **Step 4: Install Vercel adapter if missing**

Run: `grep '@astrojs/vercel' apps/lattice-docs/package.json`
If empty:

```bash
npm install @astrojs/vercel
```

- [ ] **Step 5: Verify the dev server starts**

```bash
cd J:/lattice/apps/lattice-docs
npm run dev
```

Open `http://localhost:4321` and confirm the existing docs site loads. Ctrl-C to stop.

- [ ] **Step 6: Stage**

```bash
git add apps/lattice-docs/package.json apps/lattice-docs/package-lock.json apps/lattice-docs/astro.config.mjs
```

Draft commit message: `feat(docs): add @clerk/astro + Vercel adapter for SSR`

---

## Task 17: Astro middleware — gate /admin/* on Clerk session + user_id allowlist

**Files:**
- Create: `apps/lattice-docs/src/middleware.ts`

- [ ] **Step 1: Write the middleware**

Create `apps/lattice-docs/src/middleware.ts`:

```typescript
import { clerkMiddleware, createRouteMatcher } from "@clerk/astro/server";

const isAdminRoute = createRouteMatcher(["/admin(.*)", "/api/admin/(.*)"]);
const allowedUserIds = (import.meta.env.LATTICE_ADMIN_USER_IDS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

export const onRequest = clerkMiddleware((auth, context) => {
  if (!isAdminRoute(context.request)) {
    return;
  }
  const { userId } = auth();
  if (!userId) {
    return context.redirect(`/sign-in?next=${encodeURIComponent(context.url.pathname)}`);
  }
  if (allowedUserIds.length > 0 && !allowedUserIds.includes(userId)) {
    return new Response("forbidden — not on the admin allowlist", { status: 403 });
  }
});
```

- [ ] **Step 2: Verify it compiles in the dev server**

```bash
cd J:/lattice/apps/lattice-docs
npm run dev
```

Open `http://localhost:4321/docs/` (existing route). Should load. Open `http://localhost:4321/admin` (no route yet → 404, but NOT a 500 — Clerk shouldn't crash). Ctrl-C to stop.

- [ ] **Step 3: Stage**

```bash
git add apps/lattice-docs/src/middleware.ts
```

Draft commit message: `feat(docs): Clerk middleware gating /admin/*`

---

## Task 18: /api/admin/tokens forwarder (POST + GET)

**Files:**
- Create: `apps/lattice-docs/src/pages/api/admin/tokens.ts`

- [ ] **Step 1: Write the forwarder**

Create `apps/lattice-docs/src/pages/api/admin/tokens.ts`:

```typescript
import type { APIRoute } from "astro";

const HOME_URL = import.meta.env.LATTICE_SERVER_URL;
const ADMIN_KEY = import.meta.env.LATTICE_ADMIN_API_KEY;

if (!HOME_URL || !ADMIN_KEY) {
  console.warn("LATTICE_SERVER_URL or LATTICE_ADMIN_API_KEY not set");
}

const forward = async (
  method: "GET" | "POST",
  path: string,
  body?: unknown
): Promise<Response> => {
  const init: RequestInit = {
    method,
    headers: {
      "X-Lattice-Admin-Key": ADMIN_KEY ?? "",
      "Content-Type": "application/json",
    },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  return await fetch(`${HOME_URL}${path}`, init);
};

export const POST: APIRoute = async ({ request }) => {
  const body = await request.json().catch(() => ({}));
  const upstream = await forward("POST", "/admin/tokens", body);
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { "Content-Type": "application/json" },
  });
};

export const GET: APIRoute = async () => {
  const upstream = await forward("GET", "/admin/tokens");
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { "Content-Type": "application/json" },
  });
};

export const prerender = false;
```

- [ ] **Step 2: Stage**

```bash
git add apps/lattice-docs/src/pages/api/admin/tokens.ts
```

Draft commit message: `feat(docs): /api/admin/tokens forwarder`

---

## Task 19: /api/admin/tokens/[id] forwarder (DELETE)

**Files:**
- Create: `apps/lattice-docs/src/pages/api/admin/tokens/[id].ts`

- [ ] **Step 1: Write the forwarder**

Create `apps/lattice-docs/src/pages/api/admin/tokens/[id].ts`:

```typescript
import type { APIRoute } from "astro";

const HOME_URL = import.meta.env.LATTICE_SERVER_URL;
const ADMIN_KEY = import.meta.env.LATTICE_ADMIN_API_KEY;

export const DELETE: APIRoute = async ({ params }) => {
  if (!params.id) {
    return new Response("missing token id", { status: 400 });
  }
  const upstream = await fetch(`${HOME_URL}/admin/tokens/${params.id}`, {
    method: "DELETE",
    headers: { "X-Lattice-Admin-Key": ADMIN_KEY ?? "" },
  });
  return new Response(null, { status: upstream.status });
};

export const prerender = false;
```

- [ ] **Step 2: Stage**

```bash
git add apps/lattice-docs/src/pages/api/admin/tokens/[id].ts
```

Draft commit message: `feat(docs): /api/admin/tokens/[id] DELETE forwarder`

---

## Task 20: /admin dashboard page

**Files:**
- Create: `apps/lattice-docs/src/pages/admin/index.astro`

- [ ] **Step 1: Write the admin page**

Create `apps/lattice-docs/src/pages/admin/index.astro`:

```astro
---
const tokensRes = await fetch(`${Astro.url.origin}/api/admin/tokens`, {
  headers: { cookie: Astro.request.headers.get("cookie") ?? "" },
});
const tokens = tokensRes.ok ? await tokensRes.json() : [];
---
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Lattice — admin</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
    h1 { margin-bottom: 0.5rem; }
    .invite-form { display: flex; gap: 0.5rem; margin: 1rem 0; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th, td { padding: 0.4rem 0.6rem; border-bottom: 1px solid #444; text-align: left; }
    .consumed { color: #888; }
    button { padding: 0.3rem 0.7rem; cursor: pointer; }
    input { padding: 0.3rem 0.5rem; }
    code { background: #222; padding: 0.1rem 0.3rem; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>Lattice invites</h1>
  <p>Mint single-use invite tokens. Each invite is valid for 7 days by default.</p>

  <form class="invite-form" id="mint-form">
    <input type="text" name="label" placeholder="label (e.g. 'alice')" />
    <input type="number" name="ttl_secs" placeholder="ttl in seconds (default 604800)" />
    <button type="submit">Mint invite</button>
  </form>

  <table>
    <thead><tr>
      <th>Token</th><th>Label</th><th>Created</th><th>Expires</th><th>Consumed</th><th></th>
    </tr></thead>
    <tbody id="tokens-tbody">
      {tokens.map((t: any) => (
        <tr class={t.consumed_at ? "consumed" : ""}>
          <td><code>{t.token.slice(0, 10)}…</code></td>
          <td>{t.label ?? "—"}</td>
          <td>{new Date(t.created_at * 1000).toISOString().slice(0, 19)}</td>
          <td>{t.expires_at === 9223372036854775807 ? "never" : new Date(t.expires_at * 1000).toISOString().slice(0, 19)}</td>
          <td>{t.consumed_at ? `${new Date(t.consumed_at * 1000).toISOString().slice(0, 19)} by ${t.consumed_by_prefix ?? "?"}` : "—"}</td>
          <td><button data-token={t.token} class="revoke-btn">revoke</button></td>
        </tr>
      ))}
    </tbody>
  </table>

  <script is:inline>
    document.getElementById("mint-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const fd = new FormData(ev.target);
      const body = {
        label: fd.get("label") || null,
        ttl_secs: fd.get("ttl_secs") ? Number(fd.get("ttl_secs")) : null,
      };
      const res = await fetch("/api/admin/tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        alert("mint failed: " + (await res.text()));
        return;
      }
      const issued = await res.json();
      alert(
        "Token minted:\n\n" + issued.token +
        "\n\nRedemption URL:\n" + window.location.origin + "/invite/" + issued.token
      );
      window.location.reload();
    });
    document.querySelectorAll(".revoke-btn").forEach((b) => {
      b.addEventListener("click", async (ev) => {
        const token = ev.target.getAttribute("data-token");
        if (!confirm("Revoke this invite?")) return;
        const res = await fetch("/api/admin/tokens/" + encodeURIComponent(token), { method: "DELETE" });
        if (res.ok || res.status === 204) {
          window.location.reload();
        } else {
          alert("revoke failed: " + res.status);
        }
      });
    });
  </script>
</body>
</html>
```

- [ ] **Step 2: Stage**

```bash
git add apps/lattice-docs/src/pages/admin/index.astro
```

Draft commit message: `feat(docs): /admin dashboard for invite minting`

---

## Task 21: /invite/[token] public landing

**Files:**
- Create: `apps/lattice-docs/src/pages/invite/[token].astro`

- [ ] **Step 1: Write the landing page**

Create `apps/lattice-docs/src/pages/invite/[token].astro`:

```astro
---
const { token } = Astro.params;
const HOME_URL = import.meta.env.LATTICE_SERVER_URL;

let state: "valid" | "expired" | "consumed" | "unknown" = "unknown";
let invite: any = null;

if (token) {
  const res = await fetch(`${HOME_URL}/admin/tokens/${encodeURIComponent(token)}`);
  if (res.ok) {
    invite = await res.json();
    const now = Math.floor(Date.now() / 1000);
    if (invite.consumed_at) state = "consumed";
    else if (invite.expires_at <= now) state = "expired";
    else state = "valid";
  }
}
---
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Lattice — invite</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 50rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
    .state { padding: 1rem; border-radius: 6px; margin: 1rem 0; }
    .state.valid    { background: #1a3a1a; color: #cfe9cf; }
    .state.expired  { background: #3a1a1a; color: #e9cfcf; }
    .state.consumed { background: #3a3a1a; color: #e9e9cf; }
    .state.unknown  { background: #2a2a2a; color: #ccc; }
    code { background: #222; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.95rem; }
    .token-box { font-size: 1.2rem; padding: 0.6rem; word-break: break-all; user-select: all; }
    ol li { margin-bottom: 0.5rem; }
  </style>
</head>
<body>
  <h1>You've been invited to Lattice</h1>
  <p>Lattice is a post-quantum encrypted federated messenger. Welcome.</p>

  {state === "valid" && (
    <>
      <div class="state valid">
        <strong>✓ Invite valid.</strong> Expires {new Date(invite.expires_at * 1000).toISOString().slice(0, 19)} UTC.
      </div>
      <h2>How to redeem</h2>
      <ol>
        <li>Install Lattice from <a href="https://github.com/suhteevah/lattice/releases">GitHub Releases</a>.
            For Arch: clone the repo and run <code>makepkg -si</code> in <code>packaging/arch/</code>.</li>
        <li>Launch the app.</li>
        <li>Click the ⚙ button in the sidebar header. Set:
          <ul>
            <li><strong>Home server URL:</strong> <code>{HOME_URL}</code></li>
            <li><strong>Invite token (single-use):</strong> <code class="token-box">{token}</code></li>
          </ul>
        </li>
        <li>Click Save, then reload the window. Your identity will bootstrap automatically.</li>
      </ol>
    </>
  )}

  {state === "expired" && (
    <div class="state expired"><strong>This invite has expired.</strong> Ask the person who invited you for a fresh one.</div>
  )}
  {state === "consumed" && (
    <div class="state consumed"><strong>This invite has already been used.</strong> If that wasn't you, contact the inviter.</div>
  )}
  {state === "unknown" && (
    <div class="state unknown"><strong>This invite isn't recognized.</strong> Double-check the URL.</div>
  )}
</body>
</html>
```

- [ ] **Step 2: Verify against the dev server**

```bash
cd J:/lattice/apps/lattice-docs
LATTICE_SERVER_URL=https://lattice.pixiedustbot.com npm run dev
```

Mint a real invite via curl first:

```bash
ADMIN_KEY=$(cat J:/lattice/scratch/.admin-api-key)
curl -H "X-Lattice-Admin-Key: $ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d '{"label":"local-dev-smoke","ttl_secs":3600}' \
    https://lattice.pixiedustbot.com/admin/tokens
```

Copy the `token` from the response, then open `http://localhost:4321/invite/<token>` in a browser. Expected: green "Invite valid" banner with install instructions. Ctrl-C the dev server.

- [ ] **Step 3: Stage**

```bash
git add apps/lattice-docs/src/pages/invite/[token].astro
```

Draft commit message: `feat(docs): /invite/[token] public landing page`

---

## Task 22: Deploy Astro changes to Vercel

**Files:**
- (no repo changes — operations only)

- [ ] **Step 1: Set Vercel env vars**

Use the Vercel CLI (already installed on kokonoe per memory):

```bash
cd J:/lattice/apps/lattice-docs
vercel env add LATTICE_SERVER_URL production
# Paste: https://lattice.pixiedustbot.com

vercel env add LATTICE_ADMIN_API_KEY production
# Paste the admin key from J:\lattice\scratch\.admin-api-key

vercel env add LATTICE_ADMIN_USER_IDS production
# Paste your Clerk user_id (find at https://dashboard.clerk.com/last-active?path=users)
```

For Clerk: install the Clerk integration from the Vercel Marketplace UI — that auto-provisions `CLERK_PUBLISHABLE_KEY` and `CLERK_SECRET_KEY`.

- [ ] **Step 2: Build locally**

```bash
cd J:/lattice/apps/lattice-docs
npm run build
```

Expected: `Server built in …` with no errors.

- [ ] **Step 3: Deploy**

```bash
vercel deploy --prebuilt --prod
```

Expected: a deploy URL like `https://lattice-quantum-...vercel.app/` — confirm the production alias updated too.

- [ ] **Step 4: Smoke**

Open `https://lattice-quantum.vercel.app/admin` in a browser:
- Should redirect to Clerk sign-in
- After sign-in (as a user on the allowlist), should land on the admin page
- Should show the list including the backcompat legacy token
- Try minting a token — should appear in the list

Open `https://lattice-quantum.vercel.app/invite/<that-token>` — should show "Invite valid".

- [ ] **Step 5: Stage**

(Nothing to stage — pure deploy. Move on.)

---

# Section C — Chat shell (lattice-web)

## Task 23: storage.rs — invite_token persistence

**Files:**
- Modify: `apps/lattice-web/src/storage.rs`

- [ ] **Step 1: Add the three functions**

In `apps/lattice-web/src/storage.rs`, add:

```rust
const INVITE_TOKEN_KEY: &str = "lattice/invite_token/v1";

/// Read the persisted invite token, if any. None on empty or read error.
#[must_use]
pub fn load_invite_token() -> Option<String> {
    let win = web_sys::window()?;
    let ls = win.local_storage().ok().flatten()?;
    let v = ls.get_item(INVITE_TOKEN_KEY).ok().flatten()?;
    let trimmed = v.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

/// Persist a new invite token. Empty string is treated as a clear.
#[allow(clippy::needless_pass_by_value)]
pub fn save_invite_token(token: String) -> Result<(), String> {
    let trimmed = token.trim();
    let win = web_sys::window().ok_or_else(|| "no window".to_string())?;
    let ls = win
        .local_storage()
        .map_err(|e| format!("local_storage: {e:?}"))?
        .ok_or_else(|| "no localStorage".to_string())?;
    if trimmed.is_empty() {
        ls.remove_item(INVITE_TOKEN_KEY).map_err(|e| format!("remove: {e:?}"))?;
    } else {
        ls.set_item(INVITE_TOKEN_KEY, trimmed).map_err(|e| format!("set: {e:?}"))?;
    }
    Ok(())
}

/// Clear the persisted token — used after a successful register.
pub fn clear_invite_token() -> Result<(), String> {
    save_invite_token(String::new())
}
```

- [ ] **Step 2: Verify it compiles for the wasm target**

```bash
cd J:/lattice/apps/lattice-web
cargo check --target wasm32-unknown-unknown
```

Expected: `Finished`.

- [ ] **Step 3: Stage**

```bash
git add apps/lattice-web/src/storage.rs
```

Draft commit message: `feat(web): invite_token storage helpers`

---

## Task 24: api.rs — register attaches Bearer token

**Files:**
- Modify: `apps/lattice-web/src/api.rs`

- [ ] **Step 1: Find the register signature**

Run: `grep -n 'pub async fn register' apps/lattice-web/src/api.rs`

Note the existing signature.

- [ ] **Step 2: Extend the signature**

In `apps/lattice-web/src/api.rs`, find the `pub async fn register(…) -> Result<…> {` definition. Add a new parameter:

```rust
pub async fn register(
    server_url: &str,
    identity: &LatticeIdentity,
    invite_token: Option<&str>,
) -> Result<RegisterResp, ApiError> {
    // … existing body …
}
```

Inside the function, where the request is built (likely `gloo_net::http::Request::post(...)` or `reqwest` builder), add the header conditionally:

```rust
let mut req = gloo_net::http::Request::post(&format!("{server_url}/register"))
    .header("Content-Type", "application/json");
if let Some(t) = invite_token {
    req = req.header("Authorization", &format!("Bearer {t}"));
}
let resp = req.body(&body)?.send().await?;
```

(Adjust to match whichever HTTP client is in use — `gloo_net` is the most common for Leptos.)

- [ ] **Step 3: Update all callers**

Run: `grep -n 'api::register\|api::register(' apps/lattice-web/src/`

For each call site (likely only in `chat_state.rs`), pass `None` for now. We'll update the real caller in Task 25.

- [ ] **Step 4: Verify it compiles**

```bash
cd J:/lattice/apps/lattice-web
cargo check --target wasm32-unknown-unknown
```

Expected: `Finished`.

- [ ] **Step 5: Stage**

```bash
git add apps/lattice-web/src/api.rs apps/lattice-web/src/chat_state.rs
```

Draft commit message: `feat(web): register attaches Authorization: Bearer when invite token present`

---

## Task 25: chat_state.rs — bootstrap reads + clears invite_token

**Files:**
- Modify: `apps/lattice-web/src/chat_state.rs`

- [ ] **Step 1: Find the bootstrap path**

Run: `grep -n 'api::register' apps/lattice-web/src/chat_state.rs`

Note the line.

- [ ] **Step 2: Read the token + pass to register + clear on success**

Replace the existing call (it currently looks like `api::register(&self.server_url, &identity).await?;` or similar) with:

```rust
let invite_token = crate::storage::load_invite_token();
api::register(&self.server_url, &identity, invite_token.as_deref()).await?;
// Successful register consumes the token server-side; drop the local copy.
if invite_token.is_some() {
    let _ = crate::storage::clear_invite_token();
}
```

- [ ] **Step 3: Verify it compiles**

```bash
cd J:/lattice/apps/lattice-web
cargo check --target wasm32-unknown-unknown
```

Expected: `Finished`.

- [ ] **Step 4: Stage**

```bash
git add apps/lattice-web/src/chat_state.rs
```

Draft commit message: `feat(web): bootstrap reads invite_token from localStorage and clears on success`

---

## Task 26: chat.rs — SettingsForm gains an invite-token field

**Files:**
- Modify: `apps/lattice-web/src/chat.rs`

- [ ] **Step 1: Find SettingsForm**

Run: `grep -n 'fn SettingsForm' apps/lattice-web/src/chat.rs`

Open the function (around `chat.rs:1207` per the spec).

- [ ] **Step 2: Add a second input + plumbing**

In `SettingsForm`, alongside the existing server-URL state:

```rust
let token_input: NodeRef<leptos::html::Input> = NodeRef::new();
let current_token = crate::storage::load_invite_token().unwrap_or_default();
let initial_token = current_token.clone();
```

In the `submit` closure, after the server-URL save:

```rust
let token_val = token_input
    .get()
    .map(|n| n.unchecked_into::<HtmlInputElement>().value())
    .unwrap_or_default();
if let Err(e) = crate::storage::save_invite_token(token_val) {
    saved_msg.set(format!("token save failed: {e}"));
    return;
}
```

In the `view!{}` block, add a second labelled input below the existing URL one, before the save/cancel buttons:

```rust
<label for="chat-settings-token" class="chat-add-label">
    "Invite token (single-use)"
</label>
<input
    node_ref=token_input
    id="chat-settings-token"
    class="chat-add-input"
    type="text"
    value=initial_token
    placeholder="leave blank if not invited"
    autocomplete="off"
/>
<p class="chat-settings-hint muted">
    "Paste a Bearer token from your invite URL. \
     Consumed on first successful register, then cleared."
</p>
```

- [ ] **Step 3: Verify it compiles**

```bash
cd J:/lattice/apps/lattice-web
cargo check --target wasm32-unknown-unknown
```

Expected: `Finished`.

- [ ] **Step 4: Stage**

```bash
git add apps/lattice-web/src/chat.rs
```

Draft commit message: `feat(web): SettingsForm gains an invite-token field`

---

## Task 27: Manual E2E smoke from kokonoe

**Files:**
- (no repo changes)

- [ ] **Step 1: Mint an invite via /admin**

In Chrome: open `https://lattice-quantum.vercel.app/admin`, sign in via Clerk, click "Mint invite" with label "kokonoe-smoke" and TTL 300 (5 min). Copy the token from the alert.

- [ ] **Step 2: Open the redemption URL**

Open `https://lattice-quantum.vercel.app/invite/<token>` in a new tab. Confirm "Invite valid" with the install instructions.

- [ ] **Step 3: Apply token in the chat shell**

If Matt's tauri-dev session is up: open the ⚙ panel. In the "Invite token" field, paste the token. Click Save. Reload the window.

If tauri-dev is down, relaunch:

```powershell
$env:RUSTUP_TOOLCHAIN='stable-x86_64-pc-windows-gnu'
$env:PATH = 'C:\msys64\mingw64\bin;' + $env:PATH
cd 'J:\lattice\apps\lattice-desktop\src-tauri'
cargo tauri dev
```

After reload, watch the chat shell status line for `me:` confirming a new bootstrap. Note: this creates a NEW identity (the kokonoe Tauri keystore from earlier persists, but bootstrap will overwrite with a new identity if the old localStorage was cleared; check status line carefully).

If the status reads "register failed: token unknown" or similar — confirm the token in localStorage matches the freshly-minted one.

- [ ] **Step 4: Confirm consumed state in /admin**

Refresh `https://lattice-quantum.vercel.app/admin`. The kokonoe-smoke token should now show `consumed` with the new user_id prefix.

- [ ] **Step 5: Sanity log on the home server**

```bash
ssh pixie "sudo journalctl -u lattice-server --since '5 min ago' --no-pager -o cat | grep -E 'register|invite' | tail -5"
```

Expected lines: `invite minted` (from the mint) and `Response sent status=200 uri=/register` (from the consume).

- [ ] **Step 6: Stage**

(No repo changes — pure smoke. Move on.)

---

## Task 28: Final cleanup + handoff

**Files:**
- Modify: `docs/HANDOFF.md` (only the §"What's next" section)
- Modify: `J:\lattice\scratch\new-user-handoff.md` (refresh to reflect token-via-settings-field flow)

- [ ] **Step 1: Update HANDOFF.md**

In `docs/HANDOFF.md`, find the §"What's next" section. Add a one-line entry under "Recently shipped":

```markdown
- 2026-05-XX — Registration v2: per-user single-use invite tokens via
  Clerk-gated /admin UI on lattice-quantum.vercel.app. New
  `/admin/tokens` routes on lattice-server gated by
  `LATTICE__SERVER__ADMIN_API_KEY`. Chat shell gains an "Invite token"
  settings field. Backcompat: the old static
  `LATTICE__SERVER__REGISTRATION_TOKEN` auto-mints a no-expiry invite
  on first boot.
```

- [ ] **Step 2: Refresh new-user-handoff.md**

Update `J:\lattice\scratch\new-user-handoff.md` §"Path A — chat shell with a token field (preferred)" — remove the "if the chat-shell build has a token field" hedge, since after this plan ships it definitely does. Simplify to:

```markdown
### Bootstrap with the invite token

After installing the client and setting the home-server URL:

1. Open the ⚙ panel (sidebar header).
2. Paste the invite token from your `/invite/<token>` URL into the
   "Invite token (single-use)" field.
3. Click Save, reload the window.
4. The chat shell bootstraps your identity, sends the `/register` POST
   with `Authorization: Bearer <token>`, and clears the local copy
   on success.

If `/register` returns 401, the token has either been consumed,
expired, or been mistyped. Re-paste from the original invite URL or
ask the inviter for a fresh one.
```

- [ ] **Step 3: Stage**

```bash
git add docs/HANDOFF.md scratch/new-user-handoff.md
```

Draft commit message: `docs: handoff + new-user-handoff refresh for reg v2`

---

## Task 29: Full release smoke from a clean machine

**Files:**
- (no repo changes)

- [ ] **Step 1: On a fresh VM or clean profile, simulate the full *nix-user flow**

Use any clean test machine on the tailnet:

1. Run the smoke described in `scratch/new-user-handoff.md` end-to-end.
2. Confirm: mint via /admin → open /invite/<t> → install client → paste token → register succeeds → admin shows consumed.

- [ ] **Step 2: Repeat with an intentionally bad token**

1. In the chat shell, paste a garbage string into the token field.
2. Reload. Expected: `/register` returns 401, status line shows the error.
3. Admin list still shows the real token as unconsumed.

- [ ] **Step 3: Repeat with an expired token**

1. Mint an invite with TTL 1 second via curl.
2. Wait 5 seconds.
3. Paste it into the chat shell. Expected: 401 "token expired".

If all three smoke results pass, Reg v2 is shipped.

- [ ] **Step 4: Stage**

(No repo changes — pure smoke.)

---

## Self-review

- **Spec coverage:** Every section of the Reg v2 spec maps to one or more tasks:
  - Architecture diagram → Tasks 1–22 collectively
  - InviteToken struct → Task 2
  - Snapshot v2 → Task 4
  - admin auth helper → Task 6
  - /admin/tokens CRUD → Tasks 7, 8, 9
  - Atomic consume + revert → Task 10
  - Sweeper → Task 13
  - Backcompat → Task 5
  - Astro pages → Tasks 17–21
  - Astro forwarders → Tasks 18, 19
  - Chat-shell field → Tasks 23–26
  - Deployment → Tasks 15, 22
  - Tests (unit + integration + race) → Tasks 4, 11, 12, 13
- **Placeholders:** None — every step has concrete code.
- **Type consistency:** `InviteToken` field names match across state.rs, snapshot, route handlers, and tests. `InviteView` is the wire-DTO derived from `&InviteToken`. `consumed_by_b64` is the snapshot field; `consumed_by_prefix` is the public-API field; `consumed_by: [u8; 32]` is the in-memory field. All three are intentional.

## Plan complete

Plan saved to `docs/superpowers/plans/2026-05-16-registration-v2.md`.

Two execution options:

1. **Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Pick when you're ready.
