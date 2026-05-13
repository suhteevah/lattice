# Self-hosting

This guide covers running your own `lattice-server` for production
use. This page links the operator-facing "why" and "what to watch"
to the mechanical steps in the repository's deploy notes.

If you just want to develop locally, [quickstart.md](quickstart.md)
is faster: it uses `scripts/run-server-dev.ps1` and binds to
`127.0.0.1`. This page is for putting Lattice on the public
internet.

---

## Architecture recap

A home server is a single static binary that handles:

- Account registry (`POST /register`).
- KeyPackage publication and fetch (`POST /key_packages`,
  `GET /key_packages/<uid>`).
- MLS group commit log (`POST /group/<gid>/commit`).
- Pending Welcome enumeration
  (`GET /welcomes/pending/<uid>`).
- Application-message inbox (`POST /group/<gid>/messages`,
  `GET /group/<gid>/messages?since=N`,
  `GET /group/<gid>/messages/ws`).
- Server-issued sealed-sender certs (`POST /group/<gid>/issue_cert`).
- Federation inbox + message inbox
  (`POST /federation/inbox`,
  `POST /federation/message_inbox`).
- Federation discovery (`GET /.well-known/lattice/server`).
- Push subscription registry (`POST /push/subscribe`,
  `GET /push/subscriptions/<uid>`).
- Health check (`GET /health`).

Full request / response shapes at [api-reference.md](api-reference.md).

The current server keeps all state in memory and writes a JSON snapshot
on graceful shutdown. Future work adds Postgres-backed storage via `sqlx`.
For the current state, snapshotting is enough for small deployments;
big deployments wait for the Postgres path.

---

## Pre-flight checklist

Before bringing the server up on a public host:

- **Toolchain.** Rust stable. The project pins via
  `rust-toolchain.toml`. Build target either native Linux (`cargo
  build --release` on the box) or cross from a Windows dev box (the
  workflow in [installation.md](installation.md)).
- **Hostname.** A DNS A/AAAA record pointing at the box. Avoid IP-
  only — the federation descriptor binds to a hostname.
- **TLS strategy.** Today: terminate TLS at a reverse proxy (Caddy,
  nginx, Cloudflare). Future work: ACME via `instant-acme` inside the
  server. The federation descriptor signature does not depend on
  TLS; pubkey-pinning works either way.
- **Firewall.** One inbound port (default 443). Outbound HTTPS for
  federation pushes.
- **Federation key.** A 32-byte file at the path
  `LATTICE__FEDERATION_KEY_PATH` points to. Auto-generated on first
  start; preserve it across restarts or peers will see a different
  pubkey every time the server reboots.
- **Snapshot path.** A writable file at `LATTICE__SNAPSHOT_PATH`.
  Empty value means "no persistence" — useful for dev, dangerous
  for prod.
- **Postgres.** Required to be present in env (the typed config
  demands it) but unused today. Provide a dummy value:
  `LATTICE__DATABASE_URL=postgres://noop@localhost/noop`.

---

## Building the binary

Native Linux build, run on the deploy box:

```bash
sudo apt install -y build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
source $HOME/.cargo/env

git clone https://github.com/suhteevah/lattice.git
cd lattice
cargo build --release -p lattice-server -p lattice-cli
```

A cold build on a 1-vCPU VPS takes ~5 minutes. Binaries land at:

```
target/release/lattice-server   (~5 MB stripped)
target/release/lattice          (~5 MB stripped, the dev/admin CLI)
```

Cross-compile from Windows dev box:

```powershell
.\scripts\check-server.ps1 build -p lattice-server `
    --release --bin lattice-server `
    --target x86_64-unknown-linux-gnu

scp target\x86_64-unknown-linux-gnu\release\lattice-server `
    operator@your-server:/usr/local/bin/lattice-server
```

The release profile pins `strip = "symbols"` and `opt-level = 3` and
`lto = "fat"`, so no separate strip pass is needed.

---

## Runtime configuration

Configuration is environment-variable-driven via the `config` crate's
`LATTICE__FOO__BAR` double-underscore nesting convention. An optional
`lattice.toml` in the working directory is also read.

### Required environment variables

```bash
LATTICE__SERVER__BIND_ADDR=0.0.0.0:443
LATTICE__FEDERATION_KEY_PATH=/var/lib/lattice/federation.key
LATTICE__SNAPSHOT_PATH=/var/lib/lattice/snapshot.json
LATTICE__ENVIRONMENT=production
LATTICE__DATABASE_URL=postgres://noop@localhost/noop   # unused; required by typed config
RUST_LOG=lattice_server=info,axum=warn
```

The bind address can be `0.0.0.0:<port>` for the world to see it,
`127.0.0.1:<port>` if you front it with a reverse proxy on the same
host, or a tailscale interface address for tailnet-only access.

### Optional environment variables

| Variable | Default | Effect |
|---|---|---|
| `LATTICE__SERVER__CORS_ALLOW_ANY` | `true` | If true, server replies `Access-Control-Allow-Origin: *`. Disable in production if you want to lock the API to a known frontend origin. |
| `LATTICE__SERVER__SHUTDOWN_GRACE_SECS` | `30` | Seconds to wait for in-flight requests before flushing the snapshot and exiting. |
| `LATTICE__OBSERVABILITY__JSON` | `true` in prod | Emit `tracing` events as structured JSON (good for log aggregators). |

### Per-environment overrides

The repository ships a `crates/lattice-server/config/` directory
with `default.toml`, `development.toml`, `production.toml`. The
binary selects based on `LATTICE__ENVIRONMENT`. Env vars override
TOML.

---

## TLS

The current current server does not terminate TLS. The two supported
production patterns are:

### Pattern A — reverse proxy

Terminate TLS at Caddy / nginx / Traefik / Cloudflare and forward
plain HTTP to the server on localhost. Example Caddyfile:

```caddy
home.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Pro: standard ops surface, automatic ACME via Caddy.
Con: extra process, additional config to maintain.

### Pattern B — ACME inside the server (future)

The plan is `instant-acme` inside `lattice-server` with Let's
Encrypt issuance. Self-signed `rcgen` certs are used for dev. The
production path is on the public roadmap.

When this lands, configuration becomes:

```bash
LATTICE__TLS__MODE=acme
LATTICE__TLS__DOMAIN=home.example.com
LATTICE__TLS__ACME_DIR=https://acme-v02.api.letsencrypt.org/directory
LATTICE__TLS__CACHE_PATH=/var/lib/lattice/tls-cache
```

Until then, run behind a reverse proxy in production.

---

## Federation key

The federation key is a 32-byte Ed25519 seed at
`LATTICE__FEDERATION_KEY_PATH`. The server generates it on first
start if the file does not exist. **Preserve this file across
restarts.** If the file is lost, the server boots with a fresh
pubkey, and every peer that has TOFU-pinned the old pubkey will
refuse to accept federation pushes from your host.

Permissions: `0600`, owned by the lattice-server user. Anyone with
read access to the file can forge "server X says Y" to peer servers.

Back it up. The recommended pattern is to print the base64 of the
file once at deploy time, store it offline (password manager,
encrypted USB), and restore it on disaster recovery.

```bash
base64 /var/lib/lattice/federation.key
# Stash the output somewhere safe.
```

The pubkey itself is non-secret — peers see it in the
`/.well-known/lattice/server` descriptor.

---

## State persistence

The snapshot file at `LATTICE__SNAPSHOT_PATH` is a JSON dump of every
in-memory store: registered users, published KeyPackages, group
commit logs (including welcomes), application-message inbox plus
monotonic `seq`, federation peer registry, push subscriptions, group
replication peer lists.

The server writes the snapshot at:

- Graceful shutdown (SIGTERM, SIGINT).
- Every commit acceptance (recommended for production; configurable
  via `LATTICE__OBSERVABILITY__SNAPSHOT_EVERY_COMMIT`).

Hard crashes (SIGKILL, OOM, power loss) still lose state since the
last snapshot. Future sqlx integration closes the gap.

Verify a round-trip:

```bash
kill -TERM <server-pid>   # graceful shutdown
ls -lh /var/lib/lattice/snapshot.json   # snapshot exists
# restart the binary
systemctl start lattice-server
journalctl -u lattice-server -f
# Look for "snapshot loaded users=N groups=M" in the boot log.
```

The unit test `crates/lattice-server/src/state.rs::tests::
snapshot_round_trip_preserves_state` exercises every field.

The reference verifier script is `scripts/verify-persistence.ps1`.

---

## Systemd unit

The template at `scripts/lattice-server.service.template`:

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
Environment=LATTICE__DATABASE_URL=postgres://noop@localhost/noop
Environment=RUST_LOG=lattice_server=info,axum=warn
ExecStart=/usr/local/bin/lattice-server
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
# Hardening (recommended):
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/lattice
ProtectHome=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
```

Drop into `/etc/systemd/system/`, then:

```bash
sudo useradd --system --home /var/lib/lattice --shell /bin/false lattice
sudo mkdir -p /var/lib/lattice
sudo chown lattice:lattice /var/lib/lattice
sudo chmod 0700 /var/lib/lattice
sudo systemctl daemon-reload
sudo systemctl enable --now lattice-server
sudo journalctl -u lattice-server -f
```

If binding to `0.0.0.0:443` you may need
`AmbientCapabilities=CAP_NET_BIND_SERVICE` in the unit, or run
behind a reverse proxy on a high port.

---

## Federation setup

The federation surface is open by default — your server will accept
federation pushes from any peer whose pubkey it has TOFU-pinned.

### Outbound

Outbound federation pushes happen automatically when your users
invite remote users to groups (the `remote_routing` field in
`/group/<gid>/commit`). You do not configure peers explicitly; the
client's per-message routing drives it.

### Pinning a specific peer

For high-trust deployments you may want to **pin** a peer's
federation pubkey out-of-band rather than rely on TOFU. This is the
operator-config-driven equivalent of the client-side distrust
scoring. The wire-level support is in place (peers' pubkeys are
stored in the registry); the config knob to pre-load a pin list is
future work.

### Blocklist

Refusing to federate with a named host is a per-server admin
operation ("federation peer blocklist"). The wire-level support
is the registry's distrust flag; the admin UI is future work.

---

## Reverse proxy gotchas

A few things worth knowing if you put Caddy / nginx / Cloudflare in
front of `lattice-server`:

### WebSocket upgrade

`GET /group/<gid>/messages/ws` is a WebSocket upgrade. Reverse
proxies need to be configured to pass `Upgrade` and `Connection`
headers. Caddy and nginx do this by default with `reverse_proxy` /
`proxy_pass`. Cloudflare passes WebSockets on free plans for
specific Enterprise customers only — verify per their docs.

### Body size

MLS commits + welcomes can be 30+ KB. Default body-size limits in
nginx (`client_max_body_size`) are 1 MB. Lattice is well under that
but if you also use the same proxy for image uploads, configure
accordingly.

### Connection limits

The WebSocket path holds a long-lived connection per active
conversation. A user with N joined groups can open N WS connections.
Make sure your proxy's `worker_connections` (nginx) or
`max_concurrent_streams` (Caddy) is high enough.

### CORS

The server already replies with `Access-Control-Allow-Origin: *`
(`CorsLayer::new().allow_origin(Any)` in `lattice_server::app()`).
Do not overlay your own CORS at the reverse proxy unless you want
to **tighten** the policy — overlaying a duplicate `*` policy makes
some browsers refuse the response.

To tighten, set `LATTICE__SERVER__CORS_ALLOW_ANY=false` in env
(future work — currently the policy is hardcoded to allow-any).

---

## Cloudflare-specific notes

If you front the server with Cloudflare:

- **Proxy mode** (orange cloud) hides your IP but adds latency.
  Acceptable for most users; bad for federation pushes from peers
  far away.
- **WebSocket support** is per-plan. Free tier allows WebSockets
  but with idle timeouts that may break long-lived subscriptions.
  Use the keepalive / reconnect logic in the chat shell (auto-
  reconnect on close is shipped).
- **Cache rules.** Bypass cache for `/group/*`, `/register`,
  `/key_packages/*`, `/federation/*`, `/welcomes/*`, and
  `/.well-known/*` — everything except `/health` and any static
  assets.
- **Rate limiting.** Cloudflare's per-zone rate limits apply.
  Default plan tolerates the 5-second poll cadence; the WS path is
  one connection per user per active conversation.

---

## Observability

The server emits structured tracing via `tracing-subscriber`:

```
RUST_LOG=lattice_server=info,axum=warn,tower_http=info
```

Per-event JSON output is wired when `LATTICE__OBSERVABILITY__JSON=true`
(default in production). Pipe to your aggregator:

```
sudo journalctl -u lattice-server -f -o cat | jq .
```

What to watch for in production:

| Event | Severity | Action |
|---|---|---|
| `federation push delivered host=X status=200` | INFO | Normal. |
| `federation push delivered host=X status=4XX/5XX` | WARN | Peer is unreachable or rejecting. Check connectivity and pubkey pin. |
| `signature verify failed origin_host=X` | ERROR | Possible federation pubkey rotation or MITM. Investigate. |
| `snapshot write failed path=X error=Y` | ERROR | Disk full or perms wrong. Fix before next graceful restart. |
| `ws broadcast lagged subscriber missed=N` | WARN | Client is slow. Investigate downstream client; the broadcast channel is sized at 64 — bumps are future config work. |

Per the CLAUDE.md verbose-logging-everywhere rule: do not turn this
down. The log volume is the cost of an auditable server.

---

## Operational notes

- **Federation key safety.** Anyone with the file can impersonate
  the server. Restrict to `0600` and limit to the lattice-server
  user.
- **In-memory state.** current servers lose state on restart unless
  `LATTICE__SNAPSHOT_PATH` is set. KP inboxes, group commit logs,
  message inboxes — all vanish on SIGKILL or power loss.
- **No rate limiting.** A single client can flood `/messages`.
  Rate limits are future work. Until then, use the reverse proxy's
  rate-limit module (Caddy's `rate_limit`, nginx's `limit_req`) or
  Cloudflare's per-zone rules.
- **No auth on the API surface today.** Anyone who knows a user_id
  can register or publish a KP under it. A future milestone
  introduces auth via signed-by-federation-cert HMACs on every
  request.
- **Push payloads** are emitted as Web Push API-format encrypted
  payloads using the recipient's `keys.p256dh` + `keys.auth`. The
  registry path is in place; the actual emit hook on
  `append_message` is follow-on work.

---

## Tearing down

Graceful:

```bash
sudo systemctl stop lattice-server
# Verify final snapshot:
ls -lh /var/lib/lattice/snapshot.json
```

Forced:

```bash
sudo pkill -9 lattice-server   # discards state since last snapshot
```

Reset state to empty:

```bash
sudo systemctl stop lattice-server
sudo rm /var/lib/lattice/snapshot.json
# Federation key stays; deleting it generates a new pubkey on next
# boot and breaks every peer's TOFU pin.
sudo systemctl start lattice-server
```

Full uninstall:

```bash
sudo systemctl disable --now lattice-server
sudo rm /etc/systemd/system/lattice-server.service
sudo rm /usr/local/bin/lattice-server
sudo rm -rf /var/lib/lattice
sudo userdel lattice
```

---

## Cross-references

- [federation.md](federation.md) — how the federation surface works
  end-to-end, plus the cross-server smoke transcript.
- [api-reference.md](api-reference.md) — every HTTP endpoint.
- [troubleshooting.md](troubleshooting.md) — operator-side error
  table.
- [security-model.md](security-model.md) — what the server protects
  against and what it does not.
