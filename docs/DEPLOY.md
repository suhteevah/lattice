# Lattice — Deployment Notes

Verified deploy walkthrough for an M3-skeleton `lattice-server` on a
fresh Linux host. The current production-ready surface is the
HTTP-only single-binary path; QUIC + sqlx + ACME-TLS land as M3
polish items (see `HANDOFF.md §4 "Not done — M3 polish"`).

The reference testbed used to verify this doc:

| Node | Hostname | Role | Reachable from |
|---|---|---|---|
| pixie | `207.244.232.227` (public) | Alice's home server | Anywhere via SSH |
| cnc-server | `192.168.168.100` (LAN) + `100.108.202.49` (tailscale) | Bob's home server | LAN + tailscale |
| kokonoe | Windows 10, no public IP | Developer workstation / orchestrator | n/a |

Both lattice-server processes ran natively on Ubuntu 24.04 and
openSUSE Tumbleweed respectively. The MLS-encrypted demo message
travelled pixie → cnc-server over the public internet via an SSH
reverse tunnel (cnc is behind NAT).

---

## Prerequisites on each node

```
# Verify the toolchain. We pin to `stable` (currently rustc 1.95).
which gcc make git
gcc --version       # >= 11 recommended

# Install rustup non-interactively (skip the `which cargo` prompt;
# the toolchain auto-pins from rust-toolchain.toml at first cargo
# invocation).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
source $HOME/.cargo/env

# Workspace deps (Ubuntu/Debian):
sudo apt install -y build-essential pkg-config libssl-dev
```

If the host has sccache configured as `RUSTC_WRAPPER` and it's broken
(seen on cnc-server's openSUSE), unset it for the build:

```
RUSTC_WRAPPER= CARGO_BUILD_RUSTC_WRAPPER= cargo build --release ...
```

---

## Transfer + build

From the dev box (kokonoe in our case):

```powershell
# Tar the workspace (skipping local-only dirs that bloat the tarball).
$tarball = "$env:TEMP\lattice.tgz"
cd J:\lattice
tar --exclude='./target' --exclude='./scratch' --exclude='./.git' `
    --exclude='./apps/lattice-web/node_modules' `
    --exclude='./apps/lattice-web/dist' `
    -czf $tarball .

# Ship it.
scp $env:TEMP\lattice.tgz $node:~/lattice.tgz

# Extract + build on the remote node.
ssh $node 'rm -rf ~/lattice && mkdir ~/lattice && cd ~/lattice && \
    tar xzf ~/lattice.tgz && \
    nohup cargo build --release --bin lattice-server --bin lattice \
        > /tmp/lattice-build.log 2>&1 &'
```

A cold build takes ~5 minutes on a 1-vCPU VPS. Binaries land at
`~/lattice/target/release/{lattice-server,lattice}` and are ~5 MB each
(strip-able further; release profile already sets `strip = "symbols"`
in `Cargo.toml`).

---

## Start the server

The server reads its configuration from env vars (using the `config`
crate's `LATTICE__FOO__BAR` double-underscore nesting convention) and
optionally a `lattice.toml` file in the working directory. Minimum
viable env set:

```bash
LATTICE__SERVER__BIND_ADDR=127.0.0.1:4443          # localhost-only for
                                                    # behind-tunnel use;
                                                    # use 0.0.0.0 for
                                                    # public-IP hosts
LATTICE__FEDERATION_KEY_PATH=/var/lib/lattice/fed.key  # 32-byte raw seed;
                                                        # auto-generated
                                                        # on first start
LATTICE__SNAPSHOT_PATH=/var/lib/lattice/state.json     # JSON dump of
                                                        # in-memory state.
                                                        # Restored at
                                                        # startup,
                                                        # written on
                                                        # graceful shutdown.
                                                        # Empty = no
                                                        # persistence.
LATTICE__DATABASE_URL=postgres://noop@localhost/noop   # unused in M3
                                                        # but required
                                                        # by typed config
RUST_LOG=lattice_server=info,axum=warn

nohup ~/lattice/target/release/lattice-server > /var/log/lattice.log 2>&1 &
```

## State persistence (clean restart)

If `LATTICE__SNAPSHOT_PATH` points at a writable file, the server
restores its in-memory state from there at startup and writes a
fresh JSON dump on graceful shutdown (SIGTERM / SIGINT). All
known stores are covered: registered users, published KeyPackages,
group commit logs (including welcomes), application-message
inbox + monotonic `seq`, federation peer registry.

Hard crashes (SIGKILL, OOM, power loss) still lose any state
since the last snapshot — sqlite/sqlx integration in the M3 polish
backlog will close that gap. For the testbed, send SIGTERM
(`kill <pid>` defaults to SIGTERM) and the server flushes to disk
before exiting.

A round-trip test in `crates/lattice-server/src/state.rs::tests::
snapshot_round_trip_preserves_state` exercises every field.

Verify:

```bash
curl -s http://127.0.0.1:4443/.well-known/lattice/server | jq .
# {"wire_version":2,
#  "federation_pubkey_b64":"<32-byte-base64>",
#  "server_version":"0.1.0"}
```

The `federation_pubkey_b64` is the long-lived identity the peers
will TOFU-pin. Persist `LATTICE__FEDERATION_KEY_PATH` or peers
will see a different pubkey on every restart.

---

## Cross-host federation plumbing

Lattice servers federate via HTTP POSTs to each other's
`/federation/inbox` and `/federation/message_inbox`. Each
federation push is signed with the sender's federation key over a
canonical Prost TBS (see `crates/lattice-server/src/routes/federation.rs::
canonical_inbox_bytes`). The receiver TOFU-pins the sender's pubkey
on first contact.

For two servers to federate they need bidirectional reachability on
the bound port. Three patterns we've used:

### A) Both servers have public IPs

Trivial — bind `0.0.0.0:443` (or any port), open the firewall, point
clients at the canonical URLs. ACME-TLS lands in the M3 polish.

### B) One public IP, one behind NAT (the pixie ↔ cnc case)

The NAT'd host opens a persistent SSH reverse tunnel to the public
host. From the NAT'd host:

```bash
# From cnc (NAT'd), tunnel cnc:4443 to be reachable as
# pixie's localhost:4444. `-f` backgrounds, `-N` skips remote shell,
# `-R` is the reverse-tunnel flag.
ssh -fNR 4444:127.0.0.1:4443 \
    -o ServerAliveInterval=30 \
    -o ExitOnForwardFailure=yes \
    pixiedust@207.244.232.227
```

From the public host's perspective, `http://127.0.0.1:4444` IS the
NAT'd peer's `lattice-server`. Federation pushes targeting
`localhost:4444` cross the public internet via SSH.

For production, replace SSH tunnels with one of:
- **Tailscale** on both hosts — each peer gets a 100.x.y.z address;
  no port-forwarding, no SSH dependency, free for personal use.
- **Wireguard** between the hosts.
- **Public IP + firewall + ACME-TLS** on the NAT'd host's
  router-forwarded port.

### C) Both behind NAT

Tailscale (or another overlay) is the only realistic path. SSH
tunnels through a shared bastion would work but introduce a SPOF.

---

## Verifying the bridge

Once both servers are up + reachable, run the demo CLI from anywhere
that can reach both URLs:

```bash
~/lattice/target/release/lattice demo \
    --server-a http://<server-a>:<port-a> \
    --server-b http://<server-b>:<port-b> \
    --message cross-host-test
```

Exits 0 if the message round-trips, non-zero with an error otherwise.
Watch both servers' logs (`lattice_server=info`) — you'll see
`federation push delivered` on the sender side and `federation push
accepted` on the receiver.

For real per-action testing (each side a separate process with
file-backed state) see `scripts/e2e-per-action.ps1`.

---

## Operational notes

- **Federation key safety**: anyone with the file can impersonate the
  server. Restrict to `0600` and limit to the lattice-server user.
- **In-memory state**: M3 servers lose state on restart. KP inboxes,
  group commit logs, message inboxes — all vanish. The sqlx-backed
  persistence work is tracked in `HANDOFF.md §4 "Not done — M3 polish"`.
- **No rate limiting**: a single client can flood `/messages` —
  M5 work.
- **No auth on the API surface**: anyone who knows a user_id can
  register or publish a KP under it. M5 introduces auth via
  signed-by-federation-cert HMACs on every request.
- **Logs are verbose by default** — `RUST_LOG=lattice_server=info`
  produces structured JSON via `tracing-subscriber`. Pipe to your
  preferred log aggregator. Per CLAUDE.md the verbose path is by
  design — do not reduce.

---

## Tearing down

```bash
pkill -f lattice-server                # stops the process
rm -rf /tmp/lattice-deploy             # if you used the test layout
rm -rf ~/.lattice                      # client-side state (per-action CLI)
```

The reverse-tunnel SSH process holds the connection — kill it
separately:

```bash
pgrep -fl 'ssh.*-fNR' | head
kill <pid>
```

---

## Tonight's friend-test playbook (2026-05-11)

Smallest path to "the boys join from their own browsers".

### 1. One public-IP server

```bash
# On pixie (or any public-IP host):
ssh pixiedust@pixie
cd /tmp/lattice-deploy   # already has the lattice-server binary
LATTICE__SERVER__BIND_ADDR=0.0.0.0:4443 \
LATTICE__FEDERATION_KEY_PATH=/tmp/lattice-deploy/fed.key \
LATTICE__SNAPSHOT_PATH=/tmp/lattice-deploy/state.json \
RUST_LOG=lattice_server=debug,info \
./lattice-server
```

If pixie doesn't have the current binary yet, rebuild:

```powershell
# From J:\lattice on Windows dev box:
.\scripts\check-server.ps1 build -p lattice-server --release --bin lattice-server --target x86_64-unknown-linux-gnu
scp target\x86_64-unknown-linux-gnu\release\lattice-server pixiedust@pixie:/tmp/lattice-deploy/
```

### 2. Point the browser client at the public server

Default in `apps/lattice-web/src/app.rs` is
`http://127.0.0.1:8080`. For tonight, either:

a. Edit `DEFAULT_SERVER_URL` to your pixie URL + rebuild:
   ```rust
   const DEFAULT_SERVER_URL: &str = "http://207.244.232.227:4443";
   ```
   then `cd apps\lattice-web && trunk build --release`. Ship
   `dist/` to wherever you host the static site, or run
   `trunk serve --address 0.0.0.0` and share that URL.

b. Or stand the browser bundle up locally and have friends
   point their browsers at your machine via Tailscale /
   Cloudflare Tunnel:
   ```powershell
   cd apps\lattice-web
   trunk serve --address 0.0.0.0
   # then expose 5173 via your tunnel of choice
   ```

CORS is wildcard-allow on the server (`CorsLayer::new()
.allow_origin(Any)` in `lattice-server::app()`) so cross-origin
hits from any browser work without extra setup.

### 3. What works tonight

Every demo button at `http://<browser-host>:5173/`:

- Hybrid signature + KEM (in-WASM, no server)
- In-tab MLS Alice⇌Bob
- Server-backed Alice⇌Bob round-trip
- Sealed-sender envelopes (D-05)
- Multi-member 3-party group (M5 wire v2)
- **Live WS push (γ.4 fallback)** — open two tabs on the same
  group_id, both subscribe to `/group/:gid/messages/ws`, watch
  messages flow in real-time
- Device revocation
- Identity persistence (plaintext / Argon2id-encrypted / WebAuthn-
  PRF-encrypted)
- Federation distrust scoring (D-13)

### 4. Caveats

- Demo flows hardcode user_ids by byte (Alice=0xAA, Bob=0xBB, etc).
  Friends in different tabs share the same demo user_ids — the
  server's `register_user` is idempotent so it'll just report
  `new_registration=false` for the second tab onward. Each friend
  effectively runs the demo against their own logical Alice + Bob
  pair via the same server, not as distinct users.
- For "friend A is Alice, friend B is Bob" you'd want fresh
  random user_ids per tab; that's a chat-UI build, not a one-liner.
  Roadmap candidate: M6 hardening.

