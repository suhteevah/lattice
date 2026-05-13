# Quickstart — your first encrypted message

This walkthrough takes you from "no Lattice running anywhere" to a
working end-to-end encrypted conversation in two browser tabs. The
worked example runs entirely on `127.0.0.1` so you do not need any
domain, certificate, or network configuration. Once it works locally,
[self-hosting.md](self-hosting.md) shows how to expose it on the
public internet, and [installation.md](installation.md) shows how to
package the Tauri desktop wrapper.

Expected elapsed time: five minutes, assuming a Rust toolchain is
already installed.

---

## Prerequisites

- **Rust toolchain.** A stable `rustup`-managed toolchain. The
  project pins `stable-x86_64-pc-windows-gnu` on Windows because the
  GNU host avoids the MSVC vcvars dance; Linux and macOS use whatever
  rustup defaults to. See [development.md](development.md) for the
  full toolchain notes.
- **`trunk` for the browser bundle.** `cargo install trunk` if you do
  not have it. Trunk replaces webpack + vite for the Leptos PWA; the
  project does not use npm.
- **PowerShell 5.1 or newer on Windows.** Every helper script is a
  `.ps1` — bash scripts are not used on this repo by policy.
- **A modern browser.** Chrome 116+, Edge 116+, Firefox 122+, or
  Safari 17+. WebAssembly, `localStorage`, and `fetch` are required.
  WebAuthn PRF is optional but unlocks the hardware-bound at-rest
  encryption path described in
  [identity-and-keys.md](identity-and-keys.md).

You do **not** need Postgres, Docker, an SSL certificate, or a domain
to complete this quickstart. All state lives in memory and a JSON
snapshot under `.\\.run\\dev-server` inside the repository root.

---

## Step 1 — clone and build

From the directory you want to keep Lattice in:

```powershell
git clone https://github.com/suhteevah/lattice.git
cd lattice
.\scripts\dev-setup.ps1
```

`dev-setup.ps1` installs the wasm32 target if it is missing, pins the
Rust toolchain from `rust-toolchain.toml`, and verifies that
`cargo-audit`, `clippy`, and `rustfmt` are present. A first run can
take a minute; subsequent runs are idempotent.

Build the server binary in debug mode (release also works but takes
several minutes on a cold cache):

```powershell
cargo build -p lattice-server
```

You should see "Compiling lattice-..." for every workspace crate
followed by "Finished `dev` profile". The binary lands at
`target\debug\lattice-server.exe`.

---

## Step 2 — start a local home server

The included script binds to `127.0.0.1:8080` with a per-run scratch
directory at `.\\.run\\dev-server` inside the repository for the
federation signing key and the JSON state snapshot:

```powershell
.\scripts\run-server-dev.ps1
```

Expected log output (slightly truncated):

```
starting lattice-server on 127.0.0.1:8080 (run dir: .\.run\dev-server)
INFO lattice_server: server started bind_addr=127.0.0.1:8080 wire_version=4
INFO lattice_server: federation key loaded from .run\dev-server\federation.key
INFO lattice_server: snapshot loaded from .run\dev-server\snapshot.json users=0 groups=0
```

Sanity-check that the server is up:

```powershell
curl http://127.0.0.1:8080/health
```

You should see:

```json
{"status":"ok","service":"lattice-server","version":"0.1.0","wire_version":4}
```

The federation descriptor is also exposed:

```powershell
curl http://127.0.0.1:8080/.well-known/lattice/server
```

```json
{
  "wire_version": 4,
  "federation_pubkey_b64": "<32-byte-base64>",
  "server_version": "0.1.0"
}
```

Leave this terminal running.

---

## Step 3 — start the web client

In a **separate** PowerShell window:

```powershell
cd apps\lattice-web
.\scripts\serve.ps1
```

`serve.ps1` invokes `trunk serve` with the right environment so the
proc-macro host build does not need an MSVC toolchain. Output:

```
INFO  starting build
INFO   compiling lattice-web (wasm32)
INFO   wasm-bindgen
INFO   stripping wasm artifacts
INFO  success! bundle ready in 2.4s
INFO  serving at http://127.0.0.1:5173
```

Open `http://localhost:5173` in your first browser tab. The default
view is the chat shell — left sidebar, centre thread pane, bottom
composer. The first time the page mounts, the client runs the
identity bootstrap:

1. Generate a fresh `LatticeIdentity` (ML-DSA-65 + Ed25519 signing
   keypair plus an ML-KEM-768 encapsulation keypair).
2. POST `/register` to your local server with the new user_id.
3. POST `/key_packages` to publish your MLS KeyPackage.
4. Persist a `version: 1` plaintext blob to
   `localStorage["lattice/identity/v1"]`.

You can confirm the bootstrap completed by reading the status line at
the top of the page — it shows `me: <prefix>` where `<prefix>` is the
first eight hex characters of your user_id. Detailed bootstrap notes
live in [identity-and-keys.md](identity-and-keys.md).

---

## Step 4 — second tab, second identity

Open **`http://127.0.0.1:5173`** in a second tab. Note that the
hostname is different (`127.0.0.1` not `localhost`). Browsers
partition `localStorage` per origin, so the two hostnames map to two
independent identities — `localhost` is Alice and `127.0.0.1` is Bob.

The second tab runs the same bootstrap and ends up with its own
distinct user_id. Both tabs are now logged into the same local home
server with two different identities.

If you prefer one hostname plus an incognito window, that also works
— the incognito context has its own `localStorage` partition.

---

## Step 5 — add a conversation

In Bob's tab (`127.0.0.1:5173`):

1. Copy Alice's user_id from her tab's `me:` line. The full 64-char
   hex is shown in the debug panel if you expand "Debug tools".
2. Click the `+` button next to the sidebar header. The "Add
   conversation" form appears.
3. Paste Alice's hex into the **user_id** field.
4. Enter a label like `Alice` and click **Add**.

Behind the scenes, Bob's client:

- Computes the deterministic 1:1 group_id as
  `blake3("lattice/dm/v1/" || sorted(alice_uid, bob_uid))[..16]`.
- GETs `/key_packages/<alice_uid>` to fetch Alice's published
  KeyPackage.
- Creates an MLS group locally, calls `add_member` against Alice's
  KP, and produces a commit and a Welcome.
- POSTs the commit and Welcome to
  `/group/<gid>/commit`.
- Persists the group state to `localStorage` under
  `lattice/mls/group/<gid_b64url>/...`.

Status line:

```
chat: conversation ready (Alice)
```

The sidebar now shows `# Alice` as a new conversation entry.

---

## Step 6 — accept the conversation on Alice's side

Switch to Alice's tab. Two paths work:

**Path A — auto-discovery.** Reload the page (Ctrl+R). On bootstrap,
the client calls `GET /welcomes/pending/<alice_uid>` and discovers
that there is a pending Welcome waiting for her. She joins the group
automatically and the sidebar shows `# Bob` (placeholder label —
welcomes do not carry a peer name).

**Path B — manual add.** Click `+`, paste Bob's user_id, label it
`Bob`, hit Add. Because both sides derive the same deterministic
group_id from the sorted user_id pair, this path finds the same
group, fetches the Welcome via
`GET /group/<gid>/welcome/<alice_uid>`, and joins.

Either way, both tabs now have the conversation in their sidebar.

---

## Step 7 — send the first message

In Bob's tab, click the `# Alice` conversation. The thread pane
loads. Type `hi alice — first lattice message` into the composer and
press Enter (or click Send).

Behind the scenes:

- Bob's client encrypts the plaintext with the group's MLS
  `encrypt_application` to produce a ~3.6 KB ciphertext.
- The ciphertext is wrapped in a `SealedEnvelope` with an
  ephemeral Ed25519 signature so the server cannot link sender to
  recipient (see [security-model.md](security-model.md)).
- The envelope POSTs to `/group/<gid>/messages` and the server
  assigns it a monotonic `seq`.

Expected status:

```
chat: sent (3879 bytes)
```

Alice's tab polls `/group/<gid>/messages?since=<last_seq>` every five
seconds. Within five seconds she sees the message appear in her
thread:

```
Bob (12:34): hi alice — first lattice message
```

Reply from Alice:

```
hi bob — reply works
```

Bob's tab polls and renders it. You have just exchanged your first
post-quantum, sealed-sender, MLS-encrypted message over a federated
home-server architecture.

---

## What just happened

The seven steps above exercised every layer of Lattice's text stack:

| Step | Layer |
|---|---|
| 3 — bootstrap | `lattice-crypto::identity` + `LatticeIdentity` |
| 3 — KP publish | `lattice-crypto::mls::generate_key_package` |
| 5 — invite | `LatticeHybridCipherSuite` + `add_member` + `PqWelcomePayload` |
| 6 — join | `process_welcome_with_storage` + ML-KEM-768 decap |
| 7 — send | `encrypt_application` + sealed sender |
| 7 — receive | `fetch_messages` + `decrypt_with_sender` |

The cryptographic guarantees you get are:

- Forward secrecy. Even if Alice's device is fully compromised
  tomorrow, today's messages are protected because MLS rotates epoch
  keys on every commit.
- Post-compromise security. The next MLS commit (every send rotates
  in the current default) re-secures the channel.
- Hybrid post-quantum. Both X25519 and ML-KEM-768 must be broken to
  recover a session key.
- Sealed sender. The home server saw a ciphertext envelope with an
  ephemeral signature; it did not see who sent it.

---

## What to do next

- **Persist your identity beyond plaintext.** The bootstrap saved a
  `version: 1` blob — anyone with read access to the browser profile
  can recover the keys. Either set a passphrase to upgrade to a
  `version: 2` Argon2id-keyed blob, or run the WebAuthn PRF ceremony
  to produce a hardware-bound `version: 3` blob. Both flows are
  documented in [identity-and-keys.md](identity-and-keys.md).
- **Create a server.** Click the ★ button instead of `+` to spin up a
  Discord-style server-membership group. See
  [servers-and-channels.md](servers-and-channels.md) for the model.
- **Try federation.** Bring up a second `lattice-server` on a
  different port and have a third tab register against it. The
  cross-server demo is in [federation.md](federation.md).
- **Switch to Tauri.** `cargo tauri dev` from
  `apps\lattice-desktop\src-tauri\` opens the same UI inside a native
  window with hardware-backed key storage. See
  [installation.md](installation.md#tauri-desktop-shell).

If anything went wrong during this walkthrough,
[troubleshooting.md](troubleshooting.md) lists the common failure
modes and their fixes. The most frequent are an unbuilt server
binary, a stale `localStorage` from a previous session, and a
mismatch between the Trunk dev port and the server's CORS allow-list
(it is `Any` by default, so this usually does not bite).
