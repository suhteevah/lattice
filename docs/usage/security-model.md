# Security model

This page summarises Lattice's threat model in user-facing terms.
The full node-capture analysis is on the [Threat model](/wiki/threat_model/)
page. The goal of this page is to let a non-cryptographer reason
about what Lattice protects, what it does not protect, and how to
verify that the wire is doing what we claim.

If you are evaluating Lattice for a security-sensitive deployment,
read this page top to bottom. If you find anything that overclaims
or underclaims, please file a finding via the SECURITY.md flow at
the repo root.

---

## What Lattice protects against

### Harvest-now-decrypt-later

A passive network adversary records all your encrypted traffic
today, intending to decrypt it in five or ten years when a
cryptographically relevant quantum computer (CRQC) arrives.

**Defence:** every session key is derived from a hybrid construction
that combines classical X25519 ECDH with post-quantum ML-KEM-768.
Recovering the session key requires breaking **both**. The CRQC
defeats X25519 alone; ML-KEM-768 is a NIST-standardised lattice KEM
believed to be CRQC-safe.

The hybrid combiner is `HKDF-SHA-256(salt=0..., ikm = K_x25519 ||
K_mlkem, info = "lattice/init/v1", L = 64)`. The pattern follows
[draft-mahy-mls-xwing] in spirit. The full construction is on the
[Architecture](/wiki/architecture/) page under
"Crypto handshake spec."

### Active man-in-the-middle on identity

An active network adversary intercepts your traffic and tries to
impersonate the user you are talking to.

**Defence:** every identity claim and KeyPackage is signed by **two**
keypairs over the same transcript — ML-DSA-65 (PQ signature) and
Ed25519 (classical signature). Both signatures must verify; there is
no degrade-to-classical fallback. A future cryptanalytic break of
either algorithm does not strand identity claims signed under the
other.

The hybrid signature wire type is `HybridSignature { ml_dsa_sig:
Vec<u8>, ed25519_sig: [u8; 64] }`. See the locked design decisions in the source tree.

### Compromised home server

The most likely target. A nation-state with subpoena power, an
operator with administrative malice, or a compromised admin's
account.

**What the attacker gains** if they take over your home server:

- Encrypted message ciphertexts at rest. Useless without keys today,
  defeated by ML-KEM hybrid for harvest-now-decrypt-later.
- Social graph metadata — who is in what group.
- Routing metadata — who sent how many bytes to whom, when.
- Federation signing key — can forge "server X says Y" to peer
  servers, until rotation.
- Ability to drop, delay, reorder messages — DoS only.

**What the attacker does NOT get:**

- Plaintext message content. E2EE via MLS; the server never had
  the keys.
- User identity private keys. Device-local; server never had them.
- Group session keys. MLS keeps these on members' devices, not on
  the Delivery Service.
- Past messages. MLS forward secrecy via epoch ratcheting; an
  aggressive commit cadence shrinks the post-compromise window.
- Future messages after the next commit. MLS post-compromise
  security.
- Ability to impersonate users. No private signing keys on the
  server.

The realistic residual risk is **metadata**. The server inherently
routes; it sees envelopes. Mitigations:

| Mitigation | Status |
|---|---|
| Sealed sender on every DM | Shipped |
| Message padding to fixed buckets | Shipped |
| Hidden group rosters (MLS extension) | Shipped |
| Key transparency log (Trillian-style) | Shipped |
| Cross-server witnessing of KT roots | Shipped |
| Cover-traffic | Tracked, not yet shipped |
| Mixnet routing | Long-horizon, not committed |

### Compromised client device

Qualitatively worse than server compromise because the client has
the private keys.

**Browser (V1):**

- XSS in any dependency. Defence: strict CSP (no `unsafe-eval`,
  no `unsafe-inline`, allowlisted origins), SRI on every asset,
  audit of every dependency added.
- Malicious browser extensions with `<all_urls>` permission. **We
  cannot fully defend against this.** A browser extension with broad
  permissions can read DOM, exfiltrate `localStorage`, and observe
  every input. Document the limitation; recommend users keep
  extension count minimal.
- IndexedDB / `localStorage` cross-origin access. Defence: browser
  same-origin policy backstopped by CSP.
- Cold-storage attack (attacker has device, doesn't have
  passphrase). Defence: Argon2id KDF (m=64 MiB, t=3, p=1) over the
  passphrase before any key material decrypts; brute-force becomes
  impractical.
- Warm-session theft (attacker steals a browser session token).
  Defence: session timeout with key re-derive; root identity stays
  WebAuthn-bound.

**Native (V2 / Tauri):**

- Root key in DPAPI / Secret Service / Keychain at rest; sealed
  during sign into a `Zeroizing` RAM buffer.
- Phase G.3 moves to TPM 2.0 / Secure Enclave wrap key —
  hardware-bound at rest.
- OS keychain replaces `localStorage` for session credential
  storage.
- Platform screen-recording flags (FLAG_SECURE etc.) block
  OS-level capture. Implemented when Tauri Mobile shells ship.

Residual: rooted device / jailbroken phone bypasses most of this.
Lattice does not attempt to defend against attackers with
kernel-level access on the user's own device.

**Common mitigations (browser and native):**

- Device revocation via MLS Remove proposal. Any sibling device of
  the same user can boot the compromised one. Removed device's
  per-epoch keys stop working immediately on next decrypt.
- Forward secrecy protects past messages from network captures even
  if the current device is fully compromised.

### Cryptographic algorithm failure

Treat each primitive as potentially breakable and design for
graceful degradation.

| Primitive | If broken alone | Mitigation |
|---|---|---|
| X25519 | Hybrid KEM survives via ML-KEM-768 | Hybrid construction |
| ML-KEM-768 | Hybrid KEM survives via X25519 | Hybrid construction |
| Ed25519 | Future identity forgery possible | ML-DSA-65 co-signature |
| ML-DSA-65 | Same as Ed25519 in reverse | Ed25519 co-signature |
| ChaCha20-Poly1305 | All past + future ciphertext readable | **No second AEAD layer — accepted risk.** Algorithm has very strong security margin. |
| BLAKE3 / SHA-256 | Hash forgery; KT log corruptible | Two-hash strategy in KT log |

The AEAD layer is the single point of cryptographic failure. If
ChaCha20-Poly1305 falls, every Lattice message past and future is
readable. The accepted risk is grounded in the algorithm's very
large security margin (~256-bit security, no known weakness in
~14 years of cryptanalysis).

---

## What Lattice does NOT protect against

Honesty in scope, lifted from THREAT_MODEL §5:

- **A targeted attacker with kernel-level access to the user's
  device.** Game over. We make this expensive but not impossible.
- **A user who shares their passphrase or device with the
  attacker.** No cryptography fixes this.
- **A user installing a malicious browser extension with broad
  permissions.** See the browser-client compromise section above.
- **Real-time correlation attacks at the network ISP level.** Mixnet
  integration is long-horizon, not committed.
- **A global passive adversary observing all traffic.** Metadata
  exposure to GPAs is the fundamental open problem of federated
  systems; we shrink it with padding and sealed sender but do not
  eliminate it.
- **Notification metadata leaks.** The notification payload is
  deliberately generic ("Lattice: New message") with zero
  identifying content. The no-PII-in-notifications constraint is
  enforced at the function signature: the helper that surfaces a
  notification takes no parameters.
- **Traffic correlation.** A passive observer can correlate
  "request bursts" between clients and a server. A future
  cover-traffic toggle injects timed noise as a mitigation.

---

## Sealed sender

The construction that hides sender→recipient linkage from the routing
home server. The wire format is `MembershipCert` + `SealedEnvelope`
in `crates/lattice-protocol/src/wire.rs`.

Flow:

1. On group commit (new epoch), the owning home server issues a
   per-member `MembershipCert`:

   ```rust
   MembershipCert {
       group_id:               Uuid,
       epoch:                  u64,
       ephemeral_sender_pubkey: Ed25519PublicKey,  // sender-chosen
       valid_until:            DateTime<Utc>,       // ≤ epoch + 1h
       server_sig:             Ed25519Signature,    // server signs
   }
   ```

2. When sending, the member signs the outer `SealedEnvelope` with
   the private key matching `ephemeral_sender_pubkey`.

3. The routing server verifies (a) `server_sig` is valid for the
   issuing home server's identity key, and (b) the envelope's outer
   signature verifies under `ephemeral_sender_pubkey`. The server
   learns "some valid group member sent this" without learning
   **which** member.

4. The inner ApplicationMessage (encrypted under the MLS group
   key) carries the real sender's `LeafNodeIndex`. Recipients
   decrypt and learn the identity from there.

The construction is the well-trodden Signal model. MLS-only proofs
(`epoch_secret`-keyed MACs) would require the server to know
`epoch_secret`, which destroys the sealed property. Per-message
zero-knowledge proofs are overkill. The cert approach has a known
audit story.

Trade-off: one cert-issuance round-trip per MLS commit to the owning
server. With the current 50-msg / 5-min commit cadence this is at
most ~12 commits/hour per active group — negligible. Cert lifetime
≤ 1h bounds replay-after-revocation.

---

## MLS group keys

Every Lattice conversation runs over MLS RFC 9420. The MLS key
schedule rotates every commit (a "ratchet step") and gives:

- **Forward secrecy.** A compromise of today's keys does not reveal
  past messages.
- **Post-compromise security.** A compromise is healed by the next
  commit; future messages are safe again.
- **Group scalability.** MLS scales to ~50,000 members per group
  without per-member overhead.

Lattice's custom ciphersuite — `LATTICE_HYBRID_V1` (ID `0xF000`) —
wraps the base `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
(`0x0003`) suite and folds an ML-KEM-768 secret into the key schedule
via **per-epoch external PSK injection**.

Concretely, per commit:

1. The committer encapsulates a fresh ML-KEM-768 shared secret to
   every member's leaf init key.
2. Stores the secret in `PreSharedKeyStorage` under
   `PreSharedKeyID::External(psk_nonce)` where
   `psk_nonce = b"lattice/mls-init/v1" || epoch.to_le_bytes()`.
3. References the PSK from the commit via
   `CommitBuilder::add_psk(...)`.
4. mls-rs's key schedule computes
   `epoch_secret = Expand("epoch", Extract(joiner_secret, psk_secret))`.

The PQ secret enters under HKDF-SHA-256 at the position immediately
following `joiner_secret` derivation. Any forward-secrecy break in
either KEM alone does not compromise the epoch — which is exactly
the property the original `init_secret`-folding construction sought.

---

## Hidden membership

The hidden-membership MLS extension hides the RatchetTree from
out-of-group observers. The implementation is
`lattice-crypto::mls::hidden_membership_rules`.

What "hidden" means in practice:

- A passive observer who captures Welcome bytes for a hidden group
  cannot enumerate the group's roster from the Welcome's
  `RatchetTreeExt` — it is omitted.
- An attacker compromising the home server still sees who **joined**
  (because Welcomes are addressed to user_ids by the routing logic),
  but cannot enumerate who is currently in the group from the wire
  bytes.
- A captured home server can still enumerate group members via its
  own commit-log replay. Account-existence privacy is a non-goal
  for V1.5.

The integration test `hidden_membership_omits_ratchet_tree_from_welcome`
parses the server-visible Welcome bytes and confirms the
RatchetTreeExt tag is absent.

---

## Key transparency

A Trillian-style append-only Merkle log lives in
`crates/lattice-keytransparency/`. Per home server:

- Each `key_bundles` insertion or rotation appends a leaf:
  `H(user_id || ml_dsa_pubkey || ed25519_pubkey || x25519_pub ||
  ml_kem_pub || rotation_counter)`.
- Daily Merkle root published at `/.well-known/lattice/kt-root`.
- Server returns inclusion proofs on every bundle fetch; clients
  verify.

Cross-server witnessing:

- Each home server periodically (default: hourly) signs the latest
  root of every federation peer it has seen.
- Witness signatures gossip over the federation control stream.
- Drift (a peer publishes two different roots for the same epoch)
  triggers a user-visible warning and a +100 distrust delta.

The acceptance gate test
`malicious_swap_detection_simulation` simulates a server trying to
substitute Bob's key bundle and verifies the client's inclusion
check rejects.

Client-side verification (the chat shell calls
`/.well-known/lattice/kt-root` and verifies inclusion proofs on
every KP fetch) is follow-on UI plumbing — the cryptographic
machinery is shipped; the chat shell does not yet surface KT
warnings.

---

## Notifications constraint — no PII in payloads

When the WebSocket push fires for server-membership group
messages, the notification payload **remains generic** — no server
name, no sender, no group_id. This applies to every push surface
(UnifiedPush, FCM, APNS, web-push, Tauri OS notification API).

What the OS / push provider observes:

- A delivery to your endpoint.
- A timestamp.
- A payload size (padded to a fixed bucket).

What the OS / push provider does **not** observe:

- Who sent the message.
- Which group / server / channel it landed in.
- The plaintext (encrypted under the recipient's push subscription
  `keys.p256dh` + `keys.auth` per Web Push API).
- The conversation label.

The notification text the user sees is intentionally minimal —
something like "new lattice message" with the channel / sender
hidden until the user opens the app and the chat shell has access to
the decrypted scrollback.

This is stricter than Signal's default ("Alice: <preview>"), and
deliberately so. The home server can correlate notifications to
conversations from the per-group fan-out path; the push provider
cannot.

---

## Verifying the wire (paranoid mode)

If you want to verify that Lattice is doing what we claim, here are
the levers:

### 1. Tracing logs

Every public function in every crate has `#[instrument]` and emits
structured tracing events. Run the server with:

```
RUST_LOG=lattice_server=trace,lattice_crypto=trace
```

You will see every key derivation, every encrypt/decrypt, every
sealed-sender verification, every commit acceptance. The logs are
verbose by design (per CLAUDE.md — do not reduce).

Key material is **never** logged. The convention enforced by code
review is "log counts, lengths, identifiers only — never bytes." If
you find a log line that emits private material, please file a
SECURITY issue.

### 2. Wireshark

Capture between your browser and the server. You will see:

- HTTPS-encrypted POSTs and GETs against the home server routes.
- A federation push to `/federation/inbox` carries a base64-encoded
  body. The `commit_b64` and `welcomes[].mls_welcome_b64` are MLS
  bytes; you can decode them with the `mls-rs` test harness if you
  want to inspect the format.

### 3. Reading the source

The cryptographic surface is small enough to read end-to-end:

| Module | Lines | What it does |
|---|---|---|
| `crates/lattice-crypto/src/identity.rs` | ~300 | Hybrid signature gen / sign / verify. |
| `crates/lattice-crypto/src/hybrid_kex.rs` | ~250 | X25519 + ML-KEM-768 hybrid KEM. |
| `crates/lattice-crypto/src/aead.rs` | ~150 | ChaCha20-Poly1305 wrapper. |
| `crates/lattice-crypto/src/padding.rs` | ~80 | Fixed-bucket padding. |
| `crates/lattice-crypto/src/mls/` | ~1,200 | MLS hybrid ciphersuite + PSK injection + Welcome PQ extension. |
| `crates/lattice-protocol/src/sealed_sender.rs` | ~400 | Sealed sender seal / verify / open. |

The build is `forbid(unsafe_code)` workspace-wide (with one carve-out
for the keystore FFI in `lattice-media`, documented inline with
`// SAFETY:` comments).

### 4. Verifying a peer's federation pubkey

The descriptor at `/.well-known/lattice/server` carries the
`federation_pubkey_b64`. Compare it against an out-of-band value (a
Signal message, a phone call). The full signed-descriptor wrapper
is future work — today the response is the unsigned JSON.

### 5. KT log inclusion proofs

(UI surfacing is follow-on work.) The home server publishes a daily
Merkle root at `/.well-known/lattice/kt-root`. The client fetches
inclusion proofs with every KP fetch and verifies them against the
cached root. A silent key substitution by the home server leaves a
detectable inconsistency in the log.

---

## Auditability

Lattice is AGPL-3.0-or-later. The entire source tree is published.
The cryptographic primitives are standard NIST / IETF algorithms
implemented by `RustCrypto`, `ml-kem`, `ml-dsa`, and `mls-rs`. The
custom ciphersuite shipped in `lattice-crypto::mls` is ~1,200 lines.

There has been **no formal external audit** of Lattice. Bug-bounty
disclosure flows live at `SECURITY.md` at the repo root.
Researchers get public credit on a hall-of-fame page and beta
access for verified findings.

---

## Cross-references

- [Threat model](/wiki/threat_model/) — authoritative
  node-capture analysis, with per-attacker breakdown.
- [Architecture](/wiki/architecture/) — protocol topology
  and storage model.
- [identity-and-keys.md](identity-and-keys.md) — your keys at rest.
- [federation.md](federation.md) — server trust + TOFU + distrust
  scoring.
