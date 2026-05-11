# Lattice — THREAT MODEL

This document analyses what an attacker gains from compromising each type of
node in the Lattice topology, what is cryptographically protected against
that compromise, and what residual exposures remain. Update whenever the
architecture or mitigation set changes.

## Topology recap

Lattice has three node types:

1. **Federated home server** — `lattice-server` instance. Holds user accounts,
   group state, encrypted message store. Federates with peer servers over QUIC.
2. **Client** — V1: a browser tab running `lattice-web` with `lattice-core`
   compiled to WASM. V2: a Tauri shell on desktop or mobile. Holds private keys
   and decrypted state.
3. **Rendezvous node** — V2 only. STUN/TURN-like service for P2P NAT traversal
   on voice/video. Sees connection-attempt metadata, never plaintext media.

## Attacker capabilities considered

- **Passive network observer.** Sees traffic, cannot modify.
- **Active network adversary.** Can intercept, drop, replay, inject.
- **Compromised home server operator.** Has full filesystem + process access
  to one home server.
- **Compromised client device.** Has runtime access to one browser tab or one
  native client.
- **Future quantum adversary.** Has a CRQC; can break ECDH and Ed25519 but not
  AES-256 or ML-KEM/ML-DSA.

## 1. Home server compromise

The most likely capture target. Probably the only target a sophisticated
nation-state would bother with at scale.

### What the attacker gains

| Asset | Notes |
|---|---|
| Encrypted message ciphertexts at rest | Useless without keys (today). Harvested for QC era — defeated by ML-KEM hybrid. |
| Social graph (who is in what group) | **Real exposure.** Mitigated in V1.5 by hidden-membership MLS extension. |
| Routing metadata (who → who, when, payload size) | Size mitigated by V1 padding; timing residual; recipient set mitigated in DMs by sealed sender. |
| Federation signing key | Can forge "server X says Y" to peer servers. Mitigated by federation distrust signaling + key rotation. |
| Ability to drop / delay / reorder messages | DoS only. Mitigated in V1.5 by multi-server store-and-forward. |
| Ability to inject signed-by-server statements | No effect on user-to-user E2EE. |

### What the attacker does NOT get

| Asset | Why |
|---|---|
| Plaintext message content | E2EE via MLS; server never had keys. |
| User identity private keys | Device-local; server never had them. |
| Group session keys | MLS keeps these in members' devices, not the Delivery Service. |
| Past messages | MLS forward secrecy via epoch ratcheting. |
| Future messages after next commit | MLS post-compromise security; aggressive commit cadence shrinks the window. |
| Ability to impersonate users | No private signing keys on server. |

### Residual exposure

**Metadata.** The server inherently routes; it sees envelopes. This is the
realistic residual risk. Mitigation tracks:

- V1: sealed sender for DMs, message padding for sizes.
- V1.5: hidden group rosters, key transparency log to detect silent key
  substitution attacks during the compromise window.
- Long-horizon: optional mixnet routing for full metadata anonymity.

## 2. Client compromise

Qualitatively worse than server compromise because the client has the keys.

### V1 — browser tab compromise

The browser surface introduces failure modes native doesn't have:

- **XSS in any dependency.** Mitigation: strict CSP (no `unsafe-eval`, no
  `unsafe-inline`, allowlisted origins), SRI on every external script, audit
  of every dependency added.
- **Malicious browser extensions.** Extensions with `<all_urls>` permission
  can read DOM and exfiltrate keys. **Cannot fully defend against this.**
  Document the limitation; recommend users keep extension count minimal.
- **IndexedDB extraction by other origins.** Browser same-origin policy
  protects this; CSP backstops.
- **Cold storage attack** (attacker has device, doesn't have passphrase).
  Mitigation: argon2id KDF over passphrase before any key material is
  decrypted; m=64MiB makes brute-force impractical.
- **Warm session theft** (attacker steals a browser session token).
  Mitigation: session timeout with key re-derive; root identity stays
  WebAuthn-bound.

### V2 — native client compromise

Improves over V1 in three ways:
- Root key in Secure Enclave / StrongBox / TPM, never extractable.
- OS keychain replaces IndexedDB for session credential storage.
- Platform screen-recording flags (FLAG_SECURE etc.) block OS-level capture.

Residual: rooted device / jailbroken phone bypasses most of this. We don't
attempt to defend against attackers with kernel-level access on the user's
own device.

### Common mitigations (V1 and V2)

- **Device revocation** via MLS Remove proposal. Any sibling device of the
  same user can boot the compromised one. Removed device's epoch keys
  immediately stop working.
- **Forward secrecy** still protects past messages from network captures
  even if current device is compromised.

## 3. Rendezvous node compromise (V2 only)

### What the attacker gains

- Connection-attempt metadata (peers asking to be matched).
- Roughly the same traffic-analysis exposure as a captured STUN/TURN operator.

### What the attacker does NOT get

- Plaintext media. DTLS-SRTP handshake is end-to-end PQ-hybrid; rendezvous
  node only facilitates ICE candidate exchange.
- Long-term identity keys.

### Mitigation

- Multiple rotating rendezvous servers; client picks by latency + reputation.
- Per-call ephemeral DTLS state.

## 4. Cryptographic algorithm failure

Treat each primitive as potentially breakable in the future and design for
graceful degradation.

| Primitive | If broken alone | Mitigation |
|---|---|---|
| X25519 | Hybrid KEM survives via ML-KEM-768 layer. | Hybrid construction. |
| ML-KEM-768 | Hybrid KEM survives via X25519 layer. | Hybrid construction. |
| Ed25519 | Future identity forgery possible. | ML-DSA-65 co-signature on identity claims (V1.5). |
| ML-DSA-65 | Same as Ed25519 in reverse. | Ed25519 co-signature. |
| ChaCha20-Poly1305 | All past + future ciphertext readable. | No second AEAD layer — accepted risk. Algorithm has very strong security margin. |
| BLAKE3 / SHA-256 | Hash forgery; key transparency log corruptible. | Two-hash strategy in key transparency log (V1.5). |

## 5. What we explicitly do NOT defend against

Honesty in scope:

- **A targeted attacker with kernel-level access to the user's device.** Game
  over. We make this expensive but not impossible.
- **A user who shares their passphrase or device with the attacker.** No
  cryptography fixes this.
- **A user installing a malicious browser extension with broad permissions.**
  See V1 client section.
- **Real-time correlation attacks at the network ISP level.** Mixnet
  integration is long-horizon, not committed.
- **A global passive adversary observing all traffic.** Metadata exposure to
  GPAs is the fundamental open problem of federated systems; we shrink it
  with padding and sealed sender but do not eliminate it.

## 6. Change log

- 2026-05-10: Initial document. Reflects locked Step 1 architecture.
