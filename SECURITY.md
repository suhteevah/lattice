# Security policy

> **Status:** Lattice is pre-1.0. The protocol surface, wire formats,
> and key handling are evolving — assume security properties hold for
> the documented happy path but expect rough edges off it. Don't yet
> rely on Lattice for high-risk threat models.

## Threat model

The full threat model lives in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). High-level goals:

1. **PQ-hybrid confidentiality.** Forward secrecy + post-compromise
   secrecy against both classical and quantum adversaries via the
   custom MLS ciphersuite `LATTICE_HYBRID_V1` (0xF000) — Ed25519 +
   ML-DSA-65 for identity, X25519 + ML-KEM-768 KEM with HKDF
   combiner, ChaCha20-Poly1305 AEAD.
2. **Server never sees plaintext.** Schema migrations that add a
   plaintext message column fail CI by policy. Sealed-sender D-05
   envelopes hide the sender id from the routing server.
3. **Federation without full mesh.** Home servers exchange MLS
   ciphertext over QUIC + TOFU-pinned federation keys; no Matrix-
   style full-mesh sync.
4. **Identity at rest under user control.** Browser keys live under
   `window.localStorage["lattice/identity/v1"]`; v3 blobs are
   sealed under a WebAuthn-PRF-derived KEK so a stolen browser
   profile alone can't recover them.

## Reporting a vulnerability (D-14)

Lattice runs a **self-hosted disclosure** program. There is no
bug-bounty cash pool yet — credit + V2 beta access is the current
incentive. The program will revisit cash payouts after V1 ships
and there's revenue to fund them.

### How to report

- **Email:** `security@lattice.chat` (PGP key fingerprint and inline
  key TBA once the domain DNS lands).
- **GitHub:** `github.com/suhteevah/lattice` is the public repo but
  do **NOT** open public issues for vulnerabilities. Use the email
  channel above.
- **Encrypted alternative:** if you'd rather encrypt the report,
  include your Lattice user_id in a one-line plaintext email and the
  team will reach out over Lattice itself to continue the
  conversation.

### Scope

- The Rust workspace at `github.com/suhteevah/lattice` —
  `lattice-server`, `lattice-cli`, `lattice-crypto`,
  `lattice-protocol`, `apps/lattice-web`.
- Protocol-level issues against the wire formats in
  `lattice-protocol::wire`, the MLS ciphersuite
  `LATTICE_HYBRID_V1`, the PSK injection scheme (D-04), and the
  sealed-sender construction (D-05).

Out of scope (today):
- Cap'n Proto schema work (still on the M5 roadmap; interim Prost
  is what ships).
- The federation testbed nodes at `pixie`, `cnc`, `kokonoe-WSL` —
  those run pre-release builds for development use only and aren't
  production targets.

### What we'll credit

Reports that meet **all** of the following get a Security Hall of
Fame entry (and, when reasonable, a V2 beta invite):

- Demonstrate an attack against a documented security property of
  Lattice (confidentiality, sender unlinkability, forward / post-
  compromise secrecy, federation key authentication, ratchet
  isolation).
- Include either a working PoC or a precise enough description that
  the team can write a regression test from your report.
- Give the team a reasonable disclosure window (we target 90 days
  for protocol issues, 30 days for implementation bugs, with
  reasonable extensions for complex fixes).

### What we won't accept

- DoS via volumetric flooding of the federation transport (real DoS
  defenses are M6 / M7 work).
- Self-XSS or other vectors that require the victim to paste
  attacker-supplied code into their browser console.
- Issues in third-party dependencies that are out of our patch
  surface (those should go to the upstream project).

## Decision log

Every security-relevant choice is documented in
[`docs/DECISIONS.md`](docs/DECISIONS.md). The most operationally
relevant entries for security researchers:

- **D-02** — HKDF info string format; what's in the key derivation
  context.
- **D-03** — hybrid signature serialization (named-field Prost
  struct, not a concatenated blob).
- **D-04** — MLS ciphersuite + PSK injection (re-opened 2026-05-10
  for PSK-injection path).
- **D-05** — sealed-sender via Ed25519 sig over canonical wire bytes
  (no inner-envelope key, no HMAC).
- **D-06** — `.well-known/lattice/server` signed federation
  descriptor.
- **D-08** — identity-at-rest: Argon2id-keyed ChaCha20-Poly1305.
- **D-09** — WebAuthn passkey flow: PRF / passphrase+badge /
  refuse three-tier.

## Known limitations (M4-shipped state)

These are documented gaps, not bugs:

- **No QUIC transport yet.** Federation runs over HTTPS via
  `reqwest` + `axum`. QUIC is on the M3 polish backlog.
- **No sqlx-backed Postgres yet.** Server state is in-memory with
  JSON-snapshot persistence on SIGTERM. Multi-process / multi-host
  state is not yet supported.
- **No Cap'n Proto wire migration yet.** Prost is the interim
  format. M5 deliverable.
- **No multi-member MLS PSK rotation yet.** 1:1 groups work
  end-to-end; >2 members require the M5.5 PSK-rotation surgery
  described in HANDOFF.
- **No production CSP delivery yet.** The header lives in
  `apps/lattice-web/csp.json` and is verified by
  `scripts/verify-csp.ps1`, but no host server is wired to serve
  it in front of `dist/`.
