# Lattice — DECISIONS

Closed open questions from `ROADMAP.md` and `HANDOFF.md §10`. Once an entry
appears here it is locked — do not re-open without an explicit re-open
discussion (same convention as HANDOFF §2). Update the **Status** column if
something is re-opened so the trail is preserved.

Each entry: a one-line **Decision**, a short **Rationale**, an
**Implementation** pointer to where the decision lives in code or docs, and
the **Trade-off accepted** so future readers know what we knew.

---

## Index

| ID | Topic | Milestone | Status |
|---|---|---|---|
| D-01 | RNG strategy on wasm32 | M1 | Locked |
| D-02 | HKDF info strings | M1 | Locked |
| D-03 | Hybrid signature serialization | M1 | Locked |
| D-04 | Custom MLS ciphersuite identifier | M2 | Locked (re-opened 2026-05-10, amended) |
| D-05 | Sealed sender unwrap-key derivation | M2 | Locked |
| D-06 | Federation discovery JSON schema | M3 | Locked |
| D-07 | QUIC server certificate handling | M3 | Locked |
| D-08 | Identity persistence path | M3 | Locked |
| D-09 | WebAuthn PRF fallback flow | M4 | Locked |
| D-10 | Service worker scope | M4 | Locked |
| D-11 | Transport negotiation (WT ↔ WS) | M4 | Locked |
| D-12 | Attachment retention policy | M5 | Locked |
| D-13 | Federation distrust scoring | M5 | Locked |
| D-14 | Bug bounty platform + scope | M5 | Locked |
| D-15 | Key transparency log variant | M6 | Locked |
| D-16 | Hidden membership extension scope | M6 | Locked |
| D-17 | Push provider choice | M6 | Locked |
| D-18 | PQ-DTLS-SRTP implementation path | M7 | Locked |
| D-19 | Rendezvous infrastructure topology | M7 | Locked |
| D-20 | Secure-by-default library evaluation | cross-cutting | Locked |
| D-21 | Federation discovery method | HANDOFF §10 | Locked (= D-06) |
| D-22 | Domain choice | HANDOFF §10 | **Open — needs Matt** |
| D-23 | Push notification timing | HANDOFF §10 | Locked (= D-17, lands M6) |
| D-24 | Moderation model | HANDOFF §10 | Locked |
| D-25 | Monetization pricing | HANDOFF §10 | **Open — needs Matt** |
| D-26 | Native keystore primitive (Windows) | M7 Phase G | Locked |

---

## D-01 — RNG strategy on wasm32

**Decision:** `rand::rngs::OsRng` everywhere. On `wasm32-unknown-unknown` it
routes transparently through the `getrandom` crate's `"js"` feature →
`crypto.getRandomValues()`. The workspace `Cargo.toml` already pins
`getrandom = { version = "0.2", features = ["js"] }` — keep it.

**Rationale:** `ml-kem` and `ml-dsa` accept any `CryptoRngCore`, so
choosing a single RNG type at the call sites avoids a feature-flag matrix
per target. `OsRng` is the right default on every platform Lattice ships
to (Linux/macOS/Windows native + browser).

**Implementation:** All keypair-generation call sites in
`lattice-crypto::{identity, hybrid_kex, mls}` take `&mut impl CryptoRngCore`
and the default constructors call `OsRng`. Add `tests/wasm_rng_smoke.rs`
in `lattice-core` that generates an ML-KEM-768 keypair under wasm32 and
verifies encap/decap round-trip; gate behind `cfg(target_arch = "wasm32")`.

**Trade-off accepted:** Browser RNG quality is bounded by
`crypto.getRandomValues`. Acceptable under the WebCrypto threat model
already assumed for WebAuthn; if `crypto.getRandomValues` is compromised
the whole web platform is.

---

## D-02 — HKDF info strings

**Decision:** All HKDF info strings live as `pub const` byte slices in a
new module `lattice-crypto::constants`. Format: `b"lattice/<purpose>/v<wire-version>"`.
Strings are part of the wire contract — changing one requires bumping the
wire protocol version in `lattice-protocol`.

**Locked strings (v1):**

| Constant | Bytes | Purpose |
|---|---|---|
| `HKDF_INIT` | `b"lattice/init/v1"` | PQXDH-style initial session secret derivation |
| `HKDF_MLS_INIT` | `b"lattice/mls-init/v1"` | Namespace prefix for the per-epoch external-PSK ID that folds the ML-KEM-768 secret into the MLS key schedule. Full PSK ID = prefix `\|\|` `epoch.to_le_bytes()`. Renamed in semantics from "HKDF info" to "PSK id prefix" by the D-04 re-open of 2026-05-10; the byte string is unchanged. |
| `HKDF_AEAD_NONCE_PREFIX` | `b"lattice/aead-nonce/v1"` | Direction-specific AEAD nonce prefix |
| `HKDF_IDENTITY_CLAIM` | `b"lattice/identity-claim/v1"` | Identity-claim binding hash |
| `HKDF_KEY_PACKAGE_SIG` | `b"lattice/key-package-sig/v1"` | KeyPackage signature transcript |
| `HKDF_FEDERATION_AUTH` | `b"lattice/federation-auth/v1"` | Server-to-server auth handshake |

**Removed 2026-05-10** by the D-05 follow-up cleanup (sealed-sender
seal/verify moved to `lattice-protocol::sealed_sender` per Phase F
of the M2 build plan):

| Removed constant | Original purpose | Why removed |
|---|---|---|
| `HKDF_SEALED_SENDER` | "Sealed sender envelope key" — pre-D-05 design that AEAD-encrypted the inner payload under a key derived from the MLS epoch secret. | Superseded by D-05: the inner payload is already MLS-encrypted; there is no separate envelope-key derivation. |
| `HKDF_SEALED_SENDER_MAC` | "Outer-envelope MAC key for D-05" — referenced an HMAC on the outer envelope. | D-05 actually uses Ed25519 signatures (not HMAC) for both the server's `cert.server_sig` and the sender's `envelope.envelope_sig`. No HMAC key needed. |

**Rationale:** Spelling each info string explicitly avoids the worst
silent-drift bug class in protocols: a typo in `HKDF(salt, ikm, info)`
that produces a different, equally-valid-looking key. Centralizing the
constants in one module also gives auditors a single file to review.

**Implementation:** `crates/lattice-crypto/src/constants.rs`. Re-exported
at crate root. Doc comment on each constant references this decision.

**Trade-off accepted:** Wire version v1 is locked the moment the first
production key is derived. Any change to an info string is a breaking
wire change, even if "innocuous" — by design.

---

## D-03 — Hybrid signature serialization

**Decision:** Struct with two named fixed-size byte arrays. **NOT** a
concatenated blob.

```rust
pub struct HybridSignature {
    pub ml_dsa_sig: Vec<u8>,    // always 3309 bytes per FIPS 204
    pub ed25519_sig: [u8; 64],  // fixed
}
```

Verification requires **both** signatures to validate over the same
transcript. Either failure → overall verification failure (no
"degrade-to-classical" path).

**Type ownership:** The type is defined in `lattice-crypto::identity`
(the crate that actually computes and validates the signature).
`lattice-protocol::sig` re-exports the type for wire users. This respects
the architectural invariant that `lattice-crypto` never imports
`lattice-protocol`; the dependency runs protocol → crypto.

**Rationale:** Explicit named fields prevent the length-confusion bugs
that concat encodings invite (e.g., misreading where one sig ends and the
next begins after a crate version change). Forward-compat: adding a
future third sig (e.g., a SLH-DSA backup) is a non-breaking Prost field
addition. The ~10-byte field-header overhead is irrelevant compared to
ML-DSA-65's 3309-byte payload.

**Implementation:** Defined in `lattice-crypto::identity::HybridSignature`.
The sign helper is `lattice-crypto::identity::sign`; verification is
`lattice-crypto::identity::verify`. `lattice-protocol::sig` re-exports the
type for wire-format users. The transcript that gets signed is the **same
byte string** for both signatures — not a separate transcript per
algorithm.

**Trade-off accepted:** A small extra binary-size cost in exchange for
type safety. Both classical + PQ must agree for the signature to be
valid, so a future ML-DSA-65 cryptanalytic break doesn't strand Ed25519
signatures alone (and vice versa).

---

## D-04 — Custom MLS ciphersuite identifier

**Decision:** `0xF000` — `LATTICE_HYBRID_V1`. In the IANA private-use
range (`0xF000–0xFFFF`) reserved by RFC 9420 §17.1.

**Full name:**
`LATTICE_HYBRID_X25519_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65_ED25519`.

**Base ciphersuite wrapped:** `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
(MLS ciphersuite `0x0003`). The Lattice extension folds an ML-KEM-768
encapsulated secret into the MLS `init_secret` derivation via the
`HKDF_MLS_INIT` info string (D-02). All other MLS schedule steps are
unchanged from the base suite.

**Member credential:** Custom `Credential` type carrying a
`HybridSignature` (D-03) over the leaf-node identity claim. The MLS
framing-layer signature on each handshake message remains Ed25519 (per
base suite); identity-level claims (KeyPackage external auth,
`IdentityClaim`) use `HybridSignature`. **Document this clearly** in the
mls module — it's a footgun otherwise.

**Rationale:** Sticking with `0x0003` as the base lines up with HANDOFF §8
(ChaCha20-Poly1305 AEAD, SHA-256 hash, X25519 classical KEM). Earlier
draft picks of `0x0007` (P-384 / AES-256-GCM) didn't match the spec lock
— this entry supersedes those.

**Implementation:** `crates/lattice-crypto/src/mls.rs`, behind a
`LatticeHybridCipherSuite` struct that implements `mls-rs`'s
`CipherSuiteProvider` trait. The XWING-style construction reference is
draft-mahy-mls-xwing.

**Trade-off accepted:** A private-use ciphersuite ID means no interop
with other MLS implementations. We control both ends and have no peer
impls; accepted. If we ever pursue interop, an IETF draft submission
follows the V1.5 ship (M6).

**Re-opened 2026-05-10:** The original construction — folding the
ML-KEM-768 encapsulated secret into `init_secret` via HKDF with
`HKDF_MLS_INIT` info — assumed mls-rs exposed a public hook for
rewriting `init_secret`. Implementation research found it does not:
`KeySchedule::from_epoch_secret` is `pub(crate)` and there is no
`KeyScheduleProvider` trait. Two viable paths were identified:
**(A) PSK injection** via the standard MLS PreSharedKey mechanism with
a per-epoch external PSK; or **(B) fork mls-rs** with a ~30 line patch
to `key_schedule.rs` exposing the hook. After review (see scratch/mls-rs-api.md
in the implementation session), the hybrid path was selected:

- **M2 ships PSK injection.** Per-commit, the committer encapsulates a
  fresh ML-KEM-768 shared secret targeted at every member's leaf
  init-key, stores it in `PreSharedKeyStorage` under
  `PreSharedKeyID::External(psk_nonce)` where `psk_nonce` =
  `b"lattice/mls-init/v1" || epoch.to_le_bytes()`, and references that
  id from the commit via `CommitBuilder::add_psk(...)`. mls-rs's key
  schedule then evaluates
  `epoch_secret = Expand("epoch", Extract(joiner_secret, psk_secret))`
  — the PQ secret enters the schedule under HKDF-SHA-256 at the
  position immediately following `joiner_secret` derivation. Welcome
  wrapping still depends on the hybrid HPKE at the leaf-init-key level
  (the recipient's leaf init key is ML-KEM-768-based), so the PQ
  property of the Welcome itself is preserved through a different
  mechanism than the PSK injection point.

- **M6 retains fork as a hardening fallback.** If audit in V1 reveals
  that PSK injection is inadequate (e.g., subtle attack on
  `joiner_secret` derivation that the PSK does not cover), the V1.5
  hardening milestone vendors `mls-rs/src/group/key_schedule.rs` with
  the `KeyScheduleHook` patch and migrates groups via a coordinated
  re-key. ROADMAP M6 carries this contingency as an explicit
  scope-guard.

**Security argument for PSK-equivalence:** RFC 9420 §8 defines PSK
injection as the standard mechanism for binding external secrets into
the MLS key schedule. The MLS-WG explicitly intended this extension
point to support hybrid (classical + PQ) constructions — see Wickr /
IETF mailing-list discussion of MLS PSK for PQ hybridization. The
`epoch_secret` becomes a function of the X25519-derived
`init_secret_prev` AND the ML-KEM-768 `psk_secret` under HKDF-SHA-256,
so any forward-secrecy break in either KEM alone does not compromise
the epoch — which is exactly the property the original
`init_secret`-folding construction sought.

**Wire impact:** None on outer envelopes (PSK is internal MLS framing,
not surfaced at the Lattice protocol layer). Welcome messages gain a
custom extension carrying the ML-KEM ciphertext that joiners
decapsulate and store as PSK before invoking `Client::join_group` —
implemented as a private extension with id `0xF002`. PSK lifecycle is
spelled out in `crates/lattice-crypto/src/mls.rs` module docs.

**Implementation update:** `LatticeHybridCipherSuite` (`CipherSuiteProvider`
impl) delegates 18 of 22 trait methods to the base 0x0003 RustCrypto
suite, and overrides only `signature_key_generate`,
`signature_key_derive_public`, `sign`, `verify` to handle the packed
Ed25519 + ML-DSA-65 signature scheme (D-03). The PQ folding is **not**
done in the `CipherSuiteProvider` trait at all — it's done one level
up, in a `LatticeGroup` wrapper around `mls_rs::Group` that injects the
PSK on every `commit_builder()`.

---

## D-05 — Sealed sender unwrap-key derivation

**Decision:** Signal-style anonymous sender certificates, issued per MLS
epoch by the owning home server.

**Construction:**

1. On group commit (new epoch), the owning home server issues a
   per-member `MembershipCert`:
   ```
   MembershipCert {
       group_id:               Uuid,
       epoch:                  u64,
       ephemeral_sender_pubkey: Ed25519PublicKey,  // sender-chosen
       valid_until:            DateTime<Utc>,       // ≤ epoch + 1h
       server_sig:             Ed25519Signature,    // home server signs all above
   }
   ```
2. When sending, the member signs the outer `SealedEnvelope` with the
   private key matching `ephemeral_sender_pubkey`.
3. The routing server verifies (a) `server_sig` is valid for the issuing
   home server's identity key and (b) the envelope's outer signature
   verifies under `ephemeral_sender_pubkey`. The server learns "some
   valid group member sent this" without learning *which* member.
4. The inner ApplicationMessage (encrypted under MLS group key) carries
   the real sender's `LeafNodeIndex`. Recipients decrypt and learn the
   identity from there.

**Rationale:** This is the well-trodden Signal model. MLS-only proofs
(`epoch_secret`-keyed MACs) would require the server to know
`epoch_secret`, which destroys the sealed property. Per-message
zero-knowledge proofs are overkill. The cert approach has a known
audit story.

**Implementation:**
- Wire types: `lattice-protocol::wire::{MembershipCert, SealedEnvelope}`
  (Prost-encoded per the M2 wire-types deliverable).
- Sealing / verification: `lattice-protocol::sealed_sender::{seal,
  verify_at_router, open_at_recipient}`. The crypto is plain Ed25519
  sign/verify from `ed25519-dalek` over canonically-encoded transcript
  bytes — no Lattice-specific primitive needed, so the logic lives in
  `lattice-protocol` rather than `lattice-crypto` (decided 2026-05-10
  during M2 Phase F prep). `lattice-crypto::sealed_sender` was removed
  in the same change as a dead stub.
- Cert issuance: `lattice-server::routes::issue_cert` triggered by
  `/group/{id}/commit` (M3 scope).
- Cert refresh: clients fetch fresh certs on epoch rotation; if their
  cert expires before they get a new one, they queue outbound messages
  (M3 scope).
- Federated cert verification: peer servers trust the issuing server's
  identity key (already required for federation per D-06).

**Trade-off accepted:** Adds one cert-issuance round-trip per MLS commit
to the owning server. With M5's 50-msg / 5-min commit cadence this is at
most ~12 commits/hour per active group — negligible. Cert lifetime ≤ 1h
bounds replay-after-revocation; tighter intervals can be configured per
server policy.

---

## D-06 — Federation discovery JSON schema

**Decision:** `.well-known/lattice/server` returns the following JSON,
served with `Content-Type: application/json` and a 1-hour `Cache-Control`.

```json
{
  "version": "1",
  "server": {
    "host": "home.example.com",
    "quic_port": 4433,
    "federation_pubkey": "<base64-Ed25519-32-byte>",
    "min_wire_version": "0.1",
    "max_wire_version": "0.1"
  },
  "policy": {
    "registration_open": true,
    "federation_open": true,
    "contact": "admin@example.com"
  },
  "signed_at": "2026-05-10T12:00:00Z",
  "signature": "<base64-Ed25519-64-byte>"
}
```

The `signature` field is an Ed25519 signature over the canonical CBOR
serialization of every other field (alphabetical key order, no
indeterminate-length encodings). Federation peers MUST verify the
signature against `federation_pubkey` on every fetch.

**Rationale:** Self-signed at the descriptor level is just a
freshness/integrity guard against transit tampering — real trust comes
from out-of-band channels (DNSSEC, manual pinning, KT log in M6). The
CBOR canonical form is required because JSON has too many ambiguous
serializations for a hash-stable signature.

**Implementation:** `lattice-protocol::well_known::ServerDescriptor` with
`fn verify(&self) -> Result<()>`. Peer servers cache for 24 hours;
refresh on `signed_at` change.

**Trade-off accepted:** A captured DNS path could serve a valid-looking
descriptor with a different `federation_pubkey`, redirecting federation
to a hostile server. Mitigated by KT log inclusion proofs in M6 and by
operator manual key pinning where federation relationships are
high-trust.

---

## D-07 — QUIC server certificate handling

**Decision:**

- **Dev:** self-signed cert via the `rcgen` crate. CLI / web client pins
  on first connect (Trust-On-First-Use) and refuses on mismatch.
- **Prod:** ACME via `instant-acme` crate; Let's Encrypt certs for the
  federation hostname. Automatic renewal 30 days before expiry.

**Federation peer trust:** Peer-server certs must (a) chain to a public
CA and (b) the `federation_pubkey` from `.well-known` (D-06) must match
the transport binding presented in the QUIC handshake's
`SubjectAltName` ↔ federation-pubkey mapping. Private-CA-signed certs
are rejected for federation by default.

**Rationale:** Forcing public-CA chains for federation means a network
attacker can't trivially MITM peer-server connections. The
`.well-known`-published pubkey is what we actually pin; the CA chain is
just the bootstrap. Self-signed dev mode is necessary for local testing
and is gated by an explicit `--insecure-self-signed` CLI flag that
prints a warning every invocation.

**Implementation:** `crates/lattice-server/src/tls.rs`. Documented in
`crates/lattice-server/README.md` with a deploy walkthrough.

**Trade-off accepted:** Private federations (e.g., on-prem corporate
deployments) need to explicitly add trust anchors via config — not
turnkey. Acceptable for V1; later versions may add a federation-config
trust-anchor list.

---

## D-08 — Identity persistence path

**Decision:** Use the `directories` crate to find platform-correct
locations:

| OS | Path |
|---|---|
| Linux | `~/.local/share/lattice/identity` |
| macOS | `~/Library/Application Support/chat.lattice.lattice/identity` |
| Windows | `%APPDATA%\lattice\lattice\identity` |

**File format:**
```
header  | argon2id params (m, t, p, salt)
body    | ChaCha20-Poly1305 ciphertext over Prost-encoded Identity struct
footer  | AEAD tag
```

Decryption key = `argon2id(passphrase, salt, m=64MiB, t=3, p=1)`.

**File permissions:** `0600` on Unix. Restricted ACL to the current user
on Windows (no inheritance). Refuse to read a file with looser
permissions and tell the user how to fix it.

**Override:** `--identity-path <path>` flag on `lattice-cli` for
multiple-clients-per-machine workflows.

**Rationale:** `directories::ProjectDirs::from("chat", "lattice", "lattice")`
gives the right path on every supported OS without ad-hoc per-platform
code. Argon2id parameters match the IndexedDB-store key derivation in
M4, so the cost story is consistent across native and browser.

**Implementation:** `crates/lattice-cli/src/identity_store.rs`.

**Trade-off accepted:** Argon2id at m=64MiB adds ~250ms latency to every
CLI command that touches the identity. Acceptable for CLI; cached
in-memory for the lifetime of the process.

---

## D-09 — WebAuthn PRF fallback flow

**Decision:** Three-tier capability detection at registration time:

1. **Authenticator supports PRF extension:** derive the IndexedDB store
   key from PRF output (`hmac-secret`). No passphrase required.
2. **Authenticator without PRF:** prompt for a passphrase; argon2id
   (m=64MiB, t=3, p=1) derives the store key. UI shows a "weaker auth"
   badge with a one-paragraph explanation linking to `/docs/auth-modes`.
3. **No WebAuthn at all:** refuse registration with a clear error message
   pointing at supported browsers. We do **not** ship a
   passphrase-only-no-passkey path — that would be a footgun.

**Rationale:** PRF-equipped passkeys give us hardware-bound key
derivation without the user choosing a passphrase. Where PRF isn't
available, argon2id over a passphrase is still strong enough to keep
cold-storage attacks impractical, and being transparent about the
weaker posture is honest. Refusing the no-WebAuthn case avoids
shipping a sub-Signal security floor.

**Implementation:** `apps/lattice-web/src/auth/register.tsx`. The
`WebAuthnCredentialCreationOptions.extensions.prf` field probes for
support. The badge component lives at
`apps/lattice-web/src/components/AuthPostureBadge.tsx`.

**Trade-off accepted:** Older Android (pre-13) and some hardware tokens
lack PRF; those users see the passphrase prompt. Documented limitation;
not a security regression vs Signal.

---

## D-10 — Service worker scope

**Decision:** Register at `/sw.js` with scope `/`. In M4 the SW is a
two-responsibility stub:

1. **App shell cache:** cache the static bundle for offline draft
   compose. No message data is cached by the SW.
2. **Push handler stub:** empty handler that exists for SW registration
   to be M6-ready without a code change to `index.html`.

The SW source is bundled with SRI hash pinning identical to the rest of
`lattice-web` (verified by `scripts/verify-csp.ps1`).

**Rationale:** Registering the SW in M4 even with no push functionality
means M6 only adds handler code, not registration plumbing. Cache-only
app shell is the minimal useful scope without expanding the attack
surface.

**Implementation:** `apps/lattice-web/src/sw.ts`, compiled to `/sw.js`
by Vite. Registered from `main.tsx` after passkey unlock completes.

**Trade-off accepted:** SW adds a debugging surface and a small attack
surface (poisoned SW persists across visits). Mitigation: SW code kept
under 100 LoC in M4; CSP forbids inline SW source; SW registers
`Content-Security-Policy` for its own fetches.

---

## D-11 — Transport negotiation (WebTransport ↔ WebSocket)

**Decision:** On each session start, the web client probes in this
order:

1. **WebTransport** at `https://<server>/transport/wt` (over HTTP/3)
2. On failure / unsupported: **WebSocket** at
   `wss://<server>/transport/ws` (HTTP/1.1 upgrade or HTTP/2 framed)

The chosen transport is cached in IndexedDB under
`meta.preferred_transport` with a 24-hour TTL; re-probe on TTL expiry
or on three consecutive connection failures.

Both transports carry **identical** encrypted payloads — transport
choice is a performance/availability concern, not a security one.

**Rationale:** WebTransport gives QUIC semantics (connection migration,
no head-of-line blocking) in browsers that support it. WebSocket
fallback is mandatory because Safari < 17.6 and older Firefox lack WT.
Two server endpoints is a small cost; both routes share the same handler
behind a thin transport-adapter layer.

**Implementation:** `lattice-core::transport::{webtransport, websocket}`.
The probe lives in `lattice-core::transport::negotiate`. Server-side,
`lattice-server::routes::transport::{wt, ws}` plug into the same
session-handler crate.

**Trade-off accepted:** WS lacks QUIC's connection-migration benefit;
mobile users on a flaky network behind WS will see more reconnects.
Acceptable; M7 native shells use quinn directly and bypass this.

---

## D-12 — Attachment retention policy

**Decision:** Hybrid TTL with optional early deletion via recipient acks.

| Tier | Default | Configurable values |
|---|---|---|
| Free / small | 90 days | 30 / 90 / 365 |
| Org / SaaS | 365 days | 30 / 90 / 365 / unlimited (Org tier only) |

Recipients ack via a `local_acked_at` flag on the message; once every
known recipient acks, the owning server **may** early-delete the
ciphertext blob (configurable: `cleanup.early_delete_on_full_ack`).
When the TTL hits regardless of ack state, the server deletes — clients
that haven't synced lose access.

**Schema impact:** `mls_messages` gains `delete_after TIMESTAMPTZ NOT NULL`
(indexed) and `local_ack_count INTEGER NOT NULL DEFAULT 0`.

**Cleanup job:** hourly `pg_cron` task deletes expired rows. Logs the
deletion count only — no message IDs.

**Rationale:** Forever-until-ack creates a DoS vector (recipient never
acks → infinite storage). Hard TTL only is simple but loses the
benefit of fast deletion once everyone has the message. The hybrid
matches Signal-style semantics that users already understand.

**Implementation:** `crates/lattice-server/migrations/0002_retention.sql`,
`crates/lattice-server/src/jobs/cleanup.rs`.

**Trade-off accepted:** Recipients who go silent for > TTL lose access
to old attachments. Documented in the user-facing "How retention works"
page.

---

## D-13 — Federation distrust scoring

**Decision:** Local-only per-client distrust scoring. No gossip in V1
or V1.5.

**Score sources:**
- Manual user flag (`+50` per flag, decays linearly over 90 days)
- KT-log inconsistency detected (`+100`, no decay until cleared by admin)
- Repeated invalid `.well-known` responses (`+10` per incident, capped
  at `+50`)
- TLS handshake / federation auth failures from peer (`+5`, capped at
  `+30`)

**UI thresholds:** yellow warning badge at score 30–70, red at 71+.
Users can manually clear / unblock; the score audit log is preserved
locally for transparency.

**Rationale:** Gossip-based reputation introduces a trust-graph problem
we don't want to solve in V1 — bad actors can poison reputations of
honest servers. Local-only avoids that and still gives each user a
defensible mechanism. V1.5+ may add **opt-in signed witness statements**
(not auto-gossiped) for users who explicitly subscribe to a friend's
flag list.

**Implementation:** `lattice-core::trust::DistrustScore`, persisted in
the IndexedDB `peers` store. Score deltas are emitted as tracing events
at `INFO` level.

**Trade-off accepted:** No network-effect leverage from community-wide
flagging. Acceptable; the alternative is significantly worse.

---

## D-14 — Bug bounty platform + scope

**Decision:** Self-hosted disclosure at `<domain>/security`. Email
`security@<domain>` with a published PGP key (rotated yearly). No paid
bounty initially — public credit on a hall-of-fame page + V2 beta
access for verified findings.

**Scope:**
- In scope: `lattice-crypto`, `lattice-protocol`, `lattice-server`,
  `lattice-core`, `lattice-web`, federation behavior, sealed sender,
  identity flow
- Out of scope: third-party dependencies (report upstream), DoS
  (separately tracked under operational), social engineering
- SLA: triage within 7 days, fix or mitigation within 30 days for High
  / Critical

**Disclosure timeline:** 90 days from triage to public disclosure, or
on patch release (whichever is earlier). Coordinated disclosure for
genuine zero-days affecting peer servers.

**Rationale:** HackerOne / BugCrowd overhead doesn't make sense for a
solo project at MVP scale. Self-hosted disclosure is simpler and aligns
with the AGPL ethos. Re-evaluate post-M5 if traffic and findings
volume justify a paid platform.

**Implementation:** `apps/lattice-web/public/security.txt` + `/security`
content page + GitHub Security Advisories enabled on the repo.

**Trade-off accepted:** Lower bug-research incentive than paid
platforms. Mitigation: V2 beta access is a real perk for security
researchers who want to test PQ deployments.

---

## D-15 — Key transparency log variant

**Decision:** Trillian-style append-only Merkle log per home server with
periodic cross-server witnessing. **Not** full CONIKS.

**Per-server log:**
- Each `key_bundles` insertion / rotation appends a leaf:
  `H(user_id || ml_dsa_pubkey || ed25519_pubkey || x25519_pub || ml_kem_pub || rotation_counter)`
- Daily Merkle root published at `.well-known/lattice/kt-root`
- Server returns inclusion proofs on every bundle fetch; clients verify

**Cross-server witnessing:**
- Each home server periodically (default: hourly) signs the latest root
  of every federation peer it's seen
- Witness signatures gossiped over federation control stream
- Drift (a peer publishes two different roots for the same epoch)
  triggers a user-visible warning + a `+100` distrust delta (D-13)

**Rationale:** Full CONIKS (per-user authenticated prefix tree) is
research-grade work that gates V1.5 on a complex implementation.
Trillian-style gives equivalent **key substitution detection** with
much simpler code. The privacy property CONIKS adds (no enumeration of
account holders) is partially achieved separately via hidden membership
(D-16) for group rosters; account existence remains observable, which
matches the threat model in `THREAT_MODEL.md §1`.

**Implementation:** `crates/lattice-keytransparency/` with submodules
`{log, witness, gossip}`. Server route: `/.well-known/lattice/kt-root`,
plus `/kt/proof/{user_id}` for inclusion proofs.

**Trade-off accepted:** A captured server can still enumerate all
account holders by walking the log. Account-existence privacy is a
non-goal for V1.5; users who want enumeration resistance must wait for
the long-horizon CONIKS work.

---

## D-16 — Hidden membership extension scope

**Decision:** Implement as a private MLS extension, documented in
`lattice-protocol` schema. Wire protocol bumps to **v0.2** when shipped.
Older clients refuse to join groups that enable the extension and surface
a clear "upgrade required" error.

IETF draft submission is **post-V1.5** work, not on the roadmap.

**Rationale:** Standardization is a multi-year process; gating V1.5 on
IETF consensus would push the hardening tier indefinitely. Private
extensions are explicitly permitted in MLS via the extension framework,
and Lattice currently has no peer implementations to interop with.

**Implementation:** `lattice-crypto::mls::extensions::HiddenMembership`,
hooking into `mls-rs`'s extension trait. The extension hides the
RatchetTree from out-of-group observers by encrypting node identity
under a per-group long-term secret only members possess.

**Trade-off accepted:** No cross-implementation interop until
standardization. Acceptable; we don't have peer impls yet and won't
until well after V1.5.

---

## D-17 — Push provider choice

**Decision:** UnifiedPush primary; FCM / APNS as fallback for users
without a UnifiedPush distributor installed.

**Server side:** emits Web Push API-format encrypted payloads using the
recipient's subscribed `endpoint` and `keys.p256dh` + `keys.auth` — same
format whether the endpoint is UnifiedPush or FCM/APNS. Server doesn't
distinguish.

**Client side:** registration flow tries UnifiedPush via the platform
distributor if present (Android, Linux desktop). Falls back to FCM
registration token (Android) or APNS device token (iOS via Safari Web
Push) if UP isn't available. Clear UI indication of which path is
active, with an "install UnifiedPush" hint when fallback engages.

**Rationale:** UnifiedPush is the only privacy-respecting option that
doesn't bind users to Google/Apple. FCM/APNS see encrypted payloads
under Web Push encryption, but they observe delivery timing, recipient
ID, and message counts — that's correlation metadata we'd rather not
leak. Making UP the default and FCM/APNS opt-in-via-fallback steers
users toward the better option without locking out the majority.

**Implementation:** `apps/lattice-web/src/push/{unifiedpush, fcm, apns}.ts`.
Server emits via the standard `web-push` Rust crate; provider-agnostic
payload format.

**Trade-off accepted:** FCM/APNS users have weaker metadata posture.
Mitigation: visible warning + UP install guide. Long-horizon: explore
self-hosted push relays as a third path.

---

## D-18 — PQ-DTLS-SRTP implementation path

**Decision (revised 2026-05-11):** Bypass `webrtc::RTCPeerConnection`
and assemble our own pipeline directly from the lower-level
`webrtc-rs` crates. No vendored code. Hybrid construction:
classical DTLS handshake completes first, then HKDF folds an
ML-KEM-768 encapsulated secret into the SRTP key derivation using
the info label `b"lattice/dtls-srtp-pq/v1"` (see HKDF parameter
layout amendment below).

The pipeline is:

```text
webrtc_ice::Agent  ──Conn──▶  dtls::DTLSConn  ──Conn──▶  srtp::Session
```

**Rationale (revised):** The Phase A research (`scratch/webrtc-rs-api.md`)
found that the RFC 5705 DTLS exporter is already publicly reachable
via `DTLSConn::connection_state()` (which returns a cloned
`dtls::state::State` implementing `webrtc_util::KeyingMaterialExporter`).
`srtp::Context::new` and `srtp::config::Config` accept pre-derived
master keys directly — no patching needed. The only thing the
top-level `webrtc::RTCPeerConnection` adds is SDP / JSEP / SCTP /
DataChannel machinery that Lattice doesn't use (call setup rides
MLS application messages), and that machinery is exactly what
forces a vendor-and-patch story. By bypassing it we get to
consume every webrtc-rs crate via crates.io pins with zero diff.

**Pin (May 2026):** `dtls = "0.17.1"`,
`webrtc-srtp = "0.17.1"`, `webrtc-ice = "0.17.1"`,
`webrtc-util = "0.17.1"`, `webrtc-mdns = "0.17.1"` (optional).
NB: the old `webrtc-dtls` crates.io name is stuck at 0.12.0; the
current crate is named `dtls`. The 0.17.x line is in bugfix-only
mode (the master branch's `webrtc 0.20.0-alpha.1` is a sans-I/O
rewrite — we do not target it). Upgrade plan: revisit when 0.20
stabilizes; expect to rewrite the call-state plumbing against the
sans-I/O API.

**Implementation:** `crates/lattice-media/src/handshake.rs`
(ML-KEM-768 keypair lifecycle + DTLS exporter extraction helper;
Phase B + E), `crates/lattice-media/src/srtp.rs` (HKDF fold +
SRTP context construction; Phase B + E),
`crates/lattice-media/src/ice.rs` (`webrtc_ice::Agent` wrapper;
Phase C). No `vendor/` subtree.

**Trade-off accepted:** Tracking webrtc-rs 0.17.x bugfix-only
upstream means we inherit whatever security fixes ship between
now and the eventual 0.20 cutover. The sans-I/O rewrite is
mentioned in the upstream README explicitly; budget a rewrite of
`lattice-media::call` against the new API as long-horizon.

**Superseded sub-decision (kept for history):** The pre-2026-05-11
plan was to vendor `webrtc-rs` whole under
`crates/lattice-media/vendor/webrtc-rs/` and patch the two
`extract_session_keys_from_dtls` call sites in
`webrtc/src/dtls_transport/mod.rs`. ~30 lines of diff against
~50k lines of vendored tree. Rejected on audit-surface and
maintenance grounds — the research found that bypassing
`RTCPeerConnection` is the structurally cleaner option.

### Amendment 2026-05-11 — HKDF parameter layout pinned

The original D-18 entry pinned the info label as
`b"lattice/dtls-srtp-pq/v1"` but did not specify which HKDF parameter
(`salt` / `ikm` / `info`) it goes in. The M7 Phase B scaffold
(`crates/lattice-media/src/{constants,srtp}.rs`) pins the layout
as follows; this is the canonical wire contract between Alice and
Bob — both sides MUST derive the SRTP master with these exact
inputs or media will not decrypt.

```text
ikm  = dtls_exporter || ml_kem_768_shared_secret
       // dtls_exporter is 60 B from RFC 5705 export with
       // label = b"EXTRACTOR-dtls_srtp", context = b""; pq_ss is 32 B.

salt = empty
       // HKDF-Extract degenerates to HMAC-SHA-256(0…0, ikm) per
       // RFC 5869 §3.1. Safe here because ikm already carries 60 B
       // of high-entropy classical material; all domain separation
       // lives in info.

info = b"lattice/dtls-srtp-pq/v1"  // PQ_DTLS_SRTP_INFO_PREFIX
       || call_id                  // 16 B; CallId
       || epoch_id.to_be_bytes()   // 8 B; u64 big-endian

length = 60  // SRTP_MASTER_OKM_LEN — fits webrtc-srtp's
             // (key_16 + key_16 + salt_14 + salt_14) layout.
```

Tests in `crates/lattice-media/src/srtp.rs` pin the divergence
properties (different call_id, different epoch, different pq_ss →
different SRTP master). Any future revision MUST bump
`PQ_DTLS_SRTP_INFO_PREFIX` to `…/v2` and treat it as a wire-version
break (D-18 is at v1 currently).

---

## D-19 — Rendezvous infrastructure topology

**Decision:** Self-hosted STUN/TURN per home server, reachable at
`relay.<server-host>`. No relay federation in V2.

**Client default:** use the home server's relay. Configurable in
settings to specify an alternate relay (privacy-conscious users may
prefer a relay operator outside their home jurisdiction).

**Rationale:** Federated relays introduce a multi-operator-trust problem
without proportionate user benefit at V2 scale — and the privacy
property of "no single relay sees all my call metadata" is better served
by client-side relay rotation than by server-side federation. Self-hosted
keeps the deployment story simple for V2.

**Implementation:** Bundled `coturn`-equivalent in
`crates/lattice-media/relay/` (likely vendored `webrtc-rs` TURN bits
plus our auth integration). Deploy guide in
`crates/lattice-server/README.md`.

**Trade-off accepted:** Small-operator home servers may struggle with
TURN bandwidth (a single relayed call can use 1-2 Mbps sustained).
Documented in deploy guide; V2.5+ may add managed-relay
recommendations.

---

## D-20 — Secure-by-default library evaluation

**Decision:** Lattice's chosen stack already aligns with secure-by-default
principles for the threat model. Where general-purpose libraries fall
short, we choose specialized options:

| Concern | Industry default | Lattice choice | Why |
|---|---|---|---|
| Crypto | Tink, Themis | `RustCrypto` + `ml-kem` + `ml-dsa` | Tink/Themis don't expose ML-KEM/ML-DSA; hybrid construction needs fine control |
| HTTP headers | Helmet.js (Node) | `tower-http` `SetResponseHeader` + custom layer in `lattice-server` | Rust server, not Node |
| XSS sanitization | DOMPurify (JS) | N/A for message content | Messages render as plain text + limited markdown subset; no HTML rendering from message content |
| CSRF | Gorilla CSRF | N/A | API authenticates via MLS membership cert (D-05) and federation auth (D-02); no cookies, SameSite irrelevant |
| SSRF | `ssrf_filter` (Ruby) | Custom check in `lattice-server::federation::fetch` | Block RFC 1918, link-local, loopback, IPv6 ULA before HTTP fetch |
| Input validation | `validator` crate | `validator` crate (already pinned) | Applied on every public route's request struct |
| Deserialization | SerialKiller (Java) | Prost (M0-M4) / Cap'n Proto (M5+) | Schema-validating by construction; no reflection-based codecs |
| Template engines | Mustache, Handlebars | N/A | UI is Solid (JSX-equivalent); no string templating from untrusted input |
| Regex DoS | safe-regex | N/A | No regex on user-provided patterns |
| XML attacks | defusedxml | N/A | No XML parsing anywhere in the stack |

**Rationale:** Forgoing higher-level library ergonomics is acceptable
given audit requirements — we need to be able to read every byte of
crypto code. The SSRF and validation gaps require explicit
implementation, captured as M3 / M5 work items.

**Implementation:** Track SSRF blocking in
`crates/lattice-server/src/federation/fetch.rs`. Validation
already in route handlers via `#[derive(Validate)]`.

**Trade-off accepted:** No turnkey security middleware. Mitigation:
audit checklist in `docs/AUDIT.md` (to be authored in M5) verifies each
of the above protections is in place.

---

## D-21 — Federation discovery method

**Decision:** `.well-known/lattice/server` over HTTPS per D-06. DHT
discovery deferred to long-horizon.

**Rationale:** Subsumed by D-06.

---

## D-22 — Domain choice — **OPEN**

**Status:** Needs Matt's input. Three candidates from HANDOFF §10:

- `lattice.chat` — most discoverable, on-brand, likely available
- `lattice.im` — mature messaging TLD, almost certainly premium pricing
- `getlattice.app` — Discord-style "get" prefix

**Recommendation:** `lattice.chat` primary, `getlattice.app` as
secondary / redirect target. Acquire both if budget allows. `lattice.im`
only if it's reasonably priced (the `.im` TLD historically commands
premium fees).

**Action:** Matt to check availability + pricing at preferred registrar
and commit. Update this entry when chosen. The brand assets (UI
copy, security.txt, ACME-cert hostnames) cascade from this decision —
unblock it before M3 ships.

---

## D-23 — Push notification timing

**Decision:** Lands in M6 per D-17. Confirmed deferred from V1 per
HANDOFF §10.

**Rationale:** Subsumed by D-17.

---

## D-24 — Moderation model

**Decision:** Per-server admin tools in V1 (M5). Cross-server reputation
in V1.5 (M6) is currently scoped local-only per D-13. No global
moderation.

**Per-server admin UI (M5):**
- Ban list (per home server: user_ids barred from registration)
- Message removal *within own server's storage* — cannot recall
  ciphertext from peer servers (peers retain copies; this is a
  property of federation, not a bug)
- Group takedown for groups owned by this server (revokes all
  per-epoch certs from D-05; group can't issue new commits via this
  server)
- Federation peer blocklist (refuse to federate with named hosts)

**Cross-server abuse mitigation:** depends on each home server admin's
response. The federation distrust system (D-13) gives users a
last-resort defense even if peer admins are unresponsive.

**Rationale:** Federated systems don't have a single moderation
authority; trying to build one would either centralize the network or
ship dead code. Per-server-admin tools match Matrix's model and the
broader fediverse pattern.

**Implementation:** `crates/lattice-server/src/admin/` (admin API),
`apps/lattice-web/src/admin/` (admin UI behind passkey-gated role
check).

**Trade-off accepted:** Bad actors on poorly-moderated home servers
have a longer half-life than on Discord. Mitigation: client-side
distrust scoring + KT-log-driven warnings.

---

## D-25 — Monetization pricing — **OPEN**

**Status:** Needs Matt's input. Structure is decided; numbers are not.

**Decided structure:**
- Self-hosted: free, AGPL-3.0-or-later
- SaaS-hosted home server: tiered

**Recommended tiers (placeholder — Matt to set numbers):**

| Tier | Users | Storage | Attachment retention | Price |
|---|---|---|---|---|
| Free | up to 10 | 1 GB total | 30 days | $0 |
| Pro | up to 100 | 100 GB | 365 days | $X/mo per user |
| Org | unlimited | configurable | configurable (incl. unlimited) | custom |

**Recommendation:** Defer the actual pricing decision until **post-M5**
(after the product proves usable to a small group). Setting numbers
now risks anchoring on assumptions that the M3-M5 work will invalidate.
Leave the structure documented so M5's user-facing pricing page can fill
the numbers in.

**Action:** Matt to revisit post-M5 with usage data + comparable-pricing
research (Matrix.org, Mattermost, Wire, etc.).

---

## D-26 — Native keystore primitive (Windows)

**Decision:** Phase G.1 ships the Windows keystore on **DPAPI**
(`CryptProtectData` / `CryptUnprotectData`) under
`%LOCALAPPDATA%\Lattice\keystore\`. TPM 2.0 / Windows Hello via
NCrypt is tracked as Phase G.3 — same `Keystore` trait, different
seal primitive. Linux Secret Service + macOS Secure Enclave are
Phase G.2.

**Rationale:** Microsoft's NCrypt KSP (and the Microsoft Passport
KSP that fronts Windows Hello) does not natively support Ed25519 or
ML-DSA-65 — only RSA + ECDSA over the NIST curves. Lattice's identity
spec (HANDOFF §8) pins Ed25519 + ML-DSA-65, so the TPM is a wrapping
primitive at best, not a signing primitive. Once we accept that
"hardware-backed" on Windows really means "platform-bound seal" for
this algorithm set, DPAPI is the right starting point: zero new
crypto primitives, user-bound at-rest seal, and the trait is a drop-
in replacement target when G.3 lands. The full posture rationale lives
in `scratch/m7-phase-g-plan.md`.

**Implementation:**

- `crates/lattice-media/src/keystore/mod.rs` — `Keystore` trait
  surface (`generate`, `pubkey`, `sign`, `delete`, `list`),
  `KeyHandle` opaque identifier, `KeystoreError` enum.
- `crates/lattice-media/src/keystore/memory.rs` — `MemoryKeystore`
  for tests and non-Windows G.1 fallback.
- `crates/lattice-media/src/keystore/windows.rs` — `WindowsKeystore`,
  DPAPI seal under `%LOCALAPPDATA%\Lattice\keystore\<handle>.dpapi`
  + `.pub` sidecar.
- `apps/lattice-desktop/src-tauri/src/commands.rs` — five IPC
  commands (`keystore_generate` / `keystore_pubkey` / `keystore_sign`
  / `keystore_delete` / `keystore_list`).

**Trade-off accepted:** During [`Keystore::sign`] the secret bytes
are unsealed into a `Zeroizing` buffer in process RAM, signed, and
wiped on drop. True hardware signing — where the key never leaves
the secure module — is not achievable for Ed25519/ML-DSA-65 on
Windows. G.3's TPM 2.0 upgrade narrows the at-rest attack surface
(TPM-bound wrap key vs DPAPI's user-credential-bound wrap key) but
does not change the RAM-window property. Auditors should treat
"hardware-backed" in Lattice's native-shell context as "platform-
sealed at rest, RAM-only during sign," not as full enclave-resident
signing.

**Re-open conditions:**

- A standards-track Windows API gains Ed25519 / ML-DSA-65 NCrypt
  support → reconsider the entire architecture.
- DPAPI is found cryptographically broken or trivially extractable
  → upgrade urgency on G.3.

---

## How to add a decision

1. Pick the next free `D-NN` ID.
2. Add a row to the **Index** at the top.
3. Write the entry below, following the
   Decision / Rationale / Implementation / Trade-off format.
4. If the decision originated from a "Open questions" subsection in
   `ROADMAP.md`, replace that subsection with a brief
   `**Decisions locked:** see DECISIONS.md §D-NN`.
5. If the decision originated from `HANDOFF.md §10`, mark the entry in
   §10 as resolved with a pointer to `DECISIONS.md §D-NN`.
6. If the decision changes architecture, update `ARCHITECTURE.md` with
   the concrete details and a cross-reference back to this file.

## How to re-open a decision

Decisions are locked. To re-open:

1. Append a `**Re-opened YYYY-MM-DD:**` block to the existing entry
   describing the new evidence or change in requirements.
2. Update the Status column in the index to `Re-opened`.
3. Draft the replacement decision as a sibling block; do not delete
   the original (we want the audit trail).
4. When the new decision lands, mark the original entry `Superseded by
   D-NN` and add the new entry with the next free ID.
