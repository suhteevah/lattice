# Lattice user documentation

Welcome to the Lattice user guide. This set of pages describes how to
install, configure, and operate Lattice — a post-quantum, end-to-end
encrypted, federated messaging platform. The reference pages live
under `docs/usage/`; the internal design history (HANDOFF, DECISIONS,
ARCHITECTURE, THREAT_MODEL, ROADMAP) lives one directory up and is the
single source of truth for engineers working on the code itself.

---

## What is Lattice

Lattice is a chat application that looks and feels like Discord, behaves
like Matrix at the network layer, and uses cryptography that survives a
sufficiently large quantum computer. Concretely:

- **Browser-first.** The default client is a pure Rust + Leptos PWA
  compiled to WebAssembly. There is no JavaScript framework, no npm,
  no React, no transpiler — just a `wasm32-unknown-unknown` bundle
  served as static files.
- **Native shells.** A Tauri 2 desktop wrapper packages the same Leptos
  bundle alongside native code for voice and video. Mobile shells are
  in flight.
- **Federated, not central.** Every Lattice account lives on a **home
  server**. Servers federate with each other on demand. There is no
  central directory and no privileged operator.
- **End-to-end encrypted by default.** Every message rides MLS (RFC
  9420) over a hybrid post-quantum ciphersuite. The server stores
  ciphertext only. There is no plaintext message column anywhere in
  the data model, and a schema migration that tried to add one would
  fail CI by policy.

If you have used Discord, the conceptual map is one-to-one:

| Discord | Lattice |
|---|---|
| Account | User identity (32-byte user_id) |
| Server / guild | Server-membership MLS group (★ prefix) |
| Channel | Per-channel MLS group inside a server |
| DM | 1:1 MLS group with a deterministic group_id |
| Group DM | N-party MLS group with a random group_id |

The substantive difference is that every one of those constructs is
cryptographically end-to-end encrypted, and the operator of the home
server you log into has the same view of your traffic as a NAT
gateway — they see envelopes, not messages.

---

## What problem does Lattice solve

There are roughly three threat models worth naming.

**Harvest-now-decrypt-later.** A nation-state adversary records
encrypted traffic today and decrypts it five or ten or fifteen years
from now when a cryptographically relevant quantum computer arrives.
Signal, WhatsApp, iMessage, and Matrix all use classical-only
key-exchange algorithms (X25519 and friends); recorded sessions are
trivially decryptable on the day the CRQC ships. Lattice ships a
**hybrid** key exchange from day one — every session derives its keys
from both classical X25519 and post-quantum ML-KEM-768. Recovering the
plaintext requires breaking both.

**Centralised platform risk.** Discord can ban your account, leak your
message history, get acquired, change its terms, or shut down. Matrix
solves this with federation but inherits Matrix's UX. Lattice runs the
Matrix decentralisation story on a Discord-class interface, with the
home server you trust being the one you (or a friend) operate.

**Surveillance metadata.** Even with end-to-end encryption, the server
that routes your traffic can see who is talking to whom and when.
Lattice ships **sealed-sender** envelopes on every DM, **hidden group
rosters** as an MLS extension, and a **key transparency log** that
makes silent key substitution detectable. Cover-traffic and mixnet
integrations are tracked but unshipped — see
[security-model.md](security-model.md).

---

## Who should use Lattice

Lattice is a fit for you if any of the following are true:

- You want a real Discord replacement that you control end-to-end.
- You operate a small organisation that needs PQ-safe communications
  before regulators or insurers require it (defence, finance, biotech,
  privacy-sensitive consultancies).
- You want to self-host without re-learning Matrix's complexity
  budget.
- You are an MLS / post-quantum cryptography enthusiast and want
  something to read code in.

Lattice is **not** a fit yet if:

- You need fully-managed SaaS today with a billing portal. The
  self-hosted path is the supported one; the managed SaaS tier is
  decided in structure (DECISIONS §D-25) but not in price.
- You need a feature-parity Slack clone with threads, code blocks,
  integrations marketplaces, and Office365 SSO. Those land
  incrementally. Today's surface is DMs, groups, and Discord-style
  servers with one implicit channel per server.
- You need iOS or Android native clients. Mobile shells are tracked
  in ROADMAP M7 Phase H but not shipped.

---

## Key differentiators (comparison)

The table below summarises Lattice's posture against the four most
common alternatives. PQ stands for post-quantum.

| Property | Signal | Matrix | Discord | **Lattice** |
|---|---|---|---|---|
| End-to-end encryption | Yes | Optional per room | No | **Yes, mandatory** |
| Post-quantum hybrid KEX | Partial (PQXDH on 1:1) | No | No | **Yes, all sessions** |
| Federation | No | Yes | No | **Yes** |
| Server architecture | Central, one operator | Federated | Central, one operator | **Federated** |
| Group key agreement | Sender keys (Sesame) | Megolm + Olm | N/A | **MLS RFC 9420** |
| Identity at rest | Hardware where possible | Passphrase | Email + password | **WebAuthn PRF / passkey / OS keychain** |
| Message metadata privacy | Sealed sender | Limited | Visible to Discord | **Sealed sender + hidden membership** |
| Key transparency | Audited (announce-only) | None | None | **Trillian-style log with cross-server witnessing** |
| License | AGPL-3.0 (server) | Apache-2.0 (server) | Proprietary | **AGPL-3.0-or-later (all code)** |
| Voice / video | Yes (classical) | Yes (classical) | Yes (classical) | **PQ-hybrid DTLS-SRTP (M7, in progress)** |

The licensing position is intentional. AGPL forces a SaaS rehost of
Lattice to publish their changes, which is the only license that
defends a federated open-source product from a vertically-integrated
proprietary fork.

---

## Design system

Lattice has a single anchor colour: **lilac** at `#C8A2C8`. Every
surface, accent, and badge in the UI derives from a small palette
documented at `design/tokens/`. Dark mode is the default. The UI is
deliberately quiet — two type weights only (400 and 500), sentence
case throughout, no Title Case, no ALL CAPS except literal const
names. The conscious intent is to look unlike Discord and Slack, not
because either is wrong but because Lattice is a different product
and should feel different.

The token system lives as `design/tokens/{colors,typography,
spacing}.json`. Tailwind in lattice-web is configured to extend from
those JSON files; the future Tauri shells will consume the same files.
If you fork Lattice and want to skin it, replace the token files —
you should not need to touch the CSS itself.

---

## License

AGPL-3.0-or-later. The full text lives at `LICENSE` at the root of the
repository. If you redistribute a modified version, or run a SaaS that
exposes Lattice's source-affecting functionality to users, you must
publish your modifications under the same license. Self-hosting for
your own use or for a private group does not trigger any obligation.

---

## How to read these docs

The pages here are sequenced for someone starting with no Lattice
context. A reasonable reading order:

1. [quickstart.md](quickstart.md) — five-minute walkthrough.
2. [installation.md](installation.md) — getting to a running client.
3. [identity-and-keys.md](identity-and-keys.md) — how your keys
   work.
4. [messaging.md](messaging.md) — DMs, groups, scrollback, sealed
   sender.
5. [servers-and-channels.md](servers-and-channels.md) —
   Discord-style servers, admin model, multi-channel posture.
6. [federation.md](federation.md) — how servers find and talk to
   each other.
7. [security-model.md](security-model.md) — threat model summary,
   what's protected and what isn't.
8. [self-hosting.md](self-hosting.md) — running your own home
   server.
9. [api-reference.md](api-reference.md) — every server HTTP
   endpoint, with request and response shapes.
10. [troubleshooting.md](troubleshooting.md) — common errors and
    fixes.
11. [development.md](development.md) — building, testing, and
    contributing.

Each page is self-contained and cross-references the others where
relevant. If you find a page that says "see HANDOFF.md" without a
working pointer, please file an issue.

---

## Project status

Lattice is at milestone **M7** — voice and video are in progress; text
chat survives daily use. The browser PWA can register, exchange
keypackages, form 1:1 and N-party MLS groups, send and receive sealed
envelopes, survive page reload with scrollback intact, and federate
across home servers. The Tauri desktop wrapper builds on Windows and
Linux. iOS and Android shells are not shipped. Voice and video are
proven cryptographically end-to-end in a same-process loopback (Phase
E.2 smoke test); cross-machine signalling and OS audio capture are M7
follow-up work.

If a feature in these docs is annotated **"in progress"** or
**"upcoming"**, it is intentionally not shipped yet. Read
[HANDOFF.md](../HANDOFF.md) §1–§22 for the authoritative status as of
the last engineering session.
