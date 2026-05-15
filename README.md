# Lattice

> Post-quantum encrypted, federated messaging. A Discord replacement with
> Matrix-class decentralization at Discord-class UX speed.

**Status:** Step 1 — workspace scaffold. No business logic yet. Read
[`docs/HANDOFF.md`](docs/HANDOFF.md) first.

## Quick links

- [`docs/HANDOFF.md`](docs/HANDOFF.md) — single-read onboarding doc
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — phased security mitigations
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — node-capture analysis
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — protocol deep-dive

## What's in the box

| Path | Purpose |
|---|---|
| `crates/lattice-crypto/` | PQ hybrid crypto, MLS, sealed sender, padding |
| `crates/lattice-protocol/` | Wire schemas, envelopes |
| `crates/lattice-server/` | Home server (axum + quinn + Postgres) |
| `crates/lattice-core/` | Client core; compiles to wasm32 for browsers |
| `crates/lattice-storage/` | Encrypted local store (IndexedDB / SQLCipher) |
| `crates/lattice-keytransparency/` | V1.5 placeholder — CONIKS-style log |
| `crates/lattice-cli/` | Admin + dev CLI |
| `apps/lattice-web/` | V1 browser client (Solid + Tailwind) |
| `design/tokens/` | Lilac-anchored design system as JSON |
| `scripts/*.ps1` | PowerShell automation (Windows-first project) |
| `.github/workflows/ci.yml` | Check / fmt / clippy / test / wasm32 / audit |

## Getting started

```powershell
# One-shot dev environment bootstrap (run as Administrator)
.\scripts\dev-setup.ps1

# Day-to-day
cargo check --workspace
.\scripts\test-all.ps1            # full pre-commit gate

# Web client dev server
cd apps\lattice-web
npm run dev                       # http://localhost:5173
```

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).

## Owner

Matt Gates (suhteevah). Ridge Cell Repair LLC.

---

---

---

---

## Support This Project

If you find this project useful, consider buying me a coffee! Your support helps me keep building and sharing open-source tools.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg?logo=paypal)](https://www.paypal.me/baal_hosting)

**PayPal:** [baal_hosting@live.com](https://paypal.me/baal_hosting)

Every donation, no matter how small, is greatly appreciated and motivates continued development. Thank you!
