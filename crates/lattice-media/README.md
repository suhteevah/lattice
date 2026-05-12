# lattice-media

M7 — voice/video for Lattice. PQ-hybrid DTLS-SRTP, ICE/STUN/TURN,
and call signaling over the existing MLS application-message path.

**Status:** Phase B scaffold (2026-05-11). Module skeleton + types in
place; no behavior yet. The phase plan lives in
[`scratch/m7-build-plan.md`](../../scratch/m7-build-plan.md). The
construction spec for the PQ-hybrid SRTP key derivation will land
during Phase A research and be cross-linked here.

## Scope

- `call` — high-level call lifecycle (`Invite`, `Accept`, `End`,
  `IceCandidate`). Signaling payloads serialize into MLS
  `ApplicationMessage` envelopes via `lattice-protocol`; the server
  never sees plaintext call metadata.
- `handshake` — ML-KEM-768 ephemeral keygen + encap/decap. Owns the
  PQ secret that gets folded into the SRTP master key derivation.
- `ice` — wraps `webrtc-ice` (vendored in Phase C). ICE candidates
  are exchanged over MLS, never via plaintext server routes.
- `rendezvous` — STUN/TURN client config. Each home server runs its
  own STUN/TURN endpoint per D-19; clients rotate per call.
- `srtp` — PQ-hybrid SRTP context. Derives master keys from
  `HKDF-SHA-256(dtls_exporter || ml_kem_shared_secret, …)` and
  hands them to the (vendored, Phase D) `webrtc-srtp` context.

## Non-goals

- No fallback to classical-only DTLS-SRTP. M7 ships PQ-hybrid or
  nothing — the "tonight shortcut" path was rejected on 2026-05-11.
- No group voice/video (≥ 3 participants) in M7. Long-horizon item.
- No mixnet routing. Long-horizon item.

## Build / test

```powershell
cargo check -p lattice-media
cargo test  -p lattice-media
cargo clippy -p lattice-media --all-targets -- -D warnings
```

Phase B has trivial coverage only; meaningful tests land Phase C
(ICE gathering) and Phase E (PQ-SRTP round trip).
