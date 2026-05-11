# lattice-protocol/schema

Cap'n Proto schema for the Lattice wire protocol (M5 / ROADMAP §M5).

## Status

**Schema authored, generated bindings + Prost swap deferred to a
focused session.** The migration is sized at:

1. Install `capnp` (the schema compiler) — Windows binaries at
   <https://capnproto.org/install.html>, or `choco install capnp`.
2. Add `capnp = "0.20"` + `capnpc = "0.20"` to the workspace deps.
3. Wire `crates/lattice-protocol/build.rs`:
   ```rust
   fn main() -> std::io::Result<()> {
       capnpc::CompilerCommand::new()
           .file("schema/lattice.capnp")
           .output_path("src/")
           .run()
           .map_err(|e| std::io::Error::other(e))
   }
   ```
4. `cargo build -p lattice-protocol` regenerates `src/lattice_capnp.rs`.
5. Replace every `lattice_protocol::wire::*` use with the generated
   `lattice_capnp::*` builders/readers. There are ~50 callsites
   across `lattice-server`, `lattice-cli`, `apps/lattice-web`.
6. Bump `WIRE_VERSION` from 2 → 3 since field IDs in the generated
   schema differ from Prost's tag numbers.
7. Update the `routes_integration` test that pins `wire_version`.

## Schema review

- `Data` ↔ Prost `bytes` ↔ Rust `Vec<u8>`.
- `UInt32` / `UInt64` ↔ Prost `uint32` / `uint64` ↔ Rust `u32` / `u64`.
- `Int64` ↔ Prost `int64` ↔ Rust `i64` (Unix-epoch seconds).
- Optional message fields (`signature` on `IdentityClaim`,
  `membershipCert` on `SealedEnvelope`, `identity` on `KeyPackage`)
  use Cap'n Proto's native union for the null case. Wire-compact
  compared to Prost's presence-bit + tagged length, and the type
  system can't accidentally drop the variant tag.
- The MLS-codec-encoded blobs (KeyPackage / Welcome / Commit /
  ApplicationMessage payload bytes) stay as opaque `Data` — they
  carry their own framing via mls-rs.

## Why migrate

ROADMAP §M5:

> Cap'n Proto migration from Prost (deferred from M2). Wire version
> bump.

Justification per HANDOFF §2 (Locked decisions): **zero-copy decode,
schema-evolution-friendly, ~10× faster than JSON.** Prost was the
interim wire format used while the project bootstrapped through M2 /
M3 / M4; Cap'n Proto is the long-term contract.

Field IDs are stable. Adding a field appends to the message;
renumbering an existing field is a wire-breaking change and requires
a `WIRE_VERSION` bump.
