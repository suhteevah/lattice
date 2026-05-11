//! Cap'n Proto wire types — generated from `schema/lattice.capnp` at
//! build time by `build.rs`.
//!
//! Re-exports the codegen module via `include!`. The generated names
//! match the schema's `struct` declarations one-for-one —
//! `HybridSignatureWire`, `IdentityClaim`, `MembershipCert`,
//! `SealedEnvelope`, `KeyPackage`, `Welcome`, `Commit`,
//! `ApplicationMessage` — but encoded as Cap'n Proto builders /
//! readers rather than Prost structs.
//!
//! ## Module path
//!
//! Cap'n Proto's Rust codegen hardcodes `crate::<schema_stem>::…`
//! paths into the generated module, so this file MUST be named
//! `lattice_capnp.rs` (matching `schema/lattice.capnp`) and live at
//! the crate root.
//!
//! ## Migration status (M5, 2026-05-11)
//!
//! `wire.rs` (Prost) and `lattice_capnp.rs` (Cap'n Proto) currently
//! coexist. HTTP / sealed-sender / federation callsites still use
//! `wire::*`. Migration is staged so each callsite can be swapped +
//! tested independently rather than landing as one wire-breaking
//! commit. Once every callsite is on Cap'n Proto, the `wire`
//! module + the `prost` workspace dep will be removed and
//! `WIRE_VERSION` bumps 2 → 3.

#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]
#![allow(missing_docs)]
#![allow(unused_qualifications)]
#![allow(rustdoc::all)]
#![allow(unused)]

include!(concat!(env!("OUT_DIR"), "/lattice_capnp.rs"));
