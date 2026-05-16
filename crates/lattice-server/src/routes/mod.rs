//! Route assembly.
//!
//! Each domain gets its own submodule with a `router()` returning a partial
//! `axum::Router`. The crate-level [`crate::app`] merges them all and
//! applies cross-cutting middleware.

#![allow(
    clippy::module_name_repetitions,
    // Route Request/Response structs are documented by their JSON
    // serde shape; per-field doc comments would just duplicate the
    // field name in prose.
    missing_docs
)]
// Lints fired by route handler bodies that we deliberately accept:
// - `too_many_lines`: handler functions intentionally do all their
//   work inline so the wire shape is obvious from one read.
// - `too_many_arguments`: federation push helpers have many args by
//   design (origin host, origin URL, group id, epoch, commit bytes,
//   welcome list, routing list…). Naming them is clearer than
//   bundling.
// - `items_after_statements`: inline `#[derive(Message)] struct Tbs`
//   blocks for canonical TBS computation are placed right above
//   their first use; refactoring them to top-of-file hurts locality.
// - `struct_field_names`: `*_b64` suffixes on Request/Response
//   structs are intentional — they communicate "this is base64
//   text" to the JSON consumer.
// - `or_fun_call`, `unnecessary_lazy_evaluations`, `redundant_clone`,
//   `unused_async`: pedantic noise in error-path code that's clearer
//   with the redundant form.
#![allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::items_after_statements,
    clippy::struct_field_names,
    clippy::or_fun_call,
    clippy::unnecessary_lazy_evaluations,
    clippy::redundant_clone,
    clippy::unused_async,
    clippy::map_unwrap_or
)]

pub mod admin;
pub mod federation;
pub mod groups;
pub mod health;
pub mod identity;
pub mod push;
pub mod well_known;
