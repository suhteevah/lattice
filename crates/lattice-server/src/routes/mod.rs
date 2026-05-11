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

pub mod federation;
pub mod groups;
pub mod health;
pub mod identity;
pub mod well_known;
