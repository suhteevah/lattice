//! Route assembly.
//!
//! Each domain gets its own submodule with a `router()` returning a partial
//! `axum::Router`. The crate-level [`crate::app`] merges them all and
//! applies cross-cutting middleware.

pub mod health;
