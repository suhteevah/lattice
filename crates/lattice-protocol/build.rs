//! Build script: compile the Cap'n Proto schema(s) under `schema/`
//! to Rust modules under `OUT_DIR`, then re-export them from
//! `src/capnp.rs` via `include!`.
//!
//! Why not write the generated code into `src/`? Two reasons:
//! 1. Generated files in `src/` make every schema iteration a noisy
//!    diff that touches large autogen blobs.
//! 2. `cargo check` on a clone without `capnp` installed would 404
//!    on the missing generated module. With `OUT_DIR` the file is
//!    regenerated alongside the build, so as long as `capnp` is
//!    installed (Windows: `choco install capnproto`; macOS: `brew
//!    install capnp`; Linux: distro package) the build is
//!    self-contained.

fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/lattice.capnp")
        .run()
        .expect("compile lattice.capnp");

    println!("cargo:rerun-if-changed=schema/lattice.capnp");
    println!("cargo:rerun-if-changed=build.rs");
}
