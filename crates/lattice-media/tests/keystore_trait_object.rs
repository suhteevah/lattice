//! Integration test for the [`Keystore`] trait object pattern that
//! `lattice-desktop`'s IPC layer relies on.
//!
//! The Tauri commands receive a `State<'_, DesktopState>` whose
//! `keystore` field is `Arc<dyn Keystore>` — type-erased and shared
//! across the async runtime. This test exercises that exact pattern:
//!
//! - `Arc<dyn Keystore>` is `Send + Sync` so it can move between
//!   `tokio::task::spawn_blocking` workers.
//! - `keystore.clone()` (Arc clone) is the cheap dispatch path used
//!   by every command in `commands.rs`.
//! - Signing through the trait object produces a valid
//!   `HybridSignature` that `lattice_crypto::identity::verify`
//!   accepts.
//!
//! Skipped concerns: file-backed persistence, DPAPI integrity. Those
//! live in `crates/lattice-media/src/keystore/{memory,windows}.rs`
//! unit tests.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use lattice_crypto::identity::verify;
use lattice_media::keystore::{Keystore, KeystoreError, memory::MemoryKeystore};

#[tokio::test]
async fn trait_object_round_trip() {
    let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());

    // Move into spawn_blocking, exactly like the IPC commands do.
    let ks_for_gen = keystore.clone();
    let stored = tokio::task::spawn_blocking(move || ks_for_gen.generate("trait object test"))
        .await
        .expect("join")
        .expect("generate");

    let handle = stored.handle;
    let msg = b"phase G trait object dispatch";

    let ks_for_sign = keystore.clone();
    let sig = tokio::task::spawn_blocking(move || ks_for_sign.sign(&handle, msg))
        .await
        .expect("join")
        .expect("sign");

    verify(&stored.public, msg, &sig).expect("hybrid signature verifies");

    // Delete via trait object, then prove sign now reports NotFound.
    let ks_for_del = keystore.clone();
    let was_present = tokio::task::spawn_blocking(move || ks_for_del.delete(&handle))
        .await
        .expect("join")
        .expect("delete");
    assert!(was_present);

    let ks_for_sign_after = keystore.clone();
    let err = tokio::task::spawn_blocking(move || ks_for_sign_after.sign(&handle, msg))
        .await
        .expect("join")
        .expect_err("sign after delete must error");

    match err {
        KeystoreError::NotFound { handle: h } => assert_eq!(h, handle),
        other => panic!("wrong variant: {other:?}"),
    }
}

#[tokio::test]
async fn trait_object_list_is_stable_across_clones() {
    let keystore: Arc<dyn Keystore> = Arc::new(MemoryKeystore::new());

    let a = keystore
        .clone()
        .generate("first")
        .expect("first generate");
    let b = keystore.clone().generate("second").expect("second generate");

    let listed = keystore.clone().list().expect("list");
    assert_eq!(listed.len(), 2);
    let handles: Vec<_> = listed.iter().map(|s| s.handle).collect();
    assert!(handles.contains(&a.handle));
    assert!(handles.contains(&b.handle));
}
