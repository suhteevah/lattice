//! End-to-end Phase E.2 smoke test — the cryptographic proof that
//! Lattice's PQ-DTLS-SRTP construction works.
//!
//! Sequence (same as a real call but in one process):
//! 1. Two `IceAgent`s exchange host candidates + credentials.
//! 2. Each side `dial`/`accept` to obtain a `Conn`.
//! 3. Each side runs `negotiate_dtls` over its `Conn` (Alice = client,
//!    Bob = server) to drive the classical DTLS handshake.
//! 4. Each side calls `extract_dtls_exporter` to pull the 60-byte
//!    RFC 5705 keying material out of the completed handshake.
//! 5. Alice generates an ML-KEM-768 keypair; Bob encapsulates against
//!    Alice's pubkey to produce `(ct, pq_ss_bob)`; Alice decapsulates
//!    Bob's `ct` to obtain `pq_ss_alice`. These two MUST agree.
//! 6. Both sides run `derive_srtp_master(exporter, pq_ss, call_id, 0)`.
//!    These two 60-byte outputs MUST be byte-equal.
//! 7. Both sides run `split_srtp_master(master, role)`. Alice's
//!    `local` MUST match Bob's `remote` (and vice versa).
//!
//! If all assertions hold, the PQ-DTLS-SRTP construction works end
//! to end. Plumbing into `srtp::Session` + a real RTP round trip is
//! Phase F polish.
//!
//! Gated behind `LATTICE_NET_TESTS=1` because it binds UDP sockets.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use lattice_media::call::{CallId, Role};
use lattice_media::handshake::{
    decapsulate, default_dtls_config, encapsulate, extract_dtls_exporter, generate_keypair,
    negotiate_dtls,
};
use lattice_media::ice::IceAgent;
use lattice_media::srtp::{derive_srtp_master, split_srtp_master};
use tokio::sync::Mutex;
use tokio::time::timeout;

fn net_tests_enabled() -> bool {
    std::env::var("LATTICE_NET_TESTS").is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pq_dtls_srtp_full_loopback_converges() {
    if !net_tests_enabled() {
        eprintln!("skipping pq-dtls-srtp loopback (set LATTICE_NET_TESTS=1 to run)");
        return;
    }

    // -- ICE: same as the C.2 test ------------------------------------
    let alice_ice = Arc::new(IceAgent::new(vec![], true).await.expect("alice ice"));
    let bob_ice = Arc::new(IceAgent::new(vec![], false).await.expect("bob ice"));

    let alice_creds = alice_ice.local_credentials().await;
    let bob_creds = bob_ice.local_credentials().await;
    alice_ice
        .set_remote_credentials(bob_creds.clone())
        .await
        .expect("alice set remote");
    bob_ice
        .set_remote_credentials(alice_creds.clone())
        .await
        .expect("bob set remote");

    let bob_for_alice = Arc::clone(&bob_ice);
    let alice_seen = Arc::new(Mutex::new(0usize));
    let alice_seen_cb = Arc::clone(&alice_seen);
    alice_ice.on_local_candidate(move |maybe_line| {
        if let Some(sdp) = maybe_line {
            let bob = Arc::clone(&bob_for_alice);
            let seen = Arc::clone(&alice_seen_cb);
            tokio::spawn(async move {
                *seen.lock().await += 1;
                let _ = bob.add_remote_candidate(&sdp);
            });
        }
    });
    let alice_for_bob = Arc::clone(&alice_ice);
    let bob_seen = Arc::new(Mutex::new(0usize));
    let bob_seen_cb = Arc::clone(&bob_seen);
    bob_ice.on_local_candidate(move |maybe_line| {
        if let Some(sdp) = maybe_line {
            let alice = Arc::clone(&alice_for_bob);
            let seen = Arc::clone(&bob_seen_cb);
            tokio::spawn(async move {
                *seen.lock().await += 1;
                let _ = alice.add_remote_candidate(&sdp);
            });
        }
    });

    alice_ice.gather_candidates().expect("alice gather");
    bob_ice.gather_candidates().expect("bob gather");

    let alice_dial = {
        let ice = Arc::clone(&alice_ice);
        let creds = bob_creds.clone();
        tokio::spawn(async move { ice.dial(creds).await })
    };
    let bob_accept = {
        let ice = Arc::clone(&bob_ice);
        let creds = alice_creds.clone();
        tokio::spawn(async move { ice.accept(creds).await })
    };

    let (alice_conn, bob_conn) = timeout(Duration::from_secs(15), async {
        let alice_conn = alice_dial.await.expect("alice dial join")?;
        let bob_conn = bob_accept.await.expect("bob accept join")?;
        Ok::<_, lattice_media::error::MediaError>((alice_conn, bob_conn))
    })
    .await
    .expect("ice timeout")
    .expect("ice failure");

    // -- DTLS: handshakes run concurrently (each side blocks on the
    //    other's records). Concurrent join is required.
    let alice_dtls = {
        let config = default_dtls_config().expect("dtls config");
        let conn = Arc::clone(&alice_conn);
        tokio::spawn(async move { negotiate_dtls(conn, Role::Caller, config).await })
    };
    let bob_dtls = {
        let config = default_dtls_config().expect("dtls config");
        let conn = Arc::clone(&bob_conn);
        tokio::spawn(async move { negotiate_dtls(conn, Role::Callee, config).await })
    };
    let (alice_dtls, bob_dtls) = timeout(Duration::from_secs(15), async {
        let a = alice_dtls.await.expect("alice dtls join")?;
        let b = bob_dtls.await.expect("bob dtls join")?;
        Ok::<_, lattice_media::error::MediaError>((a, b))
    })
    .await
    .expect("dtls timeout")
    .expect("dtls failure");

    // -- Pull 60-byte exporters from each side. Both must agree (the
    //    handshake derived them deterministically from the negotiated
    //    master_secret, which is identical at both ends).
    let alice_state = alice_dtls.connection_state().await;
    let bob_state = bob_dtls.connection_state().await;
    let alice_exporter = extract_dtls_exporter(&alice_state).await.expect("alice exp");
    let bob_exporter = extract_dtls_exporter(&bob_state).await.expect("bob exp");
    assert_eq!(
        alice_exporter.as_bytes(),
        bob_exporter.as_bytes(),
        "DTLS exporters disagree — DTLS handshake didn't converge"
    );

    // -- PQ KEM round trip (carried over MLS in a real call, here we
    //    pass it directly).
    let alice_kp = generate_keypair().expect("alice kp");
    let bob_encap = encapsulate(&alice_kp.encapsulation_key).expect("bob encap");
    let alice_pq_ss = decapsulate(&alice_kp.decapsulation_key, &bob_encap.ciphertext)
        .expect("alice decap");
    assert_eq!(
        alice_pq_ss.expose(),
        bob_encap.shared_secret.expose(),
        "ML-KEM round trip didn't converge"
    );

    // -- PQ-folded SRTP master derivation.
    let call_id = CallId([0xa1u8; 16]);
    let alice_srtp = derive_srtp_master(alice_exporter.as_bytes(), &alice_pq_ss, call_id, 0)
        .expect("alice srtp derive");
    let bob_srtp = derive_srtp_master(
        bob_exporter.as_bytes(),
        &bob_encap.shared_secret,
        call_id,
        0,
    )
    .expect("bob srtp derive");
    assert_eq!(
        alice_srtp.expose(),
        bob_srtp.expose(),
        "PQ-folded SRTP masters disagree"
    );

    // -- Split into session keys per RFC 5764 §4.2. Alice's
    //    local-write must equal Bob's remote-write.
    let alice_keys = split_srtp_master(&alice_srtp, Role::Caller);
    let bob_keys = split_srtp_master(&bob_srtp, Role::Callee);
    assert_eq!(
        alice_keys.local.master_key, bob_keys.remote.master_key,
        "alice's outbound SRTP key != bob's inbound SRTP key"
    );
    assert_eq!(
        alice_keys.local.master_salt, bob_keys.remote.master_salt,
        "alice's outbound SRTP salt != bob's inbound SRTP salt"
    );
    assert_eq!(
        alice_keys.remote.master_key, bob_keys.local.master_key,
        "alice's inbound SRTP key != bob's outbound SRTP key"
    );
    assert_eq!(
        alice_keys.remote.master_salt, bob_keys.local.master_salt,
        "alice's inbound SRTP salt != bob's outbound SRTP salt"
    );

    eprintln!(
        "smoke test green | alice saw {} candidates, bob saw {}",
        alice_seen.lock().await,
        bob_seen.lock().await
    );

    let _ = alice_ice.close().await;
    let _ = bob_ice.close().await;
}
