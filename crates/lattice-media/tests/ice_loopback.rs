//! Same-process ICE loopback — drives two `IceAgent`s through
//! candidate gathering, credential exchange, and connectivity
//! checks, then verifies a small datagram round-trips over the
//! returned `Conn` pair.
//!
//! This is the foundation for Phase E (DTLS handshake over the ICE
//! `Conn`). When this test passes we know the wrapper is sound; if
//! the DTLS layer breaks in Phase E we know the bug is in the DTLS
//! plumbing, not in ICE.
//!
//! Test gated behind the `LATTICE_NET_TESTS` env var because it
//! binds real UDP sockets on the host. CI / dry-runs skip it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use lattice_media::ice::IceAgent;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Test gate. Only runs when the user sets `LATTICE_NET_TESTS=1`,
/// since it binds UDP sockets and depends on host networking.
fn net_tests_enabled() -> bool {
    std::env::var("LATTICE_NET_TESTS").is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ice_loopback_pair_connects_and_carries_a_datagram() {
    if !net_tests_enabled() {
        eprintln!("skipping ice loopback (set LATTICE_NET_TESTS=1 to run)");
        return;
    }

    // Build both agents — Alice is controlling (will dial), Bob is
    // controlled (will accept). Empty STUN/TURN list — we only need
    // host candidates for a same-machine loopback.
    let alice = Arc::new(IceAgent::new(vec![], true).await.expect("alice new"));
    let bob = Arc::new(IceAgent::new(vec![], false).await.expect("bob new"));

    // Exchange credentials before kicking off gathering. RFC 8445
    // §6.1.2.2 — set_remote_credentials must happen before
    // connectivity checks consume candidates.
    let alice_creds = alice.local_credentials().await;
    let bob_creds = bob.local_credentials().await;
    alice
        .set_remote_credentials(bob_creds.clone())
        .await
        .expect("alice set remote");
    bob.set_remote_credentials(alice_creds.clone())
        .await
        .expect("bob set remote");

    // Wire each agent's gathered candidates straight into the
    // other's add_remote_candidate. In a real call these ride over
    // MLS-encrypted `CallIceCandidate` payloads.
    let bob_for_alice_handler = Arc::clone(&bob);
    let alice_handler_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let alice_handler_log_for_cb = Arc::clone(&alice_handler_log);
    alice.on_local_candidate(move |maybe_line| {
        if let Some(sdp_line) = maybe_line {
            // Use blocking_lock would deadlock the runtime; use a
            // detached task instead. The callback signature is
            // `Fn`, so we must clone everything into the task.
            let bob = Arc::clone(&bob_for_alice_handler);
            let log = Arc::clone(&alice_handler_log_for_cb);
            tokio::spawn(async move {
                log.lock().await.push(sdp_line.clone());
                if let Err(e) = bob.add_remote_candidate(&sdp_line) {
                    eprintln!("bob.add_remote_candidate({sdp_line}) failed: {e}");
                }
            });
        }
    });

    let alice_for_bob_handler = Arc::clone(&alice);
    let bob_handler_log = Arc::new(Mutex::new(Vec::<String>::new()));
    let bob_handler_log_for_cb = Arc::clone(&bob_handler_log);
    bob.on_local_candidate(move |maybe_line| {
        if let Some(sdp_line) = maybe_line {
            let alice = Arc::clone(&alice_for_bob_handler);
            let log = Arc::clone(&bob_handler_log_for_cb);
            tokio::spawn(async move {
                log.lock().await.push(sdp_line.clone());
                if let Err(e) = alice.add_remote_candidate(&sdp_line) {
                    eprintln!("alice.add_remote_candidate({sdp_line}) failed: {e}");
                }
            });
        }
    });

    // Begin gathering on both sides.
    alice.gather_candidates().expect("alice gather");
    bob.gather_candidates().expect("bob gather");

    // Drive connectivity checks. dial() and accept() block until at
    // least one pair connects; run them concurrently and bound by a
    // hard timeout so a hung test doesn't wedge the suite.
    let alice_dial = {
        let alice = Arc::clone(&alice);
        let creds = bob_creds.clone();
        tokio::spawn(async move { alice.dial(creds).await })
    };
    let bob_accept = {
        let bob = Arc::clone(&bob);
        let creds = alice_creds.clone();
        tokio::spawn(async move { bob.accept(creds).await })
    };

    let (alice_conn, bob_conn) = match timeout(Duration::from_secs(15), async {
        let alice_conn = alice_dial.await.expect("alice dial join")?;
        let bob_conn = bob_accept.await.expect("bob accept join")?;
        Ok::<_, lattice_media::error::MediaError>((alice_conn, bob_conn))
    })
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => panic!("connectivity check failed: {e}"),
        Err(_) => panic!(
            "ICE didn't connect within 15 s. Alice gathered {} candidates, Bob gathered {}.",
            alice_handler_log.lock().await.len(),
            bob_handler_log.lock().await.len()
        ),
    };

    // Round-trip a datagram. Use a non-trivial payload so we'd see
    // either a length mismatch or a content mismatch on failure.
    let payload = b"lattice-ice-loopback-smoke-test";
    alice_conn.send(payload).await.expect("alice send");

    let mut buf = vec![0u8; payload.len() + 8];
    let n = timeout(Duration::from_secs(2), bob_conn.recv(&mut buf))
        .await
        .expect("bob recv timeout")
        .expect("bob recv error");
    assert_eq!(&buf[..n], payload);

    // Reverse direction too.
    bob_conn.send(payload).await.expect("bob send");
    let n = timeout(Duration::from_secs(2), alice_conn.recv(&mut buf))
        .await
        .expect("alice recv timeout")
        .expect("alice recv error");
    assert_eq!(&buf[..n], payload);

    alice.close().await.expect("alice close");
    bob.close().await.expect("bob close");
}
