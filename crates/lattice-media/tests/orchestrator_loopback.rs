//! M7 Phase F orchestrator smoke test.
//!
//! Drives [`lattice_media::call::run_loopback_call`] from end to end:
//! two `IceAgent`s converge, DTLS completes, ML-KEM-768 round-trips,
//! the PQ-folded SRTP master is split between Caller and Callee, both
//! sides build a real `webrtc-srtp::Context`, and a single RTP packet
//! crosses the boundary intact. Same construction the Tauri desktop
//! shell's `start_call` IPC command invokes.
//!
//! Gated behind `LATTICE_NET_TESTS=1` because it binds UDP sockets.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use lattice_media::call::{CallId, run_loopback_call};

fn net_tests_enabled() -> bool {
    std::env::var("LATTICE_NET_TESTS").is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_call_runs_full_pipeline_and_rtp_round_trip() {
    if !net_tests_enabled() {
        eprintln!("skipping orchestrator loopback (set LATTICE_NET_TESTS=1 to run)");
        return;
    }

    let call_id = CallId([0xf0u8; 16]);
    let outcome = run_loopback_call(call_id).await.expect("orchestrator");

    assert_eq!(outcome.call_id, call_id);
    assert!(
        outcome.caller_candidates_seen >= 1,
        "caller should see at least one host candidate"
    );
    assert!(
        outcome.callee_candidates_seen >= 1,
        "callee should see at least one host candidate"
    );

    // SRTP CM-80 appends 10 bytes of auth tag → protected_len =
    // plain_len + 10. Pin both lengths so a future profile swap fails
    // loudly here rather than silently changing the on-wire bytes.
    assert_eq!(
        outcome.protected_rtp_len,
        outcome.plain_rtp_len + 10,
        "SRTP CM-80 auth tag should add 10 bytes to the plain RTP"
    );
    assert_eq!(
        outcome.recovered_rtp_len, outcome.plain_rtp_len,
        "callee must recover the exact plain RTP length the caller sent"
    );

    // 4-byte hex prefix = 8 hex chars. Empty prefix would mean the
    // master derivation never ran.
    assert_eq!(outcome.srtp_master_prefix.len(), 8);
    eprintln!(
        "phase F orchestrator green | candidates caller={} callee={} | srtp master prefix={}",
        outcome.caller_candidates_seen,
        outcome.callee_candidates_seen,
        outcome.srtp_master_prefix
    );
}
