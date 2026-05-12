//! Integration test for the PQ-hybrid SRTP key derivation.
//!
//! Simulates one full call setup short of the DTLS handshake itself:
//! Alice generates an ML-KEM-768 keypair; Bob encapsulates against
//! her public key; Alice decapsulates; both sides then call
//! `derive_srtp_master` with a synthetic 60-byte DTLS exporter
//! standing in for the eventual real RFC 5705 output. Both sides
//! MUST arrive at the same `srtp_master` — that's the core
//! correctness property of the construction in `D-18` and
//! `scratch/pq-dtls-srtp-construction.md`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use lattice_media::call::CallId;
use lattice_media::handshake::{decapsulate, encapsulate, generate_keypair};
use lattice_media::srtp::derive_srtp_master;

/// A fixed 60-byte stand-in for the DTLS exporter. In Phase E this
/// becomes the actual `EXTRACTOR-dtls_srtp` output. The bytes here
/// don't need to be realistic — only that both sides see the same
/// value, which is what the DTLS handshake guarantees in practice.
const SIMULATED_DTLS_EXPORTER: [u8; 60] = [0x5au8; 60];

#[test]
fn alice_and_bob_derive_equal_srtp_master() {
    let alice_kp = generate_keypair().expect("alice keygen");

    // Bob receives Alice's CallInvite (containing alice_kp.encapsulation_key)
    // and encapsulates.
    let bob_encap = encapsulate(&alice_kp.encapsulation_key).expect("bob encap");

    // Alice receives Bob's CallAccept (containing bob_encap.ciphertext)
    // and decapsulates.
    let alice_pq_ss =
        decapsulate(&alice_kp.decapsulation_key, &bob_encap.ciphertext).expect("alice decap");

    // Both sides MUST hold the same 32-byte ML-KEM shared secret.
    assert_eq!(alice_pq_ss.expose(), bob_encap.shared_secret.expose());

    // Imagine the DTLS handshake completes here — both sides extract
    // the same 60-byte exporter material.
    let call_id = CallId([0xa1u8; 16]);
    let epoch_id: u64 = 0;

    // Alice's side.
    let alice_srtp =
        derive_srtp_master(&SIMULATED_DTLS_EXPORTER, &alice_pq_ss, call_id, epoch_id)
            .expect("alice srtp derive");

    // Bob's side — pulls the typed PqSharedSecret straight off the
    // PqEncapsulation he produced during encap. No raw-bytes
    // intermediate; this matches the actual Phase E call site.
    let bob_srtp = derive_srtp_master(
        &SIMULATED_DTLS_EXPORTER,
        &bob_encap.shared_secret,
        call_id,
        epoch_id,
    )
    .expect("bob srtp derive");

    assert_eq!(
        alice_srtp.expose(),
        bob_srtp.expose(),
        "alice and bob derive equal srtp_master after full round trip"
    );
}

#[test]
fn distinct_calls_yield_distinct_srtp_masters() {
    // Two back-to-back calls between the same pair of users should
    // produce independent SRTP keys, even if (artificially) the
    // DTLS exporter happens to match across calls. The PQ ephemeral
    // keypair is fresh per call, so pq_ss differs; and call_id
    // differs anyway. Either is sufficient on its own.
    let kp_call_1 = generate_keypair().expect("kp 1");
    let kp_call_2 = generate_keypair().expect("kp 2");

    let enc_1 = encapsulate(&kp_call_1.encapsulation_key).expect("encap 1");
    let enc_2 = encapsulate(&kp_call_2.encapsulation_key).expect("encap 2");

    let ss_1 = decapsulate(&kp_call_1.decapsulation_key, &enc_1.ciphertext).expect("decap 1");
    let ss_2 = decapsulate(&kp_call_2.decapsulation_key, &enc_2.ciphertext).expect("decap 2");

    let srtp_1 = derive_srtp_master(&SIMULATED_DTLS_EXPORTER, &ss_1, CallId([1u8; 16]), 0)
        .expect("srtp 1");
    let srtp_2 = derive_srtp_master(&SIMULATED_DTLS_EXPORTER, &ss_2, CallId([2u8; 16]), 0)
        .expect("srtp 2");

    assert_ne!(srtp_1.expose(), srtp_2.expose());
}
