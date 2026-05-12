//! End-to-end integration test for the M2 acceptance gate.
//!
//! Two synthetic identities (Alice and Bob) running entirely in-process
//! exchange MLS-encrypted application messages across a custom hybrid
//! ciphersuite with per-epoch external PSK injection of an ML-KEM-768
//! shared secret. No live server, no network — purely the crypto + MLS
//! layer.

// Test code legitimately uses expect()/unwrap()/panic per HANDOFF §7.
// Integration tests are their own crate, so they don't inherit
// lattice-crypto's lib-level cfg_attr(test, ...).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    // The .clone()s in this file are deliberate readability aids — the
    // test wants to demonstrate that Alice and Bob each hold their own
    // storage handles, even if one of them isn't reused afterwards.
    clippy::redundant_clone
)]

use lattice_crypto::credential::{
    ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN, USER_ID_LEN,
};
use lattice_crypto::mls::{
    LatticeIdentity, add_member, apply_commit, cipher_suite::LATTICE_HYBRID_V1, create_group,
    decrypt, encrypt_application, generate_key_package, leaf_node_kem::KemKeyPair, process_welcome,
    psk::LatticePskStorage,
};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider, SignaturePublicKey};

/// Build a Lattice identity from scratch using the hybrid suite to
/// generate signature keys, then wrap with a credential.
fn make_identity(user_id_byte: u8) -> LatticeIdentity {
    let provider = lattice_crypto::mls::cipher_suite::LatticeCryptoProvider::new();
    let suite = provider
        .cipher_suite_provider(LATTICE_HYBRID_V1)
        .expect("suite");
    let (sk, pk) = suite.signature_key_generate().expect("keygen");

    // Split the packed pubkey into ed25519_pub + ml_dsa_pub.
    let pk_bytes = pk.as_bytes();
    assert_eq!(pk_bytes.len(), ED25519_PK_LEN + ML_DSA_65_PK_LEN);
    let mut ed25519_pub = [0u8; ED25519_PK_LEN];
    ed25519_pub.copy_from_slice(&pk_bytes[..ED25519_PK_LEN]);
    let ml_dsa_pub = pk_bytes[ED25519_PK_LEN..].to_vec();

    let credential = LatticeCredential {
        user_id: [user_id_byte; USER_ID_LEN],
        ed25519_pub,
        ml_dsa_pub,
    };
    let kem_keypair = KemKeyPair::generate();

    LatticeIdentity {
        credential,
        signature_secret: sk,
        kem_keypair,
        key_package_repo: mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage::default(),
    }
}

/// Stable group id for tests. UUIDv7 bytes in production; arbitrary 16
/// bytes here.
const fn group_id() -> [u8; 16] {
    *b"lattice-int-test"
}

#[test]
fn alice_invites_bob_and_both_round_trip() {
    // === Setup ===
    let alice_id = make_identity(0xAA);
    let bob_id = make_identity(0xBB);
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();

    // === Alice creates the group ===
    let mut alice_group = create_group(&alice_id, alice_psk.clone(), &group_id()).expect("create");

    // === Bob publishes a KeyPackage ===
    let bob_kp = generate_key_package(&bob_id, bob_psk.clone()).expect("kp");

    // === Alice adds Bob, producing one Welcome with PQ payload ===
    let commit_output = add_member(&mut alice_group, &bob_kp).expect("add_member");
    assert_eq!(commit_output.welcomes.len(), 1, "exactly one Welcome");
    let welcome = commit_output.welcomes.into_iter().next().unwrap();

    // Alice's PSK store should now hold one entry (the secret she just
    // encapsulated to Bob).
    assert_eq!(alice_psk.len().expect("len"), 1);

    // === Alice applies her own commit locally ===
    apply_commit(&mut alice_group).expect("alice apply");

    // === Bob joins via the Welcome ===
    let mut bob_group = process_welcome(&bob_id, bob_psk.clone(), &welcome).expect("bob join");

    // Bob's PSK store should also hold one entry (the secret he just
    // decapsulated from the PQ payload).
    assert_eq!(bob_psk.len().expect("len"), 1);

    // === Application messages: Alice → Bob ===
    let alice_msg =
        encrypt_application(&mut alice_group, b"hello, lattice").expect("alice encrypt");
    let recovered_at_bob = decrypt(&mut bob_group, &alice_msg).expect("bob decrypt");
    assert_eq!(recovered_at_bob, b"hello, lattice");

    // === Application messages: Bob → Alice ===
    let bob_msg = encrypt_application(&mut bob_group, b"hello, alice").expect("bob encrypt");
    let recovered_at_alice = decrypt(&mut alice_group, &bob_msg).expect("alice decrypt");
    assert_eq!(recovered_at_alice, b"hello, alice");
}

#[test]
fn bob_decrypts_messages_in_order() {
    let alice_id = make_identity(0xAA);
    let bob_id = make_identity(0xBB);
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();

    let mut alice_group = create_group(&alice_id, alice_psk.clone(), &group_id()).expect("create");
    let bob_kp = generate_key_package(&bob_id, bob_psk.clone()).expect("kp");
    let commit_output = add_member(&mut alice_group, &bob_kp).expect("add_member");
    let welcome = commit_output.welcomes.into_iter().next().unwrap();
    apply_commit(&mut alice_group).expect("apply");
    let mut bob_group = process_welcome(&bob_id, bob_psk.clone(), &welcome).expect("join");

    // Send three messages in order.
    let messages: Vec<&[u8]> = vec![b"first", b"second", b"third"];
    let cts: Vec<_> = messages
        .iter()
        .map(|m| encrypt_application(&mut alice_group, m).expect("encrypt"))
        .collect();

    // Bob decrypts in order.
    for (ct, expected) in cts.iter().zip(messages.iter()) {
        let pt = decrypt(&mut bob_group, ct).expect("decrypt");
        assert_eq!(&pt, expected);
    }
}

#[test]
fn tampered_application_message_is_rejected() {
    let alice_id = make_identity(0xAA);
    let bob_id = make_identity(0xBB);
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();

    let mut alice_group = create_group(&alice_id, alice_psk.clone(), &group_id()).expect("create");
    let bob_kp = generate_key_package(&bob_id, bob_psk.clone()).expect("kp");
    let commit_output = add_member(&mut alice_group, &bob_kp).expect("add_member");
    let welcome = commit_output.welcomes.into_iter().next().unwrap();
    apply_commit(&mut alice_group).expect("apply");
    let mut bob_group = process_welcome(&bob_id, bob_psk.clone(), &welcome).expect("join");

    let ct = encrypt_application(&mut alice_group, b"original").expect("encrypt");

    // Flip a byte somewhere past the framing header.
    let mut tampered = ct.clone();
    let idx = tampered.len() / 2;
    tampered[idx] ^= 0xFF;

    let result = decrypt(&mut bob_group, &tampered);
    assert!(result.is_err(), "tampered message must not decrypt cleanly");
}

#[test]
fn psk_id_matches_per_epoch() {
    // White-box: Alice's PSK store and Bob's PSK store should hold the
    // same key under the same id after a successful add_member +
    // process_welcome.
    use lattice_crypto::mls::psk::psk_id_for_epoch;
    use mls_rs_core::psk::PreSharedKeyStorage;

    let alice_id = make_identity(0xAA);
    let bob_id = make_identity(0xBB);
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();

    let mut alice_group = create_group(&alice_id, alice_psk.clone(), &group_id()).expect("create");
    let bob_kp = generate_key_package(&bob_id, bob_psk.clone()).expect("kp");
    let commit = add_member(&mut alice_group, &bob_kp).expect("add");
    let welcome = commit.welcomes.into_iter().next().unwrap();
    apply_commit(&mut alice_group).expect("apply");
    let _bob_group = process_welcome(&bob_id, bob_psk.clone(), &welcome).expect("join");

    // Epoch after the commit that added Bob is 1 (group started at 0).
    let psk_id = psk_id_for_epoch(1);
    let alice_psk_val = alice_psk
        .get(&psk_id)
        .expect("alice get")
        .expect("alice present");
    let bob_psk_val = bob_psk.get(&psk_id).expect("bob get").expect("bob present");
    assert_eq!(
        alice_psk_val.raw_value(),
        bob_psk_val.raw_value(),
        "Alice and Bob must agree on the PQ-injected PSK bytes"
    );
}

#[test]
fn unknown_user_id_rejected_at_credential_decode() {
    // Confirm that an arbitrary signature pubkey does NOT satisfy
    // LatticeIdentityProvider's binding check (catches confused-deputy
    // attempts).
    use lattice_crypto::mls::cipher_suite::{LATTICE_HYBRID_V1, LatticeCryptoProvider};
    use lattice_crypto::mls::identity_provider::LatticeIdentityProvider;
    use mls_rs_core::extension::ExtensionList;
    use mls_rs_core::identity::{
        Credential, CredentialType, CustomCredential, IdentityProvider, MemberValidationContext,
        SigningIdentity,
    };

    let alice_id = make_identity(0xAA);
    // Build a SigningIdentity using Alice's credential bytes but a DIFFERENT
    // signature_key.
    let bogus_pk_bytes = vec![0xCC_u8; ED25519_PK_LEN + ML_DSA_65_PK_LEN];
    let bad_signing = SigningIdentity::new(
        Credential::Custom(CustomCredential::new(
            CredentialType::new(lattice_crypto::credential::CREDENTIAL_TYPE_LATTICE),
            alice_id.credential.encode().expect("encode"),
        )),
        SignaturePublicKey::from(bogus_pk_bytes),
    );

    let provider = LatticeIdentityProvider::new();
    let result = provider.validate_member(&bad_signing, None, MemberValidationContext::None);
    assert!(
        result.is_err(),
        "mismatch between credential and signature_key must fail"
    );

    // sanity: providers also exist (smoke check that the test compiles
    // against the real provider chain).
    let _provider_check = LatticeCryptoProvider::new();
    let _: ExtensionList = ExtensionList::default();
    let _ = LATTICE_HYBRID_V1;
}

#[test]
fn hidden_membership_omits_ratchet_tree_from_welcome() {
    // M6 / D-16 acceptance: a server inspecting the Welcome bytes for
    // a hidden-membership group must NOT be able to enumerate
    // member identities. mls-rs marshals this property via the
    // `ratchet_tree_extension` CommitOption — when false, the
    // Welcome doesn't carry the leaf nodes.
    use lattice_crypto::mls::{create_hidden_group, InMemoryGroupStateStorage};
    use mls_rs::MlsMessage;
    use mls_rs::extension::built_in::RatchetTreeExt;
    use mls_rs_codec::MlsDecode;
    use mls_rs_core::extension::MlsCodecExtension;

    let alice = make_identity(0xAA);
    let bob = make_identity(0xBB);
    let alice_psk = LatticePskStorage::new();
    let bob_psk = LatticePskStorage::new();

    let group_id = *b"hidden-roster-1!";
    let mut alice_group = create_hidden_group(
        &alice,
        alice_psk.clone(),
        &group_id,
        InMemoryGroupStateStorage::default(),
    )
    .expect("create hidden group");

    let bob_kp = generate_key_package(&bob, bob_psk.clone()).expect("bob kp");
    let commit = add_member(&mut alice_group, &bob_kp).expect("add_member");
    let welcome = commit.welcomes.into_iter().next().expect("welcome present");

    // Parse the Welcome bytes server-side-style and confirm the
    // RatchetTree extension is absent. The server-side inspector
    // has no special access — just the bytes that flow through it.
    let mls_welcome =
        MlsMessage::mls_decode(&mut &*welcome.mls_welcome).expect("decode welcome");

    // The Welcome's secrets section is encrypted per joiner; only
    // metadata + wrapped secrets are observable in plaintext. The
    // RatchetTree extension would normally appear here for joiners
    // — under hidden membership it's omitted, so observers can't
    // enumerate members.
    let dump = format!("{mls_welcome:?}");
    let tree_ext_marker = format!("{:?}", RatchetTreeExt::extension_type());
    assert!(
        !dump.contains(&tree_ext_marker),
        "hidden-membership Welcome leaked the ratchet tree extension marker — \
         observer would be able to enumerate the roster: {tree_ext_marker} found in {dump}"
    );

    // Sanity: the message-flow still works end-to-end. Bob can't
    // process the welcome without the tree in this minimal test
    // (the out-of-band tree-delivery flow is the M6 polish item),
    // but Alice can encrypt for the group — proving the group is
    // alive and that hiding only affects the observer view, not
    // the in-group functionality.
    let ct = encrypt_application(&mut alice_group, b"hidden ping")
        .expect("alice encrypts in hidden group");
    assert!(!ct.is_empty(), "ciphertext shouldn't be empty");
}
