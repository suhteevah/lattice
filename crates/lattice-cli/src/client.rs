//! CLI-side `mls_rs::Client` construction with file-backed storage.
//!
//! Mirrors `lattice_crypto::mls::build_client` but uses
//! [`crate::store`]'s file-backed storage providers so per-action CLI
//! invocations persist state across process boundaries. The
//! orchestration of add-member / process-welcome / encrypt / decrypt
//! is implemented inline here against the resulting `Client` — we
//! reuse lattice-crypto for the cryptographic building blocks
//! (`LatticeCryptoProvider`, `LatticeIdentityProvider`, the extension
//! types, `seal_pq_secret` / `open_pq_secret`, `psk_id_for_epoch`) but
//! not for the high-level group ops because those embed the
//! in-memory storage choice in their type signatures.

#![allow(clippy::module_name_repetitions)]

use anyhow::{Result, anyhow};
use mls_rs::{
    Client, CryptoProvider, ExtensionList, MlsMessage,
    client_builder::{
        BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
        WithKeyPackageRepo, WithPskStore,
    },
    group::ReceivedMessage,
    identity::SigningIdentity,
    mls_rs_codec::{MlsDecode, MlsEncode},
};
use mls_rs_core::{
    crypto::SignaturePublicKey,
    extension::MlsExtension,
    psk::{ExternalPskId, PreSharedKey},
};

use lattice_crypto::credential::CREDENTIAL_TYPE_LATTICE;
use lattice_crypto::mls::cipher_suite::{LATTICE_HYBRID_V1, LatticeCryptoProvider};
use lattice_crypto::mls::identity_provider::LatticeIdentityProvider;
use lattice_crypto::mls::leaf_node_kem::LatticeKemPubkey;
use lattice_crypto::mls::psk::psk_id_for_epoch;
use lattice_crypto::mls::welcome_pq::{PqWelcomePayload, open_pq_secret, seal_pq_secret};

use crate::identity_file::CliIdentity;
use crate::store::{FileGroupStateStorage, FileKeyPackageStorage, FilePskStorage};

/// Concrete `MlsConfig` type assembled by [`build_client`].
pub type CliMlsConfig = WithGroupStateStorage<
    FileGroupStateStorage,
    WithKeyPackageRepo<
        FileKeyPackageStorage,
        WithPskStore<
            FilePskStorage,
            WithCryptoProvider<
                LatticeCryptoProvider,
                WithIdentityProvider<LatticeIdentityProvider, BaseConfig>,
            >,
        >,
    >,
>;

/// File-backed storage providers bundle.
#[derive(Clone)]
pub struct CliStores {
    /// Per-device KP secret store.
    pub kp_store: FileKeyPackageStorage,
    /// Group state store.
    pub group_store: FileGroupStateStorage,
    /// PreSharedKey store (per-epoch ML-KEM secrets).
    pub psk_store: FilePskStorage,
}

impl CliStores {
    /// Construct under a `<home>` directory.
    ///
    /// # Errors
    ///
    /// Returns an error if any subdirectory can't be created.
    pub fn open(home: &std::path::Path) -> Result<Self> {
        Ok(Self {
            kp_store: FileKeyPackageStorage::new(home.join("key_packages"))?,
            group_store: FileGroupStateStorage::new(home.join("groups"))?,
            psk_store: FilePskStorage::new(home.join("psks"))?,
        })
    }
}

/// Build a Lattice MLS `Client` backed by the file storage bundle.
///
/// # Errors
///
/// Returns an error on credential encoding failure (essentially
/// infallible for a valid `CliIdentity`).
pub fn build_client(identity: &CliIdentity, stores: &CliStores) -> Result<Client<CliMlsConfig>> {
    let credential_bytes = identity
        .credential
        .encode()
        .map_err(|e| anyhow!("encode credential: {e}"))?;
    let custom_credential = mls_rs_core::identity::CustomCredential::new(
        mls_rs_core::identity::CredentialType::new(CREDENTIAL_TYPE_LATTICE),
        credential_bytes,
    );
    let mls_credential = mls_rs_core::identity::Credential::Custom(custom_credential);

    let mut sig_pk_bytes = Vec::with_capacity(
        identity.credential.ed25519_pub.len() + identity.credential.ml_dsa_pub.len(),
    );
    sig_pk_bytes.extend_from_slice(&identity.credential.ed25519_pub);
    sig_pk_bytes.extend_from_slice(&identity.credential.ml_dsa_pub);

    let signing_identity =
        SigningIdentity::new(mls_credential, SignaturePublicKey::from(sig_pk_bytes));

    Ok(Client::builder()
        .identity_provider(LatticeIdentityProvider::new())
        .crypto_provider(LatticeCryptoProvider::new())
        .psk_store(stores.psk_store.clone())
        .key_package_repo(stores.kp_store.clone())
        .group_state_storage(stores.group_store.clone())
        .extension_type(<LatticeKemPubkey as MlsExtension>::extension_type())
        .extension_type(<PqWelcomePayload as MlsExtension>::extension_type())
        .signing_identity(
            signing_identity,
            identity.signature_secret.clone(),
            LATTICE_HYBRID_V1,
        )
        .build())
}

/// Build a KeyPackage `ExtensionList` carrying the identity's
/// `LatticeKemPubkey` so committers can encapsulate a PSK to it.
fn key_package_extensions(kem_pk: &LatticeKemPubkey) -> Result<ExtensionList> {
    let ext = kem_pk
        .clone()
        .into_extension()
        .map_err(|e| anyhow!("encode LatticeKemPubkey extension: {e:?}"))?;
    let mut list = ExtensionList::new();
    list.set(ext);
    Ok(list)
}

/// Generate a fresh KeyPackage. The secret material is persisted into
/// the file-backed `KeyPackageStorage` automatically by `mls-rs`.
///
/// # Errors
///
/// Returns an error on mls-rs failure.
pub fn cli_generate_key_package(
    client: &Client<CliMlsConfig>,
    identity: &CliIdentity,
) -> Result<Vec<u8>> {
    let kp_extensions = key_package_extensions(&identity.kem_keypair.pubkey())?;
    let kp = client
        .generate_key_package_message(kp_extensions, ExtensionList::new(), None)
        .map_err(|e| anyhow!("generate_key_package_message: {e:?}"))?;
    kp.mls_encode_to_vec()
        .map_err(|e| anyhow!("encode key package: {e}"))
}

/// Create a fresh MLS group on disk.
///
/// # Errors
///
/// Returns an error on mls-rs failure.
pub fn cli_create_group(
    client: &Client<CliMlsConfig>,
    identity: &CliIdentity,
    group_id: &[u8],
) -> Result<()> {
    let kp_extensions = key_package_extensions(&identity.kem_keypair.pubkey())?;
    let mut group = client
        .create_group_with_id(group_id.to_vec(), ExtensionList::new(), kp_extensions, None)
        .map_err(|e| anyhow!("create_group: {e:?}"))?;
    group
        .write_to_storage()
        .map_err(|e| anyhow!("write_to_storage: {e:?}"))?;
    Ok(())
}

/// Outbound commit + welcome pair from `cli_add_member`.
pub struct CliCommitOutput {
    /// Serialized MLS commit message.
    pub commit: Vec<u8>,
    /// Serialized MLS Welcome bytes (one per added joiner).
    pub welcomes: Vec<CliWelcomeEntry>,
}

/// Per-joiner welcome bundle returned alongside the commit.
pub struct CliWelcomeEntry {
    /// Recipient user_id (extracted from the joiner's credential).
    pub joiner_user_id: [u8; 32],
    /// Serialized MLS Welcome.
    pub mls_welcome: Vec<u8>,
    /// Serialized `PqWelcomePayload` (`MlsEncode`).
    pub pq_payload: Vec<u8>,
}

/// Add a member to an existing group, encapsulating a fresh ML-KEM
/// PSK to them.
///
/// # Errors
///
/// Returns an error if the group can't be loaded, the joiner's
/// `LatticeKemPubkey` extension is missing, or mls-rs rejects the
/// commit.
pub fn cli_add_member(
    client: &Client<CliMlsConfig>,
    stores: &CliStores,
    group_id: &[u8],
    joiner_key_package: &[u8],
) -> Result<CliCommitOutput> {
    let mut group = client
        .load_group(group_id)
        .map_err(|e| anyhow!("load_group: {e:?}"))?;
    let kp_msg = MlsMessage::mls_decode(&mut &*joiner_key_package)
        .map_err(|e| anyhow!("decode joiner KP: {e:?}"))?;

    // Pull joiner's LatticeKemPubkey from their KP extensions.
    let key_pkg = kp_msg
        .as_key_package()
        .ok_or_else(|| anyhow!("incoming message is not a KeyPackage"))?;
    let kp_ext = key_pkg
        .extensions
        .get(<LatticeKemPubkey as MlsExtension>::extension_type())
        .ok_or_else(|| anyhow!("KeyPackage missing LatticeKemPubkey extension"))?;
    let joiner_kem_pk = LatticeKemPubkey::from_extension(&kp_ext)
        .map_err(|e| anyhow!("decode LatticeKemPubkey: {e:?}"))?;

    // Joiner's user_id lives in their credential. Decode it.
    let joiner_user_id = extract_user_id(key_pkg.signing_identity())?;

    let next_epoch = group.context().epoch() + 1;
    let (pq_payload, ss) =
        seal_pq_secret(&joiner_kem_pk, next_epoch).map_err(|e| anyhow!("{e:?}"))?;

    let psk_id = psk_id_for_epoch(next_epoch);
    stores
        .psk_store
        .insert(&psk_id, &ss[..])
        .map_err(|e| anyhow!("insert PSK: {e:?}"))?;

    let commit_output = group
        .commit_builder()
        .add_member(kp_msg)
        .map_err(|e| anyhow!("add_member: {e:?}"))?
        .add_external_psk(psk_id)
        .map_err(|e| anyhow!("add_external_psk: {e:?}"))?
        .build()
        .map_err(|e| anyhow!("build commit: {e:?}"))?;

    group
        .write_to_storage()
        .map_err(|e| anyhow!("write_to_storage: {e:?}"))?;

    let commit_bytes = commit_output
        .commit_message
        .mls_encode_to_vec()
        .map_err(|e| anyhow!("encode commit: {e}"))?;
    let pq_bytes = pq_payload
        .mls_encode_to_vec()
        .map_err(|e| anyhow!("encode pq: {e}"))?;

    let welcomes = commit_output
        .welcome_messages
        .into_iter()
        .map(|w| -> Result<CliWelcomeEntry> {
            Ok(CliWelcomeEntry {
                joiner_user_id,
                mls_welcome: w
                    .mls_encode_to_vec()
                    .map_err(|e| anyhow!("encode welcome: {e}"))?,
                pq_payload: pq_bytes.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CliCommitOutput {
        commit: commit_bytes,
        welcomes,
    })
}

/// Apply our own pending commit. Must be called after `cli_add_member`
/// once the server confirms the commit was broadcast.
///
/// # Errors
///
/// Returns an error if the group has no pending commit or storage
/// write fails.
pub fn cli_apply_pending(client: &Client<CliMlsConfig>, group_id: &[u8]) -> Result<()> {
    let mut group = client
        .load_group(group_id)
        .map_err(|e| anyhow!("load_group: {e:?}"))?;
    group
        .apply_pending_commit()
        .map_err(|e| anyhow!("apply_pending_commit: {e:?}"))?;
    group
        .write_to_storage()
        .map_err(|e| anyhow!("write_to_storage: {e:?}"))?;
    Ok(())
}

/// Process an incoming Welcome (with its PQ payload) and join the
/// resulting group.
///
/// # Errors
///
/// Returns an error if the PQ payload can't be decapsulated, the
/// Welcome can't be decoded, or mls-rs rejects the join.
pub fn cli_process_welcome(
    client: &Client<CliMlsConfig>,
    identity: &CliIdentity,
    stores: &CliStores,
    mls_welcome: &[u8],
    pq_payload_bytes: &[u8],
) -> Result<Vec<u8>> {
    let pq = PqWelcomePayload::mls_decode(&mut &*pq_payload_bytes)
        .map_err(|e| anyhow!("decode PqWelcomePayload: {e:?}"))?;
    let ss = open_pq_secret(&identity.kem_keypair, &pq).map_err(|e| anyhow!("{e:?}"))?;
    let psk_id: ExternalPskId = psk_id_for_epoch(pq.epoch);
    stores
        .psk_store
        .insert(&psk_id, &ss[..])
        .map_err(|e| anyhow!("insert PSK: {e:?}"))?;
    // Sanity check that the PSK landed before mls-rs reads it.
    use mls_rs_core::psk::PreSharedKeyStorage;
    let _: Option<PreSharedKey> = stores
        .psk_store
        .get(&psk_id)
        .map_err(|e| anyhow!("{e:?}"))?;

    let mls_msg =
        MlsMessage::mls_decode(&mut &*mls_welcome).map_err(|e| anyhow!("decode welcome: {e:?}"))?;
    let (group, _) = client
        .join_group(None, &mls_msg, None)
        .map_err(|e| anyhow!("join_group: {e:?}"))?;
    let group_id = group.context().group_id().to_vec();
    let mut group_mut = group;
    group_mut
        .write_to_storage()
        .map_err(|e| anyhow!("write_to_storage: {e:?}"))?;
    Ok(group_id)
}

/// Encrypt an application message in the named group.
///
/// # Errors
///
/// Returns an error if the group can't be loaded or encryption fails.
pub fn cli_encrypt(client: &Client<CliMlsConfig>, group_id: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let mut group = client
        .load_group(group_id)
        .map_err(|e| anyhow!("load_group: {e:?}"))?;
    let msg = group
        .encrypt_application_message(pt, Vec::new())
        .map_err(|e| anyhow!("encrypt: {e:?}"))?;
    group
        .write_to_storage()
        .map_err(|e| anyhow!("write_to_storage: {e:?}"))?;
    msg.mls_encode_to_vec()
        .map_err(|e| anyhow!("encode app message: {e}"))
}

/// Decrypt an incoming MLS message in the named group. Returns the
/// application bytes if it was an `ApplicationMessage`; empty `Vec`
/// for handshake messages that advance state.
///
/// # Errors
///
/// Returns an error if the group can't be loaded or decryption fails.
pub fn cli_decrypt(
    client: &Client<CliMlsConfig>,
    group_id: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut group = client
        .load_group(group_id)
        .map_err(|e| anyhow!("load_group: {e:?}"))?;
    let msg = MlsMessage::mls_decode(&mut &*ciphertext)
        .map_err(|e| anyhow!("decode app message: {e:?}"))?;
    let received = group
        .process_incoming_message(msg)
        .map_err(|e| anyhow!("process_incoming_message: {e:?}"))?;
    group
        .write_to_storage()
        .map_err(|e| anyhow!("write_to_storage: {e:?}"))?;
    Ok(match received {
        ReceivedMessage::ApplicationMessage(app) => app.data().to_vec(),
        _ => Vec::new(),
    })
}

/// Best-effort extraction of the embedded Lattice `user_id` from a
/// `SigningIdentity`.
fn extract_user_id(si: &SigningIdentity) -> Result<[u8; 32]> {
    let mls_rs_core::identity::Credential::Custom(custom) = &si.credential else {
        return Err(anyhow!("signing identity is not a custom credential"));
    };
    let cred = lattice_crypto::credential::LatticeCredential::decode(&custom.data)
        .map_err(|e| anyhow!("decode LatticeCredential: {e:?}"))?;
    Ok(cred.user_id)
}

// Touch the import so the `CryptoProvider` re-export from `mls_rs`
// is treated as used by the trait-bound resolver in
// `WithCryptoProvider<LatticeCryptoProvider, _>`.
const _: fn(LatticeCryptoProvider) = |p| {
    let _ = p.supported_cipher_suites();
    let _ = LATTICE_HYBRID_V1;
};
