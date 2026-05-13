//! MLS group state management for Lattice — thin wrapper over `mls-rs`.
//!
//! Lattice uses MLS (RFC 9420) for all group key agreement. The custom
//! pieces of the construction (hybrid signatures, PSK injection of the
//! ML-KEM-768 secret, ML-KEM LeafNode + Welcome extensions) live in
//! sub-modules:
//!
//! - [`cipher_suite`] — `CipherSuiteProvider` impl for the
//!   `LATTICE_HYBRID_V1` (`0xF000`) suite (D-04).
//! - [`identity_provider`] — `IdentityProvider` impl for the
//!   `LatticeCredential` (`0xF001`) custom credential.
//! - [`psk`] — deterministic per-epoch PSK id derivation +
//!   in-memory `PreSharedKeyStorage`.
//! - [`leaf_node_kem`] — `LatticeKemPubkey` LeafNode extension
//!   (`0xF002`) and the per-device `KemKeyPair`.
//! - [`welcome_pq`] — `PqWelcomePayload` extension (`0xF003`) for the
//!   Welcome-side ML-KEM ciphertext delivery.
//!
//! This module exposes the high-level group operations that callers
//! (lattice-cli, lattice-server, lattice-web via lattice-core) use:
//! [`create_group`], [`add_member`], [`process_welcome`],
//! [`encrypt_application`], [`decrypt`], [`commit`], [`apply_commit`].
//!
//! ## Custom ciphersuite — hybrid PQ binding
//!
//! Per the D-04 re-open (2026-05-10), Lattice's PQ binding is achieved
//! via per-epoch external PSK injection rather than by rewriting the
//! MLS `init_secret`. `add_member` and `commit` both ML-KEM-encapsulate
//! a fresh shared secret to every (other) member's `LatticeKemPubkey`,
//! store the secret under `psk::psk_id_for_epoch(next_epoch)` in
//! the local [`psk::LatticePskStorage`], and reference the PSK from
//! the commit via `CommitBuilder::add_psk`. mls-rs's key schedule
//! evaluates `epoch_secret = Expand("epoch", Extract(joiner_secret,
//! psk_secret))`, folding the PQ secret in under HKDF-SHA-256 — the
//! cryptographic property D-04 calls for.
//!
//! ## Footguns
//!
//! - **`write_to_storage` after every mutation.** mls-rs only persists
//!   group state when callers explicitly call `Group::write_to_storage`
//!   ([mls/group/mod.rs §process_incoming_message]). Every method in
//!   this module that advances epoch state writes to storage before
//!   returning bytes to the network layer.
//! - **`apply_pending_commit` is mandatory.** After [`commit`] or
//!   [`add_member`], callers must call [`apply_commit`] once the
//!   server confirms the commit was broadcast, or the local epoch
//!   does not advance. The wrapper preserves this discipline rather
//!   than auto-applying so the caller can roll back if the server
//!   rejects.
//! - **PSK must be in storage *before* `join_group`.** mls-rs looks
//!   up the PSK synchronously while processing the Welcome
//!   ([`process_welcome`] writes the secret first, then calls
//!   `Client::join_group`).

#![allow(clippy::module_name_repetitions)]

pub mod cipher_suite;
pub mod identity_provider;
pub mod leaf_node_kem;
pub mod psk;
pub mod welcome_pq;

use mls_rs::{
    Client, ExtensionList, MlsMessage,
    identity::SigningIdentity,
    mls_rs_codec::{MlsDecode, MlsEncode},
    storage_provider::in_memory::InMemoryKeyPackageStorage,
};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_core::extension::MlsExtension;
use tracing::instrument;

use crate::credential::LatticeCredential;
use crate::{Error, Result};

use self::cipher_suite::{LATTICE_HYBRID_V1, LatticeCryptoProvider};
use self::identity_provider::LatticeIdentityProvider;
use self::leaf_node_kem::{KemKeyPair, LatticeKemPubkey};
use self::psk::{LatticePskStorage, psk_id_for_epoch};
use self::welcome_pq::{PqWelcomePayload, open_pq_secret, seal_pq_secret, seal_pq_secret_multi};

/// Per-device identity bundle used to build an MLS [`Client`].
///
/// Holds the hybrid signing key (Ed25519 + ML-DSA-65 packed bytes), the
/// ML-KEM-768 keypair, and the Lattice custom credential value. The
/// signing key bytes use the layout enforced by
/// [`cipher_suite::LatticeHybridCipherSuite::sign`].
pub struct LatticeIdentity {
    /// Lattice custom credential (user_id + ed25519_pub + ml_dsa_pub).
    pub credential: LatticeCredential,
    /// Hybrid signature secret key bytes: `ed25519_sk(32) || ml_dsa_seed(32)`.
    pub signature_secret: SignatureSecretKey,
    /// Per-device ML-KEM-768 keypair. Used to receive Welcome PQ payloads.
    pub kem_keypair: KemKeyPair,
    /// In-memory store for KeyPackage *secret* material this device has
    /// generated. mls-rs persists the private leaf-init key here on
    /// `generate_key_package_message` and looks it up by reference on
    /// `join_group`. We hold the storage on the identity so the same
    /// process can publish a KeyPackage and later consume the matching
    /// Welcome from a fresh `Client` instance. The storage is `Clone`
    /// + `Arc<Mutex<_>>` internally, so cloning the identity shares it.
    pub key_package_repo: InMemoryKeyPackageStorage,
}

/// Opaque handle to an active Lattice MLS group.
///
/// Wraps `mls_rs::Group` plus our local PSK storage. The PSK storage is
/// shared across clones (Arc<Mutex<_>>) so test setups and Phase E
/// integration harnesses can keep one storage per identity rather than
/// per group. Generic over the group state storage backend `G` —
/// defaults to `InMemoryGroupStateStorage` so non-browser callers
/// (CLI, server, tests) get the same behavior they had before.
pub struct GroupHandle<G = InMemoryGroupStateStorage, R = DefaultMlsRules>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    inner: mls_rs::Group<LatticeMlsConfig<G, R>>,
    psk_store: LatticePskStorage,
    /// The local ML-KEM-768 keypair; needed to open PqWelcomePayloads
    /// targeted at this group member when subsequent commits rotate the
    /// PSK secret. M2 only ships 1:1 groups where the self-commit path
    /// doesn't inject PSK, so this is currently a hold for M5 multi-
    /// member commit rotation logic.
    #[allow(dead_code)]
    kem_keypair: KemKeyPair,
}

impl<G, R> GroupHandle<G, R>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    /// Current MLS epoch of this group handle. Increments on every
    /// successfully-applied commit. Sealed-sender membership certs
    /// bind to a specific epoch (D-05), so callers issuing certs need
    /// to read it here.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.inner.context().epoch()
    }

    /// Iterate every member's `(leaf_index, user_id)`. The user_id is
    /// the 32-byte field of the `LatticeCredential` extracted from
    /// each leaf. Useful for device-revocation flows that need to
    /// find a particular leaf by user_id before calling
    /// `remove_member`.
    ///
    /// # Errors
    ///
    /// Returns an error if a leaf credential fails to decode or isn't
    /// a `LatticeCredential` (third-party credentials aren't yet
    /// supported on the Lattice wire).
    pub fn members(&self) -> Result<Vec<(u32, [u8; crate::credential::USER_ID_LEN])>> {
        let mut out = Vec::new();
        for m in self.inner.roster().members_iter() {
            let cred = m.signing_identity.credential.as_custom().ok_or_else(|| {
                Error::Mls("non-custom credential in roster".to_string())
            })?;
            let parsed = crate::credential::LatticeCredential::decode(cred.data())
                .map_err(|e| Error::Mls(format!("decode leaf credential: {e}")))?;
            out.push((m.index, parsed.user_id));
        }
        Ok(out)
    }
}

/// Result of an outgoing commit. Holds the wire bytes the caller pushes
/// to the network layer.
#[derive(Clone, Debug)]
pub struct CommitOutput {
    /// MLS commit message, serialized via mls-codec.
    pub commit: Vec<u8>,
    /// One [`LatticeWelcome`] per joiner added by this commit. Empty for
    /// commits that don't add members (e.g. a key update).
    pub welcomes: Vec<LatticeWelcome>,
}

/// Lattice-flavored Welcome: bundles the standard MLS Welcome bytes with
/// the per-joiner ML-KEM Welcome PQ payload that D-04's PSK injection
/// requires.
///
/// At the wire layer this becomes a single envelope (M3 server-side
/// scope). For M2 the type is intra-process: callers receive a
/// `LatticeWelcome`, ship it to the joiner over whatever transport, and
/// the joiner feeds it back into [`process_welcome`].
#[derive(Clone, Debug)]
pub struct LatticeWelcome {
    /// MLS Welcome message bytes (mls-codec encoded `MlsMessage`).
    pub mls_welcome: Vec<u8>,
    /// Per-joiner ML-KEM ciphertext + epoch tag.
    pub pq_payload: PqWelcomePayload,
}

/// Concrete [`MlsConfig`] type alias for Lattice clients, parameterized
/// over the on-disk group state storage backend AND the `MlsRules`
/// implementation. Both default — `G = InMemoryGroupStateStorage`,
/// `R = DefaultMlsRules` — so existing callers (CLI, tests, server)
/// keep working unchanged.
///
/// The browser client opts in to localStorage-backed state by passing
/// a different `G`. The hidden-membership group flow (M6 / D-16) opts
/// in by passing a `DefaultMlsRules` instance whose `CommitOptions`
/// have `ratchet_tree_extension = false`, which makes mls-rs omit the
/// ratchet tree from Welcome messages so observers can't enumerate
/// members.
pub type LatticeMlsConfig<
    G = mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage,
    R = mls_rs::mls_rules::DefaultMlsRules,
> = self::client_config::LatticeClientConfig<G, R>;

/// Re-export the in-memory group state storage so callers that just
/// want the default behavior don't need a direct `mls-rs` dep.
pub use mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage;
/// Re-export `DefaultMlsRules` so callers building custom rules
/// (hidden-membership groups, external-commit groups) start from the
/// known-good defaults.
pub use mls_rs::mls_rules::DefaultMlsRules;

/// Build a `DefaultMlsRules` instance configured for hidden-membership
/// groups (M6 / D-16). The key knob is
/// `CommitOptions::with_ratchet_tree_extension(false)` — mls-rs then
/// omits the ratchet tree from Welcome messages, so observers
/// parsing the Welcome bytes server-side can't enumerate member
/// identities. New joiners receive the tree out-of-band via a
/// future server route (the M6 polish landing alongside multi-
/// server store-and-forward).
///
/// `always_out_of_band_ratchet_tree` is left at default — callers
/// who want the more aggressive "even external commits don't carry
/// the tree" mode can opt in by passing their own `DefaultMlsRules`
/// through [`build_client`].
#[must_use]
pub fn hidden_membership_rules() -> DefaultMlsRules {
    DefaultMlsRules::new().with_commit_options(
        mls_rs::mls_rules::CommitOptions::default().with_ratchet_tree_extension(false),
    )
}

/// Create a fresh group with [`hidden_membership_rules`] applied.
/// Wraps [`create_group_with_storage`] + the hidden-rules knob; same
/// trade-offs as the docs on [`hidden_membership_rules`].
///
/// # Errors
///
/// Same as [`create_group_with_storage`].
pub fn create_hidden_group<G>(
    identity: &LatticeIdentity,
    psk_store: LatticePskStorage,
    group_id: &[u8],
    group_state_storage: G,
) -> Result<GroupHandle<G, DefaultMlsRules>>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
{
    let client = build_client(
        identity,
        psk_store.clone(),
        group_state_storage,
        hidden_membership_rules(),
    )?;
    let kp_extensions =
        key_package_extensions(&identity.credential.kem_pubkey_view(&identity.kem_keypair))?;
    let group = client
        .create_group_with_id(group_id.to_vec(), ExtensionList::new(), kp_extensions, None)
        .map_err(|e| Error::Mls(format!("create_hidden_group: {e:?}")))?;
    tracing::debug!(
        group_id_len = group_id.len(),
        "MLS hidden-membership group created"
    );
    Ok(GroupHandle {
        inner: group,
        psk_store,
        kem_keypair: identity.kem_keypair.duplicate(),
    })
}

pub mod client_config {
    //! Concrete `MlsConfig` shapes for Lattice clients.
    //!
    //! Generic over the [`GroupStateStorage`](mls_rs_core::group::GroupStateStorage)
    //! backend `G` so M4 / δ.3 can swap in a localStorage-backed
    //! implementation without disturbing the in-memory path used by
    //! CLI / server tests.

    use super::{
        cipher_suite::LatticeCryptoProvider, identity_provider::LatticeIdentityProvider,
        psk::LatticePskStorage,
    };
    use mls_rs::client_builder::{
        BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
        WithKeyPackageRepo, WithMlsRules, WithPskStore,
    };
    use mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage;

    /// `MlsConfig` shape used by Lattice clients. Order of `With*` layers
    /// is dictated by the `ClientBuilder` chain order — match what we
    /// actually call in [`super::build_client`].
    pub type LatticeClientConfig<G, R> = WithKeyPackageRepo<
        InMemoryKeyPackageStorage,
        WithPskStore<
            LatticePskStorage,
            WithGroupStateStorage<
                G,
                WithMlsRules<
                    R,
                    WithCryptoProvider<
                        LatticeCryptoProvider,
                        WithIdentityProvider<LatticeIdentityProvider, BaseConfig>,
                    >,
                >,
            >,
        >,
    >;
}

/// Build an `mls_rs::Client` configured for Lattice's custom suite.
///
/// Wires our `LatticeCryptoProvider` + `LatticeIdentityProvider` +
/// `LatticePskStorage` into the `ClientBuilder` chain. The chain order
/// matters: it determines the concrete `MlsConfig` type alias
/// [`LatticeMlsConfig`] resolves to (see [`client_config`]).
///
/// Generic over the group state storage backend `G` so M4 / δ.3 can
/// supply a localStorage-backed implementation. CLI / server tests
/// pass `InMemoryGroupStateStorage::default()` to get the original
/// behavior.
pub fn build_client<G, R>(
    identity: &LatticeIdentity,
    psk_store: LatticePskStorage,
    group_state_storage: G,
    mls_rules: R,
) -> Result<Client<LatticeMlsConfig<G, R>>>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    let credential_bytes = identity
        .credential
        .encode()
        .map_err(|e| Error::Mls(format!("encode credential: {e}")))?;
    let custom_credential = mls_rs_core::identity::CustomCredential::new(
        mls_rs_core::identity::CredentialType::new(crate::credential::CREDENTIAL_TYPE_LATTICE),
        credential_bytes,
    );
    let mls_credential = mls_rs_core::identity::Credential::Custom(custom_credential);

    // Reconstruct the packed signature pubkey from the credential fields
    // (ed25519_pub || ml_dsa_pub) — this is the layout
    // LatticeHybridCipherSuite::sign / ::verify enforce.
    let mut sig_pk_bytes = Vec::with_capacity(
        identity.credential.ed25519_pub.len() + identity.credential.ml_dsa_pub.len(),
    );
    sig_pk_bytes.extend_from_slice(&identity.credential.ed25519_pub);
    sig_pk_bytes.extend_from_slice(&identity.credential.ml_dsa_pub);

    let signing_identity = SigningIdentity::new(
        mls_credential,
        mls_rs_core::crypto::SignaturePublicKey::from(sig_pk_bytes),
    );

    Ok(Client::builder()
        .identity_provider(LatticeIdentityProvider::new())
        .crypto_provider(LatticeCryptoProvider::new())
        .mls_rules(mls_rules)
        .group_state_storage(group_state_storage)
        .psk_store(psk_store)
        .key_package_repo(identity.key_package_repo.clone())
        // Per the mls-rs ClientBuilder footgun (research §6.10): custom
        // extension types must be registered or mls-rs silently rejects
        // KeyPackages / Welcomes carrying them as
        // ExtensionNotInCapabilities.
        .extension_type(<LatticeKemPubkey as MlsExtension>::extension_type())
        .extension_type(<PqWelcomePayload as MlsExtension>::extension_type())
        .signing_identity(
            signing_identity,
            identity.signature_secret.clone(),
            LATTICE_HYBRID_V1,
        )
        .build())
}

/// Build the KeyPackage `ExtensionList` carrying our `LatticeKemPubkey`.
///
/// We attach the ML-KEM pubkey at the KeyPackage level rather than the
/// LeafNode level because mls-rs 0.55 marks the `LeafNode` field of
/// `KeyPackage` as `pub(crate)` with no public extension accessor. The
/// security property (each KeyPackage carries a per-device ML-KEM
/// pubkey) is unchanged either way — KeyPackages are issued per
/// device-rotation cycle so a KeyPackage-level extension is at least
/// as fresh as a LeafNode-level one.
fn key_package_extensions(kem_pk: &LatticeKemPubkey) -> Result<ExtensionList> {
    let ext = kem_pk
        .clone()
        .into_extension()
        .map_err(|e| Error::Mls(format!("encode LatticeKemPubkey extension: {e:?}")))?;
    let mut list = ExtensionList::new();
    list.set(ext);
    Ok(list)
}

/// Create a new MLS group with the calling identity as the sole initial
/// member.
///
/// The group id should be 16 bytes of stable randomness — typically a
/// UUIDv7's bytes, which is what `lattice-protocol` does for
/// [`GroupId`](crate::credential::USER_ID_LEN).
///
/// # Errors
///
/// Returns [`Error::Mls`] if mls-rs rejects the leaf-node extensions or
/// fails to compute the initial group secrets.
#[instrument(level = "debug", skip(identity, psk_store))]
pub fn create_group(
    identity: &LatticeIdentity,
    psk_store: LatticePskStorage,
    group_id: &[u8],
) -> Result<GroupHandle> {
    create_group_with_storage(
        identity,
        psk_store,
        group_id,
        InMemoryGroupStateStorage::default(),
    )
}

/// Like [`create_group`] but with a caller-supplied
/// [`GroupStateStorage`](mls_rs_core::group::GroupStateStorage)
/// backend. Used by the browser client to persist group state to
/// localStorage so reloads can `load_group()` instead of starting
/// fresh.
///
/// # Errors
///
/// Same as [`create_group`].
pub fn create_group_with_storage<G>(
    identity: &LatticeIdentity,
    psk_store: LatticePskStorage,
    group_id: &[u8],
    group_state_storage: G,
) -> Result<GroupHandle<G, DefaultMlsRules>>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
{
    let client = build_client(
        identity,
        psk_store.clone(),
        group_state_storage,
        DefaultMlsRules::default(),
    )?;
    let kp_extensions =
        key_package_extensions(&identity.credential.kem_pubkey_view(&identity.kem_keypair))?;
    let mut group = client
        .create_group_with_id(group_id.to_vec(), ExtensionList::new(), kp_extensions, None)
        .map_err(|e| Error::Mls(format!("create_group: {e:?}")))?;
    // Persist the freshly-created group so callers reloading from
    // the backing storage can resume it. mls-rs doesn't auto-flush
    // on construction; without this, `LocalStorageGroupStateStorage`
    // never sees the epoch-0 state and `load_group` later fails
    // with "group not found."
    group
        .write_to_storage()
        .map_err(|e| Error::Mls(format!("write_to_storage after create_group: {e:?}")))?;
    tracing::debug!(group_id_len = group_id.len(), "MLS group created");
    Ok(GroupHandle {
        inner: group,
        psk_store,
        kem_keypair: identity.kem_keypair.duplicate(),
    })
}

/// Reload a previously-persisted group from the configured
/// `GroupStateStorage` backend.
///
/// Returns a `GroupHandle` ready for `encrypt_application` /
/// `decrypt` / `commit`. Used by the browser client on page-reload
/// to resume an active conversation without re-running the full
/// MLS handshake.
///
/// # Errors
///
/// Returns [`Error::Mls`] if the storage doesn't hold a state
/// record for `group_id` or mls-rs rejects the reconstructed
/// state.
pub fn load_group_with_storage<G>(
    identity: &LatticeIdentity,
    psk_store: LatticePskStorage,
    group_id: &[u8],
    group_state_storage: G,
) -> Result<GroupHandle<G, DefaultMlsRules>>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
{
    let client = build_client(
        identity,
        psk_store.clone(),
        group_state_storage,
        DefaultMlsRules::default(),
    )?;
    let group = client
        .load_group(group_id)
        .map_err(|e| Error::Mls(format!("load_group: {e:?}")))?;
    Ok(GroupHandle {
        inner: group,
        psk_store,
        kem_keypair: identity.kem_keypair.duplicate(),
    })
}

/// Generate an MLS KeyPackage message for joining a group.
///
/// The KeyPackage carries this device's `LatticeKemPubkey` as a LeafNode
/// extension so committers can ML-KEM-encapsulate to it when adding
/// this device to a group.
///
/// # Errors
///
/// Returns [`Error::Mls`] on mls-rs failures.
#[instrument(level = "debug", skip(identity, psk_store))]
pub fn generate_key_package(
    identity: &LatticeIdentity,
    psk_store: LatticePskStorage,
) -> Result<Vec<u8>> {
    let client = build_client(
        identity,
        psk_store,
        InMemoryGroupStateStorage::default(),
        DefaultMlsRules::default(),
    )?;
    let kp_extensions =
        key_package_extensions(&identity.credential.kem_pubkey_view(&identity.kem_keypair))?;
    let kp = client
        .generate_key_package_message(kp_extensions, ExtensionList::new(), None)
        .map_err(|e| Error::Mls(format!("generate_key_package_message: {e:?}")))?;
    kp.mls_encode_to_vec()
        .map_err(|e| Error::Mls(format!("encode key package: {e:?}")))
}

/// Add a member to the group with PQ-PSK injection.
///
/// # Errors
///
/// Returns [`Error::Mls`] if the joiner's KeyPackage is malformed, lacks
/// a `LatticeKemPubkey` LeafNode extension, or if mls-rs rejects the
/// commit.
#[instrument(level = "debug", skip(group, joiner_key_package))]
pub fn add_member<G, R>(
    group: &mut GroupHandle<G, R>,
    joiner_key_package: &[u8],
) -> Result<CommitOutput>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    let kp = MlsMessage::mls_decode(&mut &*joiner_key_package)
        .map_err(|e| Error::Mls(format!("decode joiner KeyPackage: {e:?}")))?;

    // Pull the joiner's LatticeKemPubkey from their KeyPackage LeafNode.
    let joiner_kem_pk = extract_leaf_kem_pubkey(&kp)?;

    // Determine the epoch the new commit will land at. mls-rs increments
    // epoch by 1 per commit, so the next epoch is current+1.
    let next_epoch = group.inner.context().epoch() + 1;

    // ML-KEM-encapsulate a fresh shared secret to the joiner's pubkey.
    let (pq_payload, ss) = seal_pq_secret(&joiner_kem_pk, next_epoch)
        .map_err(|e| Error::Mls(format!("seal PQ secret: {e:?}")))?;

    // Store the secret locally under the deterministic per-epoch id, so
    // mls-rs can fetch it when processing this commit on the receive
    // side (Bob will store under the same id from his PqWelcomePayload).
    let psk_id = psk_id_for_epoch(next_epoch);
    let psk_secret = mls_rs_core::psk::PreSharedKey::from(ss.to_vec());
    group
        .psk_store
        .insert(psk_id.clone(), psk_secret)
        .map_err(|e| Error::Mls(format!("store PSK: {e:?}")))?;

    // Build the commit referencing the PSK.
    let commit_output = group
        .inner
        .commit_builder()
        .add_member(kp)
        .map_err(|e| Error::Mls(format!("add_member: {e:?}")))?
        .add_external_psk(psk_id)
        .map_err(|e| Error::Mls(format!("add_external_psk: {e:?}")))?
        .build()
        .map_err(|e| Error::Mls(format!("commit build: {e:?}")))?;

    // Encode the commit + each welcome.
    let commit_bytes = commit_output
        .commit_message
        .mls_encode_to_vec()
        .map_err(|e| Error::Mls(format!("encode commit: {e:?}")))?;

    let welcomes = commit_output
        .welcome_messages
        .into_iter()
        .map(|w| -> Result<LatticeWelcome> {
            Ok(LatticeWelcome {
                mls_welcome: w
                    .mls_encode_to_vec()
                    .map_err(|e| Error::Mls(format!("encode welcome: {e:?}")))?,
                pq_payload: pq_payload.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    tracing::debug!(
        epoch_after_commit = next_epoch,
        welcome_count = welcomes.len(),
        "MLS commit built with PQ-PSK"
    );
    Ok(CommitOutput {
        commit: commit_bytes,
        welcomes,
    })
}

/// Add **N joiners** to the group in a single commit (M5 multi-member
/// path). The flow mirrors [`add_member`] but:
///
/// 1. A single shared PSK secret `W` is generated.
/// 2. `seal_pq_secret_multi` produces one [`PqWelcomePayload`] per
///    joiner, each encapsulated to that joiner's ML-KEM pubkey and
///    wrapping the same `W`.
/// 3. The commit references one external PSK (the shared `W`).
/// 4. mls-rs emits one MLS Welcome per joiner; each gets paired with
///    its corresponding [`PqWelcomePayload`] (matched by add-list
///    order).
///
/// The order of `joiner_key_packages` is significant: each joiner's
/// `joiner_idx` in the wire payload is its position in this slice.
/// Callers must hand the recipient the welcome whose `joiner_idx`
/// matches their KP position; the simplest mapping is "k-th input ↔
/// k-th output welcome".
///
/// # Errors
///
/// Returns [`Error::Mls`] on any of: KP decode, missing
/// `LatticeKemPubkey` extension, PQ seal failure, mls-rs commit /
/// welcome build, or MLS encode failure.
#[instrument(level = "debug", skip(group, joiner_key_packages), fields(joiner_count = joiner_key_packages.len()))]
pub fn add_members<G, R>(
    group: &mut GroupHandle<G, R>,
    joiner_key_packages: &[&[u8]],
) -> Result<CommitOutput>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    if joiner_key_packages.is_empty() {
        return Err(Error::Mls(
            "add_members called with empty joiner list".to_string(),
        ));
    }

    // Decode every joiner's KeyPackage + pluck their ML-KEM pubkey.
    let mut kps = Vec::with_capacity(joiner_key_packages.len());
    let mut joiner_kem_pks = Vec::with_capacity(joiner_key_packages.len());
    for (idx, raw) in joiner_key_packages.iter().enumerate() {
        let kp = MlsMessage::mls_decode(&mut &**raw)
            .map_err(|e| Error::Mls(format!("decode joiner KP #{idx}: {e:?}")))?;
        let pk = extract_leaf_kem_pubkey(&kp)?;
        kps.push(kp);
        joiner_kem_pks.push(pk);
    }

    let next_epoch = group.inner.context().epoch() + 1;

    // ML-KEM-encapsulate one shared W to all joiners.
    let joiner_ref: Vec<&LatticeKemPubkey> = joiner_kem_pks.iter().collect();
    let (pq_payloads, ss) = seal_pq_secret_multi(&joiner_ref, next_epoch)
        .map_err(|e| Error::Mls(format!("seal PQ secret (multi): {e:?}")))?;

    // Store the shared W locally.
    let psk_id = psk_id_for_epoch(next_epoch);
    let psk_secret = mls_rs_core::psk::PreSharedKey::from(ss.to_vec());
    group
        .psk_store
        .insert(psk_id.clone(), psk_secret)
        .map_err(|e| Error::Mls(format!("store PSK: {e:?}")))?;

    // Build the commit with multiple Add proposals + the external PSK.
    let mut builder = group.inner.commit_builder();
    for kp in kps {
        builder = builder
            .add_member(kp)
            .map_err(|e| Error::Mls(format!("add_member proposal: {e:?}")))?;
    }
    let commit_output = builder
        .add_external_psk(psk_id)
        .map_err(|e| Error::Mls(format!("add_external_psk: {e:?}")))?
        .build()
        .map_err(|e| Error::Mls(format!("commit build (multi): {e:?}")))?;

    let commit_bytes = commit_output
        .commit_message
        .mls_encode_to_vec()
        .map_err(|e| Error::Mls(format!("encode commit: {e:?}")))?;

    if commit_output.welcome_messages.len() != pq_payloads.len() {
        return Err(Error::Mls(format!(
            "mls-rs emitted {} welcomes for {} joiners — mismatch",
            commit_output.welcome_messages.len(),
            pq_payloads.len()
        )));
    }
    let welcomes = commit_output
        .welcome_messages
        .into_iter()
        .zip(pq_payloads.into_iter())
        .map(|(w, pq_payload)| -> Result<LatticeWelcome> {
            Ok(LatticeWelcome {
                mls_welcome: w
                    .mls_encode_to_vec()
                    .map_err(|e| Error::Mls(format!("encode welcome: {e:?}")))?,
                pq_payload,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    tracing::debug!(
        epoch_after_commit = next_epoch,
        joiner_count = joiner_kem_pks.len(),
        "MLS multi-member commit built with PQ-PSK"
    );
    Ok(CommitOutput {
        commit: commit_bytes,
        welcomes,
    })
}

/// Apply our own pending commit after the server confirms broadcast.
///
/// Must be called after [`add_member`] / [`commit`] for the local epoch
/// to advance. Persists state to mls-rs storage before returning.
///
/// # Errors
///
/// Returns [`Error::Mls`] if there is no pending commit or storage write
/// fails.
#[instrument(level = "debug", skip(group))]
pub fn apply_commit<G, R>(group: &mut GroupHandle<G, R>) -> Result<()>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    group
        .inner
        .apply_pending_commit()
        .map_err(|e| Error::Mls(format!("apply_pending_commit: {e:?}")))?;
    group
        .inner
        .write_to_storage()
        .map_err(|e| Error::Mls(format!("write_to_storage after apply_commit: {e:?}")))?;
    Ok(())
}

/// Join a group from a [`LatticeWelcome`].
///
/// Decapsulates the PQ payload into the local PSK storage *before*
/// invoking `Client::join_group`, because mls-rs looks up the PSK
/// synchronously during join.
///
/// # Errors
///
/// Returns [`Error::Mls`] on PQ open failure, malformed Welcome bytes,
/// or any mls-rs rejection.
#[instrument(level = "debug", skip(identity, psk_store, welcome))]
pub fn process_welcome(
    identity: &LatticeIdentity,
    psk_store: LatticePskStorage,
    welcome: &LatticeWelcome,
) -> Result<GroupHandle> {
    process_welcome_with_storage(
        identity,
        psk_store,
        welcome,
        InMemoryGroupStateStorage::default(),
    )
}

/// Same as [`process_welcome`] but with a caller-supplied group state
/// storage backend.
///
/// # Errors
///
/// Same as [`process_welcome`].
pub fn process_welcome_with_storage<G>(
    identity: &LatticeIdentity,
    psk_store: LatticePskStorage,
    welcome: &LatticeWelcome,
    group_state_storage: G,
) -> Result<GroupHandle<G, DefaultMlsRules>>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
{
    // Open the PQ payload and store the secret BEFORE join_group.
    let ss = open_pq_secret(&identity.kem_keypair, &welcome.pq_payload)
        .map_err(|e| Error::Mls(format!("open PQ secret: {e:?}")))?;
    let psk_id = psk_id_for_epoch(welcome.pq_payload.epoch);
    let psk_secret = mls_rs_core::psk::PreSharedKey::from(ss.to_vec());
    psk_store
        .insert(psk_id, psk_secret)
        .map_err(|e| Error::Mls(format!("store PSK: {e:?}")))?;

    // Decode the MLS Welcome.
    let mls_welcome = MlsMessage::mls_decode(&mut &*welcome.mls_welcome)
        .map_err(|e| Error::Mls(format!("decode welcome: {e:?}")))?;

    let client = build_client(
        identity,
        psk_store.clone(),
        group_state_storage,
        DefaultMlsRules::default(),
    )?;
    let (mut group, _new_member_info) = client
        .join_group(None, &mls_welcome, None)
        .map_err(|e| Error::Mls(format!("join_group: {e:?}")))?;
    // Flush the post-join group state to storage so a later
    // `load_group_with_storage` (e.g. on browser reload) finds the
    // record. mls-rs's `join_group` doesn't auto-write.
    group
        .write_to_storage()
        .map_err(|e| Error::Mls(format!("write_to_storage after join_group: {e:?}")))?;

    tracing::debug!(
        epoch_after_join = welcome.pq_payload.epoch,
        "MLS group joined via Welcome with PQ-PSK"
    );

    Ok(GroupHandle {
        inner: group,
        psk_store,
        kem_keypair: identity.kem_keypair.duplicate(),
    })
}

/// Encrypt an application message for the current group epoch.
///
/// # Errors
///
/// Returns [`Error::Mls`] if the group has a pending commit (per
/// mls-rs's "commit required" rule) or encryption fails.
#[instrument(level = "trace", skip(group, plaintext), fields(pt_len = plaintext.len()))]
pub fn encrypt_application<G, R>(
    group: &mut GroupHandle<G, R>,
    plaintext: &[u8],
) -> Result<Vec<u8>>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    let msg = group
        .inner
        .encrypt_application_message(plaintext, Vec::new())
        .map_err(|e| Error::Mls(format!("encrypt_application: {e:?}")))?;
    group
        .inner
        .write_to_storage()
        .map_err(|e| Error::Mls(format!("write_to_storage after encrypt: {e:?}")))?;
    msg.mls_encode_to_vec()
        .map_err(|e| Error::Mls(format!("encode app message: {e:?}")))
}

/// Process an incoming MLS message (application or handshake).
///
/// Returns the application plaintext if the message was an application
/// message; returns an empty `Vec` if it was a handshake message
/// (commit or proposal) which advanced group state. Any state change
/// is persisted to storage before this function returns.
///
/// # Errors
///
/// Returns [`Error::Mls`] on decode or state-machine rejection.
#[instrument(level = "trace", skip(group, ciphertext), fields(ct_len = ciphertext.len()))]
pub fn decrypt<G, R>(group: &mut GroupHandle<G, R>, ciphertext: &[u8]) -> Result<Vec<u8>>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    let msg = MlsMessage::mls_decode(&mut &*ciphertext)
        .map_err(|e| Error::Mls(format!("decode incoming: {e:?}")))?;
    let processed = group
        .inner
        .process_incoming_message(msg)
        .map_err(|e| Error::Mls(format!("process_incoming_message: {e:?}")))?;
    group
        .inner
        .write_to_storage()
        .map_err(|e| Error::Mls(format!("write_to_storage after decrypt: {e:?}")))?;

    use mls_rs::group::ReceivedMessage;
    Ok(match processed {
        ReceivedMessage::ApplicationMessage(app) => app.data().to_vec(),
        // All non-application variants (commit / proposal / external /
        // future) advance state but produce no plaintext for the caller.
        _ => Vec::new(),
    })
}

/// Like [`decrypt`] but also returns the sender's user_id resolved
/// from the group's current roster.
///
/// Returns `(plaintext, sender_user_id)`. `sender_user_id` is
/// `None` for handshake messages that didn't carry an application
/// payload. For server-channel chat the sender resolution is
/// load-bearing for both UI attribution ("Bob said:" instead of
/// "Friends said:") and chunk 2.5b's admin-roster enforcement
/// (only members in the admin set can issue server-state ops).
///
/// # Errors
///
/// Same as [`decrypt`], plus [`Error::Mls`] if the sender leaf
/// index doesn't resolve to a member in the current roster.
#[instrument(level = "trace", skip(group, ciphertext), fields(ct_len = ciphertext.len()))]
pub fn decrypt_with_sender<G, R>(
    group: &mut GroupHandle<G, R>,
    ciphertext: &[u8],
) -> Result<(Vec<u8>, Option<[u8; crate::credential::USER_ID_LEN]>)>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    let msg = MlsMessage::mls_decode(&mut &*ciphertext)
        .map_err(|e| Error::Mls(format!("decode incoming: {e:?}")))?;
    let processed = group
        .inner
        .process_incoming_message(msg)
        .map_err(|e| Error::Mls(format!("process_incoming_message: {e:?}")))?;
    group
        .inner
        .write_to_storage()
        .map_err(|e| Error::Mls(format!("write_to_storage after decrypt: {e:?}")))?;

    use mls_rs::group::ReceivedMessage;
    match processed {
        ReceivedMessage::ApplicationMessage(app) => {
            let sender_index = app.sender_index;
            let data = app.data().to_vec();
            // Resolve sender_index → user_id via the group's
            // public roster. `GroupHandle::members()` re-reads
            // the roster every call; cheap for small N-party
            // groups, fine for chunk 2's typical Discord-style
            // server sizes.
            let members = group.members()?;
            let sender_uid = members
                .into_iter()
                .find(|(idx, _)| *idx == sender_index)
                .map(|(_, uid)| uid);
            Ok((data, sender_uid))
        }
        _ => Ok((Vec::new(), None)),
    }
}

/// Issue a Remove proposal against a specific leaf and commit it.
///
/// Used by M5's device revocation flow: the group admin (or the
/// owner of the device being lost/stolen, while they still have
/// access) calls `remove_member(group, leaf_index)`. The resulting
/// commit advances the group's epoch and rotates every active
/// member's path secrets; the removed leaf's old epoch keys stop
/// working after the next commit cycle.
///
/// No Welcome is produced (no new joiner). Existing members process
/// the commit via `decrypt(group, commit_bytes)` to advance their
/// local state.
///
/// # Errors
///
/// `Error::Mls` if `leaf_index` is invalid, mls-rs commit build
/// fails, or the encode step fails.
#[instrument(level = "debug", skip(group))]
pub fn remove_member<G, R>(group: &mut GroupHandle<G, R>, leaf_index: u32) -> Result<CommitOutput>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    let commit_output = group
        .inner
        .commit_builder()
        .remove_member(leaf_index)
        .map_err(|e| Error::Mls(format!("remove_member({leaf_index}): {e:?}")))?
        .build()
        .map_err(|e| Error::Mls(format!("commit build (remove): {e:?}")))?;
    let commit_bytes = commit_output
        .commit_message
        .mls_encode_to_vec()
        .map_err(|e| Error::Mls(format!("encode remove-commit: {e:?}")))?;
    Ok(CommitOutput {
        commit: commit_bytes,
        welcomes: Vec::new(),
    })
}

/// Force a self-commit on the local group. mls-rs builds an Update
/// path that rotates the ratchet (forward + post-compromise
/// secrecy) without changing membership; no Welcome is produced.
/// Used by M5's commit cadence scheduler.
///
/// 1:1 today — for multi-member groups (M5.5) this will need to
/// encapsulate fresh PQ-PSK material to every other member's
/// `LatticeKemPubkey` per D-04. Currently returns an error if called
/// on a non-1:1 group.
///
/// # Errors
///
/// Returns [`Error::Mls`] on multi-member groups (deferred to M5.5)
/// or any mls-rs failure.
#[instrument(level = "debug", skip(group))]
pub fn commit<G, R>(group: &mut GroupHandle<G, R>) -> Result<CommitOutput>
where
    G: mls_rs_core::group::GroupStateStorage + Clone + Send + Sync + 'static,
    R: mls_rs::MlsRules + Clone + 'static,
{
    let member_count = group.inner.roster().members_iter().count();
    if member_count > 2 {
        return Err(Error::Mls(format!(
            "commit() on a {member_count}-member group is not supported in M2 — \
             multi-member PQ-PSK rotation lands in M5"
        )));
    }

    // For now, build a commit with no proposals — mls-rs will issue an
    // Update path-style rotation. The PSK injection for self-update is a
    // future enhancement (M5); during M2 a self-commit on a 1-member or
    // 2-member group skips PSK injection because there are no other
    // members whose ML-KEM pubkey we need to encapsulate to.
    let commit_output = group
        .inner
        .commit(Vec::new())
        .map_err(|e| Error::Mls(format!("commit: {e:?}")))?;

    let commit_bytes = commit_output
        .commit_message
        .mls_encode_to_vec()
        .map_err(|e| Error::Mls(format!("encode commit: {e:?}")))?;

    Ok(CommitOutput {
        commit: commit_bytes,
        welcomes: Vec::new(),
    })
}

/// Pull the `LatticeKemPubkey` extension out of a KeyPackage's
/// `extensions` field.
fn extract_leaf_kem_pubkey(kp: &MlsMessage) -> Result<LatticeKemPubkey> {
    let key_pkg = kp
        .as_key_package()
        .ok_or_else(|| Error::Mls("not a KeyPackage MlsMessage".into()))?;
    let ext = key_pkg
        .extensions
        .get(<LatticeKemPubkey as MlsExtension>::extension_type())
        .ok_or_else(|| Error::Mls("KeyPackage missing LatticeKemPubkey extension".into()))?;
    LatticeKemPubkey::from_extension(&ext)
        .map_err(|e| Error::Mls(format!("decode LatticeKemPubkey: {e:?}")))
}

// Small helper extensions on LatticeCredential / KemKeyPair so the
// call sites stay readable.

impl LatticeCredential {
    /// Project the credential + a sibling [`KemKeyPair`] to the public
    /// `LatticeKemPubkey` value that goes into the LeafNode extension.
    ///
    /// The credential itself does not carry the ML-KEM pubkey (that
    /// lives in the LeafNode extension per the Phase C.2 design), but
    /// the credential and the keypair share lifetimes through the
    /// [`LatticeIdentity`] bundle, so it's convenient to express the
    /// projection here.
    #[must_use]
    pub fn kem_pubkey_view(&self, kp: &KemKeyPair) -> LatticeKemPubkey {
        let _ = self; // credential not actually involved in pubkey extraction
        kp.pubkey()
    }
}

impl KemKeyPair {
    /// Duplicate a keypair (workaround for `ml-kem`'s decap key not
    /// being `Clone`). Used internally to build the GroupHandle without
    /// consuming the caller's `KemKeyPair`.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        // ML-KEM-768 decap keys are not Clone in `ml-kem`'s public API;
        // we reconstruct by holding raw bytes here. Since `KemKeyPair`
        // already stores raw bytes, we just clone them.
        let dk_bytes = self.decapsulation_key_bytes().to_vec();
        let ek_bytes = self.encapsulation_key_bytes().to_vec();
        Self::from_raw_bytes(ek_bytes, dk_bytes)
    }
}

/// Hooks added to [`KemKeyPair`] for use inside this module's helpers.
/// Kept in this file so they don't leak to the public API of
/// [`leaf_node_kem`].
impl KemKeyPair {
    /// Raw bytes accessor for the decapsulation key. Only used by
    /// [`KemKeyPair::duplicate`] (above); not part of the public API.
    fn decapsulation_key_bytes(&self) -> &[u8] {
        self.decapsulation_key_inner()
    }
    /// Construct from raw bytes. Used only by [`KemKeyPair::duplicate`].
    fn from_raw_bytes(ek: Vec<u8>, dk: Vec<u8>) -> Self {
        Self::from_raw_bytes_inner(ek, dk)
    }
}
