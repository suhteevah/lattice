//! MLS group state management — thin wrapper over `mls-rs`.
//!
//! Lattice uses MLS (RFC 9420) for all group key agreement. This module
//! pins the ciphersuite, configures the credential type, and exposes the
//! subset of `mls-rs` operations the rest of the codebase needs.
//!
//! ## Ciphersuite
//!
//! We start with `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` (mls-rs default
//! for the 256-bit security level) and **augment** it with an ML-KEM-768
//! layer in the init secret derivation. This is the open implementation
//! task tracked in `docs/HANDOFF.md §8`.
//!
//! ## Commit cadence
//!
//! Aggressive commits are part of the V1 security roadmap: every 50
//! application messages OR every 5 minutes, whichever comes first. The
//! scheduler lives here and is driven by the client core.
//!
//! ## Status
//!
//! Stub — see `docs/HANDOFF.md §6`. Real implementation lands in M2; the
//! API shape (mutable `GroupHandle`, async-friendly types) is what the
//! caller will use post-M2.

// Stubs intentionally take `&mut GroupHandle` even though the current
// no-op bodies don't mutate — M2's real implementation will mutate state.
#![allow(clippy::needless_pass_by_ref_mut)]

use tracing::instrument;

use crate::{Error, Result};

/// Opaque handle to an MLS group state. Wraps `mls_rs::Group` so callers
/// do not depend directly on `mls-rs` API surface.
pub struct GroupHandle {
    /// Internal mls-rs group state. Boxed to keep handle size stable.
    _inner: (),
}

/// Result of an outgoing commit: the commit message to broadcast, plus any
/// Welcome messages for newly added members.
#[derive(Clone, Debug)]
pub struct CommitOutput {
    /// Serialized commit framed for the wire.
    pub commit: Vec<u8>,
    /// Welcome messages indexed by recipient `key_package_ref`.
    pub welcomes: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Create a new MLS group with the calling user as the sole initial member.
///
/// # Errors
///
/// Returns [`Error::Mls`] if `mls-rs` rejects the parameters.
#[instrument(level = "debug")]
pub fn create_group(group_id: &[u8]) -> Result<GroupHandle> {
    let _ = group_id;
    tracing::debug!("mls::create_group — TODO");
    Err(Error::Mls("mls::create_group not implemented".into()))
}

/// Add a member to the group, producing a commit + Welcome.
///
/// # Errors
///
/// Returns [`Error::Mls`] on validation or proposal failures.
#[instrument(level = "debug", skip(group, key_package))]
pub fn add_member(group: &mut GroupHandle, key_package: &[u8]) -> Result<CommitOutput> {
    let _ = (group, key_package);
    tracing::debug!("mls::add_member — TODO");
    Err(Error::Mls("mls::add_member not implemented".into()))
}

/// Encrypt an application message for the current group epoch.
///
/// # Errors
///
/// Returns [`Error::Mls`] if the group is in a bad state or encryption fails.
#[instrument(level = "trace", skip(group, plaintext), fields(pt_len = plaintext.len()))]
pub fn encrypt_application(group: &mut GroupHandle, plaintext: &[u8]) -> Result<Vec<u8>> {
    let _ = (group, plaintext);
    tracing::trace!("mls::encrypt_application — TODO");
    Err(Error::Mls("mls::encrypt_application not implemented".into()))
}

/// Decrypt an incoming MLS message (application or handshake).
///
/// # Errors
///
/// Returns [`Error::Mls`] on any state machine rejection.
#[instrument(level = "trace", skip(group, ciphertext), fields(ct_len = ciphertext.len()))]
pub fn decrypt(group: &mut GroupHandle, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let _ = (group, ciphertext);
    tracing::trace!("mls::decrypt — TODO");
    Err(Error::Mls("mls::decrypt not implemented".into()))
}

/// Force a commit (rotates group keys). Called by the commit scheduler when
/// the message-count or time threshold is reached.
///
/// # Errors
///
/// Returns [`Error::Mls`] if the group cannot currently commit.
#[instrument(level = "debug", skip(group))]
pub fn commit(group: &mut GroupHandle) -> Result<CommitOutput> {
    let _ = group;
    tracing::debug!("mls::commit — TODO");
    Err(Error::Mls("mls::commit not implemented".into()))
}
