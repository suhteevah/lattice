//! Browser-local persistence for the user's `LatticeIdentity`.
//!
//! Stores the identity material in `window.localStorage` under
//! `lattice/identity/v1`. The blob is JSON-encoded with base64 fields
//! so it round-trips through a string-only key/value store.
//!
//! **At-rest threat model.** The stored bytes are NOT encrypted —
//! anyone with read access to the browser profile can recover the
//! decapsulation key + signature secret key. This is M4 Phase δ.1
//! ("persist at all") and intentionally precedes M4 Phase ε
//! (WebAuthn-PRF-keyed encryption-at-rest) per D-09. The stub blob
//! carries a `version` field so a future migration can wrap the
//! material in an Argon2id-keyed ChaCha20-Poly1305 envelope without
//! breaking older saves.

use base64::Engine;
use lattice_crypto::credential::{
    ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN, USER_ID_LEN,
};
use lattice_crypto::mls::LatticeIdentity;
use lattice_crypto::mls::leaf_node_kem::{KemKeyPair, ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN};
use mls_rs_core::crypto::SignatureSecretKey;
use serde::{Deserialize, Serialize};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const STORAGE_KEY: &str = "lattice/identity/v1";

/// Format-versioned identity blob. `version=1` is plaintext; later
/// versions will wrap secret fields in an AEAD envelope.
#[derive(Debug, Serialize, Deserialize)]
struct StoredIdentity {
    version: u32,
    user_id_b64: String,
    ed25519_pub_b64: String,
    ml_dsa_pub_b64: String,
    kem_ek_b64: String,
    kem_dk_b64: String,
    sig_sk_b64: String,
}

/// Save `identity` to `window.localStorage` under [`STORAGE_KEY`].
///
/// Overwrites any previous saved identity. Returns the byte length of
/// the serialized blob for the caller to log.
///
/// # Errors
///
/// Surfaces any failure path — missing `window`, no `localStorage`
/// support, quota exceeded, or storage backend-level errors.
pub fn save(identity: &LatticeIdentity) -> Result<usize, String> {
    let blob = StoredIdentity {
        version: 1,
        user_id_b64: B64.encode(identity.credential.user_id),
        ed25519_pub_b64: B64.encode(identity.credential.ed25519_pub),
        ml_dsa_pub_b64: B64.encode(&identity.credential.ml_dsa_pub),
        kem_ek_b64: B64.encode(identity.kem_keypair.encapsulation_key_bytes()),
        kem_dk_b64: B64.encode(identity.kem_keypair.decapsulation_key_persist()),
        sig_sk_b64: B64.encode(identity.signature_secret.as_bytes()),
    };
    let json = serde_json::to_string(&blob).map_err(|e| format!("serialize identity: {e}"))?;
    let storage = local_storage()?;
    storage
        .set_item(STORAGE_KEY, &json)
        .map_err(|e| format!("localStorage set_item: {e:?}"))?;
    Ok(json.len())
}

/// Try to load a previously-saved identity. Returns `Ok(None)` if no
/// blob is present — that's the first-run case, not an error.
///
/// # Errors
///
/// Storage-access failure or a malformed blob.
pub fn load() -> Result<Option<LatticeIdentity>, String> {
    let storage = local_storage()?;
    let Some(json) = storage
        .get_item(STORAGE_KEY)
        .map_err(|e| format!("localStorage get_item: {e:?}"))?
    else {
        return Ok(None);
    };
    let blob: StoredIdentity =
        serde_json::from_str(&json).map_err(|e| format!("parse identity blob: {e}"))?;
    if blob.version != 1 {
        return Err(format!(
            "unsupported persisted identity version {}; expected 1",
            blob.version
        ));
    }

    let user_id_vec = B64
        .decode(&blob.user_id_b64)
        .map_err(|e| format!("decode user_id: {e}"))?;
    let user_id: [u8; USER_ID_LEN] = user_id_vec.as_slice().try_into().map_err(|_| {
        format!(
            "user_id length {} (expected {USER_ID_LEN})",
            user_id_vec.len()
        )
    })?;
    let ed25519_vec = B64
        .decode(&blob.ed25519_pub_b64)
        .map_err(|e| format!("decode ed25519_pub: {e}"))?;
    let ed25519_pub: [u8; ED25519_PK_LEN] =
        ed25519_vec.as_slice().try_into().map_err(|_| {
            format!(
                "ed25519_pub length {} (expected {ED25519_PK_LEN})",
                ed25519_vec.len()
            )
        })?;
    let ml_dsa_pub = B64
        .decode(&blob.ml_dsa_pub_b64)
        .map_err(|e| format!("decode ml_dsa_pub: {e}"))?;
    if ml_dsa_pub.len() != ML_DSA_65_PK_LEN {
        return Err(format!(
            "ml_dsa_pub length {} (expected {ML_DSA_65_PK_LEN})",
            ml_dsa_pub.len()
        ));
    }
    let kem_ek = B64
        .decode(&blob.kem_ek_b64)
        .map_err(|e| format!("decode kem_ek: {e}"))?;
    if kem_ek.len() != ML_KEM_768_EK_LEN {
        return Err(format!(
            "kem_ek length {} (expected {ML_KEM_768_EK_LEN})",
            kem_ek.len()
        ));
    }
    let kem_dk = B64
        .decode(&blob.kem_dk_b64)
        .map_err(|e| format!("decode kem_dk: {e}"))?;
    if kem_dk.len() != ML_KEM_768_DK_LEN {
        return Err(format!(
            "kem_dk length {} (expected {ML_KEM_768_DK_LEN})",
            kem_dk.len()
        ));
    }
    let sig_sk_bytes = B64
        .decode(&blob.sig_sk_b64)
        .map_err(|e| format!("decode sig_sk: {e}"))?;

    let credential = LatticeCredential {
        user_id,
        ed25519_pub,
        ml_dsa_pub,
    };
    let kem_keypair = KemKeyPair::from_raw_bytes_public(kem_ek, kem_dk);
    let signature_secret = SignatureSecretKey::new(sig_sk_bytes);

    Ok(Some(LatticeIdentity {
        credential,
        signature_secret,
        kem_keypair,
        // The KeyPackage repo is intentionally regenerated empty on
        // reload — the M2 in-memory storage isn't itself persisted,
        // so old KPs won't decap incoming Welcomes anyway. Callers
        // can re-publish a fresh KP after restore.
        key_package_repo:
            mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage::default(),
    }))
}

/// Drop any persisted identity. Returns `true` if a blob existed and
/// was removed, `false` if nothing was there.
///
/// # Errors
///
/// Storage-access failure.
pub fn clear() -> Result<bool, String> {
    let storage = local_storage()?;
    let existed = storage
        .get_item(STORAGE_KEY)
        .map_err(|e| format!("localStorage get_item: {e:?}"))?
        .is_some();
    storage
        .remove_item(STORAGE_KEY)
        .map_err(|e| format!("localStorage remove_item: {e:?}"))?;
    Ok(existed)
}

fn local_storage() -> Result<web_sys::Storage, String> {
    let window = web_sys::window().ok_or_else(|| "no window".to_string())?;
    window
        .local_storage()
        .map_err(|e| format!("window.localStorage: {e:?}"))?
        .ok_or_else(|| "localStorage unavailable".to_string())
}
