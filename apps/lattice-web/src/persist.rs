//! Browser-local persistence for the user's `LatticeIdentity`.
//!
//! Stores the identity material in `window.localStorage` under
//! `lattice/identity/v1`. Two blob versions are supported:
//!
//! * **`version: 1`** — plaintext (Phase δ.1). All key material is
//!   base64-only. Anyone with read access to the browser profile can
//!   recover the keys. Use only for dev / demo.
//! * **`version: 2`** — Argon2id-keyed ChaCha20-Poly1305 envelope
//!   around the secret fields (Phase δ.2). Public material
//!   (user_id, ed25519_pub, ml_dsa_pub, kem_ek) stays in the clear;
//!   the kem decapsulation key and signature secret key concat are
//!   sealed by an Argon2id-derived KEK. Argon2id params match D-08
//!   (m=64 MiB, t=3, p=1, 32-byte output).
//!
//! D-09 (WebAuthn-PRF KEK feeds AEAD) is a future Phase ε work — when
//! that lands, we'll add `version: 3` that swaps the Argon2id step
//! for a PRF-derived KEK.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use lattice_crypto::credential::{
    ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN, USER_ID_LEN,
};
use lattice_crypto::mls::LatticeIdentity;
use lattice_crypto::mls::leaf_node_kem::{KemKeyPair, ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN};
use mls_rs_core::crypto::SignatureSecretKey;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const STORAGE_KEY: &str = "lattice/identity/v1";
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;
const KEK_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Frame the version field of every blob shape so we can dispatch on
/// it before fully parsing.
#[derive(Debug, Deserialize)]
struct VersionedHeader {
    version: u32,
}

/// Plaintext v1 blob (Phase δ.1).
#[derive(Debug, Serialize, Deserialize)]
struct V1Blob {
    version: u32,
    user_id_b64: String,
    ed25519_pub_b64: String,
    ml_dsa_pub_b64: String,
    kem_ek_b64: String,
    kem_dk_b64: String,
    sig_sk_b64: String,
}

/// Encrypted v2 blob (Phase δ.2). Secret fields are sealed under an
/// Argon2id-derived KEK; public material stays in the clear so the UI
/// can show "encrypted identity for user_id …" without prompting.
#[derive(Debug, Serialize, Deserialize)]
struct V2Blob {
    version: u32,
    user_id_b64: String,
    ed25519_pub_b64: String,
    ml_dsa_pub_b64: String,
    kem_ek_b64: String,
    /// Argon2id salt (16 random bytes).
    salt_b64: String,
    /// ChaCha20-Poly1305 nonce (12 random bytes).
    nonce_b64: String,
    /// AEAD ciphertext over `kem_dk || sig_sk_len_le(u16) || sig_sk`.
    sealed_b64: String,
}

/// Whether the persisted blob is encrypted. Surfaced by [`probe`] so
/// the UI can decide whether to prompt for a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobShape {
    /// No persisted identity at this key.
    None,
    /// Plaintext v1.
    Plaintext,
    /// Argon2id-encrypted v2.
    Encrypted,
}

/// Inspect localStorage without decoding the secret material. Used at
/// boot to decide between "auto-restore" (v1) and "prompt for
/// passphrase" (v2) without parsing the whole blob twice.
///
/// # Errors
///
/// Surfaces only storage-access failure. A malformed `version` field
/// resolves to [`BlobShape::None`] — caller's [`load`] will surface
/// the parse error on the next call.
pub fn probe() -> Result<BlobShape, String> {
    let storage = local_storage()?;
    let Some(json) = storage
        .get_item(STORAGE_KEY)
        .map_err(|e| format!("localStorage get_item: {e:?}"))?
    else {
        return Ok(BlobShape::None);
    };
    let header: VersionedHeader = match serde_json::from_str(&json) {
        Ok(h) => h,
        Err(_) => return Ok(BlobShape::None),
    };
    Ok(match header.version {
        1 => BlobShape::Plaintext,
        2 => BlobShape::Encrypted,
        _ => BlobShape::None,
    })
}

/// Save `identity` to localStorage. If `passphrase` is `Some` and
/// non-empty, write the v2 (encrypted) blob; otherwise write the v1
/// (plaintext) blob.
///
/// # Errors
///
/// Argon2 / AEAD failures, JSON serialization, storage failures.
pub fn save(identity: &LatticeIdentity, passphrase: Option<&str>) -> Result<usize, String> {
    let json = match passphrase.filter(|p| !p.is_empty()) {
        Some(pw) => encode_v2(identity, pw)?,
        None => encode_v1(identity)?,
    };
    let storage = local_storage()?;
    storage
        .set_item(STORAGE_KEY, &json)
        .map_err(|e| format!("localStorage set_item: {e:?}"))?;
    Ok(json.len())
}

fn encode_v1(identity: &LatticeIdentity) -> Result<String, String> {
    let blob = V1Blob {
        version: 1,
        user_id_b64: B64.encode(identity.credential.user_id),
        ed25519_pub_b64: B64.encode(identity.credential.ed25519_pub),
        ml_dsa_pub_b64: B64.encode(&identity.credential.ml_dsa_pub),
        kem_ek_b64: B64.encode(identity.kem_keypair.encapsulation_key_bytes()),
        kem_dk_b64: B64.encode(identity.kem_keypair.decapsulation_key_persist()),
        sig_sk_b64: B64.encode(identity.signature_secret.as_bytes()),
    };
    serde_json::to_string(&blob).map_err(|e| format!("serialize v1 identity: {e}"))
}

fn encode_v2(identity: &LatticeIdentity, passphrase: &str) -> Result<String, String> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let kek = derive_kek(passphrase, &salt)?;

    let mut plaintext = Vec::new();
    let dk_bytes = identity.kem_keypair.decapsulation_key_persist();
    plaintext.extend_from_slice(dk_bytes);
    let sk_bytes = identity.signature_secret.as_bytes();
    let sk_len_u16: u16 = sk_bytes
        .len()
        .try_into()
        .map_err(|_| format!("sig_sk too long ({} bytes)", sk_bytes.len()))?;
    plaintext.extend_from_slice(&sk_len_u16.to_le_bytes());
    plaintext.extend_from_slice(sk_bytes);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(&kek.into());
    let aad = b"lattice/persist/v2";
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad,
            },
        )
        .map_err(|e| format!("ChaCha20-Poly1305 encrypt: {e}"))?;

    let blob = V2Blob {
        version: 2,
        user_id_b64: B64.encode(identity.credential.user_id),
        ed25519_pub_b64: B64.encode(identity.credential.ed25519_pub),
        ml_dsa_pub_b64: B64.encode(&identity.credential.ml_dsa_pub),
        kem_ek_b64: B64.encode(identity.kem_keypair.encapsulation_key_bytes()),
        salt_b64: B64.encode(salt),
        nonce_b64: B64.encode(nonce_bytes),
        sealed_b64: B64.encode(&ciphertext),
    };
    serde_json::to_string(&blob).map_err(|e| format!("serialize v2 identity: {e}"))
}

/// Try to load a previously-saved identity. `passphrase` is ignored
/// for v1 blobs; required (and matched) for v2 blobs.
///
/// Returns `Ok(None)` if no blob is present.
///
/// # Errors
///
/// Storage-access failure, malformed blob, or AEAD authentication
/// failure (wrong passphrase / tampered blob).
pub fn load(passphrase: Option<&str>) -> Result<Option<LatticeIdentity>, String> {
    let storage = local_storage()?;
    let Some(json) = storage
        .get_item(STORAGE_KEY)
        .map_err(|e| format!("localStorage get_item: {e:?}"))?
    else {
        return Ok(None);
    };
    let header: VersionedHeader =
        serde_json::from_str(&json).map_err(|e| format!("parse blob header: {e}"))?;
    match header.version {
        1 => decode_v1(&json).map(Some),
        2 => {
            let pw = passphrase
                .filter(|p| !p.is_empty())
                .ok_or_else(|| "encrypted blob: passphrase required".to_string())?;
            decode_v2(&json, pw).map(Some)
        }
        v => Err(format!("unsupported persisted identity version {v}")),
    }
}

fn decode_v1(json: &str) -> Result<LatticeIdentity, String> {
    let blob: V1Blob =
        serde_json::from_str(json).map_err(|e| format!("parse v1 identity blob: {e}"))?;
    let credential = decode_credential(
        &blob.user_id_b64,
        &blob.ed25519_pub_b64,
        &blob.ml_dsa_pub_b64,
    )?;
    let kem_ek = decode_kem_ek(&blob.kem_ek_b64)?;
    let kem_dk = decode_b64_exact(&blob.kem_dk_b64, ML_KEM_768_DK_LEN, "kem_dk")?;
    let sig_sk_bytes = B64
        .decode(&blob.sig_sk_b64)
        .map_err(|e| format!("decode sig_sk: {e}"))?;
    Ok(build_identity(credential, kem_ek, kem_dk, sig_sk_bytes))
}

fn decode_v2(json: &str, passphrase: &str) -> Result<LatticeIdentity, String> {
    let blob: V2Blob =
        serde_json::from_str(json).map_err(|e| format!("parse v2 identity blob: {e}"))?;
    let credential = decode_credential(
        &blob.user_id_b64,
        &blob.ed25519_pub_b64,
        &blob.ml_dsa_pub_b64,
    )?;
    let kem_ek = decode_kem_ek(&blob.kem_ek_b64)?;

    let salt = decode_b64_exact(&blob.salt_b64, SALT_LEN, "salt")?;
    let nonce_bytes = decode_b64_exact(&blob.nonce_b64, NONCE_LEN, "nonce")?;
    let kek = derive_kek(passphrase, &salt)?;

    let cipher = ChaCha20Poly1305::new(&kek.into());
    let aad = b"lattice/persist/v2";
    let ciphertext = B64
        .decode(&blob.sealed_b64)
        .map_err(|e| format!("decode sealed_b64: {e}"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|e| format!("AEAD decrypt failed (wrong passphrase?): {e}"))?;

    if plaintext.len() < ML_KEM_768_DK_LEN + 2 {
        return Err(format!(
            "decrypted body too short: {} bytes",
            plaintext.len()
        ));
    }
    let kem_dk = plaintext[..ML_KEM_768_DK_LEN].to_vec();
    let sk_len_le: [u8; 2] = plaintext[ML_KEM_768_DK_LEN..ML_KEM_768_DK_LEN + 2]
        .try_into()
        .map_err(|_| "sk_len slice".to_string())?;
    let sk_len = u16::from_le_bytes(sk_len_le) as usize;
    let sk_start = ML_KEM_768_DK_LEN + 2;
    if plaintext.len() < sk_start + sk_len {
        return Err(format!(
            "decrypted body sk truncated: have {} need {}",
            plaintext.len(),
            sk_start + sk_len
        ));
    }
    let sig_sk_bytes = plaintext[sk_start..sk_start + sk_len].to_vec();

    Ok(build_identity(credential, kem_ek, kem_dk, sig_sk_bytes))
}

fn build_identity(
    credential: LatticeCredential,
    kem_ek: Vec<u8>,
    kem_dk: Vec<u8>,
    sig_sk_bytes: Vec<u8>,
) -> LatticeIdentity {
    let kem_keypair = KemKeyPair::from_raw_bytes_public(kem_ek, kem_dk);
    let signature_secret = SignatureSecretKey::new(sig_sk_bytes);
    LatticeIdentity {
        credential,
        signature_secret,
        kem_keypair,
        key_package_repo:
            mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage::default(),
    }
}

fn decode_credential(
    user_id_b64: &str,
    ed25519_pub_b64: &str,
    ml_dsa_pub_b64: &str,
) -> Result<LatticeCredential, String> {
    let user_id_vec = B64
        .decode(user_id_b64)
        .map_err(|e| format!("decode user_id: {e}"))?;
    let user_id: [u8; USER_ID_LEN] = user_id_vec.as_slice().try_into().map_err(|_| {
        format!(
            "user_id length {} (expected {USER_ID_LEN})",
            user_id_vec.len()
        )
    })?;
    let ed25519_vec = B64
        .decode(ed25519_pub_b64)
        .map_err(|e| format!("decode ed25519_pub: {e}"))?;
    let ed25519_pub: [u8; ED25519_PK_LEN] =
        ed25519_vec.as_slice().try_into().map_err(|_| {
            format!(
                "ed25519_pub length {} (expected {ED25519_PK_LEN})",
                ed25519_vec.len()
            )
        })?;
    let ml_dsa_pub = B64
        .decode(ml_dsa_pub_b64)
        .map_err(|e| format!("decode ml_dsa_pub: {e}"))?;
    if ml_dsa_pub.len() != ML_DSA_65_PK_LEN {
        return Err(format!(
            "ml_dsa_pub length {} (expected {ML_DSA_65_PK_LEN})",
            ml_dsa_pub.len()
        ));
    }
    Ok(LatticeCredential {
        user_id,
        ed25519_pub,
        ml_dsa_pub,
    })
}

fn decode_kem_ek(s: &str) -> Result<Vec<u8>, String> {
    decode_b64_exact(s, ML_KEM_768_EK_LEN, "kem_ek")
}

fn decode_b64_exact(s: &str, expected: usize, label: &str) -> Result<Vec<u8>, String> {
    let v = B64.decode(s).map_err(|e| format!("decode {label}: {e}"))?;
    if v.len() != expected {
        return Err(format!(
            "{label} length {} (expected {expected})",
            v.len()
        ));
    }
    Ok(v)
}

fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<[u8; KEK_LEN], String> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEK_LEN))
        .map_err(|e| format!("Argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; KEK_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|e| format!("Argon2 hash: {e}"))?;
    Ok(kek)
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
