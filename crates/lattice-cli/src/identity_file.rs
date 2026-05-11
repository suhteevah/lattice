//! Local identity persistence for the per-action CLI.
//!
//! Stores a JSON dump of the cryptographic material at
//! `<LATTICE_HOME_DIR>/identity.json`. The encrypted form (argon2id-
//! wrapped per D-08) is a follow-up — for now plain JSON sits on
//! disk under user-owned permissions.

#![allow(clippy::ptr_arg)]

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use lattice_crypto::credential::{
    ED25519_PK_LEN, LatticeCredential, ML_DSA_65_PK_LEN, USER_ID_LEN,
};
use lattice_crypto::mls::leaf_node_kem::{KemKeyPair, ML_KEM_768_DK_LEN, ML_KEM_768_EK_LEN};
use mls_rs_core::crypto::SignatureSecretKey;
use serde::{Deserialize, Serialize};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    /// 32-byte user id (BLAKE3-hashed canonical handle).
    user_id_b64: String,
    /// Ed25519 verifying key bytes (32).
    ed25519_pub_b64: String,
    /// ML-DSA-65 verifying key bytes (1952).
    ml_dsa_pub_b64: String,
    /// Packed `ed25519_sk(32) || ml_dsa_seed(32)` per
    /// `lattice-crypto::mls::cipher_suite::HYBRID_SIG_SK_LEN`.
    signature_secret_b64: String,
    /// ML-KEM-768 encapsulation key bytes (1184).
    kem_ek_b64: String,
    /// ML-KEM-768 decapsulation key bytes (2400).
    kem_dk_b64: String,
    /// Optional human display name.
    #[serde(default)]
    display_name: Option<String>,
}

/// Identity bundle plus storage-paths layout for the CLI.
pub struct CliIdentity {
    /// Credential carrying user_id + the hybrid sig public keys.
    pub credential: LatticeCredential,
    /// Packed hybrid signing key bytes (ready to feed `mls-rs`'s
    /// `signing_identity`).
    pub signature_secret: SignatureSecretKey,
    /// ML-KEM-768 keypair for PqWelcomePayload decapsulation.
    pub kem_keypair: KemKeyPair,
    /// User-facing display name (or the hex prefix of user_id).
    pub display_name: String,
}

impl CliIdentity {
    /// Persist the identity to `<home>/identity.json`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or serialization
    /// fails.
    pub fn save(&self, home: &PathBuf) -> Result<()> {
        let f = IdentityFile {
            user_id_b64: B64.encode(self.credential.user_id),
            ed25519_pub_b64: B64.encode(self.credential.ed25519_pub),
            ml_dsa_pub_b64: B64.encode(&self.credential.ml_dsa_pub),
            signature_secret_b64: B64.encode(self.signature_secret.as_bytes()),
            kem_ek_b64: B64.encode(self.kem_keypair.encapsulation_key_bytes()),
            // Use the pub(crate) accessor exposed by lattice-crypto for
            // KemKeyPair duplication — the encapsulation_key_bytes is
            // already accessible, but the decapsulation_key bytes need
            // the private inner accessor. Roundtrip via `duplicate`
            // would clone the bytes already.
            kem_dk_b64: B64.encode(self.dk_bytes_for_persist()),
            display_name: Some(self.display_name.clone()),
        };
        let path = home.join("identity.json");
        let bytes = serde_json::to_vec_pretty(&f).context("serialize identity")?;
        fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Load from disk, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is missing, malformed, or the
    /// embedded fields don't pass length validation.
    pub fn load(home: &PathBuf) -> Result<Self> {
        let path = home.join("identity.json");
        let bytes =
            fs::read(&path).with_context(|| format!("read identity from {}", path.display()))?;
        let f: IdentityFile = serde_json::from_slice(&bytes).context("parse identity.json")?;

        let user_id_v = B64.decode(&f.user_id_b64)?;
        let user_id: [u8; USER_ID_LEN] = user_id_v
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("user_id length"))?;
        let ed25519_pub_v = B64.decode(&f.ed25519_pub_b64)?;
        let ed25519_pub: [u8; ED25519_PK_LEN] = ed25519_pub_v
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ed25519_pub length"))?;
        let ml_dsa_pub = B64.decode(&f.ml_dsa_pub_b64)?;
        if ml_dsa_pub.len() != ML_DSA_65_PK_LEN {
            return Err(anyhow!("ml_dsa_pub length {}", ml_dsa_pub.len()));
        }
        let signature_secret_bytes = B64.decode(&f.signature_secret_b64)?;
        let kem_ek = B64.decode(&f.kem_ek_b64)?;
        if kem_ek.len() != ML_KEM_768_EK_LEN {
            return Err(anyhow!("kem_ek length {}", kem_ek.len()));
        }
        let kem_dk = B64.decode(&f.kem_dk_b64)?;
        if kem_dk.len() != ML_KEM_768_DK_LEN {
            return Err(anyhow!("kem_dk length {}", kem_dk.len()));
        }

        Ok(Self {
            credential: LatticeCredential {
                user_id,
                ed25519_pub,
                ml_dsa_pub,
            },
            signature_secret: SignatureSecretKey::from(signature_secret_bytes),
            kem_keypair: KemKeyPair::from_raw_bytes_public(kem_ek, kem_dk),
            display_name: f
                .display_name
                .unwrap_or_else(|| format!("user-{}", hex_prefix(&user_id))),
        })
    }

    /// Accessor for the decapsulation-key bytes used by `save()`.
    /// Calls the public `decapsulation_key_persist` accessor we added
    /// to `KemKeyPair` for exactly this purpose.
    fn dk_bytes_for_persist(&self) -> Vec<u8> {
        self.kem_keypair.decapsulation_key_persist().to_vec()
    }
}

/// Format the first 4 bytes of a user_id as a hex prefix for log lines.
#[must_use]
pub fn hex_prefix(user_id: &[u8; USER_ID_LEN]) -> String {
    let mut s = String::with_capacity(8);
    for b in &user_id[..4] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
