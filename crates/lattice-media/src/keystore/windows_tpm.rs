//! Windows TPM 2.0-backed [`Keystore`] implementation (M7 Phase G.3).
//!
//! ## Why a wrap key, not direct signing
//!
//! NCrypt's `Microsoft Platform Crypto Provider`
//! (`MS_PLATFORM_CRYPTO_PROVIDER`) — the only NCrypt KSP that talks to
//! TPM 2.0 hardware — exposes RSA and ECDSA (P-256 / P-384 / P-521)
//! only. Ed25519 and ML-DSA-65 (HANDOFF §8 spec lock) cannot be signed
//! directly inside the TPM. So we use the TPM as a **wrapping**
//! primitive instead of a signing primitive:
//!
//! 1. A single persistent RSA-2048 keypair lives in the TPM under the
//!    named handle [`WRAP_KEY_NAME`]. Non-exportable. Created lazily
//!    on first use.
//! 2. Each identity gets its own fresh 32-byte ChaCha20 key + 12-byte
//!    nonce from [`OsRng`]. We ChaCha20-Poly1305-seal the
//!    `ml_dsa_seed || ed25519_sk` blob with that per-identity key,
//!    then OAEP-wrap the 32-byte key with the TPM RSA public so only
//!    the TPM can recover it. Output goes to `<handle_hex>.tpmseal`.
//! 3. To sign: read the `.tpmseal` file, `NCryptDecrypt` the wrapped
//!    AEAD key, ChaCha20-Poly1305-unseal the secret bytes (into a
//!    [`Zeroizing`] buffer), call `lattice_crypto::identity::sign`.
//!
//! The persistent wrap key outlives any individual identity — multiple
//! `.tpmseal` files share it, each carrying its own wrapped symmetric
//! key + ciphertext. The wrap key is generated with
//! `NCRYPT_OVERWRITE_KEY_FLAG` deliberately *unset*, so re-running the
//! provisioning path against an already-provisioned machine is a no-op
//! that opens the existing key.
//!
//! ## On-disk layout (`<handle_hex>.tpmseal`)
//!
//! ```text
//!  version_byte  =1
//!  wrapped_key_len_u16_be  big-endian length of the OAEP-wrapped AEAD key
//!  wrapped_key             OAEP-wrapped 32-byte ChaCha20-Poly1305 key
//!  nonce_12                ChaCha20-Poly1305 nonce
//!  ciphertext_with_tag     ChaCha20-Poly1305(secret_blob) + 16-byte tag
//! ```
//!
//! `version_byte = 1` is a forward-compatibility gate; bumping it
//! requires a one-way migration of every persisted file. The
//! `wrapped_key_len` slot is 16 bits to keep the parser uniform — for
//! RSA-2048 it's always 256, but we don't bake that in.
//!
//! ## Posture
//!
//! - The TPM never sees the identity secret bytes; it only sees the
//!   32-byte AEAD key that wraps them.
//! - The AEAD-encrypted blob is useless without the TPM (no other
//!   process / user / machine can recover the wrap key without the
//!   physical chip).
//! - This is not PCR-bound. Sealing to PCRs is intentionally out of
//!   scope for G.3 (see `scratch/m7-phase-g-plan.md` §G.3).
//!
//! ## Sidecar
//!
//! Public-key bytes go into a sibling `.pub` JSON file with the same
//! schema as [`super::windows::WindowsKeystore`]. `list()` / `pubkey()`
//! read it without touching the TPM.

#![allow(unsafe_code)] // SAFETY: see each `unsafe` block; required for NCrypt FFI.

use std::fs;
use std::path::PathBuf;
use std::ptr;
use std::time::SystemTime;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use lattice_crypto::identity::{HybridSignature, IdentityPublicKey, generate_identity, sign};
use rand::RngCore;
use rand::rngs::OsRng;
use tracing::{debug, instrument, warn};
use windows::Win32::Security::Cryptography::{
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG,
    NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt,
    NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty,
};
use windows::core::HRESULT;
use zeroize::Zeroizing;

use super::memory::{identity_secret_from_bytes, identity_secret_to_bytes};
use super::{KeyHandle, Keystore, KeystoreError, PublicSidecar, StoredKey};

/// Suffix for the TPM-wrapped sealed blob. **Not interchangeable** with
/// the DPAPI keystore's `.dpapi` files — different wrap construction.
const SEAL_SUFFIX: &str = "tpmseal";

/// Suffix for the public-key sidecar JSON. Compatible with the DPAPI
/// keystore so a future migration tool can rewrap blobs without
/// touching the sidecars.
const SIDECAR_SUFFIX: &str = "pub";

/// Named handle for the persistent TPM-resident RSA wrap key. One per
/// machine. Generated lazily on first use; subsequent runs reopen it.
///
/// The `-v1` suffix lets us roll forward to a new wrap key on a future
/// version bump without colliding with old installs.
const WRAP_KEY_NAME: &str = "Lattice-MasterWrap-v1";

/// Modulus length for the wrap key. RSA-2048 is the minimum the TPM 2.0
/// Platform Crypto Provider supports; higher (3072/4096) is also fine
/// but slower and not needed for our throughput. The on-disk layout
/// doesn't bake this in — the `wrapped_key_len_u16_be` field handles
/// any size up to 65 535 bits of ciphertext.
const WRAP_KEY_BITS: u32 = 2048;

/// On-disk format version tag. Bump if the layout changes; old files
/// fail parse with [`KeystoreError::MalformedBlob`].
const SEAL_VERSION: u8 = 1;

/// ChaCha20-Poly1305 nonce length in bytes.
const NONCE_LEN: usize = 12;

/// ChaCha20-Poly1305 key length in bytes.
const AEAD_KEY_LEN: usize = 32;

/// `NCryptCreatePersistedKey` `dwLegacyKeySpec` value when the key
/// is created via CNG (no legacy crypto-API key-spec slot).
const KEY_SPEC_NONE: CERT_KEY_SPEC = CERT_KEY_SPEC(0);

/// File-backed TPM-wrapped keystore. Each identity is two files under
/// `dir`:
///
/// - `<handle_hex>.tpmseal` — TPM-wrapped AEAD blob.
/// - `<handle_hex>.pub` — public-key sidecar (shared schema with
///   [`super::windows::WindowsKeystore`]).
///
/// The persistent TPM-resident wrap key is shared across all
/// identities and outlives the keystore instance.
#[derive(Debug)]
pub struct TpmWindowsKeystore {
    dir: PathBuf,
}

impl TpmWindowsKeystore {
    /// Construct a TPM keystore rooted at `dir`. Creates the directory
    /// (and parents) if needed.
    ///
    /// Construction does **not** touch the TPM — provisioning happens
    /// lazily on first [`Keystore::generate`] or [`Keystore::sign`].
    /// This keeps `at_default_location()` cheap and lets callers fall
    /// back to a different keystore impl based on actual failure modes
    /// from key ops rather than an upfront probe.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] if the directory cannot be
    /// created.
    #[instrument(level = "debug")]
    pub fn new(dir: impl Into<PathBuf> + std::fmt::Debug) -> Result<Self, KeystoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        debug!(?dir, "TpmWindowsKeystore: ready");
        Ok(Self { dir })
    }

    /// Convenience constructor pointing at the conventional location
    /// `%LOCALAPPDATA%\Lattice\keystore-tpm`. Distinct from the DPAPI
    /// keystore directory so the two can coexist on the same machine
    /// during the G.1 → G.3 migration window.
    ///
    /// Falls back to the current working directory if
    /// `dirs::data_local_dir()` returns `None`.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] if directory creation fails.
    #[instrument(level = "debug")]
    pub fn at_default_location() -> Result<Self, KeystoreError> {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        Self::new(base.join("Lattice").join("keystore-tpm"))
    }

    fn seal_path(&self, handle: &KeyHandle) -> PathBuf {
        self.dir.join(format!("{}.{SEAL_SUFFIX}", handle.to_hex()))
    }

    fn sidecar_path(&self, handle: &KeyHandle) -> PathBuf {
        self.dir
            .join(format!("{}.{SIDECAR_SUFFIX}", handle.to_hex()))
    }

    fn read_sidecar(&self, handle: &KeyHandle) -> Result<StoredKey, KeystoreError> {
        let bytes = fs::read(self.sidecar_path(handle))?;
        let sidecar: PublicSidecar = serde_json::from_slice(&bytes)?;
        let (public, label, created_at) = sidecar.into_public()?;
        Ok(StoredKey {
            handle: *handle,
            public,
            label,
            created_at,
        })
    }
}

impl Keystore for TpmWindowsKeystore {
    #[instrument(level = "debug", skip(self), fields(label = %label))]
    fn generate(&self, label: &str) -> Result<StoredKey, KeystoreError> {
        let (public, secret) =
            generate_identity().map_err(|e| KeystoreError::Crypto(e.to_string()))?;
        let secret_bytes = identity_secret_to_bytes(&secret);

        let handle = KeyHandle::random();
        let created_at = SystemTime::now();

        let sealed = tpm_seal(&secret_bytes)?;
        fs::write(self.seal_path(&handle), &sealed)?;

        let sidecar = PublicSidecar::from_public(&public, label, created_at);
        let sidecar_json = serde_json::to_vec_pretty(&sidecar)?;
        fs::write(self.sidecar_path(&handle), sidecar_json)?;

        debug!(handle = %handle, sealed_len = sealed.len(), "TpmWindowsKeystore: generated key");
        Ok(StoredKey {
            handle,
            public,
            created_at,
            label: label.to_string(),
        })
    }

    #[instrument(level = "debug", skip(self), fields(handle = %handle))]
    fn pubkey(&self, handle: &KeyHandle) -> Result<IdentityPublicKey, KeystoreError> {
        match self.read_sidecar(handle) {
            Ok(stored) => Ok(stored.public),
            Err(KeystoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(KeystoreError::NotFound { handle: *handle })
            }
            Err(other) => Err(other),
        }
    }

    #[instrument(level = "debug", skip(self, message), fields(handle = %handle, msg_len = message.len()))]
    fn sign(
        &self,
        handle: &KeyHandle,
        message: &[u8],
    ) -> Result<HybridSignature, KeystoreError> {
        let sealed = match fs::read(self.seal_path(handle)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeystoreError::NotFound { handle: *handle });
            }
            Err(e) => return Err(KeystoreError::Io(e)),
        };
        let plain = tpm_unseal(&sealed)?;
        let secret = identity_secret_from_bytes(&plain)?;
        sign(&secret, message).map_err(|e| KeystoreError::Crypto(e.to_string()))
    }

    #[instrument(level = "debug", skip(self), fields(handle = %handle))]
    fn delete(&self, handle: &KeyHandle) -> Result<bool, KeystoreError> {
        let mut was_present = false;
        for path in [self.seal_path(handle), self.sidecar_path(handle)] {
            match fs::remove_file(&path) {
                Ok(()) => {
                    was_present = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    warn!(?path, error = %e, "TpmWindowsKeystore: delete partial failure");
                    return Err(KeystoreError::Io(e));
                }
            }
        }
        Ok(was_present)
    }

    #[instrument(level = "debug", skip(self))]
    fn list(&self) -> Result<Vec<StoredKey>, KeystoreError> {
        let mut entries: Vec<StoredKey> = Vec::new();
        for dirent in fs::read_dir(&self.dir)? {
            let dirent = dirent?;
            let path = dirent.path();
            if path.extension().and_then(|e| e.to_str()) != Some(SIDECAR_SUFFIX) {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(handle) = KeyHandle::from_hex(stem) else {
                continue;
            };
            if !self.seal_path(&handle).exists() {
                warn!(?path, "TpmWindowsKeystore: sidecar without matching seal — skipping");
                continue;
            }
            entries.push(self.read_sidecar(&handle)?);
        }
        entries.sort_by_key(|s| s.created_at);
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Provider + wrap-key helpers
// ---------------------------------------------------------------------------

/// RAII handle for an NCrypt provider. Freed via [`NCryptFreeObject`]
/// on drop.
struct ProviderHandle(NCRYPT_PROV_HANDLE);

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        if self.0.0 != 0 {
            // SAFETY: `self.0` is a non-null provider handle owned by
            // this RAII guard; `NCryptFreeObject` accepts any
            // `NCRYPT_HANDLE`, of which `NCRYPT_PROV_HANDLE` is a
            // documented `Into` source.
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// RAII handle for an NCrypt key. Freed via [`NCryptFreeObject`] on
/// drop. The persistent wrap key survives the free because NCrypt
/// stores the key state under the KSP — the handle is just the
/// in-process accessor.
struct KeyHandleGuard(NCRYPT_KEY_HANDLE);

impl Drop for KeyHandleGuard {
    fn drop(&mut self) {
        if self.0.0 != 0 {
            // SAFETY: `self.0` is a non-null key handle owned by this
            // RAII guard; releasing it doesn't delete the persisted
            // key, only the process accessor.
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

#[instrument(level = "debug")]
fn open_platform_provider() -> Result<ProviderHandle, KeystoreError> {
    let mut provider = NCRYPT_PROV_HANDLE(0);
    // SAFETY: `NCryptOpenStorageProvider` writes into `provider` and
    // returns `Result<()>`. The provider-name pointer is a static
    // wide-string constant from `windows-rs`; `dwflags = 0` is the
    // documented default.
    let result =
        unsafe { NCryptOpenStorageProvider(&raw mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
    result.map_err(|e| KeystoreError::TpmUnavailable {
        message: format!("NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER): {e}"),
    })?;
    if provider.0 == 0 {
        return Err(KeystoreError::TpmUnavailable {
            message: "NCryptOpenStorageProvider returned a null handle".to_string(),
        });
    }
    debug!("TPM provider opened");
    Ok(ProviderHandle(provider))
}

/// Open the persistent wrap key, creating it on first use. Translates
/// "no usable TPM 2.0 chip" errors into [`KeystoreError::TpmUnavailable`]
/// so callers can fall back. Other failures pass through as
/// [`KeystoreError::Seal`].
#[instrument(level = "debug", skip(provider))]
fn open_or_create_wrap_key(
    provider: &ProviderHandle,
) -> Result<KeyHandleGuard, KeystoreError> {
    let key_name = wide(WRAP_KEY_NAME);

    // Try to open first.
    let mut key = NCRYPT_KEY_HANDLE(0);
    // SAFETY: `NCryptOpenKey` writes to `key`. `provider.0` is a live
    // provider handle. The key-name buffer is a NUL-terminated wide
    // string we own for the call.
    let open_result = unsafe {
        NCryptOpenKey(
            provider.0,
            &raw mut key,
            windows::core::PCWSTR(key_name.as_ptr()),
            KEY_SPEC_NONE,
            NCRYPT_FLAGS(0),
        )
    };
    if open_result.is_ok() && key.0 != 0 {
        debug!("TPM wrap key opened (existing)");
        return Ok(KeyHandleGuard(key));
    }

    // Not present (or open failed) — try to create it.
    let create_err = open_result.err();
    debug!(?create_err, "TPM wrap key not openable; attempting create");
    create_wrap_key(provider, &key_name)
        .map_err(|e| classify_provisioning_error(e, create_err.as_ref()))
}

/// Create the persistent wrap key. Caller has already determined the
/// key isn't openable.
#[instrument(level = "debug", skip(provider, key_name))]
fn create_wrap_key(
    provider: &ProviderHandle,
    key_name: &[u16],
) -> Result<KeyHandleGuard, KeystoreError> {
    let mut key = NCRYPT_KEY_HANDLE(0);
    // SAFETY: writes `key`; all string pointers are owned by the caller
    // for the duration of the call.
    unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &raw mut key,
            NCRYPT_RSA_ALGORITHM,
            windows::core::PCWSTR(key_name.as_ptr()),
            KEY_SPEC_NONE,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| KeystoreError::Seal {
        message: format!("NCryptCreatePersistedKey: {e}"),
    })?;
    if key.0 == 0 {
        return Err(KeystoreError::Seal {
            message: "NCryptCreatePersistedKey returned a null handle".to_string(),
        });
    }
    let guard = KeyHandleGuard(key);

    // Set modulus length on the not-yet-finalized key.
    let bits_le = WRAP_KEY_BITS.to_le_bytes();
    // SAFETY: passes a 4-byte slice; NCrypt copies it.
    unsafe {
        NCryptSetProperty(
            guard.0,
            NCRYPT_LENGTH_PROPERTY,
            &bits_le,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| KeystoreError::Seal {
        message: format!("NCryptSetProperty(Length): {e}"),
    })?;

    // Finalize. The default export policy on
    // `MS_PLATFORM_CRYPTO_PROVIDER` is non-exportable; we leave it
    // alone rather than setting `NCRYPT_EXPORT_POLICY_PROPERTY` to 0
    // explicitly so we don't accidentally tighten or loosen the KSP's
    // own default.
    // SAFETY: live key handle; no input buffers.
    unsafe { NCryptFinalizeKey(guard.0, NCRYPT_FLAGS(0)) }.map_err(|e| KeystoreError::Seal {
        message: format!("NCryptFinalizeKey: {e}"),
    })?;

    debug!(bits = WRAP_KEY_BITS, "TPM wrap key created and finalized");
    Ok(guard)
}

/// Map a provisioning failure to either [`KeystoreError::TpmUnavailable`]
/// (the box has no TPM 2.0 chip the KSP can drive) or whatever the
/// caller raised. We look at the original `NCryptOpenKey` error too —
/// the create-path can return a confusing `NTE_BAD_KEY_STATE` when the
/// real problem is that the KSP couldn't bind to any TPM at provider
/// load time.
fn classify_provisioning_error(
    create_err: KeystoreError,
    open_err: Option<&windows::core::Error>,
) -> KeystoreError {
    let create_str = create_err.to_string();
    if is_tpm_unavailable_signal(&create_str)
        || open_err.is_some_and(|e| is_tpm_unavailable_hresult(e.code()))
    {
        return KeystoreError::TpmUnavailable {
            message: format!(
                "platform crypto provider could not provision the wrap key — no usable TPM 2.0? ({create_str})"
            ),
        };
    }
    create_err
}

/// Pattern-match the rendered error string for the small set of
/// HRESULT codes that mean "no TPM 2.0 here". Conservative — if the
/// signal isn't one of these we treat it as a real Seal failure rather
/// than masking it behind the fallback signal.
fn is_tpm_unavailable_signal(rendered: &str) -> bool {
    const SIGNALS: &[&str] = &[
        "0x80090029", // NTE_NOT_SUPPORTED
        "0x80090016", // NTE_BAD_KEYSET
        "0x80090030", // NTE_NO_MORE_ITEMS — KSP enumerated zero TPMs
        "0x80284001", // TPM_E_AREA_LOCKED-ish; TBS provider failures
        "0x80290400", // TBS_E_INTERNAL_ERROR
        "0x8029040A", // TBS_E_TPM_NOT_FOUND
    ];
    SIGNALS.iter().any(|s| rendered.contains(s))
}

const fn is_tpm_unavailable_hresult(code: HRESULT) -> bool {
    // HRESULT is a transparent i32 newtype; reinterpret the bit pattern
    // as u32 so the documented unsigned NTE_/TBS_ codes match
    // literally. `to_ne_bytes`/`from_ne_bytes` keeps clippy::pedantic
    // happy without bringing in unsafe transmute or a signed-conversion
    // cast.
    let raw = u32::from_ne_bytes(code.0.to_ne_bytes());
    matches!(
        raw,
        0x8009_0029 | 0x8009_0016 | 0x8009_0030 | 0x8028_4001 | 0x8029_0400 | 0x8029_040A
    )
}

// ---------------------------------------------------------------------------
// Seal / unseal
// ---------------------------------------------------------------------------

/// Seal arbitrary plaintext under the TPM-resident wrap key.
#[instrument(level = "debug", skip(plain), fields(plain_len = plain.len()))]
fn tpm_seal(plain: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if plain.is_empty() {
        return Err(KeystoreError::Seal {
            message: "refusing to seal empty plaintext".to_string(),
        });
    }

    let provider = open_platform_provider()?;
    let wrap_key = open_or_create_wrap_key(&provider)?;

    // Per-blob AEAD key + nonce.
    let mut aead_key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(aead_key.as_mut_slice());
    OsRng.fill_bytes(&mut nonce);

    // AEAD-encrypt the plaintext.
    let cipher = ChaCha20Poly1305::new(Key::from_slice(aead_key.as_slice()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &[],
            },
        )
        .map_err(|e| KeystoreError::Seal {
            message: format!("ChaCha20-Poly1305 encrypt: {e}"),
        })?;

    // OAEP-wrap the AEAD key with the TPM RSA public.
    let wrapped = rsa_oaep_encrypt(&wrap_key, aead_key.as_slice())?;
    let wrapped_len = u16::try_from(wrapped.len()).map_err(|_| KeystoreError::Seal {
        message: format!("wrapped key too large: {}", wrapped.len()),
    })?;

    // Layout: version || wrapped_len_be || wrapped || nonce || ct
    let mut out = Vec::with_capacity(1 + 2 + wrapped.len() + NONCE_LEN + ciphertext.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&wrapped_len.to_be_bytes());
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);

    debug!(
        wrapped_len = wrapped.len(),
        ct_len = ciphertext.len(),
        out_len = out.len(),
        "tpm_seal: sealed blob built"
    );
    Ok(out)
}

/// Inverse of [`tpm_seal`].
#[instrument(level = "debug", skip(sealed), fields(sealed_len = sealed.len()))]
fn tpm_unseal(sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    // version + wrapped_len + nonce + minimum tag = 1 + 2 + 12 + 16
    const MIN_LEN: usize = 1 + 2 + NONCE_LEN + 16;
    if sealed.len() < MIN_LEN {
        return Err(KeystoreError::MalformedBlob(format!(
            "sealed blob too short: got {} < {MIN_LEN}",
            sealed.len(),
        )));
    }
    if sealed[0] != SEAL_VERSION {
        return Err(KeystoreError::MalformedBlob(format!(
            "sealed blob version unsupported: got {}, want {SEAL_VERSION}",
            sealed[0],
        )));
    }
    let wrapped_len = u16::from_be_bytes([sealed[1], sealed[2]]) as usize;
    if wrapped_len == 0 || sealed.len() < 3 + wrapped_len + NONCE_LEN + 16 {
        return Err(KeystoreError::MalformedBlob(format!(
            "sealed blob field bounds off: wrapped_len = {wrapped_len}, total = {}",
            sealed.len(),
        )));
    }
    let wrapped = &sealed[3..3 + wrapped_len];
    let nonce_start = 3 + wrapped_len;
    let nonce = &sealed[nonce_start..nonce_start + NONCE_LEN];
    let ciphertext = &sealed[nonce_start + NONCE_LEN..];

    let provider = open_platform_provider()?;
    let wrap_key = open_or_create_wrap_key(&provider)?;

    let aead_key = rsa_oaep_decrypt(&wrap_key, wrapped)?;
    if aead_key.len() != AEAD_KEY_LEN {
        return Err(KeystoreError::Unseal {
            message: format!(
                "unwrapped AEAD key wrong length: got {}, want {AEAD_KEY_LEN}",
                aead_key.len()
            ),
        });
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(aead_key.as_slice()));
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|e| KeystoreError::Unseal {
            message: format!("ChaCha20-Poly1305 decrypt: {e}"),
        })?;

    debug!(plain_len = plain.len(), "tpm_unseal: plaintext recovered");
    Ok(Zeroizing::new(plain))
}

/// OAEP-encrypt `plain` under the TPM-resident RSA wrap key. Uses
/// SHA-256 as the MGF / label hash. No label bytes.
#[instrument(level = "debug", skip(key, plain), fields(plain_len = plain.len()))]
fn rsa_oaep_encrypt(
    key: &KeyHandleGuard,
    plain: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let sha256_alg = wide_pcwstr_from(BCRYPT_SHA256_ALGORITHM);
    let padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: windows::core::PCWSTR(sha256_alg.as_ptr()),
        pbLabel: ptr::null_mut(),
        cbLabel: 0,
    };

    // Probe the output size.
    let mut needed: u32 = 0;
    // SAFETY: `pboutput = None` tells NCrypt to write only `pcbresult`.
    // `&padding as *const _` is cast to `*const c_void`; layout matches
    // the documented `BCRYPT_OAEP_PADDING_INFO` ABI.
    unsafe {
        NCryptEncrypt(
            key.0,
            Some(plain),
            Some(ptr::from_ref(&padding).cast()),
            None,
            &raw mut needed,
            NCRYPT_PAD_OAEP_FLAG,
        )
    }
    .map_err(|e| KeystoreError::Seal {
        message: format!("NCryptEncrypt(size probe): {e}"),
    })?;
    if needed == 0 {
        return Err(KeystoreError::Seal {
            message: "NCryptEncrypt size probe returned zero".to_string(),
        });
    }

    let mut out = vec![0u8; needed as usize];
    let mut written: u32 = 0;
    // SAFETY: `out` is sized to `needed`; the call writes at most
    // `needed` bytes and reports the actual count via `&mut written`.
    unsafe {
        NCryptEncrypt(
            key.0,
            Some(plain),
            Some(ptr::from_ref(&padding).cast()),
            Some(out.as_mut_slice()),
            &raw mut written,
            NCRYPT_PAD_OAEP_FLAG,
        )
    }
    .map_err(|e| KeystoreError::Seal {
        message: format!("NCryptEncrypt: {e}"),
    })?;
    out.truncate(written as usize);
    Ok(out)
}

/// Inverse of [`rsa_oaep_encrypt`]. Returns the unwrapped bytes in a
/// [`Zeroizing`] buffer.
#[instrument(level = "debug", skip(key, wrapped), fields(wrapped_len = wrapped.len()))]
fn rsa_oaep_decrypt(
    key: &KeyHandleGuard,
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let sha256_alg = wide_pcwstr_from(BCRYPT_SHA256_ALGORITHM);
    let padding = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: windows::core::PCWSTR(sha256_alg.as_ptr()),
        pbLabel: ptr::null_mut(),
        cbLabel: 0,
    };

    // Probe the output size first.
    let mut needed: u32 = 0;
    // SAFETY: identical contract to the encrypt-path size probe.
    unsafe {
        NCryptDecrypt(
            key.0,
            Some(wrapped),
            Some(ptr::from_ref(&padding).cast()),
            None,
            &raw mut needed,
            NCRYPT_PAD_OAEP_FLAG,
        )
    }
    .map_err(|e| KeystoreError::Unseal {
        message: format!("NCryptDecrypt(size probe): {e}"),
    })?;
    if needed == 0 {
        return Err(KeystoreError::Unseal {
            message: "NCryptDecrypt size probe returned zero".to_string(),
        });
    }

    let mut buf = Zeroizing::new(vec![0u8; needed as usize]);
    let mut written: u32 = 0;
    // SAFETY: `buf` is sized to `needed`; the call writes at most
    // `needed` bytes and reports the actual count via `&mut written`.
    unsafe {
        NCryptDecrypt(
            key.0,
            Some(wrapped),
            Some(ptr::from_ref(&padding).cast()),
            Some(buf.as_mut_slice()),
            &raw mut written,
            NCRYPT_PAD_OAEP_FLAG,
        )
    }
    .map_err(|e| KeystoreError::Unseal {
        message: format!("NCryptDecrypt: {e}"),
    })?;
    buf.truncate(written as usize);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Wide-string helpers
// ---------------------------------------------------------------------------

/// Convert a Rust `&str` into a NUL-terminated UTF-16 buffer suitable
/// for passing as a `PCWSTR`. The returned `Vec` owns the storage; the
/// caller must keep it alive for the duration of the call.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Materialize the contents of a static `PCWSTR` constant into an owned
/// buffer so we don't need to rely on the constant's lifetime when we
/// pass it back through FFI. Reads the source pointer until the NUL.
fn wide_pcwstr_from(pcwstr: windows::core::PCWSTR) -> Vec<u16> {
    let mut out = Vec::with_capacity(16);
    // SAFETY: `windows-rs` `PCWSTR` constants are NUL-terminated wide
    // string literals in the binary; reading until the terminator is
    // the documented contract. We append the NUL ourselves.
    unsafe {
        let mut p = pcwstr.0;
        if !p.is_null() {
            loop {
                let c = *p;
                if c == 0 {
                    break;
                }
                out.push(c);
                p = p.add(1);
            }
        }
    }
    out.push(0);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_crypto::identity::verify;
    use tempfile::tempdir;

    /// Probe the TPM at the start of each test. Returns `true` if the
    /// platform crypto provider can open AND we can open / create the
    /// wrap key. Tests that need a working TPM bail early with a
    /// printed reason rather than failing the suite on a TPM-less box.
    fn tpm_available() -> bool {
        match open_platform_provider() {
            Ok(provider) => match open_or_create_wrap_key(&provider) {
                Ok(_) => true,
                Err(KeystoreError::TpmUnavailable { message }) => {
                    eprintln!("TPM unavailable: {message}");
                    false
                }
                Err(other) => {
                    eprintln!("TPM probe failed in an unexpected way: {other}");
                    false
                }
            },
            Err(KeystoreError::TpmUnavailable { message }) => {
                eprintln!("TPM provider unavailable: {message}");
                false
            }
            Err(other) => {
                eprintln!("TPM provider probe failed: {other}");
                false
            }
        }
    }

    #[test]
    fn round_trip_seal_unseal() {
        if !tpm_available() {
            eprintln!("skipping round_trip_seal_unseal: no TPM 2.0");
            return;
        }
        let plain = [0xA5u8; 64];
        let sealed = tpm_seal(&plain).expect("seal");
        assert_ne!(sealed.as_slice(), plain.as_slice());
        let recovered = tpm_unseal(&sealed).expect("unseal");
        assert_eq!(&recovered[..], &plain[..]);
    }

    #[test]
    fn generate_then_sign_then_verify_persistent() {
        if !tpm_available() {
            eprintln!("skipping generate_then_sign_then_verify_persistent: no TPM 2.0");
            return;
        }
        let tmp = tempdir().expect("tempdir");
        let ks = TpmWindowsKeystore::new(tmp.path()).expect("TpmWindowsKeystore");
        let stored = ks.generate("persistent").expect("generate");

        let msg = b"phase G.3 persistent sign";
        let sig = ks.sign(&stored.handle, msg).expect("sign");
        verify(&stored.public, msg, &sig).expect("verify");

        let ks2 = TpmWindowsKeystore::new(tmp.path()).expect("re-open");
        let entries = ks2.list().expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].handle, stored.handle);
        let sig2 = ks2.sign(&stored.handle, msg).expect("sign after reopen");
        verify(&stored.public, msg, &sig2).expect("verify after reopen");
    }

    #[test]
    fn delete_removes_both_files() {
        if !tpm_available() {
            eprintln!("skipping delete_removes_both_files: no TPM 2.0");
            return;
        }
        let tmp = tempdir().expect("tempdir");
        let ks = TpmWindowsKeystore::new(tmp.path()).expect("TpmWindowsKeystore");
        let stored = ks.generate("rm").expect("generate");
        assert!(ks.seal_path(&stored.handle).exists());
        assert!(ks.sidecar_path(&stored.handle).exists());
        assert!(ks.delete(&stored.handle).expect("delete"));
        assert!(!ks.seal_path(&stored.handle).exists());
        assert!(!ks.sidecar_path(&stored.handle).exists());
        assert!(!ks.delete(&stored.handle).expect("second delete returns false"));
    }

    #[test]
    fn corrupted_seal_blob_fails_unseal() {
        if !tpm_available() {
            eprintln!("skipping corrupted_seal_blob_fails_unseal: no TPM 2.0");
            return;
        }
        let tmp = tempdir().expect("tempdir");
        let ks = TpmWindowsKeystore::new(tmp.path()).expect("TpmWindowsKeystore");
        let stored = ks.generate("corrupt").expect("generate");

        // Flip the last byte of the sealed blob — that lands in the
        // ciphertext tag and Poly1305 must reject.
        let seal_path = ks.seal_path(&stored.handle);
        let mut blob = fs::read(&seal_path).expect("read sealed");
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        fs::write(&seal_path, &blob).expect("rewrite sealed");

        let err = ks.sign(&stored.handle, b"after corruption").expect_err("must error");
        match err {
            KeystoreError::Unseal { .. } => {}
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn pubkey_without_unsealing() {
        if !tpm_available() {
            eprintln!("skipping pubkey_without_unsealing: no TPM 2.0");
            return;
        }
        let tmp = tempdir().expect("tempdir");
        let ks = TpmWindowsKeystore::new(tmp.path()).expect("TpmWindowsKeystore");
        let stored = ks.generate("pubkey only").expect("generate");

        // Remove the seal blob, leave the sidecar. pubkey() still works
        // (reads sidecar only); list() filters out sealless sidecars.
        fs::remove_file(ks.seal_path(&stored.handle)).expect("rm seal");
        let listed = ks.list().expect("list");
        assert!(listed.is_empty(), "list must filter out sealless sidecars");

        let direct = ks.read_sidecar(&stored.handle).expect("read sidecar directly");
        assert_eq!(direct.public.ed25519_pk, stored.public.ed25519_pk);
    }

    #[test]
    fn wrap_key_persists_across_keystore_instances() {
        if !tpm_available() {
            eprintln!("skipping wrap_key_persists_across_keystore_instances: no TPM 2.0");
            return;
        }
        let tmp = tempdir().expect("tempdir");

        // Instance 1: generate identity A.
        let stored_a = {
            let ks = TpmWindowsKeystore::new(tmp.path()).expect("ks1");
            ks.generate("alice").expect("generate alice")
        };

        // Instance 2: generate identity B in the same directory. Both
        // must sign successfully — same persistent wrap key.
        let ks2 = TpmWindowsKeystore::new(tmp.path()).expect("ks2");
        let stored_b = ks2.generate("bob").expect("generate bob");

        let msg = b"shared-wrap-key smoke";
        let sig_a = ks2.sign(&stored_a.handle, msg).expect("sign A");
        verify(&stored_a.public, msg, &sig_a).expect("verify A");
        let sig_b = ks2.sign(&stored_b.handle, msg).expect("sign B");
        verify(&stored_b.public, msg, &sig_b).expect("verify B");
    }

    #[test]
    #[ignore = "requires a box without TPM 2.0 / where MS_PLATFORM_CRYPTO_PROVIDER provisioning fails"]
    fn tpm_unavailable_path_returns_typed_error() {
        // Manual gate: only meaningful on a host where the platform
        // crypto provider opens but cannot bind a TPM key. Sketched out
        // so future CI runs against a TPM-less VM can pick this up.
        match open_platform_provider() {
            Err(KeystoreError::TpmUnavailable { .. }) => {}
            Ok(provider) => match open_or_create_wrap_key(&provider) {
                Err(KeystoreError::TpmUnavailable { .. }) => {}
                Ok(_) => panic!("expected TpmUnavailable on a TPM-less box, got success"),
                Err(other) => panic!("expected TpmUnavailable, got {other:?}"),
            },
            Err(other) => panic!("expected TpmUnavailable, got {other:?}"),
        }
    }
}
