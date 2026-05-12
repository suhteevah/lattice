//! Windows DPAPI-backed [`Keystore`] implementation (M7 Phase G.1).
//!
//! Persists each identity as two files under a caller-supplied
//! directory (default `%LOCALAPPDATA%\Lattice\keystore`):
//!
//! - `<handle_hex>.dpapi` — `CryptProtectData` output over the 64-byte
//!   `ml_dsa_seed || ed25519_sk` concat. The OS binds the wrap key
//!   to the current Windows user credential; the blob is useless on
//!   another machine or under a different user account.
//! - `<handle_hex>.pub` — JSON sidecar holding the public-key bundle,
//!   the user-supplied label, and creation time. Read by `list()`
//!   and `pubkey()` without touching DPAPI.
//!
//! See `scratch/m7-phase-g-plan.md` for the DPAPI-vs-TPM posture
//! decision (DECISIONS §D-26) and the planned G.3 upgrade to
//! TPM 2.0 / Windows Hello via NCrypt.

#![allow(unsafe_code)] // SAFETY: see each `unsafe` block; required for DPAPI FFI.

use std::fs;
use std::path::PathBuf;
use std::ptr;
use std::time::SystemTime;

use lattice_crypto::identity::{HybridSignature, IdentityPublicKey, generate_identity, sign};
use tracing::{debug, instrument, warn};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::Zeroizing;

use super::memory::{identity_secret_from_bytes, identity_secret_to_bytes};
use super::{KeyHandle, Keystore, KeystoreError, PublicSidecar, StoredKey};

const SEAL_SUFFIX: &str = "dpapi";
const SIDECAR_SUFFIX: &str = "pub";

/// File-backed keystore that wraps secret bytes in DPAPI under a
/// caller-supplied directory. Construction creates the directory if
/// it doesn't already exist.
#[derive(Debug)]
pub struct WindowsKeystore {
    dir: PathBuf,
}

impl WindowsKeystore {
    /// Construct a keystore rooted at `dir`. Creates the directory
    /// (and parents) if needed.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] if the directory cannot be
    /// created (read-only volume, permission denied, …).
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, KeystoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        debug!(?dir, "WindowsKeystore: ready");
        Ok(Self { dir })
    }

    /// Convenience constructor pointing at the conventional location
    /// `%LOCALAPPDATA%\Lattice\keystore`. Falls back to the current
    /// working directory if `dirs::data_local_dir()` returns `None`
    /// (extremely unusual on Windows; typically only happens when the
    /// `LOCALAPPDATA` env var is unset).
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::Io`] if directory creation fails.
    pub fn at_default_location() -> Result<Self, KeystoreError> {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        Self::new(base.join("Lattice").join("keystore"))
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

impl Keystore for WindowsKeystore {
    #[instrument(level = "debug", skip(self), fields(label = %label))]
    fn generate(&self, label: &str) -> Result<StoredKey, KeystoreError> {
        let (public, secret) =
            generate_identity().map_err(|e| KeystoreError::Crypto(e.to_string()))?;
        let secret_bytes = identity_secret_to_bytes(&secret);

        let handle = KeyHandle::random();
        let created_at = SystemTime::now();

        let sealed = dpapi_protect(&secret_bytes)?;
        fs::write(self.seal_path(&handle), &sealed)?;

        let sidecar = PublicSidecar::from_public(&public, label, created_at);
        let sidecar_json = serde_json::to_vec_pretty(&sidecar)?;
        fs::write(self.sidecar_path(&handle), sidecar_json)?;

        debug!(handle = %handle, "WindowsKeystore: generated key");
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
        let plain = dpapi_unprotect(&sealed)?;
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
                    warn!(?path, error = %e, "WindowsKeystore: delete partial failure");
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
            // Skip sidecar files whose seal is missing — they're stale.
            if !self.seal_path(&handle).exists() {
                warn!(?path, "WindowsKeystore: sidecar without matching seal — skipping");
                continue;
            }
            entries.push(self.read_sidecar(&handle)?);
        }
        entries.sort_by_key(|s| s.created_at);
        Ok(entries)
    }
}

/// Wrap arbitrary bytes via DPAPI. Returns the sealed blob.
///
/// `CRYPTPROTECT_UI_FORBIDDEN` is set so DPAPI never prompts; if the
/// OS can't satisfy the protect call without user interaction (e.g. a
/// password-protected smart card credential) it returns failure
/// rather than blocking.
fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if plain.is_empty() {
        return Err(KeystoreError::Seal {
            message: "refusing to seal empty plaintext".to_string(),
        });
    }
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plain.len()).map_err(|_| KeystoreError::Seal {
            message: format!("plaintext too large for DPAPI: {}", plain.len()),
        })?,
        pbData: plain.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: `CryptProtectData` reads `input` (read-only borrow into
    // `plain`), writes a fresh blob into `output`, and returns
    // `Result<()>`. The `pbData` pointer in `output` is owned by
    // `LocalAlloc`; we free it with `LocalFree` after copying the
    // bytes into a Rust `Vec`. The optional pointers are all
    // null — DPAPI accepts that.
    let result = unsafe {
        CryptProtectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    // Always-true read of `input.pbData` is fine; the API doesn't mutate it.
    let _ = &mut input;
    result.map_err(|e| KeystoreError::Seal {
        message: format!("CryptProtectData: {e}"),
    })?;

    // SAFETY: `output.pbData` was populated by DPAPI with `output.cbData`
    // bytes; copy them into an owned Vec then free the OS allocation.
    let blob = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        slice.to_vec()
    };

    // SAFETY: `output.pbData` was allocated by DPAPI with LocalAlloc;
    // freeing it with `LocalFree` is the documented contract.
    unsafe {
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
    }

    Ok(blob)
}

/// Inverse of [`dpapi_protect`]. Returns the unsealed bytes inside a
/// [`Zeroizing`] buffer.
fn dpapi_unprotect(sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(sealed.len()).map_err(|_| KeystoreError::Unseal {
            message: format!("sealed blob too large: {}", sealed.len()),
        })?,
        pbData: sealed.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: mirror of `dpapi_protect`. `input` is a read-only view
    // of `sealed`; `output.pbData` is freshly allocated by DPAPI and
    // freed via `LocalFree` after we copy.
    let result = unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let _ = &mut input;
    result.map_err(|e| KeystoreError::Unseal {
        message: format!("CryptUnprotectData: {e}"),
    })?;

    // SAFETY: `output.pbData` is a fresh OS allocation of `output.cbData`
    // bytes; copy into a Zeroizing buffer so the plaintext is wiped
    // when the buffer drops.
    let plain = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        Zeroizing::new(slice.to_vec())
    };

    // SAFETY: same LocalAlloc/LocalFree contract as `dpapi_protect`.
    // Wipe the OS-owned plaintext first by zeroing the buffer through
    // `pbData` before freeing — DPAPI doesn't guarantee its allocator
    // zeroizes on free.
    unsafe {
        let raw_slice = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        for byte in raw_slice {
            *byte = 0;
        }
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
    }

    Ok(plain)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn _statically_assert_blob_field_types() {
    // Compile-time guard that the CRYPT_INTEGER_BLOB field shape we
    // assume above matches the binding. If `windows-rs` ever renames
    // the fields, this will fail to compile and force a fix.
    let _: u32 = CRYPT_INTEGER_BLOB::default().cbData;
    let _: *mut u8 = CRYPT_INTEGER_BLOB::default().pbData;
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_crypto::identity::verify;
    use tempfile::tempdir;

    #[test]
    fn dpapi_round_trip() {
        let plain = b"phase G DPAPI smoke";
        let sealed = dpapi_protect(plain).expect("protect");
        assert_ne!(sealed.as_slice(), plain.as_slice());
        let recovered = dpapi_unprotect(&sealed).expect("unprotect");
        assert_eq!(&recovered[..], plain);
    }

    #[test]
    fn generate_then_sign_then_verify_persistent() {
        let tmp = tempdir().expect("tempdir");
        let ks = WindowsKeystore::new(tmp.path()).expect("WindowsKeystore");
        let stored = ks.generate("persistent").expect("generate");

        let msg = b"phase G persistent sign";
        let sig = ks.sign(&stored.handle, msg).expect("sign");
        verify(&stored.public, msg, &sig).expect("verify");

        // Open a second keystore on the same directory and prove
        // listing/signing still works — that's the "survives process
        // restart" property.
        let ks2 = WindowsKeystore::new(tmp.path()).expect("re-open");
        let entries = ks2.list().expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].handle, stored.handle);
        let sig2 = ks2.sign(&stored.handle, msg).expect("sign after reopen");
        verify(&stored.public, msg, &sig2).expect("verify after reopen");
    }

    #[test]
    fn delete_removes_both_files() {
        let tmp = tempdir().expect("tempdir");
        let ks = WindowsKeystore::new(tmp.path()).expect("WindowsKeystore");
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
        let tmp = tempdir().expect("tempdir");
        let ks = WindowsKeystore::new(tmp.path()).expect("WindowsKeystore");
        let stored = ks.generate("corrupt").expect("generate");

        // Flip the last byte of the sealed blob.
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
        let tmp = tempdir().expect("tempdir");
        let ks = WindowsKeystore::new(tmp.path()).expect("WindowsKeystore");
        let stored = ks.generate("pubkey only").expect("generate");

        // Remove the seal blob, leave the sidecar. pubkey/list should
        // still work (pubkey reads sidecar only), but list filters out
        // entries whose seal is missing.
        fs::remove_file(ks.seal_path(&stored.handle)).expect("rm seal");
        let listed = ks.list().expect("list");
        assert!(listed.is_empty(), "list must filter out sealless sidecars");

        let direct = ks.read_sidecar(&stored.handle).expect("read sidecar directly");
        assert_eq!(direct.public.ed25519_pk, stored.public.ed25519_pk);
    }
}
