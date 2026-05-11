//! File-backed `mls-rs` storage providers for the per-action CLI.
//!
//! Layout under `LATTICE_HOME_DIR` (default `~/.lattice/`):
//!
//! ```text
//! identity.json                       — LatticeIdentity (serde JSON)
//! key_packages/<hex_id>.bin           — KeyPackage secrets, mls-codec-encoded
//! groups/<hex_gid>/state.bin          — Group state snapshot
//! groups/<hex_gid>/epochs/<epoch>.bin — Per-epoch record
//! psks/<hex_id>.bin                   — Pre-shared key secret bytes
//! cursors/<hex_gid>.json              — { last_message_seq: u64 } per group
//! ```
//!
//! All blobs are owned by the user; cross-invocation persistence is the
//! whole point of having these providers. Each storage type is `Clone`
//! and shares its `root: PathBuf` so a CLI invocation can build them
//! once and pass clones into the mls-rs `ClientBuilder` chain.

#![allow(clippy::module_name_repetitions)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic,))]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::error::IntoAnyError;
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use mls_rs_core::psk::{ExternalPskId, PreSharedKey, PreSharedKeyStorage};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors raised by the file-backed storage providers.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Underlying I/O failure.
    #[error("storage IO: {0}")]
    Io(#[from] io::Error),
    /// mls-codec failure.
    #[error("storage codec: {0}")]
    Codec(String),
}

impl IntoAnyError for StoreError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn ensure_dir(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path)?;
    Ok(())
}

/// File-backed [`KeyPackageStorage`]. One file per KeyPackage id.
#[derive(Clone, Debug)]
pub struct FileKeyPackageStorage {
    root: PathBuf,
}

impl FileKeyPackageStorage {
    /// Construct at `<root>/key_packages/`.
    pub fn new(root: PathBuf) -> Result<Self, StoreError> {
        ensure_dir(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, id: &[u8]) -> PathBuf {
        self.root.join(format!("{}.bin", hex(id)))
    }
}

impl KeyPackageStorage for FileKeyPackageStorage {
    type Error = StoreError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        let p = self.path_for(id);
        if p.exists() {
            fs::remove_file(p)?;
        }
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        let bytes = pkg
            .mls_encode_to_vec()
            .map_err(|e| StoreError::Codec(format!("encode KeyPackageData: {e}")))?;
        let p = self.path_for(&id);
        fs::write(p, bytes)?;
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let p = self.path_for(id);
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(p)?;
        let pkg = KeyPackageData::mls_decode(&mut &*bytes)
            .map_err(|e| StoreError::Codec(format!("decode KeyPackageData: {e}")))?;
        Ok(Some(pkg))
    }
}

/// File-backed [`GroupStateStorage`]. Per-group subdirectory holding
/// state + per-epoch records.
#[derive(Clone, Debug)]
pub struct FileGroupStateStorage {
    root: PathBuf,
}

impl FileGroupStateStorage {
    /// Construct at `<root>/groups/`.
    pub fn new(root: PathBuf) -> Result<Self, StoreError> {
        ensure_dir(&root)?;
        Ok(Self { root })
    }

    fn group_dir(&self, group_id: &[u8]) -> PathBuf {
        self.root.join(hex(group_id))
    }
    fn state_path(&self, group_id: &[u8]) -> PathBuf {
        self.group_dir(group_id).join("state.bin")
    }
    fn epoch_path(&self, group_id: &[u8], epoch: u64) -> PathBuf {
        self.group_dir(group_id)
            .join("epochs")
            .join(format!("{epoch:020}.bin"))
    }
}

impl GroupStateStorage for FileGroupStateStorage {
    type Error = StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let p = self.state_path(group_id);
        if !p.exists() {
            return Ok(None);
        }
        Ok(Some(Zeroizing::new(fs::read(p)?)))
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let p = self.epoch_path(group_id, epoch_id);
        if !p.exists() {
            return Ok(None);
        }
        Ok(Some(Zeroizing::new(fs::read(p)?)))
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let dir = self.group_dir(&state.id);
        ensure_dir(&dir.join("epochs"))?;
        fs::write(self.state_path(&state.id), state.data.as_slice())?;
        for e in epoch_inserts.into_iter().chain(epoch_updates.into_iter()) {
            fs::write(self.epoch_path(&state.id, e.id), e.data.as_slice())?;
        }
        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let dir = self.group_dir(group_id).join("epochs");
        if !dir.exists() {
            return Ok(None);
        }
        let mut max: Option<u64> = None;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let stem = name.strip_suffix(".bin").unwrap_or(&name);
            if let Ok(id) = stem.parse::<u64>() {
                max = Some(max.map_or(id, |m| m.max(id)));
            }
        }
        Ok(max)
    }
}

/// File-backed [`PreSharedKeyStorage`]. One file per `ExternalPskId`.
#[derive(Clone, Debug)]
pub struct FilePskStorage {
    root: PathBuf,
}

impl FilePskStorage {
    /// Construct at `<root>/psks/`.
    pub fn new(root: PathBuf) -> Result<Self, StoreError> {
        ensure_dir(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, id: &ExternalPskId) -> PathBuf {
        self.root.join(format!("{}.bin", hex(id.as_ref())))
    }

    /// Convenience helper: store the raw shared-secret bytes under
    /// `psk_id` (the CLI uses this when openning a `PqWelcomePayload`).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] on file-write failure.
    pub fn insert(&self, id: &ExternalPskId, psk_bytes: &[u8]) -> Result<(), StoreError> {
        fs::write(self.path_for(id), psk_bytes)?;
        Ok(())
    }
}

impl PreSharedKeyStorage for FilePskStorage {
    type Error = StoreError;

    fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
        let p = self.path_for(id);
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(p)?;
        Ok(Some(PreSharedKey::new(bytes)))
    }
}

/// Resolve the `LATTICE_HOME_DIR` env var, defaulting to
/// `~/.lattice/`. Creates the directory if missing.
pub fn resolve_home() -> Result<PathBuf, StoreError> {
    let home = if let Ok(p) = std::env::var("LATTICE_HOME_DIR") {
        PathBuf::from(p)
    } else if let Ok(p) = std::env::var("USERPROFILE") {
        PathBuf::from(p).join(".lattice")
    } else if let Ok(p) = std::env::var("HOME") {
        PathBuf::from(p).join(".lattice")
    } else {
        PathBuf::from(".lattice")
    };
    ensure_dir(&home)?;
    Ok(home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tempdir(label: &str) -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("lattice-store-test-{label}-{now}-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn key_package_round_trip() {
        let root = tempdir("kp").join("key_packages");
        let mut store = FileKeyPackageStorage::new(root).unwrap();

        // Use a placeholder KeyPackageData — we don't need a valid one
        // for the storage round-trip, only the encode/decode path.
        let kp = KeyPackageData::new(
            vec![1, 2, 3],
            mls_rs_core::crypto::HpkeSecretKey::from(vec![4; 32]),
            mls_rs_core::crypto::HpkeSecretKey::from(vec![5; 32]),
            0,
        );
        store.insert(b"id1".to_vec(), kp.clone()).unwrap();
        let fetched = store.get(b"id1").unwrap().unwrap();
        assert_eq!(fetched.key_package_bytes, kp.key_package_bytes);
        store.delete(b"id1").unwrap();
        assert!(store.get(b"id1").unwrap().is_none());
    }

    #[test]
    fn group_state_round_trip() {
        let root = tempdir("groups").join("groups");
        let mut store = FileGroupStateStorage::new(root).unwrap();
        let state = GroupState {
            id: b"g".to_vec(),
            data: Zeroizing::new(vec![9, 9, 9]),
        };
        store.write(state, vec![], vec![]).unwrap();
        assert_eq!(
            store.state(b"g").unwrap().unwrap().as_slice(),
            &[9, 9, 9][..]
        );
        assert!(store.max_epoch_id(b"g").unwrap().is_none());
    }

    #[test]
    fn group_state_epoch_records() {
        let root = tempdir("epoch").join("groups");
        let mut store = FileGroupStateStorage::new(root).unwrap();
        let state = GroupState {
            id: b"g2".to_vec(),
            data: Zeroizing::new(vec![0]),
        };
        let epochs = vec![
            EpochRecord::new(1, Zeroizing::new(vec![10])),
            EpochRecord::new(2, Zeroizing::new(vec![20])),
            EpochRecord::new(5, Zeroizing::new(vec![50])),
        ];
        store.write(state, epochs, vec![]).unwrap();
        assert_eq!(
            store.epoch(b"g2", 1).unwrap().unwrap().as_slice(),
            &[10][..]
        );
        assert_eq!(
            store.epoch(b"g2", 2).unwrap().unwrap().as_slice(),
            &[20][..]
        );
        assert_eq!(
            store.epoch(b"g2", 5).unwrap().unwrap().as_slice(),
            &[50][..]
        );
        assert_eq!(store.max_epoch_id(b"g2").unwrap(), Some(5));
    }

    #[test]
    fn psk_round_trip() {
        let root = tempdir("psk").join("psks");
        let store = FilePskStorage::new(root).unwrap();
        let id = ExternalPskId::new(b"hello".to_vec());
        assert!(store.get(&id).unwrap().is_none());
        store.insert(&id, &[42u8; 32]).unwrap();
        let fetched = store.get(&id).unwrap().unwrap();
        assert_eq!(fetched.raw_value(), &[42u8; 32][..]);
    }
}
