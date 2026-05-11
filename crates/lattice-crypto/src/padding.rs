//! Fixed-bucket message padding.
//!
//! Every Lattice plaintext is padded up to the next bucket boundary before
//! AEAD encryption. This converts a continuous size distribution into a
//! small discrete one, defeating fine-grained traffic analysis on payload
//! size.
//!
//! ## Bucket schedule
//!
//! | Bucket | Size       | Typical content                       |
//! |--------|-----------|---------------------------------------|
//! | 0      | 256 B     | Short text message, ack, presence     |
//! | 1      | 1 KiB     | Multi-paragraph text, small reaction  |
//! | 2      | 4 KiB     | Long text, small image thumbnail      |
//! | 3      | 16 KiB    | Image preview, voice note metadata    |
//! | 4      | 64 KiB    | Single image, document chunk          |
//! | 5      | 256 KiB   | Large attachment chunk                |
//!
//! Files larger than the largest bucket are chunked at the application
//! layer, with each chunk falling into a bucket. The chunk *count* is then
//! the only observable, and we mask it with cover chunks when configured.
//!
//! ## Padding format
//!
//! `padded = payload || 0x80 || 0x00 ... 0x00`
//!
//! The 0x80 marks the end of true payload. Reverse-scan for the first
//! non-zero byte to recover the boundary. This is the ISO/IEC 7816-4 style
//! used by `NaCl` and Signal.

use tracing::instrument;

use crate::{Error, Result};

/// Padding bucket sizes in bytes, in increasing order.
pub const BUCKETS: &[usize] = &[256, 1_024, 4_096, 16_384, 65_536, 262_144];

/// Maximum supported padded payload size.
pub const MAX_BUCKET: usize = 262_144;

/// Pad `payload` up to the smallest bucket that fits it.
///
/// Returns a fresh `Vec<u8>` of exactly the bucket size.
///
/// # Errors
///
/// Returns [`Error::PaddingOverflow`] if `payload.len() + 1` exceeds
/// [`MAX_BUCKET`]. The `+ 1` accounts for the mandatory marker byte.
#[instrument(level = "trace", skip(payload), fields(pt_len = payload.len()))]
pub fn pad(payload: &[u8]) -> Result<Vec<u8>> {
    let needed = payload
        .len()
        .checked_add(1)
        .ok_or(Error::PaddingOverflow(payload.len(), MAX_BUCKET))?;
    let bucket = BUCKETS.iter().copied().find(|&b| b >= needed);
    let Some(bucket_size) = bucket else {
        return Err(Error::PaddingOverflow(payload.len(), MAX_BUCKET));
    };

    let mut out = Vec::with_capacity(bucket_size);
    out.extend_from_slice(payload);
    out.push(0x80);
    out.resize(bucket_size, 0x00);

    tracing::trace!(bucket = bucket_size, "padding::pad");
    Ok(out)
}

/// Remove padding, recovering the original payload.
///
/// # Errors
///
/// Returns [`Error::Serialization`] if no end-of-payload marker is found.
#[instrument(level = "trace", skip(padded), fields(padded_len = padded.len()))]
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    // Scan from the end for the 0x80 marker, skipping trailing zeros.
    let mut idx = padded.len();
    while idx > 0 {
        idx -= 1;
        match padded[idx] {
            0x00 => {}
            0x80 => {
                tracing::trace!(unpadded_len = idx, "padding::unpad");
                return Ok(padded[..idx].to_vec());
            }
            _ => return Err(Error::Serialization("padding marker corrupted".into())),
        }
    }
    Err(Error::Serialization("padding marker missing".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_short() {
        let pt = b"hello, lattice";
        let padded = pad(pt).expect("pad");
        assert_eq!(padded.len(), 256);
        let recovered = unpad(&padded).expect("unpad");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn round_trip_at_boundary() {
        let pt = vec![0xAA; 255];
        let padded = pad(&pt).expect("pad");
        assert_eq!(padded.len(), 256);
        assert_eq!(unpad(&padded).expect("unpad"), pt);
    }

    #[test]
    fn round_trip_spills_to_next_bucket() {
        let pt = vec![0xAA; 256];
        let padded = pad(&pt).expect("pad");
        assert_eq!(padded.len(), 1_024);
        assert_eq!(unpad(&padded).expect("unpad"), pt);
    }

    #[test]
    fn rejects_oversize() {
        let pt = vec![0xAA; MAX_BUCKET];
        assert!(pad(&pt).is_err());
    }

    #[test]
    fn rejects_missing_marker() {
        let bogus = vec![0x00; 256];
        assert!(unpad(&bogus).is_err());
    }
}
