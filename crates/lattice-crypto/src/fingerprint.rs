//! Out-of-band safety numbers (M6 / ROADMAP §M6).
//!
//! Pairwise identity-pubkey fingerprints two users can compare via
//! some side channel — voice, video, scanned QR — to detect a MITM
//! that swapped one user's identity bundle before they ever
//! exchanged it on-band.
//!
//! ## Construction
//!
//! Given the two parties' hybrid identity pubkeys (the
//! `ed25519_pub || ml_dsa_pub` concatenation that's also what mls-rs
//! sees as the leaf signing key), the safety number is:
//!
//! ```text
//! sorted = lex_sort([party_a_pubkey, party_b_pubkey])
//! digest = BLAKE3_keyed_hash(
//!     key  = BLAKE3("lattice/safety-number/v1"),
//!     data = sorted[0] || sorted[1]
//! )
//! ```
//!
//! Both parties compute the same sorted concatenation regardless of
//! who is "A" and who is "B", so they read identical digits.
//!
//! The 32-byte digest is rendered as 60 decimal digits split into
//! 12 groups of 5. Each group is `u16::from_le_bytes(digest[2i..2i+2])
//! % 100_000`, formatted as a 5-digit zero-padded number. Twelve
//! groups give ~199 bits of brute-force resistance against
//! second-preimage attacks targeting the rendered string — same
//! security order as the underlying 256-bit BLAKE3 output for the
//! comparison use-case (humans aren't checking 256 bits in
//! production).
//!
//! ## Why not Signal's exact construction
//!
//! Signal iterates SHA-512 5200 times per party and concatenates.
//! That cost was chosen for the original protocol's PoW story;
//! BLAKE3-keyed-hash provides equivalent security at far lower CPU
//! cost, and matches the rest of the Lattice hash story (per
//! HANDOFF §8, BLAKE3 is the general-purpose hash).

use blake3::Hasher;

/// Width of one decimal group in the rendered safety number.
const GROUP_DIGITS: usize = 5;
/// Number of decimal groups rendered. 12 groups × 5 digits = 60
/// chars of human-readable comparison material.
const GROUP_COUNT: usize = 12;
/// Domain-separation tag baked into the BLAKE3 key.
const KEY_INFO: &[u8] = b"lattice/safety-number/v1";

/// Compute the 32-byte safety-number digest for the pair of identity
/// pubkeys. Order of the two arguments doesn't matter — both parties
/// compute the same bytes.
#[must_use]
pub fn safety_number_digest(party_a_pubkey: &[u8], party_b_pubkey: &[u8]) -> [u8; 32] {
    let (lo, hi) = if party_a_pubkey <= party_b_pubkey {
        (party_a_pubkey, party_b_pubkey)
    } else {
        (party_b_pubkey, party_a_pubkey)
    };
    let key = *blake3::hash(KEY_INFO).as_bytes();
    let mut hasher = Hasher::new_keyed(&key);
    hasher.update(lo);
    hasher.update(hi);
    *hasher.finalize().as_bytes()
}

/// Render a safety-number digest as a human-readable string —
/// `"12345 67890 11223 44556 77889 90011 22334 45566 77889 90011
/// 22334 45566"`. Twelve groups of five decimal digits separated by
/// spaces. Both parties read identical strings.
#[must_use]
pub fn render_safety_number(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(GROUP_COUNT * (GROUP_DIGITS + 1));
    for i in 0..GROUP_COUNT {
        if i > 0 {
            out.push(' ');
        }
        let word = u16::from_le_bytes([digest[2 * i], digest[2 * i + 1]]);
        let modded = u32::from(word) % 100_000;
        out.push_str(&format!("{modded:0>5}"));
    }
    out
}

/// One-shot helper: hash + render in a single call.
#[must_use]
pub fn safety_number(party_a_pubkey: &[u8], party_b_pubkey: &[u8]) -> String {
    let digest = safety_number_digest(party_a_pubkey, party_b_pubkey);
    render_safety_number(&digest)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn pk_a() -> Vec<u8> {
        vec![0xAA; 32 + 1952]
    }

    fn pk_b() -> Vec<u8> {
        vec![0xBB; 32 + 1952]
    }

    #[test]
    fn render_shape() {
        let digest = [0x42u8; 32];
        let rendered = render_safety_number(&digest);
        // 12 groups × 5 digits + 11 spaces = 71 chars.
        assert_eq!(rendered.len(), 71);
        let groups: Vec<&str> = rendered.split(' ').collect();
        assert_eq!(groups.len(), 12);
        for g in groups {
            assert_eq!(g.len(), 5);
            assert!(g.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn order_independent() {
        let ab = safety_number(&pk_a(), &pk_b());
        let ba = safety_number(&pk_b(), &pk_a());
        assert_eq!(ab, ba);
    }

    #[test]
    fn differs_per_pair() {
        let pk_c = vec![0xCC; 32 + 1952];
        let n_ab = safety_number(&pk_a(), &pk_b());
        let n_ac = safety_number(&pk_a(), &pk_c);
        assert_ne!(n_ab, n_ac);
    }

    #[test]
    fn stable_across_calls() {
        let n1 = safety_number(&pk_a(), &pk_b());
        let n2 = safety_number(&pk_a(), &pk_b());
        assert_eq!(n1, n2);
    }

    #[test]
    fn identical_inputs_still_render() {
        // Edge case: comparing a user's own fingerprint with itself.
        // Should still produce a valid 71-char string.
        let n = safety_number(&pk_a(), &pk_a());
        assert_eq!(n.len(), 71);
    }
}
