//! # lattice-keytransparency
//!
//! Append-only Merkle log of user identity-key bindings (M6 / D-15).
//!
//! Each leaf is a `(user_id, identity_pk, epoch)` tuple committing a
//! user's hybrid identity public key at a specific snapshot. Clients
//! that fetch a peer's key bundle from a home server cross-check it
//! against the server's published log root via [`InclusionProof`].
//! Auditors monitor log monotonicity over time via
//! [`ConsistencyProof`]s connecting successive roots — a malicious
//! server that silently swaps a user's key would produce a log root
//! that's no longer a consistent extension of the previous one.
//!
//! This is the **Trillian-style append-only log** path per D-15.
//! CONIKS's prefix-tree approach (which lets clients prove key
//! *absence*) is not implemented — V1's threat model accepts that
//! the server can simply refuse to publish a binding rather than
//! attesting "user X has no key", at the cost of one extra round of
//! signed `.well-known` data.
//!
//! Hash construction matches RFC 6962 §2.1:
//!   * Empty tree hash = `BLAKE3("")`.
//!   * Leaf hash = `BLAKE3(0x00 || leaf_bytes)`.
//!   * Inner hash = `BLAKE3(0x01 || left || right)`.
//!
//! BLAKE3 instead of SHA-256 because HANDOFF §8 names BLAKE3 the
//! general-purpose hash for Lattice. Tag bytes 0x00 / 0x01 still
//! domain-separate leaf inputs from inner-node inputs.
//!
//! The implementation lives entirely in-memory for M6 — persistent
//! storage (Postgres-backed log) is M7 polish. Logs survive process
//! restart via the existing `state.rs` snapshot mechanism if a
//! caller wires it in.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// One entry in the log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    /// User UUID v7 (16 bytes) or BLAKE3 user_id (32 bytes) — caller
    /// picks; the log treats the field as opaque bytes.
    pub user_id: Vec<u8>,
    /// Hybrid identity pubkey bytes (`ed25519_pub || ml_dsa_pub`).
    pub identity_pk: Vec<u8>,
    /// Logical epoch this binding applies to. Monotonically
    /// increasing per user_id; lets the server attest "this is X's
    /// key as of epoch N".
    pub epoch: u64,
}

impl Leaf {
    /// Canonical leaf encoding — used as the input to the leaf hash.
    /// Length-prefixes the variable-length fields so a forged leaf
    /// can't substitute one user_id-prefix for another.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            8 + 8 + self.user_id.len() + self.identity_pk.len() + 8,
        );
        out.extend_from_slice(&(self.user_id.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.user_id);
        out.extend_from_slice(&(self.identity_pk.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.identity_pk);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out
    }
}

/// 32-byte hash output.
pub type Hash = [u8; 32];

/// RFC 6962 leaf-hash construction.
#[must_use]
pub fn leaf_hash(leaf: &Leaf) -> Hash {
    let bytes = leaf.canonical_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x00]);
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

/// RFC 6962 inner-node hash construction.
#[must_use]
pub fn inner_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Hash of an empty tree. Stable constant.
#[must_use]
pub fn empty_tree_hash() -> Hash {
    *blake3::hash(b"").as_bytes()
}

/// In-memory append-only Merkle log. Cheap to construct, cheap to
/// query — every operation walks the leaf-hash vector. Persistence
/// is a follow-up.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Log {
    /// Stored leaves, in append order.
    leaves: Vec<Leaf>,
    /// Hash of each leaf, parallel to `leaves`. Kept around so
    /// `root_hash()` and proof builders don't re-hash each leaf on
    /// every call.
    leaf_hashes: Vec<Hash>,
}

impl Log {
    /// Construct an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a leaf. Returns the leaf's index (0-based).
    pub fn append(&mut self, leaf: Leaf) -> usize {
        let h = leaf_hash(&leaf);
        let idx = self.leaves.len();
        self.leaves.push(leaf);
        self.leaf_hashes.push(h);
        idx
    }

    /// Current number of leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// True if the log holds no leaves.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Borrow the i-th leaf.
    #[must_use]
    pub fn leaf(&self, idx: usize) -> Option<&Leaf> {
        self.leaves.get(idx)
    }

    /// Compute the current root hash. RFC 6962 §2.1 Merkle Tree Hash.
    /// O(n) over leaf-hash count.
    #[must_use]
    pub fn root_hash(&self) -> Hash {
        if self.leaf_hashes.is_empty() {
            return empty_tree_hash();
        }
        merkle_tree_hash(&self.leaf_hashes)
    }

    /// Build an inclusion proof for the leaf at `index`. Returns
    /// `None` if `index >= len()` or the log is empty.
    #[must_use]
    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaf_hashes.len() {
            return None;
        }
        let siblings = path_for(&self.leaf_hashes, index);
        Some(InclusionProof {
            leaf_index: index,
            tree_size: self.leaf_hashes.len(),
            siblings,
        })
    }

    /// Build a consistency proof connecting roots at sizes
    /// `old_size` and `new_size = self.len()`. Returns `None` when
    /// `old_size > new_size` or `old_size == 0` (no first root to
    /// prove against). RFC 6962 §2.1.2.
    #[must_use]
    pub fn consistency_proof(&self, old_size: usize) -> Option<ConsistencyProof> {
        let new_size = self.leaf_hashes.len();
        if old_size == 0 || old_size > new_size {
            return None;
        }
        let path = subproof(&self.leaf_hashes, 0, new_size, old_size, true);
        Some(ConsistencyProof {
            old_size,
            new_size,
            path,
        })
    }
}

/// Merkle inclusion proof — list of sibling hashes from the leaf's
/// position up to the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Leaf position (0-based).
    pub leaf_index: usize,
    /// Tree size the proof was issued against.
    pub tree_size: usize,
    /// Sibling hashes from leaf level up. Each entry's left/right
    /// orientation is determined by the bit pattern of `leaf_index`
    /// against `tree_size` at the time of verification.
    pub siblings: Vec<Hash>,
}

impl InclusionProof {
    /// Verify the proof connects `leaf` to `root_hash` in a tree of
    /// size `self.tree_size`. Returns `true` iff the proof checks.
    #[must_use]
    pub fn verify(&self, leaf: &Leaf, root_hash: &Hash) -> bool {
        if self.leaf_index >= self.tree_size {
            return false;
        }
        let computed = compute_root_from_path(
            &leaf_hash(leaf),
            self.leaf_index,
            self.tree_size,
            &self.siblings,
        );
        match computed {
            Some(h) => &h == root_hash,
            None => false,
        }
    }
}

/// Merkle consistency proof: proves the root at `new_size` is a
/// proper extension of the root at `old_size`. RFC 6962 §2.1.2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProof {
    /// Old tree size.
    pub old_size: usize,
    /// New tree size.
    pub new_size: usize,
    /// Subproof path elements.
    pub path: Vec<Hash>,
}

impl ConsistencyProof {
    /// Verify the proof connects `old_root` (at `self.old_size`) to
    /// `new_root` (at `self.new_size`).
    #[must_use]
    pub fn verify(&self, old_root: &Hash, new_root: &Hash) -> bool {
        if self.old_size == 0
            || self.old_size > self.new_size
            || (self.old_size < self.new_size && self.path.is_empty())
        {
            return false;
        }
        // Degenerate case: same size. The "proof" is empty and we
        // require old_root == new_root.
        if self.old_size == self.new_size {
            return old_root == new_root && self.path.is_empty();
        }

        // RFC 6962 §2.1.2 verification.
        let mut path = self.path.clone();
        let mut fn_ = self.old_size - 1;
        let mut sn = self.new_size - 1;
        // Step 1: shift right while LSB is 1 (we're inside a fully
        // populated left subtree of the old tree).
        while fn_ & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
        }

        let mut iter = path.drain(..);
        // Step 2: seed the running hashes. If fn_ is 0 we use
        // old_root as the seed for both; otherwise consume the first
        // proof element.
        let (mut fr, mut sr) = if fn_ == 0 {
            (*old_root, *old_root)
        } else {
            let p = match iter.next() {
                Some(h) => h,
                None => return false,
            };
            (p, p)
        };

        // Step 3: combine subsequent path elements.
        while fn_ != 0 {
            let p = match iter.next() {
                Some(h) => h,
                None => return false,
            };
            if fn_ & 1 == 1 || fn_ == sn {
                fr = inner_hash(&p, &fr);
                sr = inner_hash(&p, &sr);
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            } else {
                sr = inner_hash(&sr, &p);
            }
            fn_ >>= 1;
            sn >>= 1;
        }

        // Walk any remaining path elements into sr only.
        while sn != 0 {
            let p = match iter.next() {
                Some(h) => h,
                None => return false,
            };
            sr = inner_hash(&sr, &p);
            sn >>= 1;
        }

        if iter.next().is_some() {
            // Leftover path elements → malformed proof.
            return false;
        }

        fr == *old_root && sr == *new_root
    }
}

// === Internal RFC 6962 helpers ===

/// Largest power of 2 < n. Caller must ensure n >= 2.
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle Tree Hash over `hashes` (each entry is a leaf hash).
fn merkle_tree_hash(hashes: &[Hash]) -> Hash {
    match hashes.len() {
        0 => empty_tree_hash(),
        1 => hashes[0],
        n => {
            let k = split(n);
            let left = merkle_tree_hash(&hashes[..k]);
            let right = merkle_tree_hash(&hashes[k..]);
            inner_hash(&left, &right)
        }
    }
}

/// Inclusion-proof path for leaf at `m` in tree formed by `hashes`.
fn path_for(hashes: &[Hash], m: usize) -> Vec<Hash> {
    let n = hashes.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split(n);
    if m < k {
        let mut p = path_for(&hashes[..k], m);
        p.push(merkle_tree_hash(&hashes[k..]));
        p
    } else {
        let mut p = path_for(&hashes[k..], m - k);
        p.push(merkle_tree_hash(&hashes[..k]));
        p
    }
}

/// Recompute the root from a bottom-up inclusion path per
/// RFC 6962 §2.1.1. `path` is consumed innermost (leaf-level
/// sibling) first.
///
/// Returns `None` on out-of-range index, malformed proof length,
/// or unspent path elements.
fn compute_root_from_path(
    leaf_h: &Hash,
    leaf_index: usize,
    tree_size: usize,
    path: &[Hash],
) -> Option<Hash> {
    if tree_size == 0 || leaf_index >= tree_size {
        return None;
    }
    if tree_size == 1 {
        return path.is_empty().then_some(*leaf_h);
    }

    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = *leaf_h;
    let mut iter = path.iter();

    while sn != 0 {
        let elem = iter.next()?;
        if fn_ & 1 == 1 || fn_ == sn {
            r = inner_hash(elem, &r);
            // Shift up while fn_ is even (we're climbing through
            // left children).
            while fn_ != 0 && fn_ & 1 == 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = inner_hash(&r, elem);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    if iter.next().is_some() {
        return None;
    }
    Some(r)
}

/// RFC 6962 §2.1.2 SUBPROOF helper. Builds the path elements for
/// consistency proof from old size `m` to new size `n` (range
/// `[start, start+n)` of `hashes`).
fn subproof(hashes: &[Hash], start: usize, n: usize, m: usize, b: bool) -> Vec<Hash> {
    if m == n {
        if b {
            Vec::new()
        } else {
            vec![merkle_tree_hash(&hashes[start..start + n])]
        }
    } else if n == 1 {
        Vec::new()
    } else {
        let k = split(n);
        if m <= k {
            let mut p = subproof(hashes, start, k, m, b);
            p.push(merkle_tree_hash(&hashes[start + k..start + n]));
            p
        } else {
            let mut p = subproof(hashes, start + k, n - k, m - k, false);
            p.push(merkle_tree_hash(&hashes[start..start + k]));
            p
        }
    }
}

/// Errors raised by log operations. Kept for ABI compatibility with
/// the placeholder crate; the current impl doesn't return any.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Placeholder for future error variants (storage IO, signature
    /// verification, etc.). The in-memory log doesn't surface
    /// errors today.
    #[error("kt log error: {0}")]
    Inner(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn mk_leaf(idx: u8, epoch: u64) -> Leaf {
        Leaf {
            user_id: vec![idx; 32],
            identity_pk: vec![idx; 1984],
            epoch,
        }
    }

    #[test]
    fn empty_log_root() {
        let log = Log::new();
        assert_eq!(log.root_hash(), empty_tree_hash());
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let mut log = Log::new();
        let leaf = mk_leaf(1, 0);
        log.append(leaf.clone());
        assert_eq!(log.root_hash(), leaf_hash(&leaf));
    }

    #[test]
    fn two_leaf_root() {
        let mut log = Log::new();
        let a = mk_leaf(1, 0);
        let b = mk_leaf(2, 0);
        log.append(a.clone());
        log.append(b.clone());
        let expected = inner_hash(&leaf_hash(&a), &leaf_hash(&b));
        assert_eq!(log.root_hash(), expected);
    }

    #[test]
    fn root_changes_on_append() {
        let mut log = Log::new();
        log.append(mk_leaf(1, 0));
        let r1 = log.root_hash();
        log.append(mk_leaf(2, 0));
        let r2 = log.root_hash();
        assert_ne!(r1, r2);
    }

    #[test]
    fn inclusion_proof_round_trips_for_each_leaf() {
        let mut log = Log::new();
        for i in 0..7 {
            log.append(mk_leaf(i, 0));
        }
        let root = log.root_hash();
        for i in 0..7 {
            let proof = log.inclusion_proof(i).expect("proof");
            let leaf = log.leaf(i).expect("leaf").clone();
            assert!(proof.verify(&leaf, &root), "verify failed at idx {i}");
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let mut log = Log::new();
        for i in 0..5 {
            log.append(mk_leaf(i, 0));
        }
        let root = log.root_hash();
        let proof = log.inclusion_proof(2).unwrap();
        let tampered = mk_leaf(99, 0);
        assert!(!proof.verify(&tampered, &root));
    }

    #[test]
    fn inclusion_proof_rejects_wrong_root() {
        let mut log = Log::new();
        for i in 0..5 {
            log.append(mk_leaf(i, 0));
        }
        let proof = log.inclusion_proof(0).unwrap();
        let leaf = log.leaf(0).unwrap().clone();
        let bogus_root = [0xAAu8; 32];
        assert!(!proof.verify(&leaf, &bogus_root));
    }

    #[test]
    fn inclusion_proof_out_of_bounds() {
        let mut log = Log::new();
        log.append(mk_leaf(1, 0));
        assert!(log.inclusion_proof(1).is_none());
        assert!(log.inclusion_proof(99).is_none());
    }

    #[test]
    fn consistency_proof_round_trip() {
        let mut log = Log::new();
        for i in 0..3 {
            log.append(mk_leaf(i, 0));
        }
        let r3 = log.root_hash();
        for i in 3..8 {
            log.append(mk_leaf(i, 0));
        }
        let r8 = log.root_hash();
        let proof = log.consistency_proof(3).expect("proof");
        assert!(proof.verify(&r3, &r8));
    }

    #[test]
    fn consistency_proof_rejects_swapped_roots() {
        let mut log = Log::new();
        for i in 0..3 {
            log.append(mk_leaf(i, 0));
        }
        let r3 = log.root_hash();
        for i in 3..8 {
            log.append(mk_leaf(i, 0));
        }
        let r8 = log.root_hash();
        let proof = log.consistency_proof(3).unwrap();
        // Provide bogus old_root.
        let bogus = [0u8; 32];
        assert!(!proof.verify(&bogus, &r8));
        // Or bogus new_root.
        assert!(!proof.verify(&r3, &bogus));
    }

    #[test]
    fn consistency_proof_same_size_requires_matching_roots() {
        let mut log = Log::new();
        log.append(mk_leaf(1, 0));
        log.append(mk_leaf(2, 0));
        let r = log.root_hash();
        let proof = log.consistency_proof(2).expect("proof");
        assert!(proof.verify(&r, &r));
    }

    #[test]
    fn consistency_proof_rejects_old_larger_than_new() {
        let mut log = Log::new();
        log.append(mk_leaf(1, 0));
        // Trying to prove consistency from size 99 (more than exists)
        // returns None.
        assert!(log.consistency_proof(99).is_none());
    }

    #[test]
    fn consistency_proof_rejects_zero_old_size() {
        let mut log = Log::new();
        log.append(mk_leaf(1, 0));
        assert!(log.consistency_proof(0).is_none());
    }

    #[test]
    fn malicious_swap_detection_simulation() {
        // ROADMAP §M6 acceptance: "Silent-key-substitution attack
        // simulated in test — malicious server swaps Bob's key
        // bundle; client detects via KT log inclusion check."
        let mut log = Log::new();
        let alice = mk_leaf(0xAA, 0);
        let bob_real = mk_leaf(0xBB, 0);
        let bob_swapped = Leaf {
            user_id: vec![0xBB; 32],
            identity_pk: vec![0xCC; 1984], // attacker's key, different from real
            epoch: 0,
        };
        log.append(alice);
        log.append(bob_real.clone());
        let root = log.root_hash();
        let proof = log.inclusion_proof(1).unwrap();

        // Honest path: bob_real's key with the proof + root verifies.
        assert!(proof.verify(&bob_real, &root));
        // Attack path: swapped key, same proof + root, MUST fail.
        assert!(!proof.verify(&bob_swapped, &root));
    }
}
