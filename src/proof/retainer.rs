use crate::{proof::ProofNodes, Nibbles, TrieMask};
use alloy_primitives::{map::HashMap, Bytes};

#[allow(unused_imports)]
use alloc::vec::Vec;

/// Proof retainer is used to store proofs during merkle trie construction.
/// It is intended to be used within the [`HashBuilder`](crate::HashBuilder).
#[derive(Default, Debug)]
pub struct ProofRetainer {
    /// Nibbles of the target trie paths to retain proofs for.
    targets: Vec<Nibbles>,
    /// Map of retained trie node paths to RLP serialized trie nodes.
    proof_nodes: ProofNodes,
    /// Map of retained branch node paths to hash masks.
    hash_masks: HashMasks,
}

/// Map of retained branch node paths to hash masks.
pub type HashMasks = HashMap<Nibbles, TrieMask>;

impl FromIterator<Nibbles> for ProofRetainer {
    fn from_iter<T: IntoIterator<Item = Nibbles>>(iter: T) -> Self {
        Self::new(FromIterator::from_iter(iter))
    }
}

impl ProofRetainer {
    /// Create new retainer with target nibbles.
    pub fn new(targets: Vec<Nibbles>) -> Self {
        Self { targets, ..Default::default() }
    }

    /// Returns `true` if the given prefix matches the retainer target.
    pub fn matches(&self, prefix: &Nibbles) -> bool {
        self.targets.iter().any(|target| target.starts_with(prefix))
    }

    /// Returns all collected proofs and hash masks of retained branch nodes.
    pub fn into_proof_nodes(self) -> (ProofNodes, HashMasks) {
        (self.proof_nodes, self.hash_masks)
    }

    /// Retain the proof if the key matches any of the targets.
    pub fn retain(&mut self, prefix: &Nibbles, proof: &[u8], hash_mask: Option<TrieMask>) {
        if prefix.is_empty() || self.matches(prefix) {
            self.proof_nodes.insert(prefix.clone(), Bytes::from(proof.to_vec()));
            if let Some(hash_mask) = hash_mask {
                self.hash_masks.insert(prefix.clone(), hash_mask);
            }
        }
    }
}
