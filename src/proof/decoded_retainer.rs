use crate::{Nibbles, nodes::TrieNode, proof::DecodedProofNodes};
use alloy_rlp::Decodable;

use alloc::vec::Vec;

/// Proof retainer is used to store proofs during merkle trie construction.
/// It is intended to be used within the [`HashBuilder`](crate::HashBuilder).
#[derive(Default, Clone, Debug)]
pub struct DecodedProofRetainer {
    /// The nibbles of the target trie keys to retain proofs for.
    targets: Vec<Nibbles>,
    /// The map retained trie node keys to RLP serialized trie nodes.
    proof_nodes: DecodedProofNodes,
}

impl FromIterator<Nibbles> for DecodedProofRetainer {
    fn from_iter<T: IntoIterator<Item = Nibbles>>(iter: T) -> Self {
        Self::new(FromIterator::from_iter(iter))
    }
}

impl DecodedProofRetainer {
    /// Create new retainer with target nibbles.
    pub fn new(mut targets: Vec<Nibbles>) -> Self {
        targets.sort_unstable();
        Self { targets, proof_nodes: Default::default() }
    }

    /// Returns `true` if the given prefix matches the retainer target.
    pub fn matches(&self, prefix: &Nibbles) -> bool {
        self.targets
            .get(self.targets.partition_point(|target| target < prefix))
            .is_some_and(|target| target.starts_with(prefix))
    }

    /// Returns all collected proofs.
    pub fn into_proof_nodes(self) -> DecodedProofNodes {
        self.proof_nodes
    }

    /// Retain the proof if the key matches any of the targets.
    ///
    /// Returns an error if the proof could not be decoded from the given proof bytes.
    pub fn retain(&mut self, prefix: &Nibbles, proof: &[u8]) -> Result<(), alloy_rlp::Error> {
        if prefix.is_empty() || self.matches(prefix) {
            self.proof_nodes.insert(*prefix, TrieNode::decode(&mut &proof[..])?);
        }

        Ok(())
    }
}
