use crate::{HashMap, Nibbles, nodes::TrieNode, proof::ProofNodes};
use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use core::ops::Deref;

use alloc::vec::Vec;

/// A wrapper struct for trie node key to RLP encoded trie node.
#[derive(PartialEq, Eq, Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DecodedProofNodes(HashMap<Nibbles, TrieNode>);

impl Deref for DecodedProofNodes {
    type Target = HashMap<Nibbles, TrieNode>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromIterator<(Nibbles, TrieNode)> for DecodedProofNodes {
    fn from_iter<T: IntoIterator<Item = (Nibbles, TrieNode)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl Extend<(Nibbles, TrieNode)> for DecodedProofNodes {
    fn extend<T: IntoIterator<Item = (Nibbles, TrieNode)>>(&mut self, iter: T) {
        self.0.extend(iter);
    }
}

impl TryFrom<ProofNodes> for DecodedProofNodes {
    type Error = alloy_rlp::Error;

    fn try_from(proof_nodes: ProofNodes) -> Result<Self, Self::Error> {
        let mut decoded_proof_nodes =
            HashMap::with_capacity_and_hasher(proof_nodes.len(), Default::default());
        for (key, node) in proof_nodes.into_inner() {
            decoded_proof_nodes.insert(key, TrieNode::decode(&mut &node[..])?);
        }
        Ok(Self(decoded_proof_nodes))
    }
}

impl DecodedProofNodes {
    /// Return iterator over proof nodes that match the target.
    pub fn matching_nodes_iter<'a>(
        &'a self,
        target: &'a Nibbles,
    ) -> impl Iterator<Item = (&'a Nibbles, &'a TrieNode)> {
        self.0.iter().filter(|(key, _)| target.starts_with(key))
    }

    /// Return the vec of proof nodes that match the target.
    pub fn matching_nodes(&self, target: &Nibbles) -> Vec<(Nibbles, TrieNode)> {
        // Looking up every prefix of the target is cheaper than scanning a large map.
        if self.0.len() > 16 * (target.len() + 1) {
            return self.prefix_nodes(target);
        }
        self.matching_nodes_iter(target).map(|(key, node)| (*key, node.clone())).collect()
    }

    /// Return the proof nodes that match the target by looking up each of its prefixes, shortest
    /// first. Kept out of line so that it does not change the codegen of the scan.
    #[inline(never)]
    fn prefix_nodes(&self, target: &Nibbles) -> Vec<(Nibbles, TrieNode)> {
        (0..=target.len())
            .filter_map(|len| self.0.get_key_value(&target.slice_unchecked(0, len)))
            .map(|(key, node)| (*key, node.clone()))
            .collect()
    }

    /// Return the sorted vec of proof nodes that match the target.
    pub fn matching_nodes_sorted(&self, target: &Nibbles) -> Vec<(Nibbles, TrieNode)> {
        let mut nodes = self.matching_nodes(target);
        nodes.sort_unstable_by_key(|a| a.0);
        nodes
    }

    /// Insert the trie node at key.
    pub fn insert(&mut self, key: Nibbles, node: TrieNode) -> Option<TrieNode> {
        self.0.insert(key, node)
    }

    /// Insert the RLP encoded trie nodoe at key
    pub fn insert_encoded(
        &mut self,
        key: Nibbles,
        node: Bytes,
    ) -> Result<Option<TrieNode>, alloy_rlp::Error> {
        Ok(self.0.insert(key, TrieNode::decode(&mut &node[..])?))
    }

    /// Return the sorted vec of all proof nodes.
    pub fn nodes_sorted(&self) -> Vec<(Nibbles, TrieNode)> {
        let mut nodes = Vec::from_iter(self.0.iter().map(|(k, v)| (*k, v.clone())));
        nodes.sort_unstable_by_key(|a| a.0);
        nodes
    }

    /// Convert into sorted vec of all proof nodes.
    pub fn into_nodes_sorted(self) -> Vec<(Nibbles, TrieNode)> {
        let mut nodes = Vec::from_iter(self.0);
        nodes.sort_unstable_by_key(|a| a.0);
        nodes
    }

    /// Convert wrapper struct into inner map.
    pub fn into_inner(self) -> HashMap<Nibbles, TrieNode> {
        self.0
    }

    /// Extends with the elements of another `DecodedProofNodes`.
    pub fn extend_from(&mut self, other: Self) {
        self.extend(other.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::LeafNode;

    fn leaf(key: Nibbles) -> TrieNode {
        TrieNode::Leaf(LeafNode::new(key, key.to_vec()))
    }

    #[test]
    fn matching_nodes_prefix_lookup_matches_scan() {
        let mut nodes = DecodedProofNodes::default();
        // Filler that never prefixes the targets below.
        for i in 0..512u16 {
            let key = Nibbles::unpack((0x8000 + i).to_be_bytes());
            nodes.insert(key, leaf(key));
        }
        // Prefixes of the targets, skipping lengths like an extension would, plus a longer key.
        for key in [&[][..], &[1, 2], &[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6, 7, 8]]
        {
            let key = Nibbles::from_nibbles(key);
            nodes.insert(key, leaf(key));
        }

        let with_leaf = Nibbles::from_nibbles([1, 2, 3, 4, 5, 6]);
        let without_leaf = Nibbles::from_nibbles([1, 2, 3, 4, 5, 7]);
        let empty = Nibbles::default();
        for (target, expected_len) in [(with_leaf, 4), (without_leaf, 3), (empty, 1)] {
            assert!(nodes.len() > 16 * (target.len() + 1));
            let mut scan = nodes
                .matching_nodes_iter(&target)
                .map(|(key, node)| (*key, node.clone()))
                .collect::<Vec<_>>();
            scan.sort_unstable_by_key(|a| a.0);
            assert_eq!(scan.len(), expected_len);
            assert_eq!(nodes.matching_nodes(&target), scan);
            assert_eq!(nodes.matching_nodes_sorted(&target), scan);
        }
    }
}
