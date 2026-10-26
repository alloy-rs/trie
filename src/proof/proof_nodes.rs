use crate::{HashMap, Nibbles};
use alloy_primitives::Bytes;
use core::ops::Deref;

use alloc::vec::Vec;

/// A wrapper struct for trie node key to RLP encoded trie node.
#[derive(PartialEq, Eq, Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofNodes(HashMap<Nibbles, Bytes>);

impl Deref for ProofNodes {
    type Target = HashMap<Nibbles, Bytes>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromIterator<(Nibbles, Bytes)> for ProofNodes {
    fn from_iter<T: IntoIterator<Item = (Nibbles, Bytes)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl Extend<(Nibbles, Bytes)> for ProofNodes {
    fn extend<T: IntoIterator<Item = (Nibbles, Bytes)>>(&mut self, iter: T) {
        self.0.extend(iter);
    }
}

impl ProofNodes {
    /// Return iterator over proof nodes that match the target.
    pub fn matching_nodes_iter<'a>(
        &'a self,
        target: &'a Nibbles,
    ) -> impl Iterator<Item = (&'a Nibbles, &'a Bytes)> {
        self.0.iter().filter(|(key, _)| target.starts_with(key))
    }

    /// Return the vec of proof nodes that match the target.
    pub fn matching_nodes(&self, target: &Nibbles) -> Vec<(Nibbles, Bytes)> {
        // Looking up every prefix of the target is cheaper than scanning a large map.
        if self.0.len() > 16 * (target.len() + 1) {
            return self.prefix_nodes(target);
        }
        self.matching_nodes_iter(target).map(|(key, node)| (*key, node.clone())).collect()
    }

    /// Return the proof nodes that match the target by looking up each of its prefixes, shortest
    /// first. Kept out of line so that it does not change the codegen of the scan.
    #[inline(never)]
    fn prefix_nodes(&self, target: &Nibbles) -> Vec<(Nibbles, Bytes)> {
        (0..=target.len())
            .filter_map(|len| self.0.get_key_value(&target.slice_unchecked(0, len)))
            .map(|(key, node)| (*key, node.clone()))
            .collect()
    }

    /// Return the sorted vec of proof nodes that match the target.
    pub fn matching_nodes_sorted(&self, target: &Nibbles) -> Vec<(Nibbles, Bytes)> {
        let mut nodes = self.matching_nodes(target);
        nodes.sort_unstable_by_key(|a| a.0);
        nodes
    }

    /// Insert the RLP encoded trie node at key.
    pub fn insert(&mut self, key: Nibbles, node: Bytes) -> Option<Bytes> {
        self.0.insert(key, node)
    }

    /// Return the sorted vec of all proof nodes.
    pub fn nodes_sorted(&self) -> Vec<(Nibbles, Bytes)> {
        let mut nodes = Vec::from_iter(self.0.iter().map(|(k, v)| (*k, v.clone())));
        nodes.sort_unstable_by_key(|a| a.0);
        nodes
    }

    /// Convert into sorted vec of all proof nodes.
    pub fn into_nodes_sorted(self) -> Vec<(Nibbles, Bytes)> {
        let mut nodes = Vec::from_iter(self.0);
        nodes.sort_unstable_by_key(|a| a.0);
        nodes
    }

    /// Convert wrapper struct into inner map.
    pub fn into_inner(self) -> HashMap<Nibbles, Bytes> {
        self.0
    }

    /// Extends with the elements of another `ProofNodes`.
    pub fn extend_from(&mut self, other: Self) {
        self.extend(other.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_nodes_prefix_lookup_matches_scan() {
        let mut nodes = ProofNodes::default();
        // Filler that never prefixes the targets below.
        for i in 0..512u16 {
            let key = Nibbles::unpack((0x8000 + i).to_be_bytes());
            nodes.insert(key, Bytes::copy_from_slice(&i.to_be_bytes()));
        }
        // Prefixes of the targets, skipping lengths like an extension would, plus a longer key.
        for key in [&[][..], &[1, 2], &[1, 2, 3, 4], &[1, 2, 3, 4, 5, 6], &[1, 2, 3, 4, 5, 6, 7, 8]]
        {
            nodes.insert(Nibbles::from_nibbles(key), Bytes::copy_from_slice(key));
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
