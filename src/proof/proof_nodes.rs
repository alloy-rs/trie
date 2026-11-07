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
        super::matching_entries(&self.0, target)
    }

    /// Return the vec of proof nodes that match the target.
    pub fn matching_nodes(&self, target: &Nibbles) -> Vec<(Nibbles, Bytes)> {
        self.matching_nodes_iter(target).map(|(key, node)| (*key, node.clone())).collect()
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
    use alloy_primitives::{B256, keccak256};

    #[test]
    fn matching_nodes_by_lookup_and_scan_agree() {
        let target = Nibbles::unpack(B256::repeat_byte(0x12));
        let other = Nibbles::unpack(B256::repeat_byte(0x13));
        // Every prefix of the target and of another key, plus unrelated paths, so the map is
        // large enough to be searched by prefix lookups.
        let mut nodes = ProofNodes::default();
        for len in 0..=64 {
            nodes.insert(target.slice(..len), Bytes::from(vec![len as u8]));
            nodes.insert(other.slice(..len), Bytes::from(vec![len as u8, 1]));
        }
        for i in 0u64..300 {
            nodes.insert(Nibbles::unpack(keccak256(i.to_be_bytes())), Bytes::new());
        }
        assert!(nodes.len() > 4 * (target.len() + 1));

        for target in [target, target.slice(..7), other, Nibbles::default()] {
            let mut expected = nodes
                .iter()
                .filter(|(path, _)| target.starts_with(path))
                .map(|(path, node)| (*path, node.clone()))
                .collect::<Vec<_>>();
            expected.sort_unstable_by_key(|(path, _)| *path);
            assert_eq!(nodes.matching_nodes_sorted(&target), expected);
        }
    }
}
