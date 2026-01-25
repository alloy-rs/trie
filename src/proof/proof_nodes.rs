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

    fn nibbles(hex: &[u8]) -> Nibbles {
        Nibbles::from_nibbles_unchecked(hex.to_vec())
    }

    #[test]
    fn test_proof_nodes_default() {
        let nodes = ProofNodes::default();
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_proof_nodes_from_iter() {
        let nodes = ProofNodes::from_iter([
            (nibbles(&[1, 2]), Bytes::from_static(&[0xab])),
            (nibbles(&[3, 4]), Bytes::from_static(&[0xcd])),
        ]);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_proof_nodes_insert() {
        let mut nodes = ProofNodes::default();
        let key = nibbles(&[1, 2, 3]);
        let value = Bytes::from_static(&[0xab, 0xcd]);

        assert!(nodes.insert(key, value.clone()).is_none());
        assert_eq!(nodes.get(&key), Some(&value));

        let new_value = Bytes::from_static(&[0xef]);
        let old = nodes.insert(key, new_value.clone());
        assert_eq!(old, Some(value));
        assert_eq!(nodes.get(&key), Some(&new_value));
    }

    #[test]
    fn test_proof_nodes_matching_nodes_iter() {
        let nodes = ProofNodes::from_iter([
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
            (nibbles(&[1, 2, 3]), Bytes::from_static(&[0x02])),
            (nibbles(&[1, 2, 3, 4]), Bytes::from_static(&[0x03])),
            (nibbles(&[5, 6]), Bytes::from_static(&[0x04])),
        ]);

        let target = nibbles(&[1, 2, 3, 4, 5]);
        let matching: Vec<_> = nodes.matching_nodes_iter(&target).collect();
        assert_eq!(matching.len(), 3);
    }

    #[test]
    fn test_proof_nodes_matching_nodes() {
        let nodes = ProofNodes::from_iter([
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
            (nibbles(&[1, 2, 3]), Bytes::from_static(&[0x02])),
            (nibbles(&[4, 5]), Bytes::from_static(&[0x03])),
        ]);

        let target = nibbles(&[1, 2, 3, 4]);
        let matching = nodes.matching_nodes(&target);
        assert_eq!(matching.len(), 2);
    }

    #[test]
    fn test_proof_nodes_matching_nodes_sorted() {
        let nodes = ProofNodes::from_iter([
            (nibbles(&[1, 2, 3]), Bytes::from_static(&[0x02])),
            (nibbles(&[1]), Bytes::from_static(&[0x00])),
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
        ]);

        let target = nibbles(&[1, 2, 3, 4]);
        let matching = nodes.matching_nodes_sorted(&target);
        assert_eq!(matching.len(), 3);
        assert_eq!(matching[0].0, nibbles(&[1]));
        assert_eq!(matching[1].0, nibbles(&[1, 2]));
        assert_eq!(matching[2].0, nibbles(&[1, 2, 3]));
    }

    #[test]
    fn test_proof_nodes_nodes_sorted() {
        let nodes = ProofNodes::from_iter([
            (nibbles(&[3, 4]), Bytes::from_static(&[0x02])),
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
            (nibbles(&[5, 6]), Bytes::from_static(&[0x03])),
        ]);

        let sorted = nodes.nodes_sorted();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].0, nibbles(&[1, 2]));
        assert_eq!(sorted[1].0, nibbles(&[3, 4]));
        assert_eq!(sorted[2].0, nibbles(&[5, 6]));
    }

    #[test]
    fn test_proof_nodes_into_nodes_sorted() {
        let nodes = ProofNodes::from_iter([
            (nibbles(&[3, 4]), Bytes::from_static(&[0x02])),
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
        ]);

        let sorted = nodes.into_nodes_sorted();
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].0, nibbles(&[1, 2]));
        assert_eq!(sorted[1].0, nibbles(&[3, 4]));
    }

    #[test]
    fn test_proof_nodes_into_inner() {
        let nodes = ProofNodes::from_iter([(nibbles(&[1, 2]), Bytes::from_static(&[0x01]))]);

        let inner = nodes.into_inner();
        assert_eq!(inner.len(), 1);
        assert!(inner.contains_key(&nibbles(&[1, 2])));
    }

    #[test]
    fn test_proof_nodes_extend() {
        let mut nodes = ProofNodes::from_iter([(nibbles(&[1, 2]), Bytes::from_static(&[0x01]))]);

        nodes.extend([(nibbles(&[3, 4]), Bytes::from_static(&[0x02]))]);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_proof_nodes_extend_from() {
        let mut nodes1 = ProofNodes::from_iter([(nibbles(&[1, 2]), Bytes::from_static(&[0x01]))]);

        let nodes2 = ProofNodes::from_iter([
            (nibbles(&[3, 4]), Bytes::from_static(&[0x02])),
            (nibbles(&[5, 6]), Bytes::from_static(&[0x03])),
        ]);

        nodes1.extend_from(nodes2);
        assert_eq!(nodes1.len(), 3);
    }

    #[test]
    fn test_proof_nodes_deref() {
        let nodes = ProofNodes::from_iter([(nibbles(&[1, 2]), Bytes::from_static(&[0x01]))]);

        let inner: &HashMap<Nibbles, Bytes> = &nodes;
        assert_eq!(inner.len(), 1);
    }

    #[test]
    fn test_proof_nodes_clone_and_eq() {
        let nodes1 = ProofNodes::from_iter([(nibbles(&[1, 2]), Bytes::from_static(&[0x01]))]);
        let nodes2 = nodes1.clone();
        assert_eq!(nodes1, nodes2);
    }

    #[test]
    fn test_proof_nodes_matching_empty_target() {
        let nodes = ProofNodes::from_iter([
            (Nibbles::default(), Bytes::from_static(&[0x00])),
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
        ]);

        let target = Nibbles::default();
        let matching = nodes.matching_nodes(&target);
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].0, Nibbles::default());
    }

    #[test]
    fn test_proof_nodes_matching_no_match() {
        let nodes = ProofNodes::from_iter([
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
            (nibbles(&[3, 4]), Bytes::from_static(&[0x02])),
        ]);

        let target = nibbles(&[5, 6, 7]);
        let matching = nodes.matching_nodes(&target);
        assert!(matching.is_empty());
    }

    #[test]
    fn test_proof_nodes_extend_overwrites() {
        let key = nibbles(&[1, 2]);
        let mut nodes = ProofNodes::from_iter([(key, Bytes::from_static(&[0x01]))]);
        nodes.extend([(key, Bytes::from_static(&[0x02]))]);
        assert_eq!(nodes.get(&key).unwrap().as_ref(), &[0x02]);
    }

    #[test]
    fn test_proof_nodes_extend_from_overwrites() {
        let key = nibbles(&[1, 2]);
        let mut nodes1 = ProofNodes::from_iter([(key, Bytes::from_static(&[0x01]))]);
        let nodes2 = ProofNodes::from_iter([(key, Bytes::from_static(&[0x02]))]);
        nodes1.extend_from(nodes2);
        assert_eq!(nodes1.get(&key).unwrap().as_ref(), &[0x02]);
    }

    #[test]
    fn test_proof_nodes_empty_key_matches_all_targets() {
        let nodes = ProofNodes::from_iter([
            (Nibbles::default(), Bytes::from_static(&[0x00])),
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
        ]);

        // Empty key should match any target (since any nibbles starts_with empty)
        let target1 = nibbles(&[5, 6, 7]);
        let matching1 = nodes.matching_nodes(&target1);
        assert_eq!(matching1.len(), 1);
        assert_eq!(matching1[0].0, Nibbles::default());

        let target2 = nibbles(&[1, 2, 3]);
        let matching2 = nodes.matching_nodes(&target2);
        assert_eq!(matching2.len(), 2); // Both empty and [1,2] match
    }

    #[test]
    fn test_proof_nodes_matching_nodes_iter_exact_keys() {
        let nodes = ProofNodes::from_iter([
            (nibbles(&[1, 2]), Bytes::from_static(&[0x01])),
            (nibbles(&[1, 2, 3]), Bytes::from_static(&[0x02])),
            (nibbles(&[1, 2, 3, 4]), Bytes::from_static(&[0x03])),
            (nibbles(&[5, 6]), Bytes::from_static(&[0x04])),
        ]);

        let target = nibbles(&[1, 2, 3, 4, 5]);
        let mut matching_keys: Vec<_> =
            nodes.matching_nodes_iter(&target).map(|(k, _)| *k).collect();
        matching_keys.sort();

        let mut expected = vec![nibbles(&[1, 2]), nibbles(&[1, 2, 3]), nibbles(&[1, 2, 3, 4])];
        expected.sort();

        assert_eq!(matching_keys, expected);
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_proof_nodes_sorted_order() {
        use proptest::prelude::*;

        proptest!(|(entries in proptest::collection::vec(
            (proptest::collection::vec(0u8..16, 0..8), proptest::collection::vec(any::<u8>(), 0..32)),
            0..20
        ))| {
            let nodes = ProofNodes::from_iter(
                entries.into_iter().map(|(k, v)| (Nibbles::from_nibbles_unchecked(k), Bytes::from(v)))
            );

            let sorted = nodes.nodes_sorted();
            for i in 1..sorted.len() {
                prop_assert!(sorted[i - 1].0 <= sorted[i].0);
            }
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_proof_nodes_matching_is_prefix() {
        use proptest::prelude::*;

        proptest!(|(
            entries in proptest::collection::vec(
                (proptest::collection::vec(0u8..16, 0..8), proptest::collection::vec(any::<u8>(), 0..32)),
                0..20
            ),
            target in proptest::collection::vec(0u8..16, 0..10)
        )| {
            let nodes = ProofNodes::from_iter(
                entries.into_iter().map(|(k, v)| (Nibbles::from_nibbles_unchecked(k), Bytes::from(v)))
            );

            let target = Nibbles::from_nibbles_unchecked(target);
            let matching = nodes.matching_nodes(&target);

            for (key, _) in matching {
                prop_assert!(target.starts_with(&key));
            }
        });
    }
}
