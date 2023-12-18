use super::BranchNodeCompact;

/// Walker sub node for storing intermediate state root calculation state in the database.
/// See [crate::stage::MerkleCheckpoint].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StoredSubNode {
    /// The key of the current node.
    pub key: Vec<u8>,
    /// The index of the next child to visit.
    pub nibble: Option<u8>,
    /// The node itself.
    pub node: Option<BranchNodeCompact>,
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrieMask;
    use alloy_primitives::B256;

    #[test]
    fn subnode_roundtrip() {
        let subnode = StoredSubNode {
            key: vec![],
            nibble: None,
            node: Some(BranchNodeCompact {
                state_mask: TrieMask::new(1),
                tree_mask: TrieMask::new(0),
                hash_mask: TrieMask::new(1),
                hashes: vec![B256::ZERO],
                root_hash: None,
            }),
        };

        let mut encoded = vec![];
        subnode.clone().to_compact(&mut encoded);
        let (decoded, _) = StoredSubNode::from_compact(&encoded[..], 0);

        assert_eq!(subnode, decoded);
    }
}
*/
