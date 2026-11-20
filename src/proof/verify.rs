//! Proof verification logic.

use crate::{
    EMPTY_ROOT_HASH,
    nodes::{BranchNode, CHILD_INDEX_RANGE, RlpNode, TrieNode},
    proof::ProofVerificationError,
};
use alloc::vec::Vec;
use alloy_primitives::{B256, Bytes};
use alloy_rlp::{Decodable, EMPTY_STRING_CODE};
use nybbles::Nibbles;

/// Verify the proof for given key value pair against the provided state root.
///
/// The expected node value can be either [Some] if it's expected to be present
/// in the tree or [None] if this is an exclusion proof.
pub fn verify_proof<'a, I>(
    root: B256,
    key: Nibbles,
    expected_value: Option<Vec<u8>>,
    proof: I,
) -> Result<(), ProofVerificationError>
where
    I: IntoIterator<Item = &'a Bytes>,
{
    let mut proof = proof.into_iter().peekable();

    // If the proof is empty or contains only an empty node, the expected value must be None.
    if proof.peek().is_none_or(|node| node.as_ref() == [EMPTY_STRING_CODE]) {
        return if root == EMPTY_ROOT_HASH {
            if expected_value.is_none() {
                Ok(())
            } else {
                Err(ProofVerificationError::ValueMismatch {
                    path: key,
                    got: None,
                    expected: expected_value.map(Bytes::from),
                })
            }
        } else {
            Err(ProofVerificationError::RootMismatch { got: EMPTY_ROOT_HASH, expected: root })
        };
    }

    let mut walked_path = Nibbles::new();
    let mut state = WalkState::Pending(RlpNode::word_rlp(&root));
    for node in proof {
        // Check that the next proof node is the one the walk is waiting for (the root node, if we
        // just started). Once the walk has reached a value or ended, no further node is expected.
        if Some(RlpNode::from_rlp(node).as_slice()) != state.pending_node() {
            let got = Some(Bytes::copy_from_slice(node));
            let expected = state.as_slice().map(Bytes::copy_from_slice);
            return Err(ProofVerificationError::ValueMismatch { path: walked_path, got, expected });
        }

        // Decode the next node from the proof.
        state = process_trie_node(TrieNode::decode(&mut &node[..])?, &mut walked_path, &key)?;
    }

    // Reject incomplete proofs: if the walked path has not diverged from the key
    // and the walk is still waiting for a node, the proof was truncated.
    if key.starts_with(&walked_path) && matches!(state, WalkState::Pending(_)) {
        return Err(ProofVerificationError::ValueMismatch {
            path: key,
            got: state.as_slice().map(Bytes::copy_from_slice),
            expected: expected_value.map(Bytes::from),
        });
    }

    // If the walked path diverged from the key (e.g. via an extension node whose
    // key doesn't match), the key does not exist — valid exclusion.
    if walked_path != key {
        state = WalkState::Ended;
    }
    let decoded_value = state.as_slice();
    if decoded_value == expected_value.as_deref() {
        Ok(())
    } else {
        Err(ProofVerificationError::ValueMismatch {
            path: key,
            got: decoded_value.map(Bytes::copy_from_slice),
            expected: expected_value.map(Bytes::from),
        })
    }
}

/// The state of the walk from the root down the key's path.
///
/// Every proof node advances the walk:
///
/// - [`TrieNode::Branch`] looks at the child at the key's next nibble: it moves to
///   [`WalkState::Pending`] if that child is hashed, to [`WalkState::Value`] if it is an in-place
///   [`TrieNode::Leaf`], recursively to the state an in-place [`TrieNode::Branch`] (or an in-place
///   [`TrieNode::Extension`] wrapping one) gives, and to [`WalkState::Ended`] if the branch has no
///   child there or the key has no nibble left.
/// - [`TrieNode::Extension`] moves to [`WalkState::Pending`] if its child is hashed, or recursively
///   to the state its in-place child gives.
/// - [`TrieNode::Leaf`] always moves to [`WalkState::Value`].
///
/// Only [`WalkState::Pending`] accepts another proof node.
#[derive(Debug, PartialEq, Eq)]
enum WalkState {
    /// The walk waits for the proof node with this hash reference. In-place children are decoded
    /// immediately and never become pending.
    Pending(RlpNode),
    /// The walk reached a leaf with this value.
    Value(Vec<u8>),
    /// The walk ended without reaching a value: the key is not in the trie.
    Ended,
}

impl WalkState {
    /// The node reference the next proof node must match, if the walk still expects one.
    const fn pending_node(&self) -> Option<&[u8]> {
        match self {
            Self::Pending(node) => Some(node.as_slice()),
            Self::Value(_) | Self::Ended => None,
        }
    }

    /// The bytes the walk holds: the pending node reference or the leaf value.
    fn as_slice(&self) -> Option<&[u8]> {
        match self {
            Self::Pending(node) => Some(node.as_slice()),
            Self::Value(value) => Some(value.as_slice()),
            Self::Ended => None,
        }
    }
}

/// Appends a node's key to the walked path.
///
/// Returns `false`, leaving the path unchanged, if the result would exceed the 64 nibbles a key can
/// have. Only a forged proof gets there, and its path can't be any key: the walk ends as an
/// exclusion, and later proof nodes are rejected.
#[inline]
fn extend_walked_path(walked_path: &mut Nibbles, node_key: &Nibbles) -> bool {
    if walked_path.len() + node_key.len() > B256::len_bytes() * 2 {
        return false;
    }
    walked_path.extend(node_key);
    true
}

#[inline]
fn process_trie_node(
    node: TrieNode,
    walked_path: &mut Nibbles,
    key: &Nibbles,
) -> Result<WalkState, ProofVerificationError> {
    let node = match node {
        TrieNode::Branch(branch) => process_branch(branch, walked_path, key)?,
        TrieNode::Extension(extension) => {
            if !extend_walked_path(walked_path, &extension.key) {
                return Ok(WalkState::Ended);
            }
            if extension.child.is_hash() {
                WalkState::Pending(extension.child)
            } else {
                process_trie_node(TrieNode::decode(&mut &extension.child[..])?, walked_path, key)?
            }
        }
        TrieNode::Leaf(leaf) => {
            if !extend_walked_path(walked_path, &leaf.key) {
                return Ok(WalkState::Ended);
            }
            WalkState::Value(leaf.value)
        }
        TrieNode::EmptyRoot => return Err(ProofVerificationError::UnexpectedEmptyRoot),
    };
    Ok(node)
}

#[inline]
fn process_branch(
    mut branch: BranchNode,
    walked_path: &mut Nibbles,
    key: &Nibbles,
) -> Result<WalkState, ProofVerificationError> {
    if let Some(next) = key.get(walked_path.len()) {
        let mut stack_ptr = branch.as_ref().first_child_index();
        for index in CHILD_INDEX_RANGE {
            if branch.state_mask.is_bit_set(index) {
                if index == next {
                    walked_path.push(next);

                    let child = branch.stack.remove(stack_ptr);
                    if child.len() == B256::len_bytes() + 1 {
                        return Ok(WalkState::Pending(child));
                    } else {
                        // This node is encoded in-place.
                        match TrieNode::decode(&mut &child[..])? {
                            TrieNode::Branch(child_branch) => {
                                // An in-place branch node can only have direct, also in-place
                                // encoded, leaf children, as anything else overflows this branch
                                // node, making it impossible to be encoded in-place in the first
                                // place.
                                return process_branch(child_branch, walked_path, key);
                            }
                            TrieNode::Extension(child_extension) => {
                                if !extend_walked_path(walked_path, &child_extension.key) {
                                    return Ok(WalkState::Ended);
                                }

                                // If the extension node's child is a hash, the encoded extension
                                // node itself wouldn't fit for encoding in-place. So this extension
                                // node must have a child that is also encoded in-place.
                                //
                                // Since the child cannot be a leaf node (otherwise this node itself
                                // would be a leaf node, not an extension node), the child must be a
                                // branch node encoded in-place.
                                match TrieNode::decode(&mut &child_extension.child[..])? {
                                    TrieNode::Branch(extension_child_branch) => {
                                        return process_branch(
                                            extension_child_branch,
                                            walked_path,
                                            key,
                                        );
                                    }
                                    // Not produced by a valid trie, but the proof is untrusted
                                    // input, so reject it instead of panicking.
                                    TrieNode::EmptyRoot
                                    | TrieNode::Extension(_)
                                    | TrieNode::Leaf(_) => {
                                        return Err(alloy_rlp::Error::Custom(
                                            "in-place extension node child is not a branch node",
                                        )
                                        .into());
                                    }
                                }
                            }
                            TrieNode::Leaf(child_leaf) => {
                                if !extend_walked_path(walked_path, &child_leaf.key) {
                                    return Ok(WalkState::Ended);
                                }
                                return Ok(WalkState::Value(child_leaf.value));
                            }
                            TrieNode::EmptyRoot => {
                                return Err(ProofVerificationError::UnexpectedEmptyRoot);
                            }
                        }
                    };
                }
                stack_ptr += 1;
            }
        }
    }

    Ok(WalkState::Ended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HashBuilder, TrieMask,
        nodes::{BranchNode, ExtensionNode, LeafNode},
        proof::{ProofNodes, ProofRetainer},
        triehash_trie_root,
    };
    use alloy_primitives::hex;
    use alloy_rlp::{EMPTY_STRING_CODE, Encodable};
    use core::str::FromStr;

    #[test]
    fn empty_trie() {
        let key = Nibbles::unpack(B256::repeat_byte(42));
        let mut hash_builder =
            HashBuilder::default().with_proof_retainer(<ProofRetainer>::default());
        let root = hash_builder.root();
        let proof = hash_builder.take_proof_nodes();
        assert_eq!(
            proof,
            ProofNodes::from_iter([(Nibbles::default(), Bytes::from([EMPTY_STRING_CODE]))])
        );
        assert_eq!(
            verify_proof(root, key, None, proof.into_nodes_sorted().iter().map(|(_, node)| node)),
            Ok(())
        );

        let mut dummy_proof = vec![];
        BranchNode::default().encode(&mut dummy_proof);
        assert_eq!(
            verify_proof(root, key, None, [&Bytes::from(dummy_proof.clone())]),
            Err(ProofVerificationError::ValueMismatch {
                path: Nibbles::default(),
                got: Some(Bytes::from(dummy_proof)),
                expected: Some(Bytes::from(RlpNode::word_rlp(&EMPTY_ROOT_HASH)[..].to_vec()))
            })
        );
    }

    #[test]
    fn inlined_trie_leaves() {
        // root: ext(a7)
        // a7: branch(children: 1, 7, f)
        // a77: ext(d3)
        // a77d3: branch(children: 3 (key: 70, value: 0x31), 9 (key: 70, value: 0x312e32))
        let root =
            B256::from_str("8523a13fdb0aa86480a61e34443a951e85e618b5c9b23b9e74cf2754941ce061")
                .unwrap();
        let proof = [
            Bytes::from_str("e48200a7a080389e2b58154f1b8756223ec9ac277b6a166417b4279f016cb86582afb5ae6c").unwrap(),
            Bytes::from_str("f84080c7833135508234358080808080a0d03438e4f6601da47dab30f52e4325509012ebc1a1c8901fd10d37e05db48bf180808080808080c88339365083312e3180").unwrap(),
            Bytes::from_str("e08200d3dc808080c4822070318080808080c782207083312e3280808080808080").unwrap()
        ];

        let first_key = Nibbles::unpack(hex!("a77d3370"));
        let first_value = vec![0x31];
        let second_key = Nibbles::unpack(hex!("a77d3970"));
        let second_value = hex!("0x312e32").to_vec();

        assert_eq!(verify_proof(root, first_key, Some(first_value.clone()), &proof), Ok(()));
        assert_eq!(
            verify_proof(root, first_key, None, &proof),
            Err(ProofVerificationError::ValueMismatch {
                path: first_key,
                got: Some(first_value.into()),
                expected: None,
            })
        );

        assert_eq!(verify_proof(root, second_key, Some(second_value.clone()), &proof), Ok(()));
        assert_eq!(
            verify_proof(root, second_key, None, &proof),
            Err(ProofVerificationError::ValueMismatch {
                path: second_key,
                got: Some(second_value.into()),
                expected: None,
            })
        );
    }

    #[test]
    fn single_leaf_trie_proof_verification() {
        let target = Nibbles::unpack(B256::with_last_byte(0x2));
        let target_value = B256::with_last_byte(0x2);
        let non_existent_target = Nibbles::unpack(B256::with_last_byte(0x3));

        let retainer = ProofRetainer::from_iter([target, non_existent_target]);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        hash_builder.add_leaf(target, &target_value[..]);
        let root = hash_builder.root();
        assert_eq!(root, triehash_trie_root([(target.pack(), target.pack())]));

        let proof = hash_builder.take_proof_nodes().into_nodes_sorted();
        assert_eq!(
            verify_proof(
                root,
                target,
                Some(target_value.to_vec()),
                proof.iter().map(|(_, node)| node)
            ),
            Ok(())
        );
    }

    #[test]
    fn non_existent_proof_verification() {
        let range = 0..=0xf;
        let target = Nibbles::unpack(B256::with_last_byte(0xff));

        let retainer = ProofRetainer::from_iter([target]);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        for key in range.clone() {
            let hash = B256::with_last_byte(key);
            hash_builder.add_leaf(Nibbles::unpack(hash), &hash[..]);
        }
        let root = hash_builder.root();
        assert_eq!(
            root,
            triehash_trie_root(range.map(|b| (B256::with_last_byte(b), B256::with_last_byte(b))))
        );

        let proof = hash_builder.take_proof_nodes().into_nodes_sorted();
        assert_eq!(verify_proof(root, target, None, proof.iter().map(|(_, node)| node)), Ok(()));
    }

    #[test]
    fn proof_verification_with_divergent_node() {
        let existing_keys = [
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            hex!("3a00000000000000000000000000000000000000000000000000000000000000"),
            hex!("3c15000000000000000000000000000000000000000000000000000000000000"),
        ];
        let target = Nibbles::unpack(
            B256::from_str("0x3c19000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        );
        let value = B256::with_last_byte(1);

        // Build trie without a target and retain proof first.
        let retainer = ProofRetainer::from_iter([target]);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        for key in &existing_keys {
            hash_builder.add_leaf(Nibbles::unpack(B256::from_slice(key)), &value[..]);
        }
        let root = hash_builder.root();
        assert_eq!(
            root,
            triehash_trie_root(existing_keys.map(|key| (B256::from_slice(&key), value)))
        );
        let proof = hash_builder.take_proof_nodes();
        assert_eq!(proof, ProofNodes::from_iter([
            (Nibbles::default(), Bytes::from_str("f851a0c530c099d779362b6bd0be05039b51ccd0a8ed39e0b2abacab8fe0e3441251878080a07d4ee4f073ae7ce32a6cbcdb015eb73dd2616f33ed2e9fb6ba51c1f9ad5b697b80808080808080808080808080").unwrap()),
            (Nibbles::from_iter_unchecked(vec![0x3]), Bytes::from_str("f85180808080808080808080a057fcbd3f97b1093cd39d0f58dafd5058e2d9f79a419e88c2498ff3952cb11a8480a07520d69a83a2bdad373a68b2c9c8c0e1e1c99b6ec80b4b933084da76d644081980808080").unwrap()),
            (Nibbles::from_iter_unchecked(vec![0x3, 0xc]), Bytes::from_str("f842a02015000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001").unwrap())
        ]));
        assert_eq!(
            verify_proof(
                root,
                target,
                None,
                proof.into_nodes_sorted().iter().map(|(_, node)| node)
            ),
            Ok(())
        );

        let retainer = ProofRetainer::from_iter([target]);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        for key in &existing_keys {
            hash_builder.add_leaf(Nibbles::unpack(B256::from_slice(key)), &value[..]);
        }
        hash_builder.add_leaf(target, &value[..]);
        let root = hash_builder.root();
        assert_eq!(
            root,
            triehash_trie_root(
                existing_keys
                    .into_iter()
                    .map(|key| (B256::from_slice(&key), value))
                    .chain([(B256::from_slice(&target.pack()), value)])
            )
        );
        let proof = hash_builder.take_proof_nodes();
        assert_eq!(proof, ProofNodes::from_iter([
            (Nibbles::default(), Bytes::from_str("f851a0c530c099d779362b6bd0be05039b51ccd0a8ed39e0b2abacab8fe0e3441251878080a0abd80d939392f6d222f8becc15f8c6f0dbbc6833dd7e54bfbbee0c589b7fd40380808080808080808080808080").unwrap()),
            (Nibbles::from_iter_unchecked(vec![0x3]), Bytes::from_str("f85180808080808080808080a057fcbd3f97b1093cd39d0f58dafd5058e2d9f79a419e88c2498ff3952cb11a8480a09e7b3788773773f15e26ad07b72a2c25a6374bce256d9aab6cea48fbc77d698180808080").unwrap()),
            (Nibbles::from_iter_unchecked(vec![0x3, 0xc]), Bytes::from_str("e211a0338ac0a453edb0e40a23a70aee59e02a6c11597c34d79a5ba94da8eb20dd4d52").unwrap()),
            (Nibbles::from_iter_unchecked(vec![0x3, 0xc, 0x1]), Bytes::from_str("f8518080808080a020dc5b33292bfad9013bf123f7faf1efcc5c8e00c894177fc0bfb447daef522f808080a020dc5b33292bfad9013bf123f7faf1efcc5c8e00c894177fc0bfb447daef522f80808080808080").unwrap()),
            (Nibbles::from_iter_unchecked(vec![0x3, 0xc, 0x1, 0x9]), Bytes::from_str("f8419f20000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001").unwrap()),
        ]));
        assert_eq!(
            verify_proof(
                root,
                target,
                Some(value.to_vec()),
                proof.into_nodes_sorted().iter().map(|(_, node)| node)
            ),
            Ok(())
        );
    }

    #[test]
    fn extension_root_trie_proof_verification() {
        let range = 0..=0xff;
        let target = Nibbles::unpack(B256::with_last_byte(0x42));
        let target_value = B256::with_last_byte(0x42);

        let retainer = ProofRetainer::from_iter([target]);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        for key in range.clone() {
            let hash = B256::with_last_byte(key);
            hash_builder.add_leaf(Nibbles::unpack(hash), &hash[..]);
        }
        let root = hash_builder.root();
        assert_eq!(
            root,
            triehash_trie_root(range.map(|b| (B256::with_last_byte(b), B256::with_last_byte(b))))
        );

        let proof = hash_builder.take_proof_nodes().into_nodes_sorted();
        assert_eq!(
            verify_proof(
                root,
                target,
                Some(target_value.to_vec()),
                proof.iter().map(|(_, node)| node)
            ),
            Ok(())
        );
    }

    #[test]
    fn wide_trie_proof_verification() {
        let range = 0..=0xff;
        let target1 = Nibbles::unpack(B256::repeat_byte(0x42));
        let target1_value = B256::repeat_byte(0x42);
        let target2 = Nibbles::unpack(B256::repeat_byte(0xff));
        let target2_value = B256::repeat_byte(0xff);

        let retainer = ProofRetainer::from_iter([target1, target2]);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        for key in range.clone() {
            let hash = B256::repeat_byte(key);
            hash_builder.add_leaf(Nibbles::unpack(hash), &hash[..]);
        }
        let root = hash_builder.root();
        assert_eq!(
            root,
            triehash_trie_root(range.map(|b| (B256::repeat_byte(b), B256::repeat_byte(b))))
        );

        let proof = hash_builder.take_proof_nodes();

        assert_eq!(
            verify_proof(
                root,
                target1,
                Some(target1_value.to_vec()),
                proof.matching_nodes_sorted(&target1).iter().map(|(_, node)| node)
            ),
            Ok(())
        );

        assert_eq!(
            verify_proof(
                root,
                target2,
                Some(target2_value.to_vec()),
                proof.matching_nodes_sorted(&target2).iter().map(|(_, node)| node)
            ),
            Ok(())
        );
    }

    #[test]
    fn proof_verification_with_node_encoded_in_place() {
        // Building a trie with a leaf, branch, and extension encoded in place:
        //
        // - node `2a`: 0x64
        // - node `32a`: 0x64
        // - node `33b`: 0x64
        // - node `412a`: 0x64
        // - node `413b`: 0x64
        //
        // This trie looks like:
        //
        // f83f => list len = 63
        //    80
        //    80
        //    c2 => list len = 2 (leaf encoded in-place)
        //       3a => odd leaf
        //       64 => leaf node value
        //    d5 => list len = 21 (branch encoded in-place)
        //       80
        //       80
        //       c2 => list len = 2 (leaf node encoded in-place)
        //          3a => odd leaf
        //          64 leaf node value
        //       c2 => list len = 2 (leaf node encoded in-place)
        //          3b => odd leaf
        //          64 leaf node value
        //       80
        //       80
        //       80
        //       80
        //       80
        //       80
        //       80
        //       80
        //       80
        //       80
        //       80
        //       80
        //       80
        //    d7 => list len = 23 (extension encoded in-place)
        //       11 => odd extension
        //       d5 => list len = 21 (branch encoded in-place)
        //          80
        //          80
        //          c2 => list len = 2 (leaf node encoded in-place)
        //             3a => odd leaf
        //             64 leaf node value
        //          c2 => list len = 2 (leaf node encoded in-place)
        //             3b => odd leaf
        //             64 leaf node value
        //          80
        //          80
        //          80
        //          80
        //          80
        //          80
        //          80
        //          80
        //          80
        //          80
        //          80
        //          80
        //          80
        //    80
        //    80
        //    80
        //    80
        //    80
        //    80
        //    80
        //    80
        //    80
        //    80
        //    80
        //    80
        //
        // Flattened:
        // f83f8080c23a64d58080c23a64c23b6480808080808080808080808080d711d58080c23a64c23b6480808080808080808080808080808080808080808080808080
        //
        // Root hash:
        // 67dbae3a9cc1f4292b0739fa1bcb7f9e6603a6a138444656ec674e273417c918

        let mut buffer = vec![];

        let value = vec![0x64];
        let child_leaf = TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0xa]), value.clone()));

        let child_branch = TrieNode::Branch(BranchNode::new(
            vec![
                {
                    buffer.clear();
                    TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0xa]), value.clone()))
                        .rlp(&mut buffer)
                },
                {
                    buffer.clear();
                    TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0xb]), value))
                        .rlp(&mut buffer)
                },
            ],
            TrieMask::new(0b0000000000001100_u16),
        ));

        let child_extension =
            TrieNode::Extension(ExtensionNode::new(Nibbles::from_nibbles([0x1]), {
                buffer.clear();
                child_branch.rlp(&mut buffer)
            }));

        let root_branch = TrieNode::Branch(BranchNode::new(
            vec![
                {
                    buffer.clear();
                    child_leaf.rlp(&mut buffer)
                },
                {
                    buffer.clear();
                    child_branch.rlp(&mut buffer)
                },
                {
                    buffer.clear();
                    child_extension.rlp(&mut buffer)
                },
            ],
            TrieMask::new(0b0000000000011100_u16),
        ));

        let mut root_encoded = vec![];
        root_branch.encode(&mut root_encoded);

        // Just to make sure our manual encoding above is correct
        assert_eq!(
            root_encoded,
            hex!(
                "f83f8080c23a64d58080c23a64c23b6480808080808080808080808080d711d58080c23a64c23b6480808080808080808080808080808080808080808080808080"
            )
        );

        let root_hash = B256::from_slice(&hex!(
            "67dbae3a9cc1f4292b0739fa1bcb7f9e6603a6a138444656ec674e273417c918"
        ));
        let root_encoded = Bytes::from(root_encoded);
        let proof = vec![&root_encoded];

        // Node `2a`: 0x64
        verify_proof(root_hash, Nibbles::from_nibbles([0x2, 0xa]), Some(vec![0x64]), proof.clone())
            .unwrap();

        // Node `32a`: 0x64
        verify_proof(
            root_hash,
            Nibbles::from_nibbles([0x3, 0x2, 0xa]),
            Some(vec![0x64]),
            proof.clone(),
        )
        .unwrap();

        // Node `33b`: 0x64
        verify_proof(
            root_hash,
            Nibbles::from_nibbles([0x3, 0x3, 0xb]),
            Some(vec![0x64]),
            proof.clone(),
        )
        .unwrap();

        // Node `412a`: 0x64
        verify_proof(
            root_hash,
            Nibbles::from_nibbles([0x4, 0x1, 0x2, 0xa]),
            Some(vec![0x64]),
            proof.clone(),
        )
        .unwrap();

        // Node `413b`: 0x64
        verify_proof(
            root_hash,
            Nibbles::from_nibbles([0x4, 0x1, 0x3, 0xb]),
            Some(vec![0x64]),
            proof.clone(),
        )
        .unwrap();
    }

    /// Truncated proof must not be accepted as valid exclusion proof. Verifies that an incomplete
    /// proof is rejected even when the proof fragment could match an exclusion (None == None).
    /// The key 0x42 exists in the trie, so verification with a truncated proof and `expected_value
    /// = None` must fail.
    #[test]
    fn truncated_proof_rejected() {
        // Build a trie with 256 keys so the proof has multiple nodes.
        let range = 0..=0xff;
        let target = Nibbles::unpack(B256::with_last_byte(0x42));
        let target_value = B256::with_last_byte(0x42);
        let retainer = ProofRetainer::from_iter([target]);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        for key in range.clone() {
            let hash = B256::with_last_byte(key);
            hash_builder.add_leaf(Nibbles::unpack(hash), &hash[..]);
        }
        let root = hash_builder.root();
        assert_eq!(
            root,
            triehash_trie_root(range.map(|b| (B256::with_last_byte(b), B256::with_last_byte(b))))
        );

        let proof = hash_builder.take_proof_nodes().into_nodes_sorted();

        // Verify: full proof correctly accepts inclusion.
        assert_eq!(
            verify_proof(
                root,
                target,
                Some(target_value.to_vec()),
                proof.iter().map(|(_, node)| node)
            ),
            Ok(())
        );

        // Verify: full proof correctly rejects false exclusion.
        assert_eq!(
            verify_proof(root, target, None, proof.iter().map(|(_, node)| node)),
            Err(ProofVerificationError::ValueMismatch {
                path: target,
                got: Some(Bytes::copy_from_slice(&target_value[..])),
                expected: None,
            })
        );

        // Test: truncated proof to only the first node (root) must be rejected.
        let truncated: Vec<&Bytes> = proof.iter().map(|(_, node)| node).take(1).collect();
        assert!(truncated.len() < proof.len(), "proof must have multiple nodes to truncate");

        let result = verify_proof(root, target, None, truncated.iter().copied());
        assert!(
            matches!(
                result,
                Err(ProofVerificationError::ValueMismatch {
                    path,
                    got: Some(_),
                    expected: None,
                }) if path == target
            ),
            "truncated proof must be rejected while a child node is pending"
        );
    }

    #[test]
    fn leaf_prefix_is_valid_exclusion() {
        let leaf = TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0x1]), vec![0x64; 32]));
        let mut encoded = Vec::new();
        leaf.encode(&mut encoded);
        let encoded = Bytes::from(encoded);
        let root = alloy_primitives::keccak256(&encoded);

        assert_eq!(verify_proof(root, Nibbles::from_nibbles([0x1, 0x2]), None, [&encoded]), Ok(()));
    }

    #[test]
    fn truncated_proof_at_key_boundary_rejected() {
        let child = TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0x0]), vec![0x64]));
        let child = RlpNode::word_rlp(&alloy_primitives::keccak256(alloy_rlp::encode(child)));
        let pending_child = Bytes::copy_from_slice(child.as_slice());
        let root_node =
            TrieNode::Extension(ExtensionNode::new(Nibbles::from_nibbles([0x1, 0x2]), child));
        let mut encoded = Vec::new();
        root_node.encode(&mut encoded);
        let encoded = Bytes::from(encoded);
        let root = alloy_primitives::keccak256(&encoded);
        let key = Nibbles::from_nibbles([0x1, 0x2]);

        assert_eq!(
            verify_proof(root, key, Some(pending_child.to_vec()), [&encoded]),
            Err(ProofVerificationError::ValueMismatch {
                path: key,
                got: Some(pending_child.clone()),
                expected: Some(pending_child),
            })
        );
    }

    #[test]
    fn node_after_terminal_leaf_rejected() {
        let forged_value = vec![0xff; 32];
        let forged_leaf =
            TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0x2]), forged_value.clone()));
        let forged_leaf = Bytes::from(alloy_rlp::encode(forged_leaf));

        // Make the genuine terminal value look exactly like the node reference for the forged
        // suffix. A verifier that erases the Node/Value distinction will follow it as a child.
        let genuine_value = Bytes::copy_from_slice(RlpNode::from_rlp(&forged_leaf).as_slice());
        let genuine_leaf =
            TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0x1]), genuine_value.to_vec()));
        let genuine_leaf = Bytes::from(alloy_rlp::encode(genuine_leaf));
        let root = alloy_primitives::keccak256(&genuine_leaf);

        assert_eq!(
            verify_proof(
                root,
                Nibbles::from_nibbles([0x1, 0x2]),
                Some(forged_value),
                [&genuine_leaf, &forged_leaf],
            ),
            Err(ProofVerificationError::ValueMismatch {
                path: Nibbles::from_nibbles([0x1]),
                got: Some(forged_leaf),
                expected: Some(genuine_value),
            })
        );
    }

    #[test]
    fn in_place_extension_with_leaf_child_rejected() {
        // An in-place extension under a branch must point at an in-place branch. A forged branch
        // whose in-place extension points at a leaf has to be rejected, not panic.
        let leaf = TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0x2]), vec![0x01]));
        let leaf = RlpNode::from_rlp(&alloy_rlp::encode(leaf));
        let extension = TrieNode::Extension(ExtensionNode::new(Nibbles::from_nibbles([0x1]), leaf));
        let extension = RlpNode::from_rlp(&alloy_rlp::encode(extension));
        assert!(!extension.is_hash());

        // A second, hashed child makes the branch long enough to be referenced by hash.
        let sibling = RlpNode::word_rlp(&B256::repeat_byte(0x11));
        let branch =
            TrieNode::Branch(BranchNode::new(vec![extension, sibling], TrieMask::new(0b11)));
        let branch = Bytes::from(alloy_rlp::encode(branch));
        let root = alloy_primitives::keccak256(&branch);

        assert_eq!(
            verify_proof(root, Nibbles::from_nibbles([0x0, 0x1, 0x2]), None, [&branch]),
            Err(ProofVerificationError::Rlp(alloy_rlp::Error::Custom(
                "in-place extension node child is not a branch node"
            )))
        );
    }

    #[test]
    fn path_longer_than_key_space_is_exclusion() {
        // A forged proof whose node keys sum to more than 64 nibbles must not overflow the walked
        // path. The full path can't be any key, so it proves exclusion.
        let leaf = TrieNode::Leaf(LeafNode::new(Nibbles::unpack(B256::ZERO), vec![0x01]));
        let leaf = Bytes::from(alloy_rlp::encode(leaf));
        let leaf_ref = RlpNode::from_rlp(&leaf);
        assert!(leaf_ref.is_hash());
        let branch = TrieNode::Branch(BranchNode::new(vec![leaf_ref], TrieMask::new(0b1)));
        let branch = Bytes::from(alloy_rlp::encode(branch));
        let root = alloy_primitives::keccak256(&branch);
        let key = Nibbles::unpack(B256::ZERO);

        assert_eq!(verify_proof(root, key, None, [&branch, &leaf]), Ok(()));
        assert_eq!(
            verify_proof(root, key, Some(vec![0x01]), [&branch, &leaf]),
            Err(ProofVerificationError::ValueMismatch {
                path: key,
                got: None,
                expected: Some(Bytes::from_static(&[0x01])),
            })
        );

        // The same through a hashed extension node below another extension.
        let inner = TrieNode::Extension(ExtensionNode::new(
            Nibbles::unpack(B256::ZERO),
            RlpNode::word_rlp(&B256::repeat_byte(0x11)),
        ));
        let inner = Bytes::from(alloy_rlp::encode(inner));
        let outer = TrieNode::Extension(ExtensionNode::new(
            Nibbles::from_nibbles([0x0]),
            RlpNode::from_rlp(&inner),
        ));
        let outer = Bytes::from(alloy_rlp::encode(outer));
        let root = alloy_primitives::keccak256(&outer);
        assert_eq!(verify_proof(root, key, None, [&outer, &inner]), Ok(()));

        // The same through in-place children of a branch below a long hashed extension: an in-place
        // leaf, and an in-place extension over an in-place branch.
        let inner_leaf =
            alloy_rlp::encode(TrieNode::Leaf(LeafNode::new(Nibbles::new(), vec![0x01])));
        let inner_branch = alloy_rlp::encode(TrieNode::Branch(BranchNode::new(
            vec![RlpNode::from_raw(&inner_leaf).unwrap()],
            TrieMask::new(0b1),
        )));
        let in_place_children = [
            TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles([0x0; 4]), vec![0x01])),
            TrieNode::Extension(ExtensionNode::new(
                Nibbles::from_nibbles([0x0; 4]),
                RlpNode::from_raw(&inner_branch).unwrap(),
            )),
        ];
        for child in in_place_children {
            let child = RlpNode::from_raw(&alloy_rlp::encode(child)).unwrap();
            assert!(!child.is_hash());
            let branch = TrieNode::Branch(BranchNode::new(
                vec![child, RlpNode::word_rlp(&B256::repeat_byte(0x22))],
                TrieMask::new(0b11),
            ));
            let branch = Bytes::from(alloy_rlp::encode(branch));
            let extension = TrieNode::Extension(ExtensionNode::new(
                Nibbles::from_nibbles([0x0; 60]),
                RlpNode::from_rlp(&branch),
            ));
            let extension = Bytes::from(alloy_rlp::encode(extension));
            let root = alloy_primitives::keccak256(&extension);
            assert_eq!(verify_proof(root, key, None, [&extension, &branch]), Ok(()));
        }
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_proof_verification() {
        use proptest::prelude::*;

        proptest!(|(state: std::collections::BTreeMap<B256, alloy_primitives::U256>)| {
            let hashed = state.into_iter()
                .map(|(k, v)| (k, alloy_rlp::encode(v).to_vec()))
                // Collect into a btree map to sort the data
                .collect::<std::collections::BTreeMap<_, _>>();

            let retainer = ProofRetainer::from_iter(hashed.clone().into_keys().map(Nibbles::unpack));
            let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
            for (key, value) in hashed.clone() {
                hash_builder.add_leaf(Nibbles::unpack(key), &value);
            }

            let root = hash_builder.root();
            assert_eq!(root, triehash_trie_root(&hashed));

            let proofs = hash_builder.take_proof_nodes();
            for (key, value) in hashed {
                let nibbles = Nibbles::unpack(key);
                assert_eq!(verify_proof(root, nibbles, Some(value), proofs.matching_nodes_sorted(&nibbles).iter().map(|(_, node)| node)), Ok(()));
            }
        });
    }
}
