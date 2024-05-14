//! Proof verification logic.

use crate::{
    nodes::{rlp_node, word_rlp, TrieNode, CHILD_INDEX_RANGE},
    proof::ProofVerificationError,
    EMPTY_ROOT_HASH,
};
use alloc::vec::Vec;
use alloy_primitives::{Bytes, B256};
use alloy_rlp::Decodable;
use nybbles::Nibbles;

/// Verify the proof for given key value pair against the provided state root.
/// The expected node value can be either [Some] if it's expected to be present
/// in the tree or [None] if this is an exclusion proof.
pub fn verify_proof<'a, I>(
    root: B256,
    key: Nibbles,
    value: Option<Vec<u8>>,
    proof: I,
) -> Result<(), ProofVerificationError>
where
    I: IntoIterator<Item = &'a Bytes>,
{
    let mut proof = proof.into_iter().peekable();

    if proof.peek().is_none() {
        return if root == EMPTY_ROOT_HASH {
            if value.is_none() {
                Ok(())
            } else {
                Err(ProofVerificationError::ValueMismatch {
                    path: key,
                    got: None,
                    expected: value.map(Bytes::from),
                })
            }
        } else {
            Err(ProofVerificationError::RootMismatch { got: EMPTY_ROOT_HASH, expected: root })
        };
    }

    let mut walked_path = Nibbles::default();
    let mut next_value = Some(word_rlp(&root));
    for node in proof {
        if Some(rlp_node(node)) != next_value {
            let got = Some(Bytes::copy_from_slice(node));
            let expected = next_value.map(|b| Bytes::copy_from_slice(&b));
            return Err(ProofVerificationError::ValueMismatch { path: walked_path, got, expected });
        }

        next_value = match TrieNode::decode(&mut &node[..])? {
            TrieNode::Branch(branch) => 'val: {
                if let Some(next) = key.get(walked_path.len()) {
                    let mut stack_ptr = branch.as_ref().first_child_index();
                    for index in CHILD_INDEX_RANGE {
                        if branch.state_mask.is_bit_set(index) {
                            if index == *next {
                                walked_path.push(*next);
                                break 'val Some(branch.stack[stack_ptr].clone());
                            }
                            stack_ptr += 1;
                        }
                    }
                }

                None
            }
            TrieNode::Extension(extension) => {
                walked_path.extend_from_slice(&extension.key);
                Some(extension.child)
            }
            TrieNode::Leaf(leaf) => {
                walked_path.extend_from_slice(&leaf.key);
                Some(leaf.value.clone())
            }
        };
    }

    next_value = next_value.filter(|_| walked_path == key);
    if next_value == value {
        Ok(())
    } else {
        Err(ProofVerificationError::ValueMismatch {
            path: key,
            got: next_value.map(Bytes::from),
            expected: value.map(Bytes::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{nodes::BranchNode, proof::ProofRetainer, triehash_trie_root, HashBuilder};
    use alloy_rlp::Encodable;

    #[test]
    fn empty_trie() {
        let key = Nibbles::unpack(B256::repeat_byte(42));
        let mut hash_builder = HashBuilder::default().with_proof_retainer(ProofRetainer::default());
        let root = hash_builder.root();
        let proof = hash_builder.take_proofs();
        assert_eq!(verify_proof(root, key.clone(), None, proof.values()), Ok(()));

        let mut dummy_proof = vec![];
        BranchNode::default().encode(&mut dummy_proof);
        assert_eq!(
            verify_proof(root, key, None, [&Bytes::from(dummy_proof.clone())]),
            Err(ProofVerificationError::ValueMismatch {
                path: Nibbles::default(),
                got: Some(Bytes::from(dummy_proof)),
                expected: Some(Bytes::from(word_rlp(&EMPTY_ROOT_HASH)))
            })
        );
    }

    #[test]
    fn single_leaf_trie_proof_verification() {
        let target = Nibbles::unpack(B256::with_last_byte(0x2));
        let target_value = B256::with_last_byte(0x2);
        let non_existent_target = Nibbles::unpack(B256::with_last_byte(0x3));

        let retainer = ProofRetainer::from_iter([target.clone(), non_existent_target]);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        hash_builder.add_leaf(target.clone(), &target_value[..]);
        let root = hash_builder.root();
        assert_eq!(root, triehash_trie_root([(target.pack(), target.pack())]));

        let proof = hash_builder.take_proofs();
        assert_eq!(verify_proof(root, target, Some(target_value.to_vec()), proof.values()), Ok(()));
    }

    #[test]
    fn non_existent_proof_verification() {
        let range = 0..=0xf;
        let target = Nibbles::unpack(B256::with_last_byte(0xff));

        let retainer = ProofRetainer::from_iter([target.clone()]);
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

        let proof = hash_builder.take_proofs();
        assert_eq!(verify_proof(root, target, None, proof.values()), Ok(()));
    }

    #[test]
    fn extension_root_trie_proof_verification() {
        let range = 0..=0xff;
        let target = Nibbles::unpack(B256::with_last_byte(0x42));
        let target_value = B256::with_last_byte(0x42);

        let retainer = ProofRetainer::from_iter([target.clone()]);
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

        let proof = hash_builder.take_proofs();
        assert_eq!(verify_proof(root, target, Some(target_value.to_vec()), proof.values()), Ok(()));
    }

    #[test]
    fn wide_trie_proof_verification() {
        let range = 0..=0xff;
        let target1 = Nibbles::unpack(B256::repeat_byte(0x42));
        let target1_value = B256::repeat_byte(0x42);
        let target2 = Nibbles::unpack(B256::repeat_byte(0xff));
        let target2_value = B256::repeat_byte(0xff);

        let retainer = ProofRetainer::from_iter([target1.clone(), target2.clone()]);
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

        let proof = hash_builder.take_proofs();

        let proof1 = proof.iter().filter_map(|(k, v)| target1.starts_with(k).then_some(v));
        assert_eq!(
            verify_proof(root, target1.clone(), Some(target1_value.to_vec()), proof1),
            Ok(())
        );

        let proof2 = proof.iter().filter_map(|(k, v)| target2.starts_with(k).then_some(v));
        assert_eq!(
            verify_proof(root, target2.clone(), Some(target2_value.to_vec()), proof2),
            Ok(())
        );
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

            let proofs = hash_builder.take_proofs();
            for (key, value) in hashed {
                let nibbles = Nibbles::unpack(key);
                let proof = proofs.iter().filter_map(|(k, v)| nibbles.starts_with(k).then_some(v));
                assert_eq!(verify_proof(root, nibbles.clone(), Some(value), proof), Ok(()));
            }
        });
    }
}
