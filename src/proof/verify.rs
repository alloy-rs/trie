//! Proof verification logic.

use crate::{
    nodes::{rlp_node, TrieNode, CHILD_INDEX_RANGE},
    proof::ProofVerificationError,
    EMPTY_ROOT_HASH,
};
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::Decodable;
use nybbles::Nibbles;

/// Verify the proof for given key value pair against the provided state root.
pub fn verify_proof<'a, I>(
    proof: I,
    root: B256,
    key: B256,
    value: Vec<u8>,
) -> Result<(), ProofVerificationError>
where
    I: IntoIterator<Item = &'a Bytes>,
    I::IntoIter: DoubleEndedIterator,
{
    let mut proof = proof.into_iter().rev().peekable();

    if root == EMPTY_ROOT_HASH && proof.peek().is_none() {
        return Ok(());
    }

    let mut target = Nibbles::unpack(key);
    let mut expected_value = value;

    for node in proof {
        let nibbles_verified = match TrieNode::decode(&mut &node[..])? {
            TrieNode::Branch(branch) => {
                let value = 'val: {
                    if let Some(last) = target.last() {
                        let mut stack_ptr = branch.as_ref().first_child_index();
                        for index in CHILD_INDEX_RANGE {
                            if branch.state_mask.is_bit_set(index) {
                                if index == last {
                                    break 'val &branch.stack[stack_ptr];
                                }
                                stack_ptr += 1;
                            }
                        }
                    }

                    return Err(ProofVerificationError::missing_branch_child(target));
                };

                if value != &expected_value {
                    let got = Bytes::copy_from_slice(value.as_slice());
                    let expected = Bytes::from(expected_value);
                    return Err(ProofVerificationError::value_mismatch(target, got, expected));
                }

                1
            }
            TrieNode::Extension(extension) => {
                if !target.ends_with(&extension.key) {
                    return Err(ProofVerificationError::unexpected_key(target, extension.key));
                }

                if extension.child != expected_value {
                    let got = Bytes::copy_from_slice(extension.child.as_slice());
                    let expected = Bytes::from(expected_value);
                    return Err(ProofVerificationError::value_mismatch(target, got, expected));
                }

                extension.key.len()
            }
            TrieNode::Leaf(leaf) => {
                if !target.ends_with(&leaf.key) {
                    return Err(ProofVerificationError::unexpected_key(target, leaf.key));
                }

                if leaf.value != expected_value {
                    let got = Bytes::copy_from_slice(leaf.value.as_slice());
                    let expected = Bytes::from(expected_value);
                    return Err(ProofVerificationError::value_mismatch(target, got, expected));
                }

                leaf.key.len()
            }
        };
        target.truncate(target.len() - nibbles_verified);
        expected_value = rlp_node(node);
    }

    let computed_root = if expected_value.len() == B256::len_bytes() + 1 {
        B256::from_slice(&expected_value[1..])
    } else {
        keccak256(expected_value)
    };

    if root == computed_root {
        Ok(())
    } else {
        Err(ProofVerificationError::RootMismatch { got: computed_root, expected: root })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{nodes::BranchNode, proof::ProofRetainer, triehash_trie_root, HashBuilder};
    use alloy_rlp::Encodable;

    #[test]
    fn empty_trie() {
        let key = B256::repeat_byte(42);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(ProofRetainer::default());
        let root = hash_builder.root();
        let proof = hash_builder.take_proofs();
        assert_eq!(verify_proof(proof.values(), root, key, vec![]), Ok(()));

        let mut dummy_proof = vec![];
        BranchNode::default().encode(&mut dummy_proof);
        assert_eq!(
            verify_proof([&Bytes::from(dummy_proof)], root, key, vec![]),
            Err(ProofVerificationError::missing_branch_child(Nibbles::unpack(key)))
        );
    }

    #[test]
    fn single_leaf_trie_proof_verifcation() {
        let target = B256::with_last_byte(0x2);

        let retainer = ProofRetainer::from_iter([target].map(Nibbles::unpack));
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        hash_builder.add_leaf(Nibbles::unpack(target), &target[..]);
        let root = hash_builder.root();
        assert_eq!(root, triehash_trie_root([(target, target)]));

        let proof = hash_builder.take_proofs();
        assert_eq!(verify_proof(proof.values(), root, target, target.to_vec()), Ok(()));
    }

    #[test]
    fn extension_root_trie_proof_verification() {
        let range = 0..=0xf; // 0xff
        let target = B256::with_last_byte(0x2); // 0x42

        let retainer = ProofRetainer::from_iter([target].map(Nibbles::unpack));
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
        assert_eq!(verify_proof(proof.values(), root, target, target.to_vec()), Ok(()));
    }

    #[test]
    fn wide_trie_proof_verification() {
        let range = 0..=0xff;
        let target1 = B256::repeat_byte(0x42);
        let target2 = B256::repeat_byte(0xff);

        let retainer = ProofRetainer::from_iter([target1, target2].map(Nibbles::unpack));
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

        let proof1 =
            proof.iter().filter_map(|(k, v)| Nibbles::unpack(target1).starts_with(k).then_some(v));
        assert_eq!(verify_proof(proof1, root, target1, target1.to_vec()), Ok(()));

        let proof2 =
            proof.iter().filter_map(|(k, v)| Nibbles::unpack(target2).starts_with(k).then_some(v));
        assert_eq!(verify_proof(proof2, root, target2, target2.to_vec()), Ok(()));
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
                let proof = proofs.iter().filter_map(|(k, v)| Nibbles::unpack(key).starts_with(k).then_some(v));
                assert_eq!(verify_proof(proof, root, key, value), Ok(()));
            }
        });
    }
}
