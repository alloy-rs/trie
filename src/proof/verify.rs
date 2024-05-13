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
/// Returns the leaf node value for the given key.
pub fn verify_proof<'a, I>(
    proof: I,
    root: B256,
    key: B256,
) -> Result<Option<Vec<u8>>, ProofVerificationError>
where
    I: IntoIterator<Item = &'a Bytes>,
{
    let mut proof = proof.into_iter().peekable();

    if proof.peek().is_none() {
        return if root == EMPTY_ROOT_HASH {
            Ok(None)
        } else {
            return Err(ProofVerificationError::RootMismatch {
                got: EMPTY_ROOT_HASH,
                expected: root,
            });
        };
    }

    let target = Nibbles::unpack(key);
    let mut walked_path = Nibbles::default();
    let mut expected_value = Some(word_rlp(&root));
    for node in proof {
        if Some(rlp_node(node)) != expected_value {
            let got = Some(Bytes::copy_from_slice(node));
            let expected = expected_value.map(|b| Bytes::copy_from_slice(&b));
            return Err(ProofVerificationError::ValueMismatch { path: walked_path, got, expected });
        }

        expected_value = match TrieNode::decode(&mut &node[..])? {
            TrieNode::Branch(branch) => 'val: {
                if let Some(next) = target.get(walked_path.len()) {
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
                Some(extension.child).filter(|_| target.starts_with(&walked_path))
            }
            TrieNode::Leaf(leaf) => {
                walked_path.extend_from_slice(&leaf.key);
                Some(leaf.value.clone()).filter(|_| target.starts_with(&walked_path))
            }
        };
    }

    Ok(expected_value)
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
        assert_eq!(verify_proof(proof.values(), root, key), Ok(None));

        let mut dummy_proof = vec![];
        BranchNode::default().encode(&mut dummy_proof);
        assert_eq!(
            verify_proof([&Bytes::from(dummy_proof.clone())], root, key),
            Err(ProofVerificationError::ValueMismatch {
                path: Nibbles::default(),
                got: Some(Bytes::from(dummy_proof)),
                expected: Some(Bytes::from(word_rlp(&EMPTY_ROOT_HASH)))
            })
        );
    }

    #[test]
    fn single_leaf_trie_proof_verification() {
        let target = B256::with_last_byte(0x2);
        let non_existent_target = B256::with_last_byte(0x3);

        let retainer = ProofRetainer::from_iter([target, non_existent_target].map(Nibbles::unpack));
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        hash_builder.add_leaf(Nibbles::unpack(target), &target[..]);
        let root = hash_builder.root();
        assert_eq!(root, triehash_trie_root([(target, target)]));

        let proof = hash_builder.take_proofs();
        assert_eq!(verify_proof(proof.values(), root, target), Ok(Some(target.to_vec())));
    }

    #[test]
    fn non_existent_proof_verification() {
        let range = 0..=0xf;
        let target = B256::with_last_byte(0xff);

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
        assert_eq!(verify_proof(proof.values(), root, target), Ok(None));
    }

    #[test]
    fn extension_root_trie_proof_verification() {
        let range = 0..=0xff;
        let target = B256::with_last_byte(0x42);

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
        assert_eq!(verify_proof(proof.values(), root, target), Ok(Some(target.to_vec())));
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
        assert_eq!(verify_proof(proof1, root, target1), Ok(Some(target1.to_vec())));

        let proof2 =
            proof.iter().filter_map(|(k, v)| Nibbles::unpack(target2).starts_with(k).then_some(v));
        assert_eq!(verify_proof(proof2, root, target2), Ok(Some(target2.to_vec())));
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
                assert_eq!(verify_proof(proof, root, key), Ok(Some(value)));
            }
        });
    }
}
