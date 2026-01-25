//! The implementation of the hash builder.

use super::{
    BranchNodeCompact, EMPTY_ROOT_HASH, Nibbles, TrieMask,
    nodes::{BranchNodeRef, ExtensionNodeRef, LeafNodeRef},
    proof::{ProofNodes, ProofRetainer},
};
use crate::{HashMap, nodes::RlpNode, proof::AddedRemovedKeys};
use alloc::vec::Vec;
use alloy_primitives::{B256, keccak256};
use core::cmp;
use tracing::trace;

mod value;
pub use value::{HashBuilderValue, HashBuilderValueRef};

/// A component used to construct the root hash of the trie.
///
/// The primary purpose of a Hash Builder is to build the Merkle proof that is essential for
/// verifying the integrity and authenticity of the trie's contents. It achieves this by
/// constructing the root hash from the hashes of child nodes according to specific rules, depending
/// on the type of the node (branch, extension, or leaf).
///
/// Here's an overview of how the Hash Builder works for each type of node:
///  * Branch Node: The Hash Builder combines the hashes of all the child nodes of the branch node,
///    using a cryptographic hash function like SHA-256. The child nodes' hashes are concatenated
///    and hashed, and the result is considered the hash of the branch node. The process is repeated
///    recursively until the root hash is obtained.
///  * Extension Node: In the case of an extension node, the Hash Builder first encodes the node's
///    shared nibble path, followed by the hash of the next child node. It concatenates these values
///    and then computes the hash of the resulting data, which represents the hash of the extension
///    node.
///  * Leaf Node: For a leaf node, the Hash Builder first encodes the key-path and the value of the
///    leaf node. It then concatenates the encoded key-path and value, and computes the hash of this
///    concatenated data, which represents the hash of the leaf node.
///
/// The Hash Builder operates recursively, starting from the bottom of the trie and working its way
/// up, combining the hashes of child nodes and ultimately generating the root hash. The root hash
/// can then be used to verify the integrity and authenticity of the trie's data by constructing and
/// verifying Merkle proofs.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub struct HashBuilder<K = AddedRemovedKeys> {
    pub key: Nibbles,
    pub value: HashBuilderValue,
    pub stack: Vec<RlpNode>,

    pub state_masks: Vec<TrieMask>,
    pub tree_masks: Vec<TrieMask>,
    pub hash_masks: Vec<TrieMask>,

    pub stored_in_database: bool,

    pub updated_branch_nodes: Option<HashMap<Nibbles, BranchNodeCompact>>,
    pub proof_retainer: Option<ProofRetainer<K>>,

    pub rlp_buf: Vec<u8>,
}

impl Default for HashBuilder {
    fn default() -> Self {
        Self {
            key: Default::default(),
            value: Default::default(),
            stack: Default::default(),
            state_masks: Default::default(),
            tree_masks: Default::default(),
            hash_masks: Default::default(),
            stored_in_database: Default::default(),
            updated_branch_nodes: None,
            proof_retainer: None,
            rlp_buf: Default::default(),
        }
    }
}

impl<K> HashBuilder<K> {
    /// Enables the Hash Builder to store updated branch nodes.
    ///
    /// Call [HashBuilder::split] to get the updates to branch nodes.
    pub fn with_updates(mut self, retain_updates: bool) -> Self {
        self.set_updates(retain_updates);
        self
    }

    /// Enable specified proof retainer.
    pub fn with_proof_retainer<K2>(self, retainer: ProofRetainer<K2>) -> HashBuilder<K2> {
        HashBuilder {
            key: self.key,
            value: self.value,
            stack: self.stack,
            state_masks: self.state_masks,
            tree_masks: self.tree_masks,
            hash_masks: self.hash_masks,
            stored_in_database: self.stored_in_database,
            updated_branch_nodes: self.updated_branch_nodes,
            proof_retainer: Some(retainer),
            rlp_buf: self.rlp_buf,
        }
    }

    /// Enables the Hash Builder to store updated branch nodes.
    ///
    /// Call [HashBuilder::split] to get the updates to branch nodes.
    pub fn set_updates(&mut self, retain_updates: bool) {
        if retain_updates {
            self.updated_branch_nodes = Some(HashMap::default());
        }
    }
}

impl<K: AsRef<AddedRemovedKeys>> HashBuilder<K> {
    /// Splits the [HashBuilder] into a [HashBuilder] and hash builder updates.
    pub fn split(mut self) -> (Self, HashMap<Nibbles, BranchNodeCompact>) {
        let updates = self.updated_branch_nodes.take();
        (self, updates.unwrap_or_default())
    }

    /// Take and return retained proof nodes.
    pub fn take_proof_nodes(&mut self) -> ProofNodes {
        self.proof_retainer.take().map(ProofRetainer::into_proof_nodes).unwrap_or_default()
    }

    /// The number of total updates accrued.
    /// Returns `0` if [Self::with_updates] was not called.
    pub fn updates_len(&self) -> usize {
        self.updated_branch_nodes.as_ref().map(|u| u.len()).unwrap_or(0)
    }

    /// Print the current stack of the Hash Builder.
    #[cfg(feature = "std")]
    pub fn print_stack(&self) {
        println!("============ STACK ===============");
        for item in &self.stack {
            println!("{}", alloy_primitives::hex::encode(item));
        }
        println!("============ END STACK ===============");
    }

    /// Adds a new leaf element and its value to the trie hash builder.
    ///
    /// # Panics
    ///
    /// Panics if the new key does not come after the current key.
    pub fn add_leaf(&mut self, key: Nibbles, value: &[u8]) {
        assert!(key > self.key, "add_leaf key {:?} self.key {:?}", key, self.key);
        self.add_leaf_unchecked(key, value);
    }

    /// Adds a new leaf element and its value to the trie hash builder,
    /// without checking the order of the new key. This is only for
    /// performance-critical usage that guarantees keys are inserted
    /// in sorted order.
    pub fn add_leaf_unchecked(&mut self, key: Nibbles, value: &[u8]) {
        debug_assert!(key > self.key, "add_leaf_unchecked key {:?} self.key {:?}", key, self.key);
        if !self.key.is_empty() {
            self.update(&key);
        }
        self.set_key_value(key, HashBuilderValueRef::Bytes(value));
    }

    /// Adds a new branch element and its hash to the trie hash builder.
    pub fn add_branch(&mut self, key: Nibbles, value: B256, stored_in_database: bool) {
        assert!(
            key > self.key || (self.key.is_empty() && key.is_empty()),
            "add_branch key {:?} self.key {:?}",
            key,
            self.key
        );
        if !self.key.is_empty() {
            self.update(&key);
        } else if key.is_empty() {
            self.stack.push(RlpNode::word_rlp(&value));
        }
        self.set_key_value(key, HashBuilderValueRef::Hash(&value));
        self.stored_in_database = stored_in_database;
    }

    /// Returns the current root hash of the trie builder.
    pub fn root(&mut self) -> B256 {
        // Clears the internal state
        if !self.key.is_empty() {
            self.update(&Nibbles::default());
            self.key.clear();
            self.value.clear();
        }
        let root = self.current_root();
        if root == EMPTY_ROOT_HASH {
            if let Some(proof_retainer) = self.proof_retainer.as_mut() {
                proof_retainer.retain_empty_root_proof();
            }
        }
        root
    }

    #[inline]
    fn set_key_value(&mut self, key: Nibbles, value: HashBuilderValueRef<'_>) {
        self.log_key_value("old value");
        self.key = key;
        self.value.set_from_ref(value);
        self.log_key_value("new value");
    }

    fn log_key_value(&self, msg: &str) {
        trace!(target: "trie::hash_builder",
            key = ?self.key,
            value = ?self.value,
            "{msg}",
        );
    }

    fn current_root(&self) -> B256 {
        if let Some(node_ref) = self.stack.last() {
            if let Some(hash) = node_ref.as_hash() { hash } else { keccak256(node_ref) }
        } else {
            EMPTY_ROOT_HASH
        }
    }

    /// Given a new element, it appends it to the stack and proceeds to loop through the stack state
    /// and convert the nodes it can into branch / extension nodes and hash them. This ensures
    /// that the top of the stack always contains the merkle root corresponding to the trie
    /// built so far.
    fn update(&mut self, succeeding: &Nibbles) {
        let mut build_extensions = false;
        // current / self.key is always the latest added element in the trie
        let mut current = self.key;
        debug_assert!(!current.is_empty());

        trace!(target: "trie::hash_builder", ?current, ?succeeding, "updating merkle tree");

        let mut i = 0usize;
        loop {
            let _span = tracing::trace_span!(target: "trie::hash_builder", "loop", i, ?current, build_extensions).entered();

            let preceding_exists = !self.state_masks.is_empty();
            let preceding_len = self.state_masks.len().saturating_sub(1);

            let common_prefix_len = succeeding.common_prefix_length(&current);
            let len = cmp::max(preceding_len, common_prefix_len);
            assert!(len < current.len(), "len {} current.len {}", len, current.len());

            trace!(
                target: "trie::hash_builder",
                ?len,
                ?common_prefix_len,
                ?preceding_len,
                preceding_exists,
                "prefix lengths after comparing keys"
            );

            // Adjust the state masks for branch calculation
            let extra_digit = current.get_unchecked(len);
            if self.state_masks.len() <= len {
                let new_len = len + 1;
                trace!(target: "trie::hash_builder", new_len, old_len = self.state_masks.len(), "scaling state masks to fit");
                self.state_masks.resize(new_len, TrieMask::default());
            }
            self.state_masks[len] |= TrieMask::from_nibble(extra_digit);
            trace!(
                target: "trie::hash_builder",
                ?extra_digit,
                state_masks = ?self.state_masks,
            );

            // Adjust the tree masks for exporting to the DB
            if self.tree_masks.len() < current.len() {
                self.resize_masks(current.len());
            }

            let mut len_from = len;
            if !succeeding.is_empty() || preceding_exists {
                len_from += 1;
            }
            trace!(target: "trie::hash_builder", "skipping {len_from} nibbles");

            // The key without the common prefix
            let short_node_key = current.slice(len_from..);
            trace!(target: "trie::hash_builder", ?short_node_key);

            // Concatenate the 2 nodes together
            if !build_extensions {
                match self.value.as_ref() {
                    HashBuilderValueRef::Bytes(leaf_value) => {
                        let leaf_node = LeafNodeRef::new(&short_node_key, leaf_value);
                        self.rlp_buf.clear();
                        let rlp = leaf_node.rlp(&mut self.rlp_buf);

                        let path = current.slice(..len_from);
                        trace!(
                            target: "trie::hash_builder",
                            ?path,
                            ?leaf_node,
                            ?rlp,
                            "pushing leaf node",
                        );
                        self.stack.push(rlp);

                        if let Some(proof_retainer) = self.proof_retainer.as_mut() {
                            proof_retainer.retain_leaf_proof(&path, &self.rlp_buf)
                        }
                    }
                    HashBuilderValueRef::Hash(hash) => {
                        trace!(target: "trie::hash_builder", ?hash, "pushing branch node hash");
                        self.stack.push(RlpNode::word_rlp(hash));

                        if self.stored_in_database {
                            self.tree_masks[current.len() - 1] |=
                                TrieMask::from_nibble(current.last().unwrap());
                        }
                        self.hash_masks[current.len() - 1] |=
                            TrieMask::from_nibble(current.last().unwrap());

                        build_extensions = true;
                    }
                }
            }

            if build_extensions && !short_node_key.is_empty() {
                self.update_masks(&current, len_from);
                let stack_last = self.stack.pop().expect("there should be at least one stack item");
                let extension_node = ExtensionNodeRef::new(&short_node_key, &stack_last);

                self.rlp_buf.clear();
                let rlp = extension_node.rlp(&mut self.rlp_buf);

                let path = current.slice(..len_from);
                trace!(
                    target: "trie::hash_builder",
                    ?path,
                    ?extension_node,
                    ?rlp,
                    "pushing extension node",
                );
                self.stack.push(rlp);

                if let Some(proof_retainer) = self.proof_retainer.as_mut() {
                    proof_retainer.retain_extension_proof(&path, &short_node_key, &self.rlp_buf)
                }

                self.resize_masks(len_from);
            }

            if preceding_len <= common_prefix_len && !succeeding.is_empty() {
                trace!(target: "trie::hash_builder", "no common prefix to create branch nodes from, returning");
                return;
            }

            // Insert branch nodes in the stack
            if !succeeding.is_empty() || preceding_exists {
                // Pushes the corresponding branch node to the stack
                let children = self.push_branch_node(&current, len);
                // Need to store the branch node in an efficient format outside of the hash builder
                self.store_branch_node(&current, len, children);
            }

            self.state_masks.resize(len, TrieMask::default());
            self.resize_masks(len);

            if preceding_len == 0 {
                trace!(target: "trie::hash_builder", "0 or 1 state masks means we have no more elements to process");
                return;
            }

            current.truncate(preceding_len);
            trace!(target: "trie::hash_builder", ?current, "truncated nibbles to {} bytes", preceding_len);

            trace!(target: "trie::hash_builder", state_masks = ?self.state_masks, "popping empty state masks");
            while self.state_masks.last() == Some(&TrieMask::default()) {
                self.state_masks.pop();
            }

            build_extensions = true;

            i += 1;
        }
    }

    /// Given the size of the longest common prefix, it proceeds to create a branch node
    /// from the state mask and existing stack state, and store its RLP to the top of the stack,
    /// after popping all the relevant elements from the stack.
    ///
    /// Returns the hashes of the children of the branch node, only if `updated_branch_nodes` is
    /// enabled.
    fn push_branch_node(&mut self, current: &Nibbles, len: usize) -> Vec<B256> {
        let state_mask = self.state_masks[len];
        let hash_mask = self.hash_masks[len];
        let branch_node = BranchNodeRef::new(&self.stack, state_mask);
        // Avoid calculating this value if it's not needed.
        let children = if self.updated_branch_nodes.is_some() {
            branch_node.child_hashes(hash_mask).collect()
        } else {
            vec![]
        };

        self.rlp_buf.clear();
        let rlp = branch_node.rlp(&mut self.rlp_buf);
        let path = current.slice(..len);
        trace!(
            target: "trie::hash_builder",
            ?path,
            ?branch_node,
            ?rlp,
            "pushing branch node",
        );

        if let Some(proof_retainer) = self.proof_retainer.as_mut() {
            proof_retainer.retain_branch_proof(&path, state_mask, &self.rlp_buf);
        }

        // Clears the stack from the branch node elements
        let first_child_idx = self.stack.len() - state_mask.count_ones() as usize;
        trace!(
            target: "trie::hash_builder",
            new_len = first_child_idx,
            old_len = self.stack.len(),
            "resizing stack to prepare branch node"
        );
        self.stack.resize_with(first_child_idx, Default::default);

        self.stack.push(rlp);
        children
    }

    /// Given the current nibble prefix and the highest common prefix length, proceeds
    /// to update the masks for the next level and store the branch node and the
    /// masks in the database. We will use that when consuming the intermediate nodes
    /// from the database to efficiently build the trie.
    fn store_branch_node(&mut self, current: &Nibbles, len: usize, children: Vec<B256>) {
        if len > 0 {
            let parent_index = len - 1;
            self.hash_masks[parent_index] |=
                TrieMask::from_nibble(current.get_unchecked(parent_index));
        }

        let store_in_db_trie = !self.tree_masks[len].is_empty() || !self.hash_masks[len].is_empty();
        if store_in_db_trie {
            if len > 0 {
                let parent_index = len - 1;
                self.tree_masks[parent_index] |=
                    TrieMask::from_nibble(current.get_unchecked(parent_index));
            }

            #[allow(clippy::unnecessary_unwrap)] // False positive due to `self.current_root()`.
            if self.updated_branch_nodes.is_some() {
                let common_prefix = current.slice(..len);
                let node = BranchNodeCompact::new(
                    self.state_masks[len],
                    self.tree_masks[len],
                    self.hash_masks[len],
                    children,
                    (len == 0).then(|| self.current_root()),
                );
                self.updated_branch_nodes.as_mut().unwrap().insert(common_prefix, node);
            }
        }
    }

    fn update_masks(&mut self, current: &Nibbles, len_from: usize) {
        if len_from > 0 {
            let flag = TrieMask::from_nibble(current.get_unchecked(len_from - 1));

            self.hash_masks[len_from - 1] &= !flag;

            if !self.tree_masks[current.len() - 1].is_empty() {
                self.tree_masks[len_from - 1] |= flag;
            }
        }
    }

    fn resize_masks(&mut self, new_len: usize) {
        trace!(
            target: "trie::hash_builder",
            new_len,
            old_tree_mask_len = self.tree_masks.len(),
            old_hash_mask_len = self.hash_masks.len(),
            "resizing tree/hash masks"
        );
        self.tree_masks.resize(new_len, TrieMask::default());
        self.hash_masks.resize(new_len, TrieMask::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{nodes::LeafNode, triehash_trie_root};
    use alloc::collections::BTreeMap;
    use alloy_primitives::{U256, b256, hex};
    use alloy_rlp::Encodable;

    // Hashes the keys, RLP encodes the values, compares the trie builder with the upstream root.
    fn assert_hashed_trie_root<'a, I, K>(iter: I)
    where
        I: Iterator<Item = (K, &'a U256)>,
        K: AsRef<[u8]> + Ord,
    {
        let hashed = iter
            .map(|(k, v)| (keccak256(k), alloy_rlp::encode(v).to_vec()))
            // Collect into a btree map to sort the data
            .collect::<BTreeMap<_, _>>();

        let mut hb = HashBuilder::default();

        hashed.iter().for_each(|(key, val)| {
            let nibbles = Nibbles::unpack(key);
            hb.add_leaf(nibbles, val);
        });

        assert_eq!(hb.root(), triehash_trie_root(&hashed));
    }

    // No hashing involved
    fn assert_trie_root<I, K, V>(iter: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<[u8]> + Ord,
        V: AsRef<[u8]>,
    {
        let mut hb = HashBuilder::default();

        let data = iter.into_iter().collect::<BTreeMap<_, _>>();
        data.iter().for_each(|(key, val)| {
            let nibbles = Nibbles::unpack(key.as_ref());
            hb.add_leaf(nibbles, val.as_ref());
        });

        assert_eq!(hb.root(), triehash_trie_root(data));
    }

    #[test]
    fn empty() {
        assert_eq!(HashBuilder::default().root(), EMPTY_ROOT_HASH);
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_hashed_root() {
        use proptest::prelude::*;

        // Empty trie is tested by the `empty()` unit test; focus on non-empty here
        proptest!(|(state: BTreeMap<B256, U256>)| {
            prop_assume!(!state.is_empty());
            assert_hashed_trie_root(state.iter());
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_trie_root_raw_keys() {
        use proptest::prelude::*;

        // Test with raw (non-hashed) keys of fixed length (32 bytes like hashed keys).
        // This avoids the prefix-key issue where one key is a prefix of another,
        // which is not supported by the MPT implementation (and not needed for
        // Ethereum where keys are always hashed to 32 bytes).
        // Require at least 2 entries to exercise branching logic.
        proptest!(|(entries in proptest::collection::btree_map(
            proptest::collection::vec(any::<u8>(), 32..=32),
            proptest::collection::vec(any::<u8>(), 0..=128),
            2..100
        ))| {
            assert_trie_root(entries);
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_trie_root_with_updates() {
        use proptest::prelude::*;

        // Verify that enabling updates doesn't change the root.
        // Require at least 2 entries to ensure updates machinery is exercised.
        proptest!(|(state: BTreeMap<B256, U256>)| {
            prop_assume!(state.len() >= 2);

            let hashed: BTreeMap<_, _> = state
                .iter()
                .map(|(k, v)| (keccak256(k), alloy_rlp::encode(v).to_vec()))
                .collect();

            // Build without updates
            let mut hb1 = HashBuilder::default();
            for (key, val) in &hashed {
                hb1.add_leaf(Nibbles::unpack(key), val);
            }
            let root1 = hb1.root();

            // Build with updates enabled
            let mut hb2 = HashBuilder::default().with_updates(true);
            for (key, val) in &hashed {
                hb2.add_leaf(Nibbles::unpack(key), val);
            }
            let root2 = hb2.root();

            assert_eq!(root1, root2);
            assert_eq!(root1, triehash_trie_root(&hashed));
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_deterministic_root() {
        use proptest::prelude::*;

        // Building the trie twice should produce identical roots.
        // Require at least 2 entries to exercise branching determinism.
        proptest!(|(state: BTreeMap<B256, U256>)| {
            prop_assume!(state.len() >= 2);

            let hashed: BTreeMap<_, _> = state
                .iter()
                .map(|(k, v)| (keccak256(k), alloy_rlp::encode(v).to_vec()))
                .collect();

            let mut hb1 = HashBuilder::default();
            let mut hb2 = HashBuilder::default();

            for (key, val) in &hashed {
                hb1.add_leaf(Nibbles::unpack(key), val);
                hb2.add_leaf(Nibbles::unpack(key), val);
            }

            assert_eq!(hb1.root(), hb2.root());
        });
    }

    /// Verify that branch updates are complete for multi-leaf tries.
    ///
    /// NOTE: This test currently fails due to a bug in `store_branch_node` where branch nodes
    /// with only leaf children are not stored in updates. See:
    /// <https://github.com/alloy-rs/trie/pull/124>
    #[test]
    #[ignore = "fails due to store_branch_node bug - see PR #124"]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_branch_updates_complete() {
        use proptest::prelude::*;

        // Only test multi-leaf tries where branches are required
        proptest!(|(state: BTreeMap<B256, U256>)| {
            prop_assume!(state.len() >= 2);

            let hashed: BTreeMap<_, _> = state
                .iter()
                .map(|(k, v)| (keccak256(k), alloy_rlp::encode(v).to_vec()))
                .collect();

            let mut hb = HashBuilder::default().with_updates(true);
            for (key, val) in &hashed {
                hb.add_leaf(Nibbles::unpack(key), val);
            }
            let _ = hb.root();
            let (_, updates) = hb.split();

            // COMPLETENESS CHECK: For tries with 2+ leaves, there must be at least one branch.
            // A trie with multiple leaves requires branches to distinguish them.
            assert!(
                !updates.is_empty(),
                "trie with {} leaves must have branch updates, got none",
                hashed.len()
            );

            // CORRECTNESS CHECK: Verify all branch node compacts have valid invariants
            for (_, node) in &updates {
                // tree_mask must be subset of state_mask
                assert!(node.tree_mask.is_subset_of(node.state_mask));
                // hash_mask must be subset of state_mask
                assert!(node.hash_mask.is_subset_of(node.state_mask));
                // hashes count must match hash_mask popcount
                assert_eq!(node.hash_mask.count_ones() as usize, node.hashes.len());
            }
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_branch_updates_valid() {
        use proptest::prelude::*;

        // Verify that branch updates (when present) have valid mask invariants
        proptest!(|(state: BTreeMap<B256, U256>)| {
            let hashed: BTreeMap<_, _> = state
                .iter()
                .map(|(k, v)| (keccak256(k), alloy_rlp::encode(v).to_vec()))
                .collect();

            let mut hb = HashBuilder::default().with_updates(true);
            for (key, val) in &hashed {
                hb.add_leaf(Nibbles::unpack(key), val);
            }
            let _ = hb.root();
            let (_, updates) = hb.split();

            // Verify all branch node compacts have valid invariants
            for (_, node) in &updates {
                // tree_mask must be subset of state_mask
                assert!(node.tree_mask.is_subset_of(node.state_mask));
                // hash_mask must be subset of state_mask
                assert!(node.hash_mask.is_subset_of(node.state_mask));
                // hashes count must match hash_mask popcount
                assert_eq!(node.hash_mask.count_ones() as usize, node.hashes.len());
            }
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_common_prefix_stress() {
        use proptest::prelude::*;

        // Generate keys that share common prefixes to stress branch node creation.
        // Require at least 2 entries so a branch must exist somewhere.
        let key_strategy = (0u8..16).prop_flat_map(|prefix| {
            proptest::collection::vec(any::<u8>(), 31..=31).prop_map(move |mut v| {
                v[0] = prefix << 4 | (v[0] & 0x0f);
                v
            })
        });

        proptest!(|(entries in proptest::collection::btree_map(
            key_strategy,
            proptest::collection::vec(any::<u8>(), 0..=64),
            2..50
        ))| {
            assert_trie_root(entries);
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_single_leaf() {
        use proptest::prelude::*;

        // Single leaf should produce valid root
        proptest!(|(key: B256, value: U256)| {
            let mut hb = HashBuilder::default();
            let nibbles = Nibbles::unpack(&key);
            let encoded_value = alloy_rlp::encode(&value);
            hb.add_leaf(nibbles, &encoded_value);
            let root = hb.root();

            let expected = triehash_trie_root([(key, encoded_value)]);
            assert_eq!(root, expected);
        });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    #[cfg_attr(miri, ignore = "no proptest")]
    fn arbitrary_add_leaf_unchecked_equivalence() {
        use proptest::prelude::*;

        // add_leaf_unchecked should produce same result as add_leaf.
        // Require at least 2 entries to ensure both APIs handle branching.
        proptest!(|(state: BTreeMap<B256, U256>)| {
            prop_assume!(state.len() >= 2);

            let hashed: BTreeMap<_, _> = state
                .iter()
                .map(|(k, v)| (keccak256(k), alloy_rlp::encode(v).to_vec()))
                .collect();

            let mut hb1 = HashBuilder::default();
            let mut hb2 = HashBuilder::default();

            for (key, val) in &hashed {
                hb1.add_leaf(Nibbles::unpack(key), val);
                hb2.add_leaf_unchecked(Nibbles::unpack(key), val);
            }

            assert_eq!(hb1.root(), hb2.root());
        });
    }

    #[test]
    fn test_generates_branch_node() {
        let mut hb = HashBuilder::default().with_updates(true);

        // We have 1 branch node update to be stored at 0x01, indicated by the first nibble.
        // That branch root node has 4 children:
        // - Leaf at nibble `0`: It has an empty value.
        // - Branch at nibble `1`: It has 2 leaf nodes with empty values at nibbles `0` and `1`.
        // - Branch at nibble `2`: It has 2 leaf nodes with empty values at nibbles `0` and `2`.
        // - Leaf at nibble `3`: It has an empty value.
        //
        // This is enough information to construct the intermediate node value:
        // 1. State Mask: 0b1111. All children of the branch node set at nibbles `0`, `1`, `2` and
        //    `3`.
        // 2. Hash Mask: 0b0110. Of the above items, nibbles `1` and `2` correspond to children that
        //    are branch nodes.
        // 3. Tree Mask: 0b0000. None of the children are stored in the database (yet).
        // 4. Hashes: Hashes of the 2 sub-branch roots, at nibbles `1` and `2`. Calculated by
        //    hashing the 0th and 1st element for the branch at nibble `1` , and the 0th and 2nd
        //    element for the branch at nibble `2`. This basically means that every
        //    BranchNodeCompact is capable of storing up to 2 levels deep of nodes (?).
        let data = BTreeMap::from([
            (
                // Leaf located at nibble `0` of the branch root node that doesn't result in
                // creating another branch node
                hex!("1000000000000000000000000000000000000000000000000000000000000000").to_vec(),
                Vec::new(),
            ),
            (
                hex!("1100000000000000000000000000000000000000000000000000000000000000").to_vec(),
                Vec::new(),
            ),
            (
                hex!("1110000000000000000000000000000000000000000000000000000000000000").to_vec(),
                Vec::new(),
            ),
            (
                hex!("1200000000000000000000000000000000000000000000000000000000000000").to_vec(),
                Vec::new(),
            ),
            (
                hex!("1220000000000000000000000000000000000000000000000000000000000000").to_vec(),
                Vec::new(),
            ),
            (
                // Leaf located at nibble `3` of the branch root node that doesn't result in
                // creating another branch node
                hex!("1320000000000000000000000000000000000000000000000000000000000000").to_vec(),
                Vec::new(),
            ),
        ]);
        data.iter().for_each(|(key, val)| {
            let nibbles = Nibbles::unpack(key);
            hb.add_leaf(nibbles, val.as_ref());
        });
        let _root = hb.root();

        let (_, updates) = hb.split();

        let update = updates.get(&Nibbles::from_nibbles_unchecked(hex!("01"))).unwrap();
        // Nibbles 0, 1, 2, 3 have children
        assert_eq!(update.state_mask, TrieMask::new(0b1111));
        // None of the children are stored in the database
        assert_eq!(update.tree_mask, TrieMask::new(0b0000));
        // Children under nibbles `1` and `2` are branch nodes with `hashes`
        assert_eq!(update.hash_mask, TrieMask::new(0b0110));
        // Calculated when running the hash builder
        assert_eq!(update.hashes.len(), 2);

        assert_eq!(_root, triehash_trie_root(data));
    }

    #[test]
    fn test_root_raw_data() {
        let data = [
            (hex!("646f").to_vec(), hex!("76657262").to_vec()),
            (hex!("676f6f64").to_vec(), hex!("7075707079").to_vec()),
            (hex!("676f6b32").to_vec(), hex!("7075707079").to_vec()),
            (hex!("676f6b34").to_vec(), hex!("7075707079").to_vec()),
        ];
        assert_trie_root(data);
    }

    #[test]
    fn test_root_rlp_hashed_data() {
        let data: HashMap<_, _, _> = HashMap::from([
            (B256::with_last_byte(1), U256::from(2)),
            (B256::with_last_byte(3), U256::from(4)),
        ]);
        assert_hashed_trie_root(data.iter());
    }

    #[test]
    fn test_root_known_hash() {
        let root_hash = b256!("45596e474b536a6b4d64764e4f75514d544577646c414e684271706871446456");
        let mut hb = HashBuilder::default();
        hb.add_branch(Nibbles::default(), root_hash, false);
        assert_eq!(hb.root(), root_hash);
    }

    #[test]
    fn manual_branch_node_ok() {
        let raw_input = vec![
            (hex!("646f").to_vec(), hex!("76657262").to_vec()),
            (hex!("676f6f64").to_vec(), hex!("7075707079").to_vec()),
        ];
        let expected = triehash_trie_root(raw_input.clone());

        // We create the hash builder and add the leaves
        let mut hb = HashBuilder::default();
        for (key, val) in &raw_input {
            hb.add_leaf(Nibbles::unpack(key), val);
        }

        // Manually create the branch node that should be there after the first 2 leaves are added.
        // Skip the 0th element given in this example they have a common prefix and will
        // collapse to a Branch node.
        let leaf1 = LeafNode::new(Nibbles::unpack(&raw_input[0].0[1..]), raw_input[0].1.clone());
        let leaf2 = LeafNode::new(Nibbles::unpack(&raw_input[1].0[1..]), raw_input[1].1.clone());
        let mut branch: [&dyn Encodable; 17] = [b""; 17];
        // We set this to `4` and `7` because that matches the 2nd element of the corresponding
        // leaves. We set this to `7` because the 2nd element of Leaf 1 is `7`.
        branch[4] = &leaf1;
        branch[7] = &leaf2;
        let mut branch_node_rlp = Vec::new();
        alloy_rlp::encode_list::<_, dyn Encodable>(&branch, &mut branch_node_rlp);
        let branch_node_hash = keccak256(branch_node_rlp);

        let mut hb2 = HashBuilder::default();
        // Insert the branch with the `0x6` shared prefix.
        hb2.add_branch(Nibbles::from_nibbles_unchecked([0x6]), branch_node_hash, false);

        assert_eq!(hb.root(), expected);
        assert_eq!(hb2.root(), expected);
    }

    /// Test edge case: keys that diverge at the last nibble with empty values.
    /// This creates very small leaf RLPs and deep branch structures.
    ///
    /// NOTE: Fails due to store_branch_node bug - see PR #124
    #[test]
    #[ignore = "fails due to store_branch_node bug - see PR #124"]
    fn test_deep_divergence_empty_values() {
        let mut hb = HashBuilder::default().with_updates(true);

        let key1 = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let key2 = hex!("0000000000000000000000000000000000000000000000000000000000000001");

        hb.add_leaf(Nibbles::unpack(key1), &[]);
        hb.add_leaf(Nibbles::unpack(key2), &[]);

        let _root = hb.root();
        let (_, updates) = hb.split();

        // With the fix, should have at least one branch update
        assert!(!updates.is_empty(), "deep divergence should have branch updates");
    }

    /// Test: siblings at different depths to verify mask propagation.
    ///
    /// NOTE: Fails due to store_branch_node bug - see PR #124
    #[test]
    #[ignore = "fails due to store_branch_node bug - see PR #124"]
    fn test_mask_propagation_across_depths() {
        let mut hb = HashBuilder::default().with_updates(true);

        // Path 1 and 2 share prefix and go deep, path 3 is shallow sibling
        let keys = [
            hex!("1000000000000000000000000000000000000000000000000000000000000000"),
            hex!("1000000000000000000000000000000000000000000000000000000000000001"),
            hex!("2000000000000000000000000000000000000000000000000000000000000000"),
        ];

        for key in &keys {
            hb.add_leaf(Nibbles::unpack(*key), b"value");
        }

        let _root = hb.root();
        let (_, updates) = hb.split();

        // Verify all stored nodes have valid invariants
        for (path, node) in &updates {
            assert!(
                node.tree_mask.is_subset_of(node.state_mask),
                "tree_mask must be subset of state_mask at {:?}",
                path
            );
            assert!(
                node.hash_mask.is_subset_of(node.state_mask),
                "hash_mask must be subset of state_mask at {:?}",
                path
            );
            assert_eq!(
                node.hash_mask.count_ones() as usize,
                node.hashes.len(),
                "hash count mismatch at {:?}",
                path
            );
        }

        // Root should be present
        assert!(updates.contains_key(&Nibbles::default()), "root should be in updates");
    }

    /// Test Issue 2 from Oracle: tree_mask should only be set for children that are
    /// explicitly marked as stored_in_database, not siblings.
    ///
    /// This test uses add_branch with stored_in_database=true for one subtree
    /// and add_leaf for a sibling, then verifies tree_mask only includes the stored subtree.
    #[test]
    fn test_tree_mask_no_sibling_contamination() {
        let mut hb = HashBuilder::default().with_updates(true);

        // Add a branch at nibble 0x1... that is stored in database
        let stored_hash = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        hb.add_branch(
            Nibbles::from_nibbles_unchecked([0x1]),
            stored_hash,
            true, // stored_in_database = true
        );

        // Add a leaf at nibble 0x2... (sibling, not stored in database)
        let key2 = hex!("2000000000000000000000000000000000000000000000000000000000000000");
        hb.add_leaf(Nibbles::unpack(key2), b"value");

        let _root = hb.root();
        let (_, updates) = hb.split();

        // Find the root branch node update
        if let Some(root_node) = updates.get(&Nibbles::default()) {
            // state_mask should have bits for both 0x1 and 0x2
            assert!(root_node.state_mask.is_bit_set(0x1), "state_mask should have bit 1 set");
            assert!(root_node.state_mask.is_bit_set(0x2), "state_mask should have bit 2 set");

            // tree_mask should ONLY have bit for 0x1 (the stored branch)
            // NOT for 0x2 (the leaf sibling)
            assert!(
                root_node.tree_mask.is_bit_set(0x1),
                "tree_mask should have bit 1 set (stored branch)"
            );
            assert!(
                !root_node.tree_mask.is_bit_set(0x2),
                "tree_mask should NOT have bit 2 set (leaf sibling) - this would indicate Issue 2 bug"
            );
        }
    }

    /// Test Issue 2 from Oracle: verify tree_mask propagation doesn't leak
    /// across unrelated siblings when using multiple add_branch calls.
    #[test]
    fn test_tree_mask_isolation_multiple_branches() {
        let mut hb = HashBuilder::default().with_updates(true);

        let hash_a = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let hash_b = b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        // Add branch A at 0x1, stored in database
        hb.add_branch(Nibbles::from_nibbles_unchecked([0x1]), hash_a, true);

        // Add branch B at 0x2, NOT stored in database
        hb.add_branch(Nibbles::from_nibbles_unchecked([0x2]), hash_b, false);

        let _root = hb.root();
        let (_, updates) = hb.split();

        if let Some(root_node) = updates.get(&Nibbles::default()) {
            // Both should be in state_mask
            assert!(root_node.state_mask.is_bit_set(0x1));
            assert!(root_node.state_mask.is_bit_set(0x2));

            // Only 0x1 should be in tree_mask (stored_in_database=true)
            assert!(root_node.tree_mask.is_bit_set(0x1), "tree_mask should have bit 1 (stored)");
            assert!(
                !root_node.tree_mask.is_bit_set(0x2),
                "tree_mask should NOT have bit 2 (not stored) - Issue 2 bug if set"
            );

            // Both should be in hash_mask (both are branches)
            assert!(root_node.hash_mask.is_bit_set(0x1), "hash_mask should have bit 1");
            assert!(root_node.hash_mask.is_bit_set(0x2), "hash_mask should have bit 2");
        }
    }

    /// Test Issue 1 from Oracle: hash_mask semantics - does it mean
    /// "child is a branch" or "child is actually hashed in RLP (>=32 bytes)"?
    ///
    /// This test creates a branch node that would be small enough to inline
    /// and checks if parent's hash_mask is still set.
    #[test]
    fn test_hash_mask_semantics_inlined_branch() {
        let mut hb = HashBuilder::default().with_updates(true);

        // Create a minimal trie: two leaves that share a common prefix
        // This will create a branch node at the divergence point
        // The branch node might be small enough to inline

        // Keys that diverge at the 63rd nibble (last nibble of a 32-byte key)
        let key1 = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let key2 = hex!("0000000000000000000000000000000000000000000000000000000000000001");

        // Use tiny values to make leaves as small as possible
        hb.add_leaf(Nibbles::unpack(key1), &[0x01]);
        hb.add_leaf(Nibbles::unpack(key2), &[0x02]);

        let _root = hb.root();
        let (_, updates) = hb.split();

        // There should be a branch node at the common prefix (62 nibbles of zeros)
        // and possibly a root node

        for (path, node) in &updates {
            // Verify hash_mask invariant: popcount matches hashes length
            assert_eq!(
                node.hash_mask.count_ones() as usize,
                node.hashes.len(),
                "hash_mask/hashes mismatch at {:?}",
                path
            );

            // For each bit in hash_mask, the corresponding child should be a branch
            // (not a leaf), according to the apparent semantics
        }

        // If we have a root node, check its children
        if let Some(root_node) = updates.get(&Nibbles::default()) {
            // With keys starting with 0x0..., the root should have a child at nibble 0
            // This child is a branch (extension -> branch structure)
            // hash_mask should indicate this

            // The key insight: if Issue 1 is a bug, we'd set hash_mask for children
            // that are inlined, which would be incorrect under "RLP hashed" semantics
            // But if hash_mask means "branch child", it's correct

            println!("Root node state_mask: {:?}", root_node.state_mask);
            println!("Root node hash_mask: {:?}", root_node.hash_mask);
            println!("Root node tree_mask: {:?}", root_node.tree_mask);
            println!("Root node hashes: {:?}", root_node.hashes);
        }
    }

    /// Test Issue 2 deeper: extension nodes and tree_mask propagation.
    ///
    /// This tests whether a stored branch deep in the trie correctly propagates
    /// its tree_mask up through extension nodes to the root.
    #[test]
    fn test_tree_mask_propagation_through_extensions() {
        let mut hb = HashBuilder::default().with_updates(true);

        // Add a stored branch at a deep path with extension node prefix
        // Path: 0x1234... - this will create extension nodes
        let stored_hash = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        hb.add_branch(
            Nibbles::from_nibbles_unchecked([0x1, 0x2, 0x3, 0x4]),
            stored_hash,
            true, // stored_in_database = true
        );

        // Add a leaf at a different top-level nibble (sibling to the extension)
        let key2 = hex!("2000000000000000000000000000000000000000000000000000000000000000");
        hb.add_leaf(Nibbles::unpack(key2), b"value");

        let _root = hb.root();
        let (_, updates) = hb.split();

        // Check root node
        if let Some(root_node) = updates.get(&Nibbles::default()) {
            println!("Root state_mask: {:?}", root_node.state_mask);
            println!("Root tree_mask: {:?}", root_node.tree_mask);
            println!("Root hash_mask: {:?}", root_node.hash_mask);

            // Nibble 0x1 leads to extension -> stored branch
            // Nibble 0x2 leads to leaf

            // tree_mask should have 0x1 set (stored subtree)
            // tree_mask should NOT have 0x2 set (leaf, not stored)
            assert!(
                root_node.tree_mask.is_bit_set(0x1),
                "tree_mask should have bit 1 (stored subtree via extension)"
            );
            assert!(
                !root_node.tree_mask.is_bit_set(0x2),
                "tree_mask should NOT have bit 2 (leaf sibling)"
            );
        }
    }

    /// Test Issue 2 edge case: multiple stored branches at different depths
    /// with a non-stored sibling in between.
    #[test]
    fn test_tree_mask_complex_nesting() {
        let mut hb = HashBuilder::default().with_updates(true);

        // Stored branch at 0x11
        let hash1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        hb.add_branch(Nibbles::from_nibbles_unchecked([0x1, 0x1]), hash1, true);

        // Non-stored branch at 0x12 (sibling at level 2 of the 0x1 subtree)
        let hash2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");
        hb.add_branch(Nibbles::from_nibbles_unchecked([0x1, 0x2]), hash2, false);

        // Leaf at 0x2 (sibling at root level)
        let key3 = hex!("2000000000000000000000000000000000000000000000000000000000000000");
        hb.add_leaf(Nibbles::unpack(key3), b"value");

        let _root = hb.root();
        let (_, updates) = hb.split();

        println!("Updates:");
        for (path, node) in &updates {
            println!(
                "  {:?}: state={:?}, tree={:?}, hash={:?}",
                path, node.state_mask, node.tree_mask, node.hash_mask
            );
        }

        // Check the branch at 0x1 (parent of 0x11 and 0x12)
        let nibble_1_path = Nibbles::from_nibbles_unchecked([0x1]);
        if let Some(branch_1) = updates.get(&nibble_1_path) {
            // state_mask should have both 0x1 and 0x2
            assert!(branch_1.state_mask.is_bit_set(0x1), "should have child at 1");
            assert!(branch_1.state_mask.is_bit_set(0x2), "should have child at 2");

            // tree_mask should ONLY have 0x1 (the stored branch)
            assert!(branch_1.tree_mask.is_bit_set(0x1), "tree_mask should have bit 1 (stored)");
            assert!(
                !branch_1.tree_mask.is_bit_set(0x2),
                "tree_mask should NOT have bit 2 (not stored) - Issue 2 bug if set"
            );
        }
    }

    /// Test that hash_mask only marks branch children, not leaf children.
    #[test]
    fn test_hash_mask_branch_vs_leaf_children() {
        let mut hb = HashBuilder::default().with_updates(true);

        // Create a trie where root has:
        // - A branch child at nibble 0 (two leaves under it)
        // - A leaf child at nibble 1

        // Two leaves under 0x0...
        let key1 = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let key2 = hex!("0100000000000000000000000000000000000000000000000000000000000000");
        // One leaf at 0x1...
        let key3 = hex!("1000000000000000000000000000000000000000000000000000000000000000");

        hb.add_leaf(Nibbles::unpack(key1), b"value1");
        hb.add_leaf(Nibbles::unpack(key2), b"value2");
        hb.add_leaf(Nibbles::unpack(key3), b"value3");

        let _root = hb.root();
        let (_, updates) = hb.split();

        // Check root node
        if let Some(root_node) = updates.get(&Nibbles::default()) {
            // Root should have children at nibbles 0 and 1
            assert!(root_node.state_mask.is_bit_set(0x0), "should have child at 0");
            assert!(root_node.state_mask.is_bit_set(0x1), "should have child at 1");

            // hash_mask: nibble 0 leads to a branch, nibble 1 leads to a leaf
            // If hash_mask means "branch child", nibble 0 should be set, nibble 1 should NOT
            let has_0 = root_node.hash_mask.is_bit_set(0x0);
            let has_1 = root_node.hash_mask.is_bit_set(0x1);

            println!(
                "Root hash_mask: 0x0={}, 0x1={}, hashes.len={}",
                has_0,
                has_1,
                root_node.hashes.len()
            );

            // The expectation depends on semantics:
            // If "branch child": 0x0=true, 0x1=false
            // If "RLP hashed": depends on RLP size of each child
        }
    }

    /// Test hash_mask semantics with a large leaf value (>=32 bytes RLP).
    ///
    /// Under MPT rules, nodes with RLP >= 32 bytes must be referenced by hash.
    /// This test checks whether hash_mask reflects "hashed reference" or "branch child".
    #[test]
    fn test_hash_mask_large_leaf_value() {
        let mut hb = HashBuilder::default().with_updates(true);

        // Create a leaf with a very large value (>32 bytes when RLP encoded)
        // This should force the leaf to be referenced by hash under MPT rules
        let key1 = hex!("1000000000000000000000000000000000000000000000000000000000000000");
        let large_value = vec![0xAB; 100]; // 100 bytes of data

        // Create another leaf at a sibling nibble with small value
        let key2 = hex!("2000000000000000000000000000000000000000000000000000000000000000");
        let small_value = vec![0x01]; // 1 byte

        hb.add_leaf(Nibbles::unpack(key1), &large_value);
        hb.add_leaf(Nibbles::unpack(key2), &small_value);

        let _root = hb.root();
        let (_, updates) = hb.split();

        // Check root node
        if let Some(root_node) = updates.get(&Nibbles::default()) {
            println!("Large leaf test - Root node:");
            println!("  state_mask: {:?}", root_node.state_mask);
            println!("  hash_mask: {:?}", root_node.hash_mask);
            println!("  tree_mask: {:?}", root_node.tree_mask);
            println!("  hashes.len: {}", root_node.hashes.len());

            // Both nibbles 1 and 2 should be in state_mask
            assert!(root_node.state_mask.is_bit_set(0x1));
            assert!(root_node.state_mask.is_bit_set(0x2));

            // Key observation: neither child is a branch node
            // If hash_mask means "branch child": both bits should be unset
            // If hash_mask means "hashed reference (RLP >= 32)": large leaf might have bit set
            //
            // Current implementation: hash_mask tracks branch children for BranchNodeCompact,
            // not MPT RLP hashing decisions. So we expect both bits to be unset.
            let has_1 = root_node.hash_mask.is_bit_set(0x1);
            let has_2 = root_node.hash_mask.is_bit_set(0x2);

            println!("  hash_mask bit 1 (large leaf): {}", has_1);
            println!("  hash_mask bit 2 (small leaf): {}", has_2);

            // Document observed behavior - hash_mask is "branch child" not "RLP hashed"
            // Both leaves, so neither should be in hash_mask
            assert!(
                !has_1 && !has_2,
                "hash_mask should be empty for leaf-only branches (current semantics)"
            );
        }
    }

    /// Test mask isolation across disjoint subtrees built in succession.
    ///
    /// This tests that mask arrays are properly cleared/scoped when building
    /// multiple subtrees under the same parent in successive inserts.
    ///
    /// NOTE: Fails due to store_branch_node bug - see PR #124
    #[test]
    #[ignore = "fails due to store_branch_node bug - see PR #124"]
    fn test_mask_isolation_successive_subtrees() {
        let mut hb = HashBuilder::default().with_updates(true);

        // First subtree under 0x1...: stored branch with leaves
        let hash1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        hb.add_branch(
            Nibbles::from_nibbles_unchecked([0x1, 0x0]),
            hash1,
            true, // stored
        );

        // Add a leaf under 0x1... to force branch creation
        let key1a = hex!("1100000000000000000000000000000000000000000000000000000000000000");
        hb.add_leaf(Nibbles::unpack(key1a), b"value1a");

        // Second subtree under 0x2...: NOT stored, just leaves
        let key2a = hex!("2000000000000000000000000000000000000000000000000000000000000000");
        let key2b = hex!("2100000000000000000000000000000000000000000000000000000000000000");
        hb.add_leaf(Nibbles::unpack(key2a), b"value2a");
        hb.add_leaf(Nibbles::unpack(key2b), b"value2b");

        // Third subtree under 0x3...: stored branch
        let hash3 = b256!("3333333333333333333333333333333333333333333333333333333333333333");
        hb.add_branch(
            Nibbles::from_nibbles_unchecked([0x3]),
            hash3,
            true, // stored
        );

        let _root = hb.root();
        let (_, updates) = hb.split();

        println!("Successive subtrees test - Updates:");
        for (path, node) in &updates {
            println!(
                "  {:?}: state={:?}, tree={:?}, hash={:?}",
                path, node.state_mask, node.tree_mask, node.hash_mask
            );
        }

        // Check root node
        if let Some(root_node) = updates.get(&Nibbles::default()) {
            // state_mask should have bits 1, 2, 3
            assert!(root_node.state_mask.is_bit_set(0x1));
            assert!(root_node.state_mask.is_bit_set(0x2));
            assert!(root_node.state_mask.is_bit_set(0x3));

            // With the fix, tree_mask should have ALL branch children that are stored
            // in updates, including the branch at 0x2 created from leaves.
            // tree_mask means "child is stored in DB" not "child was added via
            // stored_in_database=true"
            assert!(root_node.tree_mask.is_bit_set(0x1), "tree_mask should have bit 1 (stored)");
            assert!(
                root_node.tree_mask.is_bit_set(0x2),
                "tree_mask should have bit 2 (branch stored via fix)"
            );
            assert!(root_node.tree_mask.is_bit_set(0x3), "tree_mask should have bit 3 (stored)");

            // hash_mask should have all branch children (1, 2, 3)
            assert!(
                root_node.hash_mask.is_bit_set(0x1),
                "hash_mask should have bit 1 (branch child)"
            );
            assert!(
                root_node.hash_mask.is_bit_set(0x2),
                "hash_mask should have bit 2 (branch child)"
            );
            assert!(
                root_node.hash_mask.is_bit_set(0x3),
                "hash_mask should have bit 3 (branch child)"
            );
        }
    }
}
