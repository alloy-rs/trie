//! The implementation of the hash builder.

use super::{
    nodes::{word_rlp, BranchNodeRef, ExtensionNodeRef, LeafNodeRef},
    proof::ProofRetainer,
    BranchNodeCompact, Nibbles, TrieMask, EMPTY_ROOT_HASH,
};
use crate::HashMap;
use alloy_primitives::{hex, keccak256, Bytes, B256};
use core::cmp;
use tracing::trace;

#[allow(unused_imports)]
use alloc::{collections::BTreeMap, vec::Vec};

mod value;
pub use value::HashBuilderValue;

/// A component used to construct the root hash of the trie. The primary purpose of a Hash Builder
/// is to build the Merkle proof that is essential for verifying the integrity and authenticity of
/// the trie's contents. It achieves this by constructing the root hash from the hashes of child
/// nodes according to specific rules, depending on the type of the node (branch, extension, or
/// leaf).
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
#[derive(Debug, Default)]
#[allow(missing_docs)]
pub struct HashBuilder {
    pub key: Nibbles,
    pub stack: Vec<Vec<u8>>,
    pub value: HashBuilderValue,

    pub groups: Vec<TrieMask>,
    pub tree_masks: Vec<TrieMask>,
    pub hash_masks: Vec<TrieMask>,

    pub stored_in_database: bool,

    pub updated_branch_nodes: Option<HashMap<Nibbles, BranchNodeCompact>>,
    pub proof_retainer: Option<ProofRetainer>,

    pub rlp_buf: Vec<u8>,
}

impl HashBuilder {
    /// Enables the Hash Builder to store updated branch nodes.
    ///
    /// Call [HashBuilder::split] to get the updates to branch nodes.
    pub fn with_updates(mut self, retain_updates: bool) -> Self {
        self.set_updates(retain_updates);
        self
    }

    /// Enable specified proof retainer.
    pub fn with_proof_retainer(mut self, retainer: ProofRetainer) -> Self {
        self.proof_retainer = Some(retainer);
        self
    }

    /// Enables the Hash Builder to store updated branch nodes.
    ///
    /// Call [HashBuilder::split] to get the updates to branch nodes.
    pub fn set_updates(&mut self, retain_updates: bool) {
        if retain_updates {
            self.updated_branch_nodes = Some(HashMap::new());
        }
    }

    /// Splits the [HashBuilder] into a [HashBuilder] and hash builder updates.
    pub fn split(mut self) -> (Self, HashMap<Nibbles, BranchNodeCompact>) {
        let updates = self.updated_branch_nodes.take();
        (self, updates.unwrap_or_default())
    }

    /// Take and return the proofs retained.
    pub fn take_proofs(&mut self) -> BTreeMap<Nibbles, Bytes> {
        self.proof_retainer.take().map(ProofRetainer::into_proofs).unwrap_or_default()
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
            println!("{}", hex::encode(item));
        }
        println!("============ END STACK ===============");
    }

    /// Adds a new leaf element and its value to the trie hash builder.
    pub fn add_leaf(&mut self, key: Nibbles, value: &[u8]) {
        assert!(key > self.key);
        if !self.key.is_empty() {
            self.update(&key);
        }
        self.set_key_value(key, value);
    }

    /// Adds a new branch element and its hash to the trie hash builder.
    pub fn add_branch(&mut self, key: Nibbles, value: B256, stored_in_database: bool) {
        assert!(key > self.key || (self.key.is_empty() && key.is_empty()));
        if !self.key.is_empty() {
            self.update(&key);
        } else if key.is_empty() {
            self.stack.push(word_rlp(&value));
        }
        self.set_key_value(key, value);
        self.stored_in_database = stored_in_database;
    }

    /// Returns the current root hash of the trie builder.
    pub fn root(&mut self) -> B256 {
        // Clears the internal state
        if !self.key.is_empty() {
            self.update(&Nibbles::default());
            self.key.clear();
            self.value = HashBuilderValue::Bytes(vec![]);
        }
        self.current_root()
    }

    fn set_key_value<T: Into<HashBuilderValue>>(&mut self, key: Nibbles, value: T) {
        trace!(target: "trie::hash_builder", key = ?self.key, value = ?self.value, "old key/value");
        self.key = key;
        self.value = value.into();
        trace!(target: "trie::hash_builder", key = ?self.key, value = ?self.value, "new key/value");
    }

    fn current_root(&self) -> B256 {
        if let Some(node_ref) = self.stack.last() {
            if node_ref.len() == B256::len_bytes() + 1 {
                B256::from_slice(&node_ref[1..])
            } else {
                keccak256(node_ref)
            }
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
        let mut current = self.key.clone();

        trace!(target: "trie::hash_builder", ?current, ?succeeding, "updating merkle tree");

        let mut i = 0usize;
        loop {
            let _span = tracing::trace_span!(target: "trie::hash_builder", "loop", i, ?current, build_extensions).entered();

            let preceding_exists = !self.groups.is_empty();
            let preceding_len = self.groups.len().saturating_sub(1);

            let common_prefix_len = succeeding.common_prefix_length(current.as_slice());
            let len = cmp::max(preceding_len, common_prefix_len);
            assert!(len < current.len());

            trace!(
                target: "trie::hash_builder",
                ?len,
                ?common_prefix_len,
                ?preceding_len,
                preceding_exists,
                "prefix lengths after comparing keys"
            );

            // Adjust the state masks for branch calculation
            let extra_digit = current[len];
            if self.groups.len() <= len {
                let new_len = len + 1;
                trace!(target: "trie::hash_builder", new_len, old_len = self.groups.len(), "scaling state masks to fit");
                self.groups.resize(new_len, TrieMask::default());
            }
            self.groups[len] |= TrieMask::from_nibble(extra_digit);
            trace!(
                target: "trie::hash_builder",
                ?extra_digit,
                groups = ?self.groups,
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
                match &self.value {
                    HashBuilderValue::Bytes(leaf_value) => {
                        let leaf_node = LeafNodeRef::new(&short_node_key, leaf_value);
                        trace!(target: "trie::hash_builder", ?leaf_node, "pushing leaf node");
                        trace!(target: "trie::hash_builder", rlp = {
                            self.rlp_buf.clear();
                            hex::encode(leaf_node.rlp(&mut self.rlp_buf))
                        }, "leaf node rlp");

                        self.rlp_buf.clear();
                        self.stack.push(leaf_node.rlp(&mut self.rlp_buf));
                        self.retain_proof_from_buf(&current.slice(..len_from));
                    }
                    HashBuilderValue::Hash(hash) => {
                        trace!(target: "trie::hash_builder", ?hash, "pushing branch node hash");
                        self.stack.push(word_rlp(hash));

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
                let stack_last =
                    self.stack.pop().expect("there should be at least one stack item; qed");
                let extension_node = ExtensionNodeRef::new(&short_node_key, &stack_last);
                trace!(target: "trie::hash_builder", ?extension_node, "pushing extension node");
                trace!(target: "trie::hash_builder", rlp = {
                    self.rlp_buf.clear();
                    hex::encode(extension_node.rlp(&mut self.rlp_buf))
                }, "extension node rlp");

                self.rlp_buf.clear();
                self.stack.push(extension_node.rlp(&mut self.rlp_buf));
                self.retain_proof_from_buf(&current.slice(..len_from));
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
                // Need to store the branch node in an efficient format
                // outside of the hash builder
                self.store_branch_node(&current, len, children);
            }

            self.groups.resize(len, TrieMask::default());
            self.resize_masks(len);

            if preceding_len == 0 {
                trace!(target: "trie::hash_builder", "0 or 1 state masks means we have no more elements to process");
                return;
            }

            current.truncate(preceding_len);
            trace!(target: "trie::hash_builder", ?current, "truncated nibbles to {} bytes", preceding_len);

            trace!(target: "trie::hash_builder", groups = ?self.groups, "popping empty state masks");
            while self.groups.last() == Some(&TrieMask::default()) {
                self.groups.pop();
            }

            build_extensions = true;

            i += 1;
        }
    }

    /// Given the size of the longest common prefix, it proceeds to create a branch node
    /// from the state mask and existing stack state, and store its RLP to the top of the stack,
    /// after popping all the relevant elements from the stack.
    fn push_branch_node(&mut self, current: &Nibbles, len: usize) -> Vec<B256> {
        let state_mask = self.groups[len];
        let hash_mask = self.hash_masks[len];
        let branch_node = BranchNodeRef::new(&self.stack, &state_mask);
        let children = branch_node.child_hashes(hash_mask).collect();

        self.rlp_buf.clear();
        let rlp = branch_node.rlp(&mut self.rlp_buf);
        self.retain_proof_from_buf(&current.slice(..len));

        // Clears the stack from the branch node elements
        let first_child_idx = self.stack.len() - state_mask.count_ones() as usize;
        trace!(
            target: "trie::hash_builder",
            new_len = first_child_idx,
            old_len = self.stack.len(),
            "resizing stack to prepare branch node"
        );
        self.stack.resize(first_child_idx, vec![]);

        trace!(target: "trie::hash_builder", "pushing branch node with {:?} mask from stack", state_mask);
        trace!(target: "trie::hash_builder", rlp = hex::encode(&rlp), "branch node rlp");
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
            self.hash_masks[parent_index] |= TrieMask::from_nibble(current[parent_index]);
        }

        let store_in_db_trie = !self.tree_masks[len].is_empty() || !self.hash_masks[len].is_empty();
        if store_in_db_trie {
            if len > 0 {
                let parent_index = len - 1;
                self.tree_masks[parent_index] |= TrieMask::from_nibble(current[parent_index]);
            }

            let mut n = BranchNodeCompact::new(
                self.groups[len],
                self.tree_masks[len],
                self.hash_masks[len],
                children,
                None,
            );

            if len == 0 {
                n.root_hash = Some(self.current_root());
            }

            // Send it over to the provided channel which will handle it on the
            // other side of the HashBuilder
            trace!(target: "trie::hash_builder", node = ?n, "intermediate node");
            let common_prefix = current.slice(..len);
            if let Some(nodes) = self.updated_branch_nodes.as_mut() {
                nodes.insert(common_prefix, n);
            }
        }
    }

    fn retain_proof_from_buf(&mut self, prefix: &Nibbles) {
        if let Some(proof_retainer) = self.proof_retainer.as_mut() {
            proof_retainer.retain(prefix, &self.rlp_buf)
        }
    }

    fn update_masks(&mut self, current: &Nibbles, len_from: usize) {
        if len_from > 0 {
            let flag = TrieMask::from_nibble(current[len_from - 1]);

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
    use alloy_primitives::{b256, hex, U256};
    use alloy_rlp::Encodable;

    // Hashes the keys, RLP encodes the values, compares the trie builder with the upstream root.
    fn assert_hashed_trie_root<'a, I, K>(iter: I)
    where
        I: Iterator<Item = (K, &'a U256)>,
        K: AsRef<[u8]> + Ord,
    {
        let hashed = iter
            .map(|(k, v)| (keccak256(k.as_ref()), alloy_rlp::encode(v).to_vec()))
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
        I: Iterator<Item = (K, V)>,
        K: AsRef<[u8]> + Ord,
        V: AsRef<[u8]>,
    {
        let mut hb = HashBuilder::default();

        let data = iter.collect::<BTreeMap<_, _>>();
        data.iter().for_each(|(key, val)| {
            let nibbles = Nibbles::unpack(key);
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
        proptest!(|(state: BTreeMap<B256, U256>)| {
            assert_hashed_trie_root(state.iter());
        });
    }

    #[test]
    fn test_generates_branch_node() {
        let mut hb = HashBuilder::default().with_updates(true);

        // We have 1 branch node update to be stored at 0x01, indicated by the first nibble.
        // That branch root node has 2 branch node children present at 0x1 and 0x2.
        // - 0x1 branch: It has the 2 empty items, at `0` and `1`.
        // - 0x2 branch: It has the 2 empty items, at `0` and `2`.
        // This is enough information to construct the intermediate node value:
        // 1. State Mask: 0b111. The children of the branch + the branch value at `0`, `1` and `2`.
        // 2. Hash Mask: 0b110. Of the above items, `1` and `2` correspond to sub-branch nodes.
        // 3. Tree Mask: 0b000.
        // 4. Hashes: The 2 sub-branch roots, at `1` and `2`, calculated by hashing
        // the 0th and 1st element for the 0x1 branch (according to the 3rd nibble),
        // and the 0th and 2nd element for the 0x2 branch (according to the 3rd nibble).
        // This basically means that every BranchNodeCompact is capable of storing up to 2 levels
        // deep of nodes (?).
        let data = BTreeMap::from([
            (
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
                // unrelated leaf
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
        assert_eq!(update.state_mask, TrieMask::new(0b1111)); // 1st nibble: 0, 1, 2, 3
        assert_eq!(update.tree_mask, TrieMask::new(0));
        assert_eq!(update.hash_mask, TrieMask::new(6)); // in the 1st nibble, the ones with 1 and 2 are branches with `hashes`
        assert_eq!(update.hashes.len(), 2); // calculated while the builder is running

        assert_eq!(_root, triehash_trie_root(data));
    }

    #[test]
    fn test_root_raw_data() {
        let data = vec![
            (hex!("646f").to_vec(), hex!("76657262").to_vec()),
            (hex!("676f6f64").to_vec(), hex!("7075707079").to_vec()),
            (hex!("676f6b32").to_vec(), hex!("7075707079").to_vec()),
            (hex!("676f6b34").to_vec(), hex!("7075707079").to_vec()),
        ];
        assert_trie_root(data.into_iter());
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
            hb.add_leaf(Nibbles::unpack(key), val.as_slice());
        }

        // Manually create the branch node that should be there after the first 2 leaves are added.
        // Skip the 0th element given in this example they have a common prefix and will
        // collapse to a Branch node.
        let leaf1 = LeafNode::new(Nibbles::unpack(&raw_input[0].0[1..]), raw_input[0].1.clone());
        let leaf2 = LeafNode::new(Nibbles::unpack(&raw_input[1].0[1..]), raw_input[1].1.clone());
        let mut branch: [&dyn Encodable; 17] = [b""; 17];
        // We set this to `4` and `7` because that mathces the 2nd element of the corresponding
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

    #[test]
    fn test_updates_root() {
        // let subscriber = tracing_subscriber::FmtSubscriber::builder()
        //     .with_max_level(tracing::Level::TRACE)
        //     .finish();
        // tracing::subscriber::set_global_default(subscriber).unwrap();
        let mut hb = HashBuilder::default().with_updates(true);
        let account = Vec::new();

        let mut key = Nibbles::unpack(hex!(
            "a711355ec1c8f7e26bb3ccbcb0b75d870d15846c0b98e5cc452db46c37faea40"
        ));
        hb.add_leaf(key, account.as_ref());

        key = Nibbles::unpack(hex!(
            "a77d337781e762f3577784bab7491fcc43e291ce5a356b9bc517ac52eed3a37a"
        ));
        hb.add_leaf(key, account.as_ref());

        key = Nibbles::unpack(hex!(
            "a77d397a32b8ab5eb4b043c65b1f00c93f517bc8883c5cd31baf8e8a279475e3"
        ));
        hb.add_leaf(key, account.as_ref());

        key = Nibbles::unpack(hex!(
            "a7f936599f93b769acf90c7178fd2ddcac1b5b4bc9949ee5a04b7e0823c2446e"
        ));
        hb.add_leaf(key, account.as_ref());

        let _root = hb.root();
        let (_, updates) = hb.split();
        assert!(updates.len() > 0);
    }
}
