use crate::{Nibbles, TrieMask};
use alloc::vec::Vec;
use alloy_primitives::{B256, map::B256Set};

/// Provides added and removed keys for an account or storage trie.
///
/// Used by the [`crate::proof::ProofRetainer`] to determine which nodes may be ancestors of newly
/// added or removed leaves. This information allows for generation of more complete proofs which
/// include the nodes necessary for adding and removing leaves from the trie.
#[derive(Debug, Default, Clone)]
pub struct AddedRemovedKeys {
    /// Keys which are known to be removed from the trie.
    removed_keys: B256Set,
    /// Keys which are known to be added to the trie.
    added_keys: B256Set,
    /// Assume that all keys have been added.
    assume_added: bool,
    /// Cached sorted nibbles for removed keys (for O(log n) prefix lookup).
    removed_nibbles: Vec<Nibbles>,
    /// Cached sorted nibbles for added keys (for O(log n) prefix lookup).
    added_nibbles: Vec<Nibbles>,
}

impl AsRef<Self> for AddedRemovedKeys {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AddedRemovedKeys {
    /// Sets the `assume_added` flag, which can be used instead of `insert_added` if exact
    /// additions aren't known and you want to optimistically collect all proofs which _might_ be
    /// necessary.
    pub const fn with_assume_added(mut self, assume_added: bool) -> Self {
        self.assume_added = assume_added;
        self
    }

    /// Sets the key as being a removed key. This removes the key from the `added_keys` set if it
    /// was previously inserted into it.
    pub fn insert_removed(&mut self, key: B256) {
        // Remove from added keys
        if self.added_keys.remove(&key) {
            let nibbles = Nibbles::unpack(&key);
            if let Ok(idx) = self.added_nibbles.binary_search(&nibbles) {
                self.added_nibbles.remove(idx);
            }
        }
        // Insert into removed keys
        if self.removed_keys.insert(key) {
            let nibbles = Nibbles::unpack(&key);
            let idx = self.removed_nibbles.partition_point(|n| n < &nibbles);
            self.removed_nibbles.insert(idx, nibbles);
        }
    }

    /// Unsets the key as being a removed key.
    pub fn remove_removed(&mut self, key: &B256) {
        if self.removed_keys.remove(key) {
            let nibbles = Nibbles::unpack(key);
            if let Ok(idx) = self.removed_nibbles.binary_search(&nibbles) {
                self.removed_nibbles.remove(idx);
            }
        }
    }

    /// Sets the key as being an added key. This removes the key from the `removed_keys` set if it
    /// was previously inserted into it.
    pub fn insert_added(&mut self, key: B256) {
        // Remove from removed keys
        if self.removed_keys.remove(&key) {
            let nibbles = Nibbles::unpack(&key);
            if let Ok(idx) = self.removed_nibbles.binary_search(&nibbles) {
                self.removed_nibbles.remove(idx);
            }
        }
        // Insert into added keys
        if self.added_keys.insert(key) {
            let nibbles = Nibbles::unpack(&key);
            let idx = self.added_nibbles.partition_point(|n| n < &nibbles);
            self.added_nibbles.insert(idx, nibbles);
        }
    }

    /// Clears all keys which have been added via `insert_added`.
    pub fn clear_added(&mut self) {
        self.added_keys.clear();
        self.added_nibbles.clear();
    }

    /// Returns true if the given key path is marked as removed.
    pub fn is_removed(&self, path: &B256) -> bool {
        self.removed_keys.contains(path)
    }

    /// Returns true if the given key path is marked as added.
    pub fn is_added(&self, path: &B256) -> bool {
        self.assume_added || self.added_keys.contains(path)
    }

    /// Returns true if the given path prefix is the prefix of an added key.
    ///
    /// Uses binary search over cached sorted nibbles for O(log n) lookup.
    pub fn is_prefix_added(&self, prefix: &Nibbles) -> bool {
        if self.assume_added {
            return true;
        }
        if prefix.is_empty() {
            return !self.added_nibbles.is_empty();
        }
        // Binary search to find first key >= prefix
        let idx = self.added_nibbles.partition_point(|n| n < prefix);
        idx < self.added_nibbles.len() && self.added_nibbles[idx].starts_with(prefix)
    }

    /// Returns a mask containing a bit set for each child of the branch which is a prefix of a
    /// removed leaf.
    ///
    /// Uses binary search to find the range of matching keys for O(log n + m) where m is matches.
    pub fn get_removed_mask(&self, branch_path: &Nibbles) -> TrieMask {
        let mut mask = TrieMask::default();

        // Binary search to find first key >= branch_path
        let start = self.removed_nibbles.partition_point(|n| n < branch_path);

        // Iterate only through keys that could match
        for nibbles in self.removed_nibbles.iter().skip(start) {
            if !nibbles.starts_with(branch_path) {
                break; // No more matches possible (sorted order)
            }
            let child_bit = nibbles.get_unchecked(branch_path.len());
            mask.set_bit(child_bit);
        }
        mask
    }
}
