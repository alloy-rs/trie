use crate::{BranchNodeCompact, Nibbles};

/// Account storage trie node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StorageTrieEntry {
    /// The nibbles of the intermediate node
    pub nibbles: Nibbles,
    /// Encoded node.
    pub node: BranchNodeCompact,
}
